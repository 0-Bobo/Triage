"""Static self-modifying-code unwrap.

Some reversing challenges ship the real code encrypted and decrypt it in a
tiny ``RWE`` stub at entry. The canonical shape: mangled ``e_ident``,
overlapping ``RWX`` ``PT_LOAD``s, and a ~68-byte decoder that walks the text
backwards running e.g. ``ror 7 / not / rol 3`` on every byte. When the decoder
takes **no key** — the transform is fixed — the plaintext is fully recoverable
without running anything.

This strategy does not try to disassemble an arbitrary obfuscated decoder.
Instead it:

1. detects the SMC shape (RWE ``PT_LOAD``, or a trashed ELF ``e_ident``),
2. repairs the header if needed,
3. brute-forces a small family of reversible per-byte transforms over the
   RWE region — identity, ``xor k``, ``not``, ``rol/ror n``, ``add/sub k``
   and the reference composite ``rol1; not; rol3`` (+ its inverse) — scoring
   each result by how much of it decodes as valid x86 and whether flag-shaped
   ASCII appears,
4. writes the repaired + decoded image to a temp file and re-runs the flag
   scan plus the ``emulate`` / ``keygen`` strategies on the clear image.

Even when no flag falls out, the decoded artifact + the recovered transform
are handed back — that is the manual next step served on a plate.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from triage_web.autopwn.runner import extract_flags
from triage_web.loader import BinaryLoader

HAS_CAPSTONE = importlib.util.find_spec("capstone") is not None  # engine.Disassembler needs it

_ELF_MAGIC = b"\x7fELF"
_DEFAULT_LOAD_BASE = 0x400000  # non-PIE statics live here


@dataclass
class SmcResult:
    ok: bool
    flag: str | None = None
    transform: str | None = None  # human-readable description of the winning unwrap
    region: tuple[int, int] | None = None  # (file_off, length) that was decoded
    decoded_path: str | None = None  # repaired + decrypted image on disk
    header_repaired: bool = False
    antidebug_patched: bool = False  # hand-rolled fork/ptrace syscalls neutralised
    score: float = 0.0  # valid-x86 ratio of the decoded region
    reason: str = ""
    log: list[str] = field(default_factory=list)


# ── the per-byte transform family ───────────────────────────────────────


def _rol(x: int, n: int) -> int:
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF if n else x & 0xFF


def _ref_decode(x: int) -> int:
    """The reference composite decoder: ``ror 7`` (== ``rol 1``
    for a byte), then ``not``, then ``rol 3``."""
    x = _rol(x, 1)
    x = (~x) & 0xFF
    return _rol(x, 3)


def _ref_encode(x: int) -> int:
    x = _rol(x, 5)  # inverse of rol 3
    x = (~x) & 0xFF
    return _rol(x, 7)  # inverse of rol 1


def _transforms() -> list[tuple[str, list[int]]]:
    """``(name, 256-entry lookup table)`` for every candidate unwrap."""
    out: list[tuple[str, list[int]]] = [("identity", list(range(256)))]
    out.append(("not", [(~x) & 0xFF for x in range(256)]))
    for k in range(1, 256):
        out.append((f"xor 0x{k:02x}", [x ^ k for x in range(256)]))
    for n in range(1, 8):
        out.append((f"rol {n}", [_rol(x, n) for x in range(256)]))
        out.append((f"ror {n}", [_rol(x, 8 - n) for x in range(256)]))
    for k in (1, 2, 3, 4, 5, 7, 0x10, 0x2A, 0x7F, 0x80, 0xAA):
        out.append((f"sub 0x{k:02x}", [(x - k) & 0xFF for x in range(256)]))
        out.append((f"add 0x{k:02x}", [(x + k) & 0xFF for x in range(256)]))
    # this composite is an involution (rol1;not;rol3 == its own inverse)
    out.append(("rol1;not;rol3", [_ref_decode(x) for x in range(256)]))
    return out


def _apply(table: list[int], data: bytes) -> bytes:
    return bytes(table[b] for b in data)


# ── scoring ────────────────────────────────────────────────────────────

# Almost *any* byte stream disassembles to "some" x86 instruction and even a
# skip-junk sweep "covers" most garbage, so neither is a usable signal. What
# actually separates a correct decode from noise:
#
# * **structural byte signatures** a real x86-64 image almost always contains
#   and random bytes almost never do — the SysV `_start` stack align, the
#   `push rbp; mov rbp, rsp` prologue, `endbr64`, multi-byte NOP padding;
# * a **low rate of junk / privileged / obsolete mnemonics** (capstone emits
#   `arpl`, `bound`, `das`, `outsb`, `lds`, `verr`… all over decoded garbage);
# * a **plausible control-flow fraction** — some branches, not zero, not half.
_START_SIGS = (
    b"\x48\x83\xe4\xf0",  # and rsp, 0xfffffffffffffff0   (_start)
    b"\x55\x48\x89\xe5",  # push rbp ; mov rbp, rsp        (frame prologue)
    b"\xf3\x0f\x1e\xfa",  # endbr64                        (CET)
    b"\x0f\x1f\x44",  # nop dword [rax+rax+0]          (alignment padding)
    b"\x48\x8d\x3d",  # lea rdi, [rip + x]             (string/arg load)
)
_JUNK_MNEMONICS = frozenset(
    """arpl bound das daa aaa aas salc les lds lcall ljmp retf insb insd outsb outsd
    verr verw sldt lldt ltr str lar lsl rsm ud0 ud1 femms getsec
    lods stos scas xlatb in out int1 into hlt iretd iret sysenter sysexit""".split()
)
_CF_MNEMONICS = frozenset(
    "call jmp ret je jne jz jnz jg jge jl jle ja jae jb jbe js jns jo jno jp loop test cmp".split()
)


def _disasm_rows(code: bytes, bits: int) -> list[dict]:
    try:
        from triage_web.engine import Disassembler

        return Disassembler("x86_64" if bits == 64 else "x86").disassemble(code, 0, skip_junk=True)
    except Exception:  # pragma: no cover - engine/capstone unavailable
        return []


def _code_score(code: bytes, bits: int = 64) -> float:
    """0..1 — how much this looks like a real x86 function body."""
    if not HAS_CAPSTONE or len(code) < 16:
        return 0.0
    sigs = sum(1 for s in _START_SIGS if s in code)
    struct = min(1.0, 0.4 * sigs)

    rows = _disasm_rows(code, bits)
    n = len(rows)
    if n < 8:
        return 0.15 * struct
    junk = sum(1 for r in rows if r["mnemonic"] in _JUNK_MNEMONICS) / n
    cf = sum(1 for r in rows if r["mnemonic"] in _CF_MNEMONICS) / n
    sanity = max(0.0, 1.0 - 6.0 * junk)
    cf_ok = 1.0 if 0.04 <= cf <= 0.45 else 0.3
    return 0.5 * struct + 0.35 * sanity + 0.15 * cf_ok


def _score(decoded: bytes, bits: int) -> float:
    s = _code_score(decoded, bits)
    if extract_flags(decoded):
        s += 0.25
    return s


_MARGIN = 0.15  # a real decode is a landslide over identity, not a nose


def _best_transform(region: bytes, bits: int) -> tuple[str, list[int], float]:
    """Pick the transform whose output looks most like real code. Identity
    wins unless a transform beats the as-is region by a clear margin — so a
    binary that simply isn't encrypted is reported as ``identity``, not
    "unwrapped" into noise that happens to score a hair higher."""
    identity_tbl = list(range(256))
    base = _score(region, bits)
    best_name, best_tbl, best_score = "identity", identity_tbl, base
    for name, tbl in _transforms():
        if name == "identity":
            continue
        s = _score(_apply(tbl, region), bits)
        if s > best_score:
            best_name, best_tbl, best_score = name, tbl, s
    if best_name != "identity" and best_score < base + _MARGIN:
        return "identity", identity_tbl, base
    return best_name, best_tbl, best_score


# ── ELF header repair ──────────────────────────────────────────────────


def _repair_eident(raw: bytearray) -> bool:
    """Such a target overwrites ``e_ident[4..15]``. Restore a sane 64-bit LE
    identification block. Returns True if anything changed."""
    if raw[:4] != _ELF_MAGIC or len(raw) < 20:
        return False
    want = bytes([2, 1, 1, 0]) + b"\x00" * 8  # class64, LE, version1, then padding
    if raw[4:16] == want:
        return False
    raw[4:16] = want
    return True


def _rwe_region(ldr: BinaryLoader) -> tuple[int, int] | None:
    """File offset + length of the writable-executable ``PT_LOAD`` span,
    using ``vaddr - 0x400000`` as the offset for non-PIE statics."""
    for seg in ldr.get_segments():
        if seg["type"] == "PT_LOAD" and set(seg["flags"]) >= {"W", "X"}:
            off = max(0, seg["vaddr"] - _DEFAULT_LOAD_BASE)
            length = min(seg["filesz"], 0x4000)  # cap: decoders wrap the text, not the whole file
            if length >= 16:
                return off, length
    return None


def _phdrs(raw: bytes) -> list[dict]:
    """Hand-rolled ELF64-LE program-header parse — works on files pyelftools
    rejects (overlapping segments, no section table)."""
    import struct

    if len(raw) < 64 or raw[:4] != _ELF_MAGIC or raw[4] != 2:
        return []
    e_phoff = struct.unpack_from("<Q", raw, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", raw, 0x36)[0]
    e_phnum = struct.unpack_from("<H", raw, 0x38)[0]
    out = []
    for i in range(min(e_phnum, 64)):
        b = e_phoff + i * e_phentsize
        if b + 56 > len(raw):
            break
        p_type, p_flags = struct.unpack_from("<II", raw, b)
        p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack_from("<QQQQQQ", raw, b + 8)
        out.append(
            {
                "phoff": b,
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
            }
        )
    return out


def _drop_contained_load(raw: bytearray) -> list[str]:
    """Zero the ``p_type`` of any non-primary ``PT_LOAD`` whose span sits
    entirely inside another ``PT_LOAD`` — the overlapping stub segment that
    makes ``cle`` / angr throw ``Can't find backer to remove``. After the SMC
    decode + ``e_entry`` repoint that segment is dead weight."""
    import struct

    loads = [p for p in _phdrs(bytes(raw)) if p["type"] == 1]
    if len(loads) < 2:
        return []
    notes: list[str] = []
    for p in loads:
        span = (p["vaddr"], p["vaddr"] + max(p["memsz"], p["filesz"]))
        for q in loads:
            if q is p:
                continue
            qend = q["vaddr"] + max(q["memsz"], q["filesz"])
            if q["vaddr"] <= span[0] and span[1] <= qend and (span[1] - span[0]) < (qend - q["vaddr"]):
                struct.pack_into("<I", raw, p["phoff"], 0)  # PT_NULL
                notes.append(f"dropped overlapping PT_LOAD @ vaddr {p['vaddr']:#x} (len {span[1] - span[0]:#x})")
                break
    return notes


def _decoder_region(raw: bytes) -> tuple[int, int] | None:
    """Read the entry decoder stub and recover the byte range it rewrites.

    The decoder stub is ``mov eax, END ; mov ecx, COUNT ; loop { transform
    [rax]; dec rax }`` — so the encrypted span is ``[END-COUNT, END]``. We
    skip-junk-disassemble the smallest executable segment covering
    ``e_entry`` and pull the two largest 32-bit immediates that look like an
    in-image code pointer and an iteration count."""
    import struct

    phdrs = _phdrs(raw)
    if not phdrs:
        return None
    e_entry = struct.unpack_from("<Q", raw, 0x18)[0]
    loads = [p for p in phdrs if p["type"] == 1]
    image_base = min((p["vaddr"] for p in loads), default=_DEFAULT_LOAD_BASE)
    stub = min(
        (p for p in phdrs if p["flags"] & 1 and p["vaddr"] <= e_entry < p["vaddr"] + p["filesz"]),
        key=lambda p: p["filesz"],
        default=None,
    )
    if stub is None:
        return None
    code = raw[stub["offset"] : stub["offset"] + min(stub["filesz"], 0x200)]
    try:
        from triage_web.engine import Disassembler

        insns = Disassembler("x86_64").disassemble(code, stub["vaddr"], skip_junk=True)
    except Exception:  # pragma: no cover - capstone/engine unavailable
        return None

    imms: list[int] = []
    for ins in insns:
        if ins["mnemonic"] in ("mov", "add", "sub", "lea") and "," in ins["op_str"]:
            tail = ins["op_str"].split(",")[-1].strip().lstrip("$")
            try:
                imms.append(int(tail, 16) if tail.startswith("0x") else int(tail))
            except ValueError:
                continue
    big_lo, big_hi = image_base, image_base + max((p["filesz"] for p in loads), default=0x4000)
    ends = [v for v in imms if big_lo <= v <= big_hi]
    counts = [v for v in imms if 0x10 <= v <= 0x8000]
    if not ends or not counts:
        return None
    end = max(ends)
    count = max(c for c in counts if c < end - big_lo) if any(c < end - big_lo for c in counts) else max(counts)
    # the loop rewrites `count` bytes ending *at* `end` inclusive: [end-count+1, end]
    start_off = (end - image_base) - count + 1
    if start_off < 0 or (end - image_base) >= len(raw):
        return None
    return start_off, count


# ── hand-rolled anti-debug neutralisation ─────────────────────────────

# SMC challenges routinely pair the decoder with hand-written syscall stubs
# for `fork` + `ptrace(PTRACE_ATTACH/TRACEME)` so the real check runs across a
# cooperating process tree that no static tool (or plain unicorn/angr) can
# follow. Symbol interposition (`LD_PRELOAD`) can't touch a raw `syscall`
# instruction — but the decoded image is on disk now, so we can. Forcing the
# fork/clone stub to "return 0" collapses the tree to one process; forcing
# ptrace to "return 0" makes every anti-trace check pass.
_NEUTER_SYSCALLS = {
    56: "clone",
    57: "fork",
    58: "vfork",
    101: "ptrace",
}


def _neuter_antidebug(raw: bytearray, image_base: int, text: tuple[int, int]) -> list[str]:
    """Patch `mov (r|e)ax, <fork|clone|ptrace>; syscall` → `... ; xor eax, eax`
    in the decoded text. Returns a note per stub patched."""
    off, length = text
    try:
        from triage_web.engine import Disassembler

        rows = Disassembler("x86_64").disassemble(bytes(raw[off : off + length]), image_base + off, skip_junk=True)
    except Exception:  # pragma: no cover - engine/capstone unavailable
        return []
    notes: list[str] = []
    last_imm: int | None = None
    for ins in rows:
        m, ops = ins["mnemonic"], ins["op_str"].replace(" ", "")
        if m == "mov" and ops.startswith(("rax,", "eax,")):
            tail = ops.split(",", 1)[1]
            try:
                last_imm = int(tail, 16) if tail.startswith("0x") else int(tail)
            except ValueError:
                last_imm = None
        elif m == "syscall" and last_imm in _NEUTER_SYSCALLS:
            pos = ins["address"] - image_base
            if raw[pos : pos + 2] == b"\x0f\x05":
                raw[pos : pos + 2] = b"\x31\xc0"  # xor eax, eax → the stub now returns 0
                notes.append(f"neutralised hand-rolled {_NEUTER_SYSCALLS[last_imm]}() syscall @ {ins['address']:#x}")
            last_imm = None
    return notes


# ── entry point ────────────────────────────────────────────────────────


def _discard_unless_kept(work: str, result: SmcResult) -> SmcResult:
    """Delete the staged ``work`` copy unless ``result`` hands it back as
    ``decoded_path``. Every strategy run that doesn't produce a useful decode
    has no further use for the on-disk copy — without this, every classified
    SMC candidate that isn't actually decodable (the common case) leaves a
    full copy of the binary behind in the temp dir forever."""
    if result.decoded_path != work:
        try:
            os.unlink(work)
        except OSError:
            pass
    return result


def solve_smc(path: str, *, chain: bool = True, neuter_antidebug: bool = True, timeout: float = 30.0) -> SmcResult:
    if not HAS_CAPSTONE:
        return SmcResult(False, reason="capstone not installed")

    raw = bytearray(Path(path).read_bytes())
    if raw[:4] != _ELF_MAGIC:
        return SmcResult(False, reason="not an ELF")

    log: list[str] = []
    repaired = _repair_eident(raw)
    if repaired:
        log.append("repaired mangled e_ident[4..15]")

    tmp = tempfile.NamedTemporaryFile(prefix="triage_smc_", suffix=".elf", delete=False)
    tmp.write(raw)
    tmp.close()
    work = tmp.name

    ldr = BinaryLoader(work)
    try:
        bits = ldr.get_info().get("bits", 64)
        rwe = _rwe_region(ldr)
    except Exception as exc:  # pragma: no cover - repaired header still unparseable
        return _discard_unless_kept(
            work, SmcResult(False, reason=f"cannot parse after repair: {exc}", header_repaired=repaired, log=log)
        )
    finally:
        ldr.close()

    # Prefer the exact span the entry stub rewrites; fall back to the whole
    # RWE segment, then the whole file.
    stub_region = _decoder_region(bytes(raw))
    region = stub_region or rwe
    if stub_region:
        log.append(f"entry decoder stub rewrites [0x{stub_region[0]:x}..0x{stub_region[0] + stub_region[1]:x}]")
    if region is None and not repaired:
        return _discard_unless_kept(
            work, SmcResult(False, reason="no RWE segment and header looks intact — not an SMC target", log=log)
        )
    off, length = region or (0, min(len(raw), 0x4000))

    name, tbl, score = _best_transform(bytes(raw[off : off + length]), bits)
    log.append(f"region [0x{off:x}..0x{off + length:x}] best unwrap: {name!r} (x86-valid score {score:.2f})")
    if name == "identity":
        return _discard_unless_kept(
            work,
            SmcResult(
                False,
                reason="no per-byte transform made the RWE region look like code",
                transform="identity",
                region=(off, length),
                header_repaired=repaired,
                decoded_path=work if repaired else None,
                log=log,
            ),
        )

    raw[off : off + length] = _apply(tbl, bytes(raw[off : off + length]))

    antidebug = False
    if neuter_antidebug:
        notes = _neuter_antidebug(raw, _DEFAULT_LOAD_BASE, (off, length))
        if notes:
            antidebug = True
            log.extend(notes)

    entry_patched = False
    if stub_region and region is stub_region:
        # the decoder stub would re-run the (now inert) transform on plaintext
        # and corrupt it — repoint e_entry past it, at the decrypted region.
        import struct

        new_entry = _DEFAULT_LOAD_BASE + off
        if struct.unpack_from("<Q", raw, 0x18)[0] != new_entry:
            struct.pack_into("<Q", raw, 0x18, new_entry)
            entry_patched = True
            log.append(f"repointed e_entry to {new_entry:#x} (skips the spent decoder stub)")
        for note in _drop_contained_load(raw):  # make it cle/angr-loadable
            entry_patched = True
            log.append(note)
    Path(work).write_bytes(raw)

    res = SmcResult(
        ok=True,
        transform=name,
        region=(off, length),
        decoded_path=work,
        header_repaired=repaired or entry_patched,
        antidebug_patched=antidebug,
        score=score,
        log=log,
    )

    flags = extract_flags(bytes(raw))
    if flags:
        res.flag = flags[0]
        log.append(f"flag string in the decoded image: {flags[0]}")
        return res

    if chain:
        res.flag = _chain(work, timeout, log)

    if not res.flag:
        res.reason = "unwrapped the SMC layer; decoded image saved — run emulate/keygen/angr on it"
    return res


def _chain(decoded_path: str, timeout: float, log: list[str]) -> str | None:
    """Run the cheap static strategies against the now-clear image."""
    try:
        from triage_web.autopwn.strat_emulate import emulate_for_flag

        r = emulate_for_flag(decoded_path)
        if r.ok and r.flag:
            log.append(f"emulate on decoded image → {r.flag}")
            return r.flag
    except Exception as exc:  # pragma: no cover - backend optional / unstable
        log.append(f"emulate chain failed: {exc}")
    try:
        from triage_web.autopwn.strat_keygen import solve_keygen

        r = solve_keygen(decoded_path, timeout=timeout)
        if r.flag:
            log.append(f"keygen on decoded image → {r.flag}")
            return r.flag
    except Exception as exc:  # pragma: no cover
        log.append(f"keygen chain failed: {exc}")
    return None
