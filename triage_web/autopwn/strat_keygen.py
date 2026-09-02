"""Static keygen: recover an ``input == CONSTANT`` gate.

Many "enter the key" crackmes reduce to a single compare against a
hard-coded value that guards a call to the flag-printing routine. angr can
brute this too, but it is slow and it cannot touch some architectures
(SPARC). This strategy disassembles the guard, reads the constant, and —
when the win function builds its output from immediates — even
reconstructs the printed flag without running anything.

Handles x86 / x86-64 / SPARC / MIPS / ARM / AArch64 / PPC. On a runnable
x86 ELF it also feeds the recovered key to the process and captures the
real flag.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from triage_web.autopwn.runner import extract_flags, run_target, target_kind
from triage_web.loader import BinaryLoader

try:
    import capstone as _cs

    HAS_CAPSTONE = True
except ImportError:  # pragma: no cover
    HAS_CAPSTONE = False

_WIN_NAMES = ("win", "show_flag", "get_flag", "print_flag", "printflag", "backdoor", "secret", "success", "flag")
_BRANCH = {"je", "jz", "jne", "jnz", "beq", "bne", "be", "bnz", "cbz", "cbnz"}


@dataclass
class KeygenResult:
    ok: bool
    key: str | None = None  # formatted for the program's input (hex / decimal)
    key_int: int | None = None
    win: str | None = None
    win_addr: int | None = None
    guard_addr: int | None = None
    flag: str | None = None
    stdout: bytes = b""
    reason: str = ""
    log: list[str] = field(default_factory=list)


def solve_keygen(path: str, *, run: bool = True, timeout: float = 20.0) -> KeygenResult:
    if not HAS_CAPSTONE:
        return KeygenResult(False, reason="capstone not installed")
    ldr = BinaryLoader(path)
    log: list[str] = []
    try:
        info = ldr.get_info()
        md = _md_for(info)
        if md is None:
            return KeygenResult(False, reason=f"no disassembler mode for {info['arch']}", log=log)
        md.detail = False

        try:
            code, base = ldr._get_text_section()
        except Exception:  # pragma: no cover
            return KeygenResult(False, reason="could not read .text", log=log)
        insns = _disasm_all(md, bytes(code), base, fixed=info["arch"] not in ("x86", "x86_64"))
        if not insns:
            return KeygenResult(False, reason="disassembly produced nothing", log=log)

        wins = _win_addrs(ldr, log)
        if not wins:
            return KeygenResult(False, reason="no win-style function found", log=log)

        guard = _find_guard(insns, wins, log)
        if guard is None:
            return KeygenResult(False, reason="no constant-compare guard reaches the win function", log=log)
        key_int, guard_addr, win_addr = guard
        win_name = next((n for n, a in wins.items() if a == win_addr), hex(win_addr))
        log.append(f"guard @ {guard_addr:#x}: input must equal {key_int:#x} to reach {win_name}")

        fmt = _input_format(ldr)
        key_str = _format_key(key_int, fmt, info["bits"])
        res = KeygenResult(
            ok=True,
            key=key_str,
            key_int=key_int,
            win=win_name,
            win_addr=win_addr,
            guard_addr=guard_addr,
            log=log,
        )

        static_flag = _reconstruct_win_output(ldr, insns, win_addr, log)
        if static_flag:
            res.flag = static_flag

        if run and info["arch"] in ("x86", "x86_64") and target_kind(path) == "elf":
            proc = run_target(path, stdin=(key_str + "\n").encode(), timeout=timeout)
            res.stdout = proc.stdout + proc.stderr
            flags = extract_flags(res.stdout)
            if flags:
                res.flag = flags[0]
            elif proc.runnable:
                log.append(f"fed key {key_str!r}, program said: {proc.text.strip()[:160]!r}")

        if not res.flag:
            res.reason = "recovered the key but could not obtain the flag here — run the target with it"
        return res
    finally:
        ldr.close()


def _disasm_all(md, code: bytes, base: int, *, fixed: bool) -> list:
    """Linear sweep that survives bytes capstone can't decode.

    capstone's ``disasm`` generator halts at the first undecodable byte; on
    fixed-width ISAs (SPARC/MIPS/ARM/PPC) we step 4 and resume, on x86 we
    step 1, so a single bad opcode doesn't hide the rest of ``.text``."""
    out: list = []
    step = 4 if fixed else 1
    pos = 0
    while pos < len(code):
        got = list(md.disasm(code[pos:], base + pos))
        if got:
            out.extend(got)
            consumed = (got[-1].address + got[-1].size) - (base + pos)
            pos += max(consumed, step)
        else:
            pos += step
        if len(out) > 200_000:  # pragma: no cover - safety valve
            break
    return out


def _md_for(info):
    a, bits = info["arch"], info["bits"]
    be = _cs.CS_MODE_BIG_ENDIAN
    le = _cs.CS_MODE_LITTLE_ENDIAN
    table = {
        "x86_64": (_cs.CS_ARCH_X86, _cs.CS_MODE_64),
        "x86": (_cs.CS_ARCH_X86, _cs.CS_MODE_32),
        "ARM": (_cs.CS_ARCH_ARM, _cs.CS_MODE_ARM),
        "AArch64": (_cs.CS_ARCH_ARM64, _cs.CS_MODE_ARM),
        "SPARC": (_cs.CS_ARCH_SPARC, be),
        "SPARC64": (_cs.CS_ARCH_SPARC, be | _cs.CS_MODE_V9),
        "MIPS": (_cs.CS_ARCH_MIPS, (_cs.CS_MODE_MIPS64 if bits == 64 else _cs.CS_MODE_MIPS32) | be),
        "PPC": (_cs.CS_ARCH_PPC, _cs.CS_MODE_32 | be),
        "PPC64": (_cs.CS_ARCH_PPC, _cs.CS_MODE_64 | be),
    }
    got = table.get(a)
    if got is None:
        return None
    try:
        return _cs.Cs(*got)
    except _cs.CsError:  # pragma: no cover
        try:
            return _cs.Cs(got[0], le)
        except _cs.CsError:
            return None


def _win_addrs(ldr, log) -> dict[str, int]:
    out: dict[str, int] = {}
    for name, addr in ldr.get_functions():
        low = name.lower()
        if any(h in low for h in _WIN_NAMES):
            out[name] = addr
    if out:
        log.append("win candidates: " + ", ".join(f"{n}@{a:#x}" for n, a in out.items()))
    return out


def _imm_from_op(op: str) -> int | None:
    op = op.strip().lstrip("$#")
    if not re.fullmatch(r"-?0x[0-9a-fA-F]+|-?\d+", op):
        return None
    return int(op, 0) & 0xFFFFFFFFFFFFFFFF


_CMP = ("cmp", "cmpl", "cmpq", "subcc", "cmpw", "cmpwi", "subs", "cmpi", "cmpb")
_STOP = ("call", "callq", "jmp", "ret", "retl", "return", "jal", "bl")


_TRIVIAL = {0, 1, 2, 3, 4, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}


def _find_guard(insns, wins, log) -> tuple[int, int, int] | None:
    """For each branch/call whose target is a win function, walk the
    preceding basic block(s) *forward* keeping a reg→immediate map, and
    collect every compare-against-constant. Return the strongest — a magic
    value beats a loop counter / ``scanf() == 1`` return check."""
    win_set = set(wins.values())
    candidates: list[tuple[int, int, int]] = []
    for i, insn in enumerate(insns):
        tgt = _branch_target(insn)
        if tgt is None or tgt not in win_set:
            continue
        start = i - 1
        blocks = 0
        while start > 0 and start > i - 90:
            if insns[start - 1].mnemonic.lower() in _STOP:
                blocks += 1
                if blocks >= 2:  # allow one preceding basic block for the setup
                    break
            start -= 1
        reg_imm: dict[str, int] = {}
        for k in range(start, i):
            m = insns[k].mnemonic.lower()
            parts = [p.strip() for p in insns[k].op_str.split(",")]
            if m in _CMP:
                for p in parts:
                    v = _imm_from_op(p)
                    if v is None:
                        v = reg_imm.get(p)
                    if v is not None:
                        candidates.append((v, insns[k].address, tgt))
            elif m in ("mov", "movl", "movabs", "li", "ldi", "set", "movz", "movw") and len(parts) == 2:
                v = _imm_from_op(parts[1])
                if v is not None:
                    reg_imm[parts[0]] = v
            elif m == "sethi" and len(parts) == 2:
                v = _imm_from_op(parts[0])
                if v is not None:
                    reg_imm[parts[1]] = (v << 10) & 0xFFFFFFFF
            else:
                dst, imm = _accum_target(m, parts)
                if dst is not None and dst in reg_imm:
                    reg_imm[dst] |= imm
    if not candidates:
        return None
    non_trivial = [c for c in candidates if c[0] not in _TRIVIAL]
    pool = non_trivial or candidates
    # strongest = largest magnitude (a real key dwarfs a small enum / length check)
    best = max(pool, key=lambda c: c[0] if c[0] < 2**63 else c[0] - 2**64)
    if len(pool) > 1:
        log.append(f"compare guards seen: {[hex(c[0]) for c in candidates]}; chose {best[0]:#x}")
    return best


def _accum_target(mn: str, parts: list[str]) -> tuple[str | None, int]:
    """A ``dst |= imm`` low-bits accumulate, in either operand order:
    x86 ``or rd, imm`` (rd==parts[0]); SPARC ``or rs1, imm, rd`` (rs1==rd)."""
    if mn not in ("or", "add", "ori", "addi", "movk", "movt"):
        return None, 0
    if len(parts) == 2:  # x86: or rd, imm
        v = _imm_from_op(parts[1])
        return (parts[0], v) if v is not None else (None, 0)
    if len(parts) == 3 and parts[0] == parts[2]:  # SPARC: or rs1, imm, rd  (rs1 == rd)
        v = _imm_from_op(parts[1])
        return (parts[0], v) if v is not None else (None, 0)
    if len(parts) == 3 and parts[0] == parts[1]:  # or rd, rd, imm
        v = _imm_from_op(parts[2])
        return (parts[0], v) if v is not None else (None, 0)
    return None, 0


def _branch_target(insn) -> int | None:
    m = insn.mnemonic.lower()
    if m in ("call", "callq", "bl", "jal", "jmp") or m in _BRANCH or m.startswith(("b", "j")):
        return _imm_from_op(insn.op_str.split(",")[-1])
    return None


def _input_format(ldr) -> str:
    """'hex' | 'dec' — how the program reads its key."""
    try:
        blob = bytes(ldr._raw)
    except Exception:  # pragma: no cover
        return "hex"
    if b"%x" in blob or b"%X" in blob:
        return "hex"
    if re.search(rb"%l?[du]", blob):
        return "dec"
    return "hex"


def _format_key(key_int: int, fmt: str, bits: int) -> str:
    if fmt == "dec":
        signed = key_int
        if bits <= 32 and key_int >= 2**31:
            signed = key_int - 2**32
        return str(signed)
    return format(key_int, "x")


def _reconstruct_win_output(ldr, insns, win_addr, log) -> str | None:
    """Concatenate the printable 4-byte immediates the win function loads,
    prefixed by any 'NAME…%s'-style format string it uses."""
    body = [x for x in insns if win_addr <= x.address < win_addr + 0x200]
    if not body:
        return None
    chunks: list[bytes] = []
    reg_hi: dict[str, int] = {}
    started = False

    def _take(word_be: int, order: str) -> bool:  # returns True to keep scanning
        nonlocal started
        width = 8 if (order == "le" and word_be >> 32) else 4
        b = word_be.to_bytes(width, "big" if order == "be" else "little")
        if all(32 <= c < 127 for c in b):
            chunks.append(b)
            started = True
            return True
        return not started  # once a run started, the first non-ASCII word ends it

    for x in body:
        m = x.mnemonic.lower()
        if m in ("call", "callq", "jal", "bl"):
            break  # the string is assembled before the print call
        parts = [p.strip() for p in x.op_str.split(",")]
        if m == "sethi" and len(parts) == 2:
            v = _imm_from_op(parts[0])
            if v is not None:
                reg_hi[parts[1]] = (v << 10) & 0xFFFFFFFF
        elif (dst := _accum_target(m, parts)[0]) is not None and dst in reg_hi:
            full = (reg_hi.pop(dst) | _accum_target(m, parts)[1]) & 0xFFFFFFFF
            if not _take(full, "be"):
                break
        elif m in ("mov", "movabs", "movl") and len(parts) == 2:
            v = _imm_from_op(parts[1])
            if v is not None and v >> 8 and not _take(v, "le"):
                break
    body_str = b"".join(chunks).rstrip(b"\x00")
    if not body_str or not body_str.isascii():
        return None
    prefix = _win_format_prefix(ldr)
    for cand in ((prefix + body_str.decode("latin-1")), "FLAG-" + body_str.decode("latin-1")):
        hits = extract_flags(cand.encode())
        if hits:
            log.append(f"statically reconstructed win output: {hits[0]}")
            return hits[0]
    return None


def _win_format_prefix(ldr) -> str:
    try:
        blob = bytes(ldr._raw)
    except Exception:  # pragma: no cover
        return ""
    m = re.search(rb"([A-Za-z0-9_]{2,12}[-_]?)%s", blob)
    return m.group(1).decode("latin-1") if m else ""
