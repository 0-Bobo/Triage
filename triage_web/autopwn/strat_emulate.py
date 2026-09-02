"""Concrete function emulation for "the flag is built/printed in memory" CTFs.

Maps the target's PT_LOAD segments into unicorn, runs one function (``main``
by default) with libc PLT stubs modelled in Python, then scans captured
output and all writable memory for a flag. Deterministic and fast — the
right tool when a program constructs the flag but never shows it
(``Binaries/challenge1``), or prints it through a hand-rolled routine.

x86 / x86-64 ELF only. Anything else returns ``ok=False`` and the caller
should fall through to angr.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from triage_web.autopwn.runner import extract_flags
from triage_web.loader import BinaryLoader

try:
    import unicorn as _uc
    import unicorn.x86_const as _x86

    HAS_UNICORN = True
except ImportError:  # pragma: no cover - unicorn is an install-time optional dep
    HAS_UNICORN = False


@dataclass
class EmulateResult:
    ok: bool
    flag: str | None = None
    stdout: bytes = b""
    reason: str = ""
    memory_hits: list[str] = field(default_factory=list)
    trace_tail: list[str] = field(default_factory=list)


_STACK_BASE = 0x7F000000
_STACK_SIZE = 0x200000
_HEAP_BASE = 0x11000000
_HEAP_SIZE = 0x400000
_FAKE_RET = 0x9F000000


def emulate_for_flag(
    path: str,
    *,
    func: str | int | None = None,
    stdin: bytes = b"",
    max_insns: int = 200_000,
    flag_pattern: str | None = None,
) -> EmulateResult:
    if not HAS_UNICORN:
        return EmulateResult(False, reason="unicorn not installed")

    ldr = BinaryLoader(path)
    try:
        return _emulate(ldr, func, stdin, max_insns, flag_pattern)
    finally:
        ldr.close()


def _emulate(ldr, func, stdin, max_insns, flag_pattern) -> EmulateResult:
    info = ldr.get_info()
    if info["format"] != "ELF" or info["arch"] not in ("x86", "x86_64"):
        return EmulateResult(False, reason=f"emulator supports x86 ELF only, got {info['arch']} {info['format']}")

    is64 = info["bits"] == 64
    mode = _uc.UC_MODE_64 if is64 else _uc.UC_MODE_32
    mu = _uc.Uc(_uc.UC_ARCH_X86, mode)
    r = _x86
    sp_reg = r.UC_X86_REG_RSP if is64 else r.UC_X86_REG_ESP
    ptr = 8 if is64 else 4

    raw = bytes(ldr._raw)
    for seg in _iter_load_segments(ldr):
        v0 = seg["vaddr"] & ~0xFFF
        v1 = (seg["vaddr"] + seg["memsz"] + 0xFFF) & ~0xFFF
        try:
            mu.mem_map(v0, max(v1 - v0, 0x1000))
        except _uc.UcError:
            pass  # overlapping / already mapped
        mu.mem_write(seg["vaddr"], raw[seg["offset"] : seg["offset"] + seg["filesz"]])

    mu.mem_map(_STACK_BASE - _STACK_SIZE, _STACK_SIZE)
    mu.mem_map(_HEAP_BASE, _HEAP_SIZE)
    mu.mem_map(_FAKE_RET & ~0xFFF, 0x1000)
    sp = _STACK_BASE - 0x1000
    mu.reg_write(sp_reg, sp)

    plt = _plt_targets(ldr)
    state = _EmuState(mu, r, is64, ptr, bytearray(stdin), plt)
    mu.hook_add(_uc.UC_HOOK_CODE, state.on_code)
    mu.hook_add(_uc.UC_HOOK_MEM_UNMAPPED, state.on_unmapped)

    start = _resolve_func(ldr, func)
    if start is None:
        return EmulateResult(False, reason=f"could not resolve start function {func!r}")

    sp -= ptr
    mu.mem_write(sp, _FAKE_RET.to_bytes(ptr, "little"))
    mu.reg_write(sp_reg, sp)

    try:
        mu.emu_start(start, _FAKE_RET, count=max_insns)
    except _uc.UcError as exc:
        state.trace.append(f"unicorn stop: {exc}")

    hits: list[str] = []
    for lo, hi, _perm in mu.mem_regions():
        if hi - lo > 0x400000:
            continue
        try:
            blob = bytes(mu.mem_read(lo, min(hi - lo + 1, 0x200000)))
        except _uc.UcError:
            continue
        hits += extract_flags(blob, flag_pattern)

    out_flags = extract_flags(bytes(state.stdout), flag_pattern)
    flag = (out_flags + hits + [None])[0]
    return EmulateResult(
        ok=flag is not None,
        flag=flag,
        stdout=bytes(state.stdout),
        reason="" if flag else "no flag in output or memory after emulation",
        memory_hits=list(dict.fromkeys(hits)),
        trace_tail=state.trace[-12:],
    )


def _iter_load_segments(ldr):
    segs = []
    elf = getattr(ldr, "_elf", None)
    if elf is not None:
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                segs.append(
                    {
                        "vaddr": seg["p_vaddr"],
                        "offset": seg["p_offset"],
                        "filesz": seg["p_filesz"],
                        "memsz": seg["p_memsz"],
                    }
                )
    return segs


def _plt_targets(ldr) -> dict[int, str]:
    """address of each imported-function PLT slot → bare name."""
    out: dict[int, str] = {}
    for imp in ldr.get_imports():
        addr = imp.get("address") or 0
        if addr:
            out[addr] = imp["name"].split("@")[0]
    return out


def _resolve_func(ldr, func) -> int | None:
    if isinstance(func, int):
        return func
    funcs = dict(ldr.get_functions())
    if func:
        return funcs.get(func)
    return funcs.get("main") or ldr.entry_point or None


class _EmuState:
    """Minimal libc model + stdout capture for the emulator."""

    def __init__(self, mu, r, is64, ptr, stdin: bytearray, plt: dict[int, str]):
        self.mu = mu
        self.r = r
        self.is64 = is64
        self.ptr = ptr
        self.stdin = stdin
        self.plt = plt
        self.heap = _HEAP_BASE
        self.stdout = bytearray()
        self.trace: list[str] = []

    def _sp(self):
        return self.mu.reg_read(self.r.UC_X86_REG_RSP if self.is64 else self.r.UC_X86_REG_ESP)

    def _arg(self, i: int) -> int:
        if self.is64:
            regs = [
                self.r.UC_X86_REG_RDI,
                self.r.UC_X86_REG_RSI,
                self.r.UC_X86_REG_RDX,
                self.r.UC_X86_REG_RCX,
                self.r.UC_X86_REG_R8,
                self.r.UC_X86_REG_R9,
            ]
            return self.mu.reg_read(regs[i])
        return int.from_bytes(self.mu.mem_read(self._sp() + self.ptr * (i + 1), self.ptr), "little")

    def _ret(self, value: int):
        sp = self._sp()
        retaddr = int.from_bytes(self.mu.mem_read(sp, self.ptr), "little")
        self.mu.reg_write(self.r.UC_X86_REG_RSP if self.is64 else self.r.UC_X86_REG_ESP, sp + self.ptr)
        self.mu.reg_write(self.r.UC_X86_REG_RAX if self.is64 else self.r.UC_X86_REG_EAX, value & (2**64 - 1))
        self.mu.reg_write(self.r.UC_X86_REG_RIP if self.is64 else self.r.UC_X86_REG_EIP, retaddr)

    def _cstr(self, addr: int, cap: int = 4096) -> bytes:
        out = b""
        while len(out) < cap:
            ch = bytes(self.mu.mem_read(addr + len(out), 1))
            if ch == b"\x00":
                break
            out += ch
        return out

    def on_unmapped(self, mu, access, addr, size, value, user):
        self.trace.append(f"unmapped access @ {addr:#x}")
        return False

    def on_code(self, mu, addr, size, user):
        name = self.plt.get(addr)
        if name is None:
            return
        handler = getattr(self, f"_lib_{name}", None)
        self.trace.append(f"call {name}()" if handler else f"call {name}() [stubbed 0]")
        if handler:
            handler()
        else:
            self._ret(0)

    def _alloc(self, n: int) -> int:
        a = self.heap
        self.heap += (n + 15) & ~15
        return a

    def _lib_malloc(self):
        self._ret(self._alloc(self._arg(0)))

    def _lib_calloc(self):
        n = self._arg(0) * self._arg(1)
        a = self._alloc(n)
        self.mu.mem_write(a, b"\x00" * n)
        self._ret(a)

    def _lib_realloc(self):
        self._ret(self._arg(0) or self._alloc(self._arg(1)))

    def _lib_free(self):
        self._ret(0)

    def _lib_memset(self):
        s, c, n = self._arg(0), self._arg(1), self._arg(2)
        self.mu.mem_write(s, bytes([c & 0xFF]) * n)
        self._ret(s)

    def _lib_memcpy(self):
        d, s, n = self._arg(0), self._arg(1), self._arg(2)
        self.mu.mem_write(d, bytes(self.mu.mem_read(s, n)))
        self._ret(d)

    _lib_memmove = _lib_memcpy

    def _lib_strcpy(self):
        d, s = self._arg(0), self._arg(1)
        self.mu.mem_write(d, self._cstr(s) + b"\x00")
        self._ret(d)

    def _lib_strncpy(self):
        d, s, n = self._arg(0), self._arg(1), self._arg(2)
        self.mu.mem_write(d, (self._cstr(s) + b"\x00" * n)[:n])
        self._ret(d)

    def _lib_strcat(self):
        d, s = self._arg(0), self._arg(1)
        self.mu.mem_write(d + len(self._cstr(d)), self._cstr(s) + b"\x00")
        self._ret(d)

    def _lib_strlen(self):
        self._ret(len(self._cstr(self._arg(0))))

    def _lib_puts(self):
        self.stdout += self._cstr(self._arg(0)) + b"\n"
        self._ret(1)

    def _lib_fputs(self):
        self.stdout += self._cstr(self._arg(0))
        self._ret(1)

    def _lib_printf(self):
        fmt = self._cstr(self._arg(0))
        if b"%s" in fmt:
            fmt = fmt.replace(b"%s", self._cstr(self._arg(1)), 1)
        self.stdout += fmt
        self._ret(len(fmt))

    def _lib_write(self):
        _fd, buf, n = self._arg(0), self._arg(1), self._arg(2)
        self.stdout += bytes(self.mu.mem_read(buf, n))
        self._ret(n)

    def _lib_read(self):
        _fd, buf, n = self._arg(0), self._arg(1), self._arg(2)
        take, self.stdin = self.stdin[:n], self.stdin[n:]
        self.mu.mem_write(buf, bytes(take))
        self._ret(len(take))

    def _lib_fgets(self):
        buf, n = self._arg(0), self._arg(1)
        nl = self.stdin.find(b"\n")
        cut = (nl + 1) if 0 <= nl < n - 1 else n - 1
        take, self.stdin = self.stdin[:cut], self.stdin[cut:]
        self.mu.mem_write(buf, bytes(take) + b"\x00")
        self._ret(buf)

    def _lib_atoi(self):
        try:
            self._ret(int(self._cstr(self._arg(0)).strip() or b"0"))
        except ValueError:
            self._ret(0)

    _lib_strtol = _lib_atoi
