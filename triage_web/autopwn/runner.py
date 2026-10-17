"""Process bridge for the auto-solver.

Linux ELF targets run inside the configured WSL distro; PE targets run
natively on Windows (or through ``wine`` when we are ourselves on Linux).
Everything here is best-effort: if no runtime is available the caller gets a
``ProcResult`` with ``runnable is False`` and should fall back to a static
strategy (angr / unicorn).

**Sandboxing.** Targets and generated exploit scripts are untrusted. Every
ELF / script execution is wrapped, when the tooling is present, in an
isolation layer (``bwrap`` preferred, else ``unshare``):

* ``net=False`` (default) — no network at all, read-only root, private
  ``/tmp``. For static self-tests (emulate / keygen / ret2win).
* ``net=True`` — a loopback-only network island (server + client isolated
  together, no route off the host). For the UAF / format-string network
  self-tests.

Set ``TRIAGE_SANDBOX=off`` to run bare (a ``ProcResult.note`` records it);
``TRIAGE_SANDBOX=strict`` refuses to run unsandboxed.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

# Flag shapes, most specific first. ``extract_flags`` returns matches in this
# priority order so the orchestrator can pick the best candidate.
_FLAG_PATTERNS: tuple[str, ...] = (
    r"[A-Za-z0-9_]{0,20}(?:pico|HTB|flare|corctf|uiuctf|dice|CTF|ctf|flag|FLAG|key|KEY)"
    r"[A-Za-z0-9_]{0,20}\{[^}\r\n]{1,160}\}",
    r"FLAG-[0-9A-Za-z_?!.-]{4,120}",
    r"[A-Za-z0-9_]{2,32}\{[0-9A-Za-z_@!?.$%#*-]{4,160}\}",
)


@dataclass
class ProcResult:
    """Outcome of a single target / script execution."""

    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    seconds: float
    cmd: str
    runnable: bool = True  # False → no runtime available for this target
    note: str = ""
    flags: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return (self.stdout + b"\n" + self.stderr).decode("utf-8", "replace")

    def best_flag(self) -> str | None:
        return self.flags[0] if self.flags else None


def have_wsl() -> bool:
    return platform.system() == "Windows" and shutil.which("wsl") is not None


def _on_linux() -> bool:
    return platform.system() == "Linux"


def to_wsl(path: str | Path) -> str:
    """``C:\\Projects\\x`` → ``/mnt/c/Projects/x``. Pass-through if already POSIX."""
    p = str(path)
    if p.startswith("/"):
        return p
    win = PureWindowsPath(p)
    drive = win.drive.rstrip(":").lower()
    rest = "/".join(win.parts[1:]) if win.drive else "/".join(win.parts)
    return f"/mnt/{drive}/{rest}" if drive else "/" + rest


def run_path(path: str | Path) -> str:
    """The path a generated script should use to open the target: a WSL
    path when scripts will run under WSL, otherwise the absolute path."""
    ap = str(Path(path).resolve())
    return to_wsl(ap) if (not _on_linux() and have_wsl()) else ap


def target_kind(path: str | Path) -> str:
    """``elf`` | ``pe`` | ``unknown`` from the magic bytes."""
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError:
        return "unknown"
    if magic[:4] == b"\x7fELF":
        return "elf"
    if magic[:2] == b"MZ":
        return "pe"
    return "unknown"


def extract_flags(data: bytes | str, extra_pattern: str | None = None) -> list[str]:
    """Return flag-looking substrings, most-confident first, de-duplicated."""
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    seen: dict[str, None] = {}
    patterns = list(_FLAG_PATTERNS)
    if extra_pattern:
        patterns.insert(0, extra_pattern)
    for pat in patterns:
        for m in re.finditer(pat, text):
            hit = m.group(0).strip()
            if hit not in seen:
                seen[hit] = None
    return list(seen)


def _popen(cmd: list[str], stdin: bytes, timeout: float) -> ProcResult:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return ProcResult(
            returncode=None,
            stdout=exc.stdout or b"",
            stderr=exc.stderr or b"",
            timed_out=True,
            seconds=round(time.monotonic() - started, 3),
            cmd=" ".join(cmd),
        )
    except FileNotFoundError as exc:
        return ProcResult(None, b"", str(exc).encode(), False, 0.0, " ".join(cmd), runnable=False)
    out, err = proc.stdout or b"", proc.stderr or b""
    res = ProcResult(
        returncode=proc.returncode,
        stdout=out,
        stderr=err,
        timed_out=False,
        seconds=round(time.monotonic() - started, 3),
        cmd=" ".join(cmd),
    )
    res.flags = extract_flags(out + b"\n" + err)
    return res


def _wsl_bash(script: str, stdin: bytes, timeout: float) -> ProcResult:
    return _popen(["wsl", "-e", "bash", "-lc", script], stdin, timeout)


# ── sandboxing ──────────────────────────────────────────────────────────

_SANDBOX_MODE = os.environ.get("TRIAGE_SANDBOX", "auto").lower()  # auto | off | strict
_SB_UNAVAILABLE = "sandbox: no bwrap/unshare available — target ran UNSANDBOXED"


def _sh_probe(bash_prefix: list[str]) -> set[str]:
    """Which isolation tools actually *work* in the runtime we'll use.

    Presence is not enough: locked-down hosts (GitHub Actions runners, some
    containers) ship ``unshare`` but forbid unprivileged user namespaces, so a
    bare ``command -v`` check would pick a sandbox that then fails to launch the
    target. Each candidate is run as a minimal real invocation and kept only if
    it exits 0.
    """
    key = tuple(bash_prefix)
    cache = _sh_probe.__dict__.setdefault("_c", {})
    if key not in cache:
        probe = (
            "bwrap --unshare-all --ro-bind / / --dev /dev --tmpfs /tmp true 2>/dev/null && echo bwrap; "
            "unshare -rn true 2>/dev/null && echo unshare"
        )
        try:
            out = subprocess.run(
                [*bash_prefix, probe],
                capture_output=True,
                timeout=10,
                check=False,
            ).stdout.decode("utf-8", "replace")
        except (OSError, subprocess.SubprocessError):
            out = ""
        cache[key] = {t for t in ("bwrap", "unshare") if t in out.split()}
    return cache[key]


def _sandbox_wrap(inner: str, work: str, *, net: bool, bash_prefix: list[str]) -> tuple[str, str]:
    """Return ``(command, note)``. ``command`` is a bash one-liner that runs
    ``inner`` under the strongest isolation available for the ``net`` policy."""
    if _SANDBOX_MODE == "off":
        return inner, "sandbox: disabled via TRIAGE_SANDBOX=off"
    tools = _sh_probe(bash_prefix)
    q = _sh_quote(work)
    if "bwrap" in tools and not net:
        cmd = (
            "bwrap --unshare-all --die-with-parent --new-session "
            f"--ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /run "
            f"--bind {q} {q} --chdir {q} -- /bin/bash -c {_sh_quote(inner)}"
        )
        return cmd, "sandbox: bwrap (no network, ro-root, private /tmp)"
    if "unshare" in tools:
        # -rn: new user + network namespace. net=True brings loopback up so a
        # local server/client pair can still talk; net=False leaves no route at all.
        lo = "ip link set lo up 2>/dev/null; " if net else ""
        msg = "sandbox: unshare (loopback-only island)" if net else "sandbox: unshare (no network)"
        return f"unshare -rn /bin/bash -c {_sh_quote(lo + inner)}", msg
    if _SANDBOX_MODE == "strict":
        return "", _SB_UNAVAILABLE + " — refused (TRIAGE_SANDBOX=strict)"
    return inner, _SB_UNAVAILABLE


def run_target(
    path: str | Path,
    *,
    stdin: bytes = b"",
    argv: tuple[str, ...] = (),
    env: dict[str, str] | None = None,
    timeout: float = 15.0,
    cwd: str | Path | None = None,
    net: bool = False,
) -> ProcResult:
    """Execute a target binary once and capture its output.

    ELF → WSL (or native when we're on Linux), wrapped in a sandbox (see the
    module docstring); pass ``net=True`` for a loopback-only island. PE runs
    natively on Windows (or ``wine`` under WSL/Linux) — not sandboxed here.
    Returns ``runnable=False`` when nothing can run it.
    """
    path = Path(path).resolve()
    kind = target_kind(path)
    arg_str = " ".join(_sh_quote(a) for a in argv)
    env_prefix = "".join(f"{k}={_sh_quote(v)} " for k, v in (env or {}).items())

    if kind == "elf":
        if _on_linux():
            work = str(cwd) if cwd else str(path.parent)
            inner = f"cd {_sh_quote(work)} && exec {env_prefix}./{_sh_quote(path.name)} {arg_str}"
            cmd, note = _sandbox_wrap(inner, work, net=net, bash_prefix=["/bin/bash", "-c"])
            if not cmd:
                return ProcResult(None, b"", note.encode(), False, 0.0, "", runnable=False, note=note)
            res = _popen(["/bin/bash", "-c", cmd], stdin, timeout)
            res.note = note
            return res
        if have_wsl():
            work = str(cwd) if cwd else to_wsl(str(path.parent))
            wp = to_wsl(path)
            inner = (
                f"cd {_sh_quote(to_wsl(work))} && chmod +x {_sh_quote(wp)} 2>/dev/null; "
                f"{env_prefix}{_sh_quote(wp)} {arg_str}"
            )
            cmd, note = _sandbox_wrap(inner, to_wsl(work), net=net, bash_prefix=["wsl", "-e", "bash", "-lc"])
            if not cmd:
                return ProcResult(None, b"", note.encode(), False, 0.0, "", runnable=False, note=note)
            res = _wsl_bash(cmd, stdin, timeout)
            res.note = note
            return res
        return ProcResult(None, b"", b"no ELF runtime (need WSL or Linux)", False, 0.0, "", runnable=False)

    if kind == "pe":
        if platform.system() == "Windows":
            return _popen([str(path), *argv], stdin, timeout)
        runner = shutil.which("wine")
        if runner:
            return _popen([runner, str(path), *argv], stdin, timeout)
        return ProcResult(None, b"", b"no PE runtime (need Windows or wine)", False, 0.0, "", runnable=False)

    return ProcResult(None, b"", f"unknown target format: {path}".encode(), False, 0.0, "", runnable=False)


def run_script(
    src: str,
    *,
    python: str | None = None,
    timeout: float = 60.0,
    stdin: bytes = b"",
    env: dict[str, str] | None = None,
    net: bool = True,
    server_cmd: str | None = None,
    server_port: int | None = None,
) -> ProcResult:
    """Run a generated Python solver/exploit script, sandboxed.

    On Windows the script runs inside WSL using ``python`` (default:
    ``~/pwn-venv/bin/python`` if present, else ``python3``) so pwntools and a
    real Linux process environment are available. On Linux it runs directly.
    Exploit scripts default to ``net=True`` (loopback-only island) since the
    UAF / format-string self-tests talk to a local service.

    ``server_cmd``, when given, is a shell command for a local helper
    service (e.g. a self-test's own target) started in the background
    *inside the same sandboxed invocation* as the script, so both share one
    network namespace and can actually reach each other over loopback. A
    server started as a separate ``subprocess.Popen`` on the host can never
    be reached by a ``net=True``-sandboxed client: that sandbox's loopback
    is its own isolated namespace, not the host's. ``server_port``, if
    given, is polled until it accepts a connection before the script runs;
    without it, a fixed short delay is used instead.
    """
    src = "# -*- coding: utf-8 -*-\n" + src  # tolerate non-ASCII bytes read from stdin
    env_pairs = [f"{k}={_sh_quote(v)}" for k, v in (env or {}).items()]
    heredoc = "__TRIAGE_SOLVER_EOF__"

    server_prefix, server_suffix = "", ""
    if server_cmd:
        wait = (
            f"for _i in $(seq 1 25); do (exec 3<>/dev/tcp/127.0.0.1/{server_port}) 2>/dev/null "
            "&& exec 3<&- 3>&- && break; sleep 0.2; done; "
            if server_port
            else "sleep 1; "
        )
        server_prefix = f"({server_cmd}) >/dev/null 2>&1 & SERVER_PID=$!; {wait}"
        # Lands on its own line right after the heredoc terminator (see both
        # call sites below), so no leading `;` - a bare `;` there is a bash
        # syntax error ("unexpected token `;'"), not a harmless no-op.
        server_suffix = "kill $SERVER_PID 2>/dev/null || true"

    if _on_linux():
        interp = python or shutil.which("python3") or "python3"
        base = (
            server_prefix
            + " ".join(env_pairs)
            + (" " if env_pairs else "")
            + f"{interp} - <<'{heredoc}'\n{src}\n{heredoc}\n"
            + server_suffix
        )
        cmd, note = _sandbox_wrap(base, os.getcwd(), net=net, bash_prefix=["/bin/bash", "-c"])
        if not cmd:
            return ProcResult(None, b"", note.encode(), False, 0.0, "", runnable=False, note=note)
        res = _popen(["/bin/bash", "-c", cmd], stdin, timeout)
        res.note = note
        return res

    if not have_wsl():
        return ProcResult(
            None, b"", b"no python runtime for solver scripts (need WSL or Linux)", False, 0.0, "", runnable=False
        )
    interp = python or "$( [ -x ~/pwn-venv/bin/python ] && echo ~/pwn-venv/bin/python || command -v python3 )"
    prefix = " ".join([*env_pairs, "PYTHONUTF8=1"]) + " "
    base = server_prefix + f"{prefix}{interp} - <<'{heredoc}'\n{src}\n{heredoc}\n" + server_suffix
    cmd, note = _sandbox_wrap(base, "$HOME", net=net, bash_prefix=["wsl", "-e", "bash", "-lc"])
    if not cmd:
        return ProcResult(None, b"", note.encode(), False, 0.0, "", runnable=False, note=note)
    res = _wsl_bash(cmd, stdin, timeout)
    res.note = note
    return res


def _sh_quote(s: str) -> str:
    if s and re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"
