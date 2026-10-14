"""Detect whether a usable WSL pwntools/Triton environment is available.

The auto-solver's heavier strategies need a Linux process to run generated
exploit scripts against (``runner.run_script``), which on Windows means a
WSL distro with a ``~/pwn-venv`` virtualenv that has ``pwntools`` and
``triton`` importable. The probe also checks Z3, angr and Unicorn, whose
Solvers-panel scripts run in that same venv. This module answers "is that
environment usable right now?" without running or touching any solver — it
only probes.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from triage_web.autopwn import runner

# Tokens the WSL probe prints for each of the six independent checks.
_VENV_OK, _VENV_MISSING = "VENV_OK", "VENV_MISSING"
_PWNTOOLS_OK, _PWNTOOLS_MISSING = "PWNTOOLS_OK", "PWNTOOLS_MISSING"
_TRITON_OK, _TRITON_MISSING = "TRITON_OK", "TRITON_MISSING"
_Z3_OK, _Z3_MISSING = "Z3_OK", "Z3_MISSING"
_UNICORN_OK, _UNICORN_MISSING = "UNICORN_OK", "UNICORN_MISSING"
_ANGR_OK, _ANGR_MISSING = "ANGR_OK", "ANGR_MISSING"
_ALL_TOKENS = (
    _VENV_OK,
    _VENV_MISSING,
    _PWNTOOLS_OK,
    _PWNTOOLS_MISSING,
    _TRITON_OK,
    _TRITON_MISSING,
    _Z3_OK,
    _Z3_MISSING,
    _UNICORN_OK,
    _UNICORN_MISSING,
    _ANGR_OK,
    _ANGR_MISSING,
)

# Fixed literal probe — every path here is a hardcoded constant, never a
# caller-supplied value. If this ever grows a caller-supplied argument it
# MUST be passed through runner._sh_quote() first, exactly as runner.py
# requires for every other shell command it builds.
# angr goes last: it's the heaviest import, so if detect()'s timeout hits
# mid-import, every token printed before it is still captured (runner._popen
# keeps partial stdout on TimeoutExpired).
_PROBE = (
    f"[ -x ~/pwn-venv/bin/python ] && echo {_VENV_OK} || echo {_VENV_MISSING}; "
    f'~/pwn-venv/bin/python -c "import pwn" 2>/dev/null && echo {_PWNTOOLS_OK} || echo {_PWNTOOLS_MISSING}; '
    f'~/pwn-venv/bin/python -c "import triton" 2>/dev/null && echo {_TRITON_OK} || echo {_TRITON_MISSING}; '
    f'~/pwn-venv/bin/python -c "import z3" 2>/dev/null && echo {_Z3_OK} || echo {_Z3_MISSING}; '
    f'~/pwn-venv/bin/python -c "import unicorn" 2>/dev/null && echo {_UNICORN_OK} || echo {_UNICORN_MISSING}; '
    f'~/pwn-venv/bin/python -c "import angr" 2>/dev/null && echo {_ANGR_OK} || echo {_ANGR_MISSING}; '
    "true"
)

_FIELD_NAMES = (
    "wsl_installed",
    "distro_running",
    "venv_exists",
    "pwntools_ok",
    "triton_ok",
    "z3_ok",
    "angr_ok",
    "unicorn_ok",
)

# Three ``.parent`` hops from triage_web/autopwn/wsl_env.py reaches the repo
# root, where wsl/ already lives alongside triage_web/.
_SETUP_SCRIPT = Path(__file__).resolve().parent.parent.parent / "wsl" / "setup_pwn_env.sh"


@dataclass
class WslEnvStatus:
    """Result of a single ``detect()`` probe."""

    wsl_installed: bool
    distro_running: bool
    venv_exists: bool
    pwntools_ok: bool
    triton_ok: bool
    z3_ok: bool
    angr_ok: bool
    unicorn_ok: bool
    detail: str = ""

    @property
    def usable(self) -> bool:
        """The pwntools + Triton gate Phase 8 defined — z3_ok, angr_ok and
        unicorn_ok are reported separately and do not feed this formula."""
        return self.wsl_installed and self.distro_running and self.venv_exists and self.pwntools_ok and self.triton_ok


def detect(*, timeout: float = 15.0) -> WslEnvStatus:
    """Probe for a usable WSL + ``~/pwn-venv`` environment. Never raises."""
    if not runner.have_wsl():
        return WslEnvStatus(
            wsl_installed=False,
            distro_running=False,
            venv_exists=False,
            pwntools_ok=False,
            triton_ok=False,
            z3_ok=False,
            angr_ok=False,
            unicorn_ok=False,
            detail="WSL not installed (wsl.exe not found on PATH)",
        )

    result = runner._wsl_bash(_PROBE, b"", timeout)
    text = result.text
    if not result.runnable or not any(token in text for token in _ALL_TOKENS):
        return WslEnvStatus(
            wsl_installed=True,
            distro_running=False,
            venv_exists=False,
            pwntools_ok=False,
            triton_ok=False,
            z3_ok=False,
            angr_ok=False,
            unicorn_ok=False,
            detail=text[-300:],
        )

    return WslEnvStatus(
        wsl_installed=True,
        distro_running=True,
        venv_exists=_VENV_OK in text,
        pwntools_ok=_PWNTOOLS_OK in text,
        triton_ok=_TRITON_OK in text,
        z3_ok=_Z3_OK in text,
        angr_ok=_ANGR_OK in text,
        unicorn_ok=_UNICORN_OK in text,
        detail="",
    )


def run_setup(*, timeout: float = 1800.0) -> runner.ProcResult:
    """Run ``wsl/setup_pwn_env.sh`` to provision or repair ``~/pwn-venv``.

    On Linux it runs the script directly; on Windows it's driven through WSL
    exactly like every other script ``runner`` executes. Never raises - a
    non-runnable ``ProcResult`` comes back when neither path is available.
    """
    if runner.platform.system() == "Linux":
        return runner._popen(["bash", str(_SETUP_SCRIPT)], b"", timeout)

    if not runner.have_wsl():
        return runner.ProcResult(
            None, b"", b"WSL not installed (wsl.exe not found on PATH)", False, 0.0, "", runnable=False
        )

    wsl_path = runner.to_wsl(_SETUP_SCRIPT)
    return runner._wsl_bash(f"bash {runner._sh_quote(wsl_path)}", b"", timeout)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m triage_web.autopwn.wsl_env",
        description=__doc__,
    )
    ap.add_argument("--setup", action="store_true", help="provision/repair ~/pwn-venv instead of just detecting it")
    ap.add_argument("--timeout", type=float, default=1800.0, help="seconds to allow the setup script to run")
    args = ap.parse_args(argv)

    if args.setup:
        result = run_setup(timeout=args.timeout)
        print(result.text)
        return 0 if result.returncode == 0 else 1

    status = detect()
    for field_name in _FIELD_NAMES:
        mark = "[PASS]" if getattr(status, field_name) else "[FAIL]"
        print(f"{mark} {field_name}")
    if status.detail:
        print(f"  detail: {status.detail}")
    print(f"usable: {status.usable}")
    return 0 if status.usable else 1


if __name__ == "__main__":
    raise SystemExit(main())
