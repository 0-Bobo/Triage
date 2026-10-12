"""Detect whether a usable WSL pwntools/Triton environment is available.

The auto-solver's heavier strategies need a Linux process to run generated
exploit scripts against (``runner.run_script``), which on Windows means a
WSL distro with a ``~/pwn-venv`` virtualenv that has ``pwntools`` and
``triton`` importable. This module answers "is that environment usable right
now?" without running or touching any solver — it only probes.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from triage_web.autopwn import runner

# Tokens the WSL probe prints for each of the three independent checks.
_VENV_OK, _VENV_MISSING = "VENV_OK", "VENV_MISSING"
_PWNTOOLS_OK, _PWNTOOLS_MISSING = "PWNTOOLS_OK", "PWNTOOLS_MISSING"
_TRITON_OK, _TRITON_MISSING = "TRITON_OK", "TRITON_MISSING"
_ALL_TOKENS = (_VENV_OK, _VENV_MISSING, _PWNTOOLS_OK, _PWNTOOLS_MISSING, _TRITON_OK, _TRITON_MISSING)

# Fixed literal probe — every path here is a hardcoded constant, never a
# caller-supplied value. If this ever grows a caller-supplied argument it
# MUST be passed through runner._sh_quote() first, exactly as runner.py
# requires for every other shell command it builds.
_PROBE = (
    f"[ -x ~/pwn-venv/bin/python ] && echo {_VENV_OK} || echo {_VENV_MISSING}; "
    f'~/pwn-venv/bin/python -c "import pwn" 2>/dev/null && echo {_PWNTOOLS_OK} || echo {_PWNTOOLS_MISSING}; '
    f'~/pwn-venv/bin/python -c "import triton" 2>/dev/null && echo {_TRITON_OK} || echo {_TRITON_MISSING}; '
    "true"
)

_FIELD_NAMES = ("wsl_installed", "distro_running", "venv_exists", "pwntools_ok", "triton_ok")


@dataclass
class WslEnvStatus:
    """Result of a single ``detect()`` probe."""

    wsl_installed: bool
    distro_running: bool
    venv_exists: bool
    pwntools_ok: bool
    triton_ok: bool
    detail: str = ""

    @property
    def usable(self) -> bool:
        return self.wsl_installed and self.distro_running and self.venv_exists and self.pwntools_ok and self.triton_ok


def detect(*, timeout: float = 15.0) -> WslEnvStatus:
    """Probe for a usable WSL + ``~/pwn-venv`` environment. Never raises."""
    if not runner.have_wsl():
        return WslEnvStatus(False, False, False, False, False, "WSL not installed (wsl.exe not found on PATH)")

    result = runner._wsl_bash(_PROBE, b"", timeout)
    text = result.text
    if not result.runnable or not any(token in text for token in _ALL_TOKENS):
        return WslEnvStatus(True, False, False, False, False, text[-300:])

    return WslEnvStatus(
        wsl_installed=True,
        distro_running=True,
        venv_exists=_VENV_OK in text,
        pwntools_ok=_PWNTOOLS_OK in text,
        triton_ok=_TRITON_OK in text,
        detail="",
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m triage_web.autopwn.wsl_env",
        description=__doc__,
    )
    ap.parse_args(argv)

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
