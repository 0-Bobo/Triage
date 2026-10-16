#!/usr/bin/env bash
# Idempotent provisioning / repair for ~/pwn-venv (the web app's own deps,
# pwntools, and triton-library).
#   Run from WSL:      bash /mnt/c/Projects/Triage/wsl/setup_pwn_env.sh
#   From Windows:      python -m triage_web.autopwn.wsl_env --setup
# Safe to re-run - only touches what a check just found missing. Does NOT need
# sudo (if python3-venv is missing, the exact apt command is reported for you
# to run yourself). No `set -e`: one failed dependency must never stop the
# script from checking and reporting on the rest.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV="$HOME/pwn-venv"
FAILURES=0

pass() {
  local name="$1" note="${2:-}"
  if [ -n "$note" ]; then
    echo "[PASS] $name ($note)"
  else
    echo "[PASS] $name"
  fi
}

fail() {
  local name="$1" detail="$2"
  echo "[FAIL] $name: $detail"
  FAILURES=$((FAILURES + 1))
}

echo "==> checking python3 venv module"
VENV_MODULE_OK=1
if ! python3 -c "import venv" >/dev/null 2>&1; then
  VENV_MODULE_OK=0
  fail "venv-module" "python3's venv module is not usable; run: sudo apt-get install -y python3-venv"
fi

echo "==> checking \$HOME/pwn-venv"
VENV_USABLE=0
if [ "$VENV_MODULE_OK" -eq 1 ]; then
  if [ -x "$VENV/bin/python" ]; then
    pass "pwn-venv" "already exists"
    VENV_USABLE=1
  else
    CREATE_ERR=$(python3 -m venv "$VENV" 2>&1 1>/dev/null)
    CREATE_RC=$?
    if [ "$CREATE_RC" -eq 0 ] && [ -x "$VENV/bin/python" ]; then
      pass "pwn-venv"
      VENV_USABLE=1
    else
      fail "pwn-venv" "python3 -m venv failed: ${CREATE_ERR: -300}"
    fi
  fi
fi

if [ "$VENV_USABLE" -eq 1 ]; then
  # Keep pip current - harmless no-op when it already is. Not one of the
  # reported dependencies, so its own failure is ignored.
  "$VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true

  echo "==> checking web app dependencies"
  REQUIREMENTS_WEB="$REPO_ROOT/requirements-web.txt"
  if "$VENV/bin/python" -c "import fastapi" >/dev/null 2>&1; then
    pass "web-stack" "already importable"
  elif [ ! -f "$REQUIREMENTS_WEB" ]; then
    fail "web-stack" "requirements-web.txt not found at $REQUIREMENTS_WEB"
  else
    INSTALL_ERR=$("$VENV/bin/python" -m pip install --quiet -r "$REQUIREMENTS_WEB" 2>&1 1>/dev/null)
    if "$VENV/bin/python" -c "import fastapi" >/dev/null 2>&1; then
      pass "web-stack"
    else
      fail "web-stack" "pip install -r requirements-web.txt failed: ${INSTALL_ERR: -300}"
    fi
  fi

  echo "==> checking pwntools"
  if "$VENV/bin/python" -c "import pwn" >/dev/null 2>&1; then
    pass "pwntools" "already importable"
  else
    INSTALL_ERR=$("$VENV/bin/python" -m pip install --quiet pwntools 2>&1 1>/dev/null)
    if "$VENV/bin/python" -c "import pwn" >/dev/null 2>&1; then
      pass "pwntools"
    else
      fail "pwntools" "pip install pwntools failed: ${INSTALL_ERR: -300}"
    fi
  fi

  echo "==> checking triton-library"
  if "$VENV/bin/python" -c "import triton" >/dev/null 2>&1; then
    pass "triton-library" "already importable"
  else
    INSTALL_ERR=$("$VENV/bin/python" -m pip install --quiet --pre triton-library 2>&1 1>/dev/null)
    if "$VENV/bin/python" -c "import triton" >/dev/null 2>&1; then
      pass "triton-library"
    else
      fail "triton-library" "pip install --pre triton-library failed: ${INSTALL_ERR: -300}; build from source instead - see https://github.com/JonathanSalwan/Triton (cmake, libcapstone>=5.0 required; libboost/libz3 optional)"
    fi
  fi
else
  fail "web-stack" "skipped - pwn-venv not available"
  fail "pwntools" "skipped - pwn-venv not available"
  fail "triton-library" "skipped - pwn-venv not available"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "==> all checks passed"
  exit 0
else
  echo "==> $FAILURES check(s) failed"
  exit 1
fi
