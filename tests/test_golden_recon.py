"""Golden-output lock on ``autopwn.recon()`` for the sample fixtures.

``recon()`` is deterministic and backend-light (loader + capstone + the
declarative registry's scoring), so it belongs in the fast test path. This
catches an arch-detection / protection-parse / registry-scoring regression
that the behaviour-focused orchestration tests would miss because they do
not assert the *exact* ranked plan.

Strategy-level golden output (``strat_smc`` decoded bytes, ``strat_angr``
recovered offsets, …) is deliberately NOT here: it needs checked-in CTF
binaries and the heavy optional backends. See ``docs/TODO.md`` P3 — the
canary job (``make deps-canary``) covers the backend-churn side.

Regenerate a case after an *intentional* scoring change: run the test, read
the assertion diff, and write the new shape into the matching JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from triage_web.autopwn import recon

GOLDEN = Path(__file__).parent / "golden" / "recon"
SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# name -> the classification outcome it pins
CASES = {
    "keygate": "constant-compare -> keygen leads",
    "ret2win": "BOF sink + win() -> ret2win leads",
    "keycheck": "string check -> emulate/angr/z3/brute",
    "vuln_pie": "PIE + Full RELRO -> no keygen, ret2win demoted",
    "vuln_rwx": "RWX PT_LOAD -> smc leads",
}


def shape(rc: dict) -> dict:
    """The toolchain-stable, regression-critical slice of a recon dict."""
    return {
        "format": rc["format"],
        "arch": rc["arch"],
        "bits": rc["bits"],
        "protections": rc["protections"],
        "plan": [p["name"] for p in rc["plans"]],
    }


@pytest.mark.parametrize("name", CASES, ids=list(CASES))
def test_recon_matches_golden(name: str) -> None:
    binary = SAMPLES / name
    if not binary.exists():
        pytest.skip(f"sample {name} not present")
    got = shape(recon(str(binary)))
    expected = json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))
    assert got == expected, f"recon shape drifted for {name} ({CASES[name]})"
