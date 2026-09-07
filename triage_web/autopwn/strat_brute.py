"""Recover a key from a runnable checker with a feedback oracle.

Two modes, tried in order:

1. **char-by-char** — the classic ``for i: if input[i] != key[i]: reject``
   crackme. For each position we try every candidate byte on top of the
   confirmed prefix and keep the one whose response stands apart from the
   rest (more output, a new "correct"-ish word, or the flag itself).
2. **short keyspace** — if position 0 already can't be distinguished but the
   program clearly wants a tiny key (digits only), brute the whole space up
   to a hard try cap.

Everything is bounded by ``timeout`` and a total-runs ceiling; a checker that
gives no usable signal is reported as such rather than looped on forever.
"""

from __future__ import annotations

import platform
import string
import time
from dataclasses import dataclass, field

from triage_web.autopwn.runner import extract_flags, have_wsl, run_target, target_kind
from triage_web.loader import BinaryLoader

_GOOD_WORDS = ("correct", "congrat", "well done", "access granted", "you win", "good job", "unlocked")
_BAD_WORDS = ("wrong", "invalid", "denied", "nope", "incorrect", "try again")
_MAX_RUNS = 4000


@dataclass
class BruteResult:
    ok: bool
    flag: str | None = None
    key: str | None = None
    tries: int = 0
    reason: str = ""
    log: list[str] = field(default_factory=list)


def solve_brute(path: str, *, timeout: float = 90.0, max_len: int = 24) -> BruteResult:
    if target_kind(path) != "elf" or not (have_wsl() or platform.system() == "Linux"):
        return BruteResult(False, reason="no runtime to execute the checker (need Linux or WSL)")

    ldr = BinaryLoader(path)
    try:
        blob = bytes(ldr._raw)
    finally:
        ldr.close()
    digits_only = b"%d" in blob and b"%s" not in blob

    log: list[str] = []
    deadline = time.monotonic() + timeout
    runs = 0

    def _try(candidate: bytes) -> tuple[int | None, bytes]:
        nonlocal runs
        runs += 1
        p = run_target(path, stdin=candidate + b"\n", argv=(candidate.decode("latin-1"),), timeout=6.0)
        return p.returncode, (p.stdout + b"\n" + p.stderr)

    charset = (string.digits if digits_only else string.digits + string.ascii_letters + "_-{}!?.").encode()

    # ── mode 1: char-by-char ──
    prefix = b""
    for pos in range(max_len):
        if time.monotonic() > deadline or runs > _MAX_RUNS:
            break
        scored: list[tuple[float, int]] = []
        for c in charset:
            if time.monotonic() > deadline or runs > _MAX_RUNS:
                break
            rc, out = _try(prefix + bytes([c]))
            flags = extract_flags(out)
            if flags:
                log.append(f"flag surfaced while brute-forcing position {pos}")
                return BruteResult(
                    True, flag=flags[0], key=(prefix + bytes([c])).decode("latin-1"), tries=runs, log=log
                )
            scored.append((_score(out, rc), c))
        if not scored:
            break
        scored.sort(reverse=True)
        best_score, best_c = scored[0]
        runner_up = scored[1][0] if len(scored) > 1 else best_score
        if best_score <= 0 or best_score == runner_up:
            log.append(f"position {pos}: no byte stands out (best={best_score:.2f}); stopping char-by-char")
            break
        prefix += bytes([best_c])
        log.append(f"position {pos}: {chr(best_c)!r} (score {best_score:.2f})")
        rc, out = _try(prefix)
        if any(w.encode() in out.lower() for w in _GOOD_WORDS):
            flags = extract_flags(out)
            return BruteResult(
                True, flag=flags[0] if flags else None, key=prefix.decode("latin-1"), tries=runs, log=log
            )

    # ── mode 2: short digit keyspace ──
    if digits_only and not prefix and runs < _MAX_RUNS:
        log.append("falling back to full brute over a small digit keyspace")
        for length in range(1, 5):
            for n in range(10**length):
                if time.monotonic() > deadline or runs > _MAX_RUNS:
                    return BruteResult(
                        False, reason="exhausted the run/time budget in short-keyspace brute", tries=runs, log=log
                    )
                cand = str(n).encode()
                rc, out = _try(cand)
                flags = extract_flags(out)
                if flags or any(w.encode() in out.lower() for w in _GOOD_WORDS):
                    return BruteResult(True, flag=flags[0] if flags else None, key=cand.decode(), tries=runs, log=log)

    if prefix:
        return BruteResult(
            False,
            key=prefix.decode("latin-1"),
            tries=runs,
            log=log,
            reason=f"recovered a likely prefix {prefix!r} but the checker never confirmed a full key",
        )
    return BruteResult(
        False, tries=runs, reason="the checker gave no usable pass/fail signal to brute against", log=log
    )


def _score(out: bytes, rc: int | None) -> float:
    """How 'promising' a response is: longer output, a good word, a clean
    exit, and the absence of a reject word all push it up."""
    low = out.lower()
    s = len(out) * 0.01
    if any(w.encode() in low for w in _GOOD_WORDS):
        s += 10.0
    if any(w.encode() in low for w in _BAD_WORDS):
        s -= 3.0
    if rc == 0:
        s += 1.0
    return s
