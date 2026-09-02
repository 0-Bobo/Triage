"""The per-strategy result record.

Kept in its own module so the registry and the orchestrator can both import
it without a cycle through ``triage_web.autopwn.__init__``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Attempt:
    strategy: str
    ok: bool
    seconds: float
    detail: str = ""
    flag: str | None = None
    script: str = ""
    # How much to trust ``flag`` / the recovered parameters. A strategy sets
    # this itself; the orchestrator fills in "solved" when a strategy returned
    # a flag without saying. "" means the strategy did not run far enough to
    # judge. Kept coarse on purpose — it is a caution flag, not a score.
    confidence: str = ""  # "solved" | "likely" | "guess" | ""
