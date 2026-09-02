"""Pick which solver strategies to try, and in what order, for a target.

Thin adapter: build the static :class:`~triage_web.autopwn.registry.StaticView`
from a ``BinaryLoader`` and hand it to the strategy registry, which owns the
scoring. Kept as its own entry point because ``recon`` and the tests call
``classify(path)`` directly.
"""

from __future__ import annotations

from triage_web.autopwn.registry import StratPlan, build_view, plan
from triage_web.loader import BinaryLoader

__all__ = ["StratPlan", "classify"]


def classify(path: str, capa: frozenset[str] = frozenset()) -> list[StratPlan]:
    """Ranked strategy plan for ``path``. ``capa`` is an optional set of capa
    rule/namespace names (lowercased) that lets capability matches reprioritise
    the plan; empty means "static signals only"."""
    ldr = BinaryLoader(path)
    try:
        return plan(build_view(ldr, capa))
    finally:
        ldr.close()
