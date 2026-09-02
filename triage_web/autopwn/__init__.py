"""Recon + first-move accelerator for CTF binaries.

The primary output is the **recon**: format / arch / protections, the
ranked strategy plan, and — per strategy — the recovered parameters
(win address, overflow offset, struct size, compare key, decoded SMC) and
a runnable exploit *scaffold*. A recovered flag is a bonus when the shape
is simple enough; ``solve(path)`` runs the strategies in priority order and
stops at the first flag, but a failed solve still hands back the full
picture so the next move is a copy-paste away.

Strategies: **emulate** (unicorn), **keygen** (static constant-compare),
**angr** (symbolic), **ret2win** (concrete overflow), **format_string**,
**uaf** (dangling callback). Every run is appended to a JSONL telemetry
log (``$TRIAGE_RESULTS`` or ``~/.triage/results.jsonl``) so the strategy
mix can be judged on real data.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from triage_web.autopwn.attempt import Attempt
from triage_web.autopwn.classify import StratPlan, classify
from triage_web.autopwn.registry import RunCtx, run_strategy
from triage_web.loader import BinaryLoader

__all__ = ["Attempt", "SolveResult", "recon", "solve"]


@dataclass
class SolveResult:
    path: str
    success: bool
    flag: str | None
    strategy: str | None
    seconds: float
    plans: list[dict] = field(default_factory=list)
    attempts: list[dict] = field(default_factory=list)
    proof: str = ""  # winning stdin / payload / script
    stdout: str = ""
    notes: str = ""
    recon: dict = field(default_factory=dict)  # full static picture — useful even on failure

    def summary(self) -> str:
        if self.success:
            conf = next((a.get("confidence") for a in reversed(self.attempts) if a.get("flag")), "") or "solved"
            return f"[+] {self.path}: {self.flag}  (via {self.strategy}, {conf}, {self.seconds:.1f}s)"
        return (
            f"[-] {self.path}: no flag in {self.seconds:.1f}s, "
            f"{len(self.attempts)} strategies tried (recon + scaffold still in the report) - {self.notes}"
        )


def _record(result: SolveResult, context: str | None = None) -> None:
    """Append one JSONL line of telemetry so the strategy mix is judgeable.

    ``context`` tags where the run came from ("practice" / "live" / a CTF
    name, caller's choice via ``solve(context=)`` or ``$TRIAGE_CTX``). It is
    the hook for answering "is this tool actually opened first, under time
    pressure?" — see ``docs/TODO.md`` P6.
    """
    dest = os.environ.get("TRIAGE_RESULTS") or str(Path.home() / ".triage" / "results.jsonl")
    row = {
        "ts": round(time.time(), 1),
        "path": result.path,
        "context": context,
        "success": result.success,
        "flag": result.flag,
        "strategy": result.strategy,
        "seconds": result.seconds,
        "plan": [p.get("name") for p in result.plans],
        "attempts": [
            {"s": a["strategy"], "ok": a["ok"], "t": a["seconds"], "conf": a["confidence"]} for a in result.attempts
        ],
        "arch": result.recon.get("arch"),
        "format": result.recon.get("format"),
        "capa_n": len(result.recon.get("capa", ())),
    }
    try:
        p = Path(dest)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
    except OSError:
        pass  # telemetry is best-effort, never fail a solve over it


def recon(path: str, *, use_capa: bool = False, on_event: Callable[[dict], None] | None = None) -> dict:
    """Static picture used by the API / CLI before solving.

    ``use_capa`` runs a flare-capa pass (slow, but cached per file) and folds
    the matched capabilities into both the returned dict and the strategy
    ranking. ``on_event`` receives a ``{"kind": "capa_running"}`` dict just
    before an *uncached* capa scan starts, so a caller can show progress.
    """
    ldr = BinaryLoader(path)
    try:
        info = ldr.get_info()
        prot = ldr.protections()
        imports = sorted({i["name"].split("@")[0] for i in ldr.get_imports()})
        funcs = [n for n, _ in ldr.get_functions()]
    finally:
        ldr.close()
    caps: frozenset[str] = frozenset()
    if use_capa:
        from triage_web.autopwn.capa_scan import capabilities

        on_start = (lambda: on_event({"kind": "capa_running"})) if on_event else None
        caps = capabilities(path, on_start=on_start)
    plans = classify(path, caps)
    out = {
        "path": path,
        "format": info["format"],
        "arch": info["arch"],
        "bits": info["bits"],
        "protections": {k: str(v) for k, v in prot.items()},
        "imports": imports,
        "functions": funcs[:60],
        "plans": [asdict(p) for p in plans],
    }
    if use_capa:
        out["capa"] = sorted(caps)
    return out


def solve(
    path: str,
    *,
    only: list[str] | None = None,
    budget_s: float = 180.0,
    flag_pattern: str | None = None,
    use_capa: bool = False,
    on_event: Callable[[dict], None] | None = None,
    context: str | None = None,
) -> SolveResult:
    """Run the strategy plan against ``path`` and stop at the first flag.

    ``use_capa`` folds a flare-capa capability pass into the strategy ranking
    (slower, off by default). ``on_event``, if given, is called with progress
    dicts as the solve runs (``kind`` in ``recon``/``plan``/``strategy_start``/
    ``strategy_done``/``done``) so a caller can stream feedback. ``context``
    (falls back to ``$TRIAGE_CTX``) is written to the telemetry row only.
    None of the three change whether a flag is found.
    """
    emit = on_event or (lambda _e: None)
    ctx = context or os.environ.get("TRIAGE_CTX")
    t0 = time.monotonic()
    try:
        rec = recon(path, use_capa=use_capa, on_event=on_event)
    except Exception as exc:  # unloadable / mangled binary
        rec = {"error": f"{type(exc).__name__}: {exc}"}
    emit({"kind": "recon", "recon": rec})
    # Reuse the plan recon already computed; re-running classify() here would
    # raise again on an unloadable binary that recon() just swallowed.
    plans: list[StratPlan] = [] if "error" in rec else [StratPlan(**p) for p in rec.get("plans", [])]
    if only:
        plans = [p for p in plans if p.name in only] or [StratPlan(n, 0, "forced") for n in only]
    emit({"kind": "plan", "plan": [asdict(p) for p in plans]})

    def _finish(*, success, flag, strategy, attempts, proof="", stdout="") -> SolveResult:
        res = SolveResult(
            path=path,
            success=success,
            flag=flag,
            strategy=strategy,
            seconds=round(time.monotonic() - t0, 2),
            plans=[asdict(p) for p in plans],
            attempts=[asdict(a) for a in attempts],
            proof=proof,
            stdout=stdout,
            recon=rec,
            notes=(
                ""
                if success
                else "; ".join(f"{a.strategy}: {a.detail[:120]}" for a in attempts if a.detail) or "no strategy applied"
            ),
        )
        _record(res, ctx)
        return res

    attempts: list[Attempt] = []
    for i, plan in enumerate(plans):
        if time.monotonic() - t0 > budget_s:
            att = Attempt(plan.name, False, 0.0, "skipped - time budget exhausted")
            attempts.append(att)
            emit({"kind": "strategy_done", "name": plan.name, "ok": False, "detail": att.detail, "seconds": 0.0})
            continue
        emit(
            {
                "kind": "strategy_start",
                "name": plan.name,
                "index": i,
                "total": len(plans),
                "why": plan.why,
                # seconds this strategy may use before the next one is skipped
                "budget_remaining": round(budget_s - (time.monotonic() - t0), 1),
            }
        )
        started = time.monotonic()
        try:
            att = _run_strategy(plan.name, path, flag_pattern, budget_s - (time.monotonic() - t0))
        except Exception as exc:  # a strategy blew up - record and keep going
            att = Attempt(plan.name, False, round(time.monotonic() - started, 2), f"crashed: {exc}")
        att.seconds = round(time.monotonic() - started, 2)
        if att.ok and att.flag and not att.confidence:
            att.confidence = "solved"  # strategy found a flag but didn't grade itself
        attempts.append(att)
        emit(
            {
                "kind": "strategy_done",
                "name": plan.name,
                "ok": bool(att.ok and att.flag),
                "flag": att.flag,
                "detail": att.detail,
                "seconds": att.seconds,
                "confidence": att.confidence,
            }
        )
        if att.ok and att.flag:
            res = _finish(
                success=True,
                flag=att.flag,
                strategy=plan.name,
                attempts=attempts,
                proof=att.script or att.detail,
                stdout=att.detail,
            )
            emit({"kind": "done", "result": asdict(res)})
            return res

    res = _finish(success=False, flag=None, strategy=None, attempts=attempts)
    emit({"kind": "done", "result": asdict(res)})
    return res


def _run_strategy(name: str, path: str, flag_pattern: str | None, remaining: float) -> Attempt:
    """Dispatch one strategy by name via the registry."""
    return run_strategy(name, RunCtx(path=path, flag_pattern=flag_pattern, remaining=remaining))
