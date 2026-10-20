"""Render a solved (or attempted) target into a standalone Markdown writeup.

Takes the same dict shape ``solve()`` already returns (``asdict(SolveResult)``,
the shape the web UI's SSE ``done`` event and ``POST /api/autopwn`` both send) -
no extra run, no extra state. One function, reused by the CLI's auto-write-on-
solve and the web UI's "Save Writeup" button via ``POST /api/autopwn/writeup``.
"""

from __future__ import annotations

from pathlib import Path

# Strategies that produce a real, runnable exploit script. Everything else
# finds the flag by analyzing or simulating the binary (no live process was
# attacked), so there's no script to show — gated on strategy identity, not
# guessed from the proof text's shape.
_SCRIPT_STRATEGIES = {"ret2win", "z3", "format_string", "uaf"}

# Vulnerability/technique class per winning strategy, for the writeup's
# labeled field (REPORT-01). Keyed on strategy identity, same as
# ``_SCRIPT_STRATEGIES`` above — not guessed from proof/why text. Strategies
# that recover a flag by analysis/simulation rather than exploiting a real
# memory-safety bug are labeled as such rather than forced into a vuln class
# that doesn't apply.
_VULN_CLASS = {
    "ret2win": "stack buffer overflow (ret2win)",
    "format_string": "format string vulnerability",
    "uaf": "use-after-free (dangling callback)",
    "angr": "memory-safety bug recovered via symbolic execution",
    "z3": "key-check guard recovered via constraint solving (no memory-safety bug)",
    "keygen": "weak key-check guard (hard-coded compare, no memory-safety bug)",
    "brute": "weak/brute-forceable secret (no memory-safety bug)",
    "emulate": "flag recovered via emulation, not vulnerability exploitation",
    "smc": "self-modifying/packed code, statically unwrapped (no memory-safety bug)",
}


def generate_writeup(result: dict) -> str:
    """Render ``result`` (an ``asdict(SolveResult)``-shaped dict) as Markdown."""
    recon = result.get("recon") or {}
    name = Path(result.get("path", "target")).name
    lines: list[str] = [f"# {name}: autopwn writeup", ""]

    lines.append(f"- Binary: `{result.get('path', '?')}`")
    if recon.get("format"):
        lines.append(f"- Format: {recon.get('arch', '?')} {recon.get('bits', '?')}-bit {recon.get('format', '?')}")
    protections = recon.get("protections") or {}
    if protections:
        lines.append("- Protections: " + ", ".join(f"{k} {v}" for k, v in protections.items()))

    success = bool(result.get("success"))
    seconds = result.get("seconds", 0)
    if success:
        lines.append(f"- Flag: `{result.get('flag')}`")
        lines.append(f"- Winning strategy: `{result.get('strategy')}` in {seconds}s")
        vuln_class = _VULN_CLASS.get(result.get("strategy") or "")
        if vuln_class:
            lines.append(f"- Vulnerability class: {vuln_class}")
    else:
        lines.append(f"- Solved: no (every strategy exhausted in {seconds}s)")
    lines.append("")

    plans = recon.get("plans") or []
    winner_plan = next((p for p in plans if p.get("name") == result.get("strategy")), None)
    if winner_plan and winner_plan.get("why"):
        lines += ["## Why this strategy", "", winner_plan["why"], ""]

    proof = (result.get("proof") or "").rstrip()
    strategy = result.get("strategy")
    if proof:
        if strategy in _SCRIPT_STRATEGIES:
            lines += ["## Exploit", "", "```python", proof, "```", ""]
        elif strategy == "smc":
            lines += [
                "## Decoded image",
                "",
                "The self-modifying-code layer was statically decoded (header repair, "
                f"stub-derived unwrap) without ever executing the target: `{proof}`.",
                "",
            ]
        else:
            lines += ["## How the flag was found", "", proof, ""]

    attempts = result.get("attempts") or []
    if attempts:
        lines += ["## Strategy log", "", "| strategy | result | detail |", "|---|---|---|"]
        for a in attempts:
            outcome = "flag" if a.get("flag") else ("ok" if a.get("ok") else "no flag")
            detail = (a.get("detail") or "").replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {a.get('strategy', '?')} | {outcome} | {detail} |")
        lines.append("")

    if result.get("notes"):
        lines += ["## Notes", "", result["notes"], ""]

    return "\n".join(lines).rstrip() + "\n"


def default_writeup_path(result: dict) -> Path:
    """Where the CLI drops the writeup: next to the target, `<stem>-writeup.md`."""
    target = Path(result.get("path", "target"))
    return target.with_name(f"{target.stem}-writeup.md")
