"""Symbolic-execution flag / password recovery.

Drives the target with a symbolic stdin (or argv) and explores toward a
"success" marker in the program's own output while pruning "failure"
paths. On a hit it reports the concrete input that reaches success and
whatever the program printed there (often the flag itself).

Best for keygen-style crackmes and password gates. Large C++ or
heavily-obfuscated targets may not converge inside the step budget — the
result then carries ``ok=False`` with a reason, and the orchestrator moves
on.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from triage_web.autopwn.runner import extract_flags

try:
    import angr
    import claripy

    HAS_ANGR = True
except ImportError:  # pragma: no cover - angr is an install-time optional dep
    HAS_ANGR = False

# angr is extremely chatty; keep it to real errors.
for _n in ("angr", "cle", "pyvex", "claripy", "archinfo"):
    logging.getLogger(_n).setLevel(logging.ERROR)

_GOOD = (b"correct", b"congrat", b"well done", b"you win", b"access granted", b"flag is", b"flag{", b":)", b"good job")
_BAD = (b"wrong", b"incorrect", b"denied", b"invalid", b"nope", b"try again", b"not welcome", b"fail", b"no.")


@dataclass
class AngrResult:
    ok: bool
    stdin: bytes | None = None
    flag: str | None = None
    stdout: bytes = b""
    reason: str = ""
    found: int = 0
    explored: int = 0
    log: list[str] = field(default_factory=list)


def solve_with_angr(
    path: str,
    *,
    find_markers: tuple[bytes, ...] = _GOOD,
    avoid_markers: tuple[bytes, ...] = _BAD,
    input_len: int = 48,
    use_argv: bool = False,
    printable: bool = True,
    step_budget: int = 60_000,
    flag_pattern: str | None = None,
) -> AngrResult:
    if not HAS_ANGR:
        return AngrResult(False, reason="angr not installed")

    log: list[str] = []
    try:
        proj = angr.Project(path, auto_load_libs=False)
    except Exception as exc:  # cle chokes on a mangled / exotic binary
        return AngrResult(False, reason=f"angr could not load the target: {exc}", log=log)

    sym = claripy.BVS("input", 8 * input_len)
    if use_argv:
        state = proj.factory.full_init_state(args=[path, sym])
    else:
        stdin = angr.SimFileStream(name="stdin", content=sym, has_end=True)
        state = proj.factory.full_init_state(
            stdin=stdin,
            add_options={angr.options.LAZY_SOLVES, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
        )
    if printable:
        for i in range(input_len):
            byte = sym.get_byte(i)
            state.solver.add(claripy.Or(byte == 0, claripy.And(byte >= 0x20, byte <= 0x7E)))

    simgr = proj.factory.simulation_manager(state)
    try:
        simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=64))
    except Exception:  # pragma: no cover - LoopSeer needs a CFG on some versions
        pass

    lower_find = tuple(m.lower() for m in find_markers)
    lower_avoid = tuple(m.lower() for m in avoid_markers)

    def _find(st) -> bool:
        return any(m in st.posix.dumps(1).lower() for m in lower_find)

    def _avoid(st) -> bool:
        return any(m in st.posix.dumps(1).lower() for m in lower_avoid)

    def _found() -> list:
        return simgr.stashes.get("found", [])

    steps = 0
    while simgr.active and not _found() and steps < step_budget:
        simgr.explore(find=_find, avoid=_avoid, num_find=1, n=20)
        steps += 20
        if steps % 8000 == 0:
            log.append(f"...{steps} steps, {len(simgr.active)} active")

    explored = steps
    if not _found():
        return AngrResult(
            False,
            reason=f"no success path within {step_budget} steps ({len(simgr.active)} active left)",
            explored=explored,
            log=log,
        )

    found = _found()[0]
    raw_in = found.posix.dumps(0)
    win_in = raw_in.split(b"\x00")[0] if not use_argv else found.solver.eval(sym, cast_to=bytes).split(b"\x00")[0]
    out = found.posix.dumps(1)
    flags = extract_flags(out, flag_pattern) or extract_flags(win_in, flag_pattern)
    return AngrResult(
        ok=True,
        stdin=win_in,
        flag=(flags or [None])[0],
        stdout=out,
        found=len(simgr.found),
        explored=explored,
        log=log,
    )
