"""Declarative solver-strategy registry.

Every strategy is one :class:`Strategy`:

* ``score(view)`` turns the static picture into ``(priority, rationale)`` or
  ``None`` when the strategy does not apply;
* ``run(ctx)`` invokes the strategy and returns an :class:`Attempt`.

:func:`plan` ranks the applicable strategies; :func:`run_strategy` dispatches
one by name. Adding a strategy is a two-step change with no ripple: write the
``strat_<x>`` module, then append one :class:`Strategy` to :data:`STRATEGIES`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from triage_web.analysis import find_win_functions
from triage_web.autopwn.attempt import Attempt
from triage_web.loader import BinaryLoader

# ── static signals every scorer reads ────────────────────────────────

_BOF_SINKS = {"gets", "strcpy", "strcat", "sprintf", "scanf", "read", "recv", "fread", "fgets", "memcpy"}
_FMT_FUNCS = {"printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "syslog", "vsnprintf"}
_NET_FUNCS = {"socket", "bind", "listen", "accept", "recv", "send"}
_INPUT_FUNCS = {"scanf", "gets", "fgets", "read", "getchar", "__isoc99_scanf", "fread"}
_WIN_HINT = ("win", "show_flag", "print_flag", "backdoor", "get_flag", "secret", "admin", "flag")


@dataclass
class StratPlan:
    name: str  # smc | keygen | emulate | z3 | ret2win | uaf | format_string | angr | brute
    score: int  # higher = try earlier
    why: str


@dataclass(frozen=True)
class StaticView:
    """Everything the scorers need, derived once from a ``BinaryLoader``."""

    path: str
    fmt: str
    arch: str
    bits: int
    imports: frozenset[str]
    func_names: frozenset[str]
    strings_lc: str
    wins: tuple[str, ...]
    smc_reason: str | None
    capa: frozenset[str] = frozenset()  # capa namespaces + rule names, lowercased

    @property
    def x86(self) -> bool:
        return self.arch in ("x86", "x86_64")

    @property
    def has_win(self) -> bool:
        return bool(self.wins) or any(any(h in n.lower() for h in _WIN_HINT) for n in self.func_names)

    @property
    def has_bof_sink(self) -> bool:
        return bool(self.imports & _BOF_SINKS)

    @property
    def has_fmt(self) -> bool:
        return bool(self.imports & _FMT_FUNCS)

    @property
    def is_net(self) -> bool:
        return bool(self.imports & _NET_FUNCS)

    @property
    def reads_input(self) -> bool:
        return bool(self.imports & _INPUT_FUNCS) or "password" in self.strings_lc or "enter" in self.strings_lc

    @property
    def checker_words(self) -> bool:
        words = ("correct", "wrong", "denied", "congrat", "flag", "password", "invalid")
        return any(w in self.strings_lc for w in words)

    def capa_hit(self, *needles: str) -> bool:
        """True if any capa rule/namespace contains one of ``needles``."""
        return any(any(n in cap for n in needles) for cap in self.capa)


def _looks_self_modifying(ldr: BinaryLoader) -> str | None:
    """RWE ``PT_LOAD`` or a trashed ELF ``e_ident`` → decrypt-at-entry shape."""
    try:
        raw = bytes(ldr._raw)
    except Exception:  # pragma: no cover - loader always has _raw
        raw = b""
    if raw[:4] == b"\x7fELF" and len(raw) >= 16:
        # a sane ident always has EI_VERSION == 1 and zero padding (bytes 9..15);
        # the oracle overwrites the lot with 0x02, which pyelftools/objdump reject
        if raw[6] != 1 or any(raw[9:16]):
            return "mangled ELF e_ident (anti-tooling)"
    for seg in ldr.get_segments():
        if seg["type"] == "PT_LOAD" and set(seg["flags"]) >= {"W", "X"}:
            return "writable+executable PT_LOAD segment"
    return None


def build_view(ldr: BinaryLoader, capa: frozenset[str] = frozenset()) -> StaticView:
    info = ldr.get_info()
    try:
        strings = "\n".join(ldr.get_strings(min_len=4)).lower()
    except Exception:  # pragma: no cover - get_strings has its own fallbacks
        strings = ""
    return StaticView(
        path=str(getattr(ldr, "path", "")),
        fmt=info["format"],
        arch=info["arch"],
        bits=info["bits"],
        imports=frozenset(i["name"].split("@")[0] for i in ldr.get_imports()),
        func_names=frozenset(n for n, _ in ldr.get_functions()),
        strings_lc=strings,
        wins=tuple(find_win_functions(ldr)),
        smc_reason=_looks_self_modifying(ldr),
        capa=capa,
    )


# ── strategy type ───────────────────────────────────────────────────

Scored = "tuple[int, str] | None"
ScoreFn = Callable[[StaticView], "tuple[int, str] | None"]
RunFn = Callable[["RunCtx"], Attempt]


@dataclass(frozen=True)
class RunCtx:
    path: str
    flag_pattern: str | None
    remaining: float  # seconds left in the overall budget


@dataclass(frozen=True)
class Strategy:
    name: str
    score: ScoreFn
    run: RunFn


# ── scorers ─────────────────────────────────────────────────────────
# Reproduce the priorities the orchestrator has always used, with capa
# capabilities nudging a strategy up when the disassembly-only signal is weak.


def _score_smc(v: StaticView) -> tuple[int, str] | None:
    if v.smc_reason:
        return 90, f"{v.smc_reason} — try a static self-modifying-code unwrap first"
    if v.capa_hit("self-modifying", "unpack", "decrypt data", "packed"):
        return 62, "capa: unpacking / self-modifying behaviour — try the SMC unwrap"
    return None


def _score_keygen(v: StaticView) -> tuple[int, str] | None:
    if v.has_win and (v.reads_input or v.checker_words):
        score = 84 if not v.x86 else 78  # only static option off-x86; cheap enough to lead elsewhere
        return score, "win-style function + reads input — check for a hard-coded compare guard"
    return None


def _score_emulate(v: StaticView) -> tuple[int, str] | None:
    if v.x86 and v.fmt == "ELF" and not v.is_net:
        score = 55
        if not v.reads_input:
            score += 25  # nothing to solve for → likely builds the flag itself
        if "flag" in v.strings_lc or "key" in v.strings_lc:
            score += 10
        return score, f"{v.arch} ELF, unicorn can run a function and scan memory"
    return None


def _score_ret2win(v: StaticView) -> tuple[int, str] | None:
    if not v.has_win:
        return None
    sink = ", ".join(sorted(v.imports & _BOF_SINKS))
    strong = "overflow" in v.strings_lc or v.has_bof_sink
    base = 80 if strong else 40
    if v.is_net:  # pragma: no cover - needs a stripped networked binary with a recoverable win sym
        base -= 18
    if not v.x86:  # pragma: no cover - needs a non-x86 (e.g. SPARC) win-function fixture
        base -= 5  # script-only but still the best lead
    why = "win-style function present" + (f" + overflow sink ({sink})" if strong else " — try a plain overflow")
    return base, why


def _score_uaf(v: StaticView) -> tuple[int, str] | None:
    if v.is_net and {"free", "getenv"} <= v.imports:  # pragma: no cover - needs a networked free()+getenv() fixture
        score = 74 if "flag" in v.strings_lc else 66
        return score, "networked service that free()s + getenv()s — check for a dangling-callback UAF"
    return None


def _score_format_string(v: StaticView) -> tuple[int, str] | None:
    if v.has_fmt and "printf" in v.imports:
        return (
            70 if v.is_net else 45,
            "printf-family import — likely a user-controlled format string" + (" on a socket" if v.is_net else ""),
        )
    return None


def _score_angr(v: StaticView) -> tuple[int, str] | None:
    if v.fmt in ("ELF", "PE") and (v.reads_input or v.checker_words):
        score = 60
        if v.bits == 32:  # pragma: no cover - needs a 32-bit checker fixture
            score += 8
        if v.is_net:  # pragma: no cover - needs a networked checker fixture
            score -= 20
        return score, "reads input + success/failure text — symbolic execution can invert it"
    return None


def _score_z3(v: StaticView) -> tuple[int, str] | None:
    """Arithmetic / checksum 'enter the key' checkers: a chain of
    add/sub/xor/mul/rol on the input compared to a constant. Needs real
    input to solve for, so keygen (constant-compare) is preferred when a
    win-style function is present."""
    if not v.reads_input or v.has_win:
        return None
    if v.capa_hit("checksum", "crc", "hash", "arithmetic", "encode data using xor"):
        return 68, "capa: arithmetic / checksum over input — solve the constraint with z3"
    if v.x86 and v.fmt in ("ELF", "PE"):
        return 42, "reads input + compares against a value — try a z3 constraint solve"
    return None


def _score_brute(v: StaticView) -> tuple[int, str] | None:
    """Char-by-char / short-keyspace brute: only worth it when the program is
    runnable and there's a pass/fail oracle but no cheaper static route."""
    if v.fmt == "ELF" and v.x86 and v.reads_input and not v.has_win:
        return 30, "runnable checker with a pass/fail oracle — brute the key char-by-char"
    return None


# ── runners ─────────────────────────────────────────────────────────
# One lazy import per strategy, so heavy backends (angr, z3, unicorn,
# pwntools) are only paid for when the strategy actually runs.


def _run_smc(ctx: RunCtx) -> Attempt:
    from triage_web.autopwn.strat_smc import solve_smc

    r = solve_smc(ctx.path, timeout=min(60.0, max(20.0, ctx.remaining)))
    detail = r.reason or "unwrapped SMC layer"
    if r.decoded_path:
        extra = ", anti-debug neutralised" if r.antidebug_patched else ""
        detail += f" [transform={r.transform!r}{extra}, decoded image: {r.decoded_path}]"
    return Attempt("smc", bool(r.flag), 0.0, detail, r.flag, r.decoded_path or "")


def _run_emulate(ctx: RunCtx) -> Attempt:
    from triage_web.autopwn.strat_emulate import emulate_for_flag

    r = emulate_for_flag(ctx.path, flag_pattern=ctx.flag_pattern)
    return Attempt("emulate", r.ok, 0.0, r.reason or f"stdout={r.stdout[:120]!r}", r.flag)


def _run_angr(ctx: RunCtx) -> Attempt:
    from triage_web.autopwn.strat_angr import solve_with_angr

    r = solve_with_angr(ctx.path, flag_pattern=ctx.flag_pattern, step_budget=int(max(4000, ctx.remaining * 300)))
    detail = r.reason or f"input={r.stdin!r} stdout={r.stdout[:160]!r}"
    return Attempt("angr", r.ok, 0.0, detail, r.flag)


def _run_keygen(ctx: RunCtx) -> Attempt:
    from triage_web.autopwn.strat_keygen import solve_keygen

    r = solve_keygen(ctx.path)
    detail = r.reason or f"key={r.key!r} → {r.win} @ {r.win_addr:#x}"
    return Attempt("keygen", bool(r.flag), 0.0, detail, r.flag, "")


def _run_uaf(ctx: RunCtx) -> Attempt:
    from triage_web.autopwn.strat_uaf import solve_uaf

    r = solve_uaf(ctx.path, timeout=min(200.0, max(60.0, ctx.remaining)))
    detail = r.reason or f"flag_func={r.flag_func:#x} struct={r.struct_size:#x} ws={r.websocket}"
    if r.flag_func is not None:
        detail += f" route={r.route}"
    return Attempt("uaf", bool(r.flag), 0.0, detail, r.flag, r.script)


def _run_ret2win(ctx: RunCtx) -> Attempt:
    from triage_web.autopwn.strat_ret2win import solve_ret2win

    r = solve_ret2win(ctx.path, timeout=min(90.0, max(20.0, ctx.remaining)))
    detail = r.reason or f"win={r.win}@{r.win_addr:#x} offset={r.offset}"
    return Attempt("ret2win", r.ok, 0.0, detail, r.flag, r.script)


def _run_format_string(ctx: RunCtx) -> Attempt:
    from triage_web.autopwn.strat_fmt import solve_format_string

    r = solve_format_string(ctx.path, timeout=min(60.0, max(15.0, ctx.remaining)))
    return Attempt("format_string", r.ok, 0.0, r.reason or f"leak={r.leak[:160]!r}", r.flag, r.script)


def _run_z3(ctx: RunCtx) -> Attempt:
    from triage_web.autopwn.strat_z3 import solve_z3

    r = solve_z3(ctx.path)
    detail = r.reason or f"key={r.key!r} → {r.win}"
    return Attempt("z3", bool(r.flag), 0.0, detail, r.flag, r.script)


def _run_brute(ctx: RunCtx) -> Attempt:
    from triage_web.autopwn.strat_brute import solve_brute

    r = solve_brute(ctx.path, timeout=min(90.0, max(20.0, ctx.remaining)))
    return Attempt("brute", bool(r.flag), 0.0, r.reason or f"key={r.key!r}", r.flag, "")


STRATEGIES: list[Strategy] = [
    Strategy("smc", _score_smc, _run_smc),
    Strategy("keygen", _score_keygen, _run_keygen),
    Strategy("emulate", _score_emulate, _run_emulate),
    Strategy("z3", _score_z3, _run_z3),
    Strategy("ret2win", _score_ret2win, _run_ret2win),
    Strategy("uaf", _score_uaf, _run_uaf),
    Strategy("format_string", _score_format_string, _run_format_string),
    Strategy("angr", _score_angr, _run_angr),
    Strategy("brute", _score_brute, _run_brute),
]

_BY_NAME: dict[str, Strategy] = {s.name: s for s in STRATEGIES}


def plan(view: StaticView) -> list[StratPlan]:
    """Rank the applicable strategies, best first, one entry per strategy."""
    plans: list[StratPlan] = []
    for s in STRATEGIES:
        scored = s.score(view)
        if scored is not None:
            plans.append(StratPlan(s.name, scored[0], scored[1]))
    if not plans:  # pragma: no cover - safety net for exotic arch/format with no signal
        plans = [
            StratPlan("emulate", 20, "no strong signal — try emulation then symbolic execution"),
            StratPlan("angr", 15, "fallback"),
        ]
    plans.sort(key=lambda p: p.score, reverse=True)
    seen: set[str] = set()
    uniq: list[StratPlan] = []
    for p in plans:
        if p.name not in seen:
            seen.add(p.name)
            uniq.append(p)
    return uniq


def run_strategy(name: str, ctx: RunCtx) -> Attempt:
    strat = _BY_NAME.get(name)
    if strat is None:
        return Attempt(name, False, 0.0, f"unknown strategy {name!r}")
    return strat.run(ctx)
