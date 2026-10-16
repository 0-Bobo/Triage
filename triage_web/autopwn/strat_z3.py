"""Constraint-solve an arithmetic 'enter the key' checker with z3.

``keygen`` handles the ``input == CONSTANT`` shape. This strategy is for the
next step up: the input goes through a short chain of reversible integer ops
(``add`` / ``sub`` / ``xor`` / ``and`` / ``or`` / ``mul`` / ``shl`` / ``shr``
/ ``rol`` / ``ror`` / ``neg`` / ``not``) and *then* the result is compared to
a constant that guards the flag path. We disassemble the guard block, replay
those ops on a symbolic input, and ask z3 for a satisfying value.

It reuses ``strat_keygen``'s disassembly + guard-finding helpers so the two
stay in step; only the modelling is new.

Known bugs, found by a reliability audit while building a real end-to-end
fixture (samples/src/arith_check.c, not yet wired into the sample set because
of the second bug below) — not fixed yet:

1. ``_score_z3`` (registry.py) only ranks this strategy when ``not v.has_win``,
   but ``solve_z3`` itself hard-requires ``_win_addrs()`` to find a win-style
   function (line ~86 below). Every name ``_win_addrs`` matches is also a
   name ``has_win`` matches, so the two conditions are mutually exclusive:
   z3 can never appear in a *natural* ranked plan under the current code,
   confirmed empirically. The real fix is teaching the solver a winless path
   (the guard's own taken branch, printing the flag directly, as its own
   implicit target) rather than requiring a separate named win function.
2. The arithmetic replay can disagree with the real compiled behaviour: on
   ``x ^= 0x1337; x += 42; x *= 3; cmp x, 0x7e``, z3 reported a "satisfying"
   key (``0x1363``) that does not actually satisfy the real binary (verified
   key is ``0x1337``) - likely a basic-block/op-sequence capture bug in
   ``_model_guard_block``. ``_run_z3`` (registry.py) already treats a
   recovered key as unconfirmed until the live replay actually produces a
   flag, so this doesn't currently surface as a false "solved", but the
   underlying model is wrong and should not be trusted for its recovered-key
   value even when z3 itself reports ``sat``.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field

from triage_web.autopwn.runner import extract_flags, run_target, target_kind
from triage_web.autopwn.strat_keygen import (
    HAS_CAPSTONE,
    _disasm_all,
    _find_guard,
    _imm_from_op,
    _md_for,
    _win_addrs,
)
from triage_web.loader import BinaryLoader

HAS_Z3 = importlib.util.find_spec("z3") is not None

_ARITH = (
    "add",
    "sub",
    "xor",
    "and",
    "or",
    "imul",
    "mul",
    "shl",
    "sal",
    "shr",
    "sar",
    "rol",
    "ror",
    "neg",
    "not",
    "inc",
    "dec",
)


@dataclass
class Z3Result:
    ok: bool
    flag: str | None = None
    key: str | None = None
    key_int: int | None = None
    win: str | None = None
    guard_addr: int | None = None
    script: str = ""
    reason: str = ""
    log: list[str] = field(default_factory=list)


def solve_z3(path: str, *, run: bool = True, timeout: float = 20.0) -> Z3Result:
    if not HAS_CAPSTONE:
        return Z3Result(False, reason="capstone not installed")
    if not HAS_Z3:
        return Z3Result(False, reason="z3-solver not installed")
    import z3

    ldr = BinaryLoader(path)
    log: list[str] = []
    try:
        info = ldr.get_info()
        md = _md_for(info)
        if md is None:
            return Z3Result(False, reason=f"no disassembler mode for {info['arch']}", log=log)
        md.detail = False
        try:
            code, base = ldr._get_text_section()
        except Exception:  # pragma: no cover
            return Z3Result(False, reason="could not read .text", log=log)
        insns = _disasm_all(md, bytes(code), base, fixed=info["arch"] not in ("x86", "x86_64"))
        wins = _win_addrs(ldr, log)
        if not wins:
            return Z3Result(False, reason="no win-style function to constrain toward", log=log)
        guard = _find_guard(insns, wins, log)
        if guard is None:
            return Z3Result(False, reason="no constant-compare guard reaches a win function", log=log)
        target_const, guard_addr, win_addr = guard
        win_name = next((n for n, a in wins.items() if a == win_addr), hex(win_addr))

        bits = 64 if info["bits"] == 64 else 32
        f, model_log = _model_guard_block(z3, insns, guard_addr, bits)
        log += model_log
        inp = z3.BitVec("inp", bits)
        solver = z3.Solver()
        solver.add(f(inp) == z3.BitVecVal(target_const, bits))
        if solver.check() != z3.sat:
            return Z3Result(
                False,
                guard_addr=guard_addr,
                win=win_name,
                reason=f"z3 could not satisfy the guard toward {win_name} (unsat / unmodelled op)",
                log=log,
            )
        key_int = solver.model()[inp].as_long()
        fmt = "hex" if _reads_hex(ldr) else "dec"
        key_str = format(key_int, "x") if fmt == "hex" else str(_as_signed(key_int, bits))
        log.append(f"z3: input {key_str!r} ({key_int:#x}) satisfies the guard at {guard_addr:#x} → {win_name}")

        res = Z3Result(
            ok=True,
            key=key_str,
            key_int=key_int,
            win=win_name,
            guard_addr=guard_addr,
            script=_emit_script(path, key_str),
            log=log,
        )
        if run and info["arch"] in ("x86", "x86_64") and target_kind(path) == "elf":
            proc = run_target(path, stdin=(key_str + "\n").encode(), timeout=timeout)
            flags = extract_flags(proc.stdout + proc.stderr)
            if flags:
                res.flag = flags[0]
            elif proc.runnable:
                log.append(f"fed {key_str!r}, program said: {proc.text.strip()[:160]!r}")
        if not res.flag:
            res.reason = "recovered a satisfying key but no flag here — run the target with it"
        return res
    finally:
        ldr.close()


def _model_guard_block(z3, insns, guard_addr, bits):
    """Return ``f(inp_bitvec) -> bitvec`` replaying the arithmetic in the basic
    block that ends at ``guard_addr``. Unmodelled ops are skipped, so the
    solver reports unsat rather than yielding a wrong key."""
    log: list[str] = []
    idx = next((i for i, ins in enumerate(insns) if ins.address == guard_addr), None)
    if idx is None:  # pragma: no cover - guard addr always came from this list
        return (lambda x: x), log
    start = idx
    while start > 0 and insns[start - 1].mnemonic.lower() not in ("call", "ret", "jmp", "retq", "callq"):
        start -= 1
    ops: list[tuple[str, int]] = []
    for ins in insns[start:idx]:
        m = ins.mnemonic.lower()
        if m not in _ARITH:
            continue
        parts = [p.strip() for p in ins.op_str.split(",")]
        imm = _imm_from_op(parts[-1]) if parts else None
        if m in ("neg", "not"):
            ops.append((m, 0))
        elif m in ("inc", "dec"):
            ops.append(("add" if m == "inc" else "sub", 1))
        elif imm is not None:
            ops.append((m, imm & ((1 << bits) - 1)))
    if ops:
        log.append("z3 model: " + " → ".join(m if m in ("neg", "not") else f"{m} {v:#x}" for m, v in ops))

    def f(x):
        mask = z3.BitVecVal((1 << bits) - 1, bits)
        for m, v in ops:
            c = z3.BitVecVal(v, bits)
            if m == "add":
                x = x + c
            elif m == "sub":
                x = x - c
            elif m == "xor":
                x = x ^ c
            elif m == "and":
                x = x & c
            elif m == "or":
                x = x | c
            elif m in ("imul", "mul"):
                x = x * c
            elif m in ("shl", "sal"):
                x = x << c
            elif m in ("shr", "sar"):
                x = z3.LShR(x, c)
            elif m == "rol":
                x = z3.RotateLeft(x, c)
            elif m == "ror":
                x = z3.RotateRight(x, c)
            elif m == "neg":
                x = -x
            elif m == "not":
                x = ~x
            x = x & mask
        return x

    return f, log


def _as_signed(v: int, bits: int) -> int:
    return v - (1 << bits) if v >= (1 << (bits - 1)) else v


def _reads_hex(ldr) -> bool:
    try:
        blob = bytes(ldr._raw)
    except Exception:  # pragma: no cover
        return False
    return b"%x" in blob or b"%X" in blob


def _emit_script(path: str, key: str) -> str:
    return (
        "from pwn import process  # noqa: F401\n"
        f"io = process({path!r})\n"
        f"io.sendline({key!r}.encode())\n"
        "print(io.recvall(timeout=5).decode(errors='replace'))\n"
    )
