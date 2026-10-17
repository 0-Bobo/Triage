"""Constraint-solve an arithmetic 'enter the key' checker with z3.

``keygen`` handles the ``input == CONSTANT`` shape. This strategy is for the
next step up: the input goes through a short chain of reversible integer ops
(``add`` / ``sub`` / ``xor`` / ``and`` / ``or`` / ``mul`` / ``shl`` / ``shr``
/ ``rol`` / ``ror`` / ``neg`` / ``not``) and *then* the result is compared to
a constant that guards the flag path. We disassemble the guard block, replay
those ops on a symbolic input, and ask z3 for a satisfying value.

It reuses ``strat_keygen``'s disassembly + guard-finding helpers so the two
stay in step; only the modelling is new.

A reliability audit (building a real end-to-end fixture,
samples/src/arith_check.c) found and fixed two bugs here:

1. ``_score_z3`` (registry.py) used to exclude ``v.has_win``, but ``solve_z3``
   itself hard-requires ``_win_addrs()`` to find a win-style function - every
   name ``_win_addrs`` matches is also a name ``has_win`` matches, so the two
   conditions were mutually exclusive and z3 could never appear in a natural
   ranked plan. Fixed by scoring it lower instead of excluding it.
2. ``_model_guard_block`` used to replay the guard as a single accumulator,
   extracting only an *immediate* operand per arithmetic instruction - so any
   op against another register (not a constant) was silently dropped instead
   of modelled. On ``x ^= 0x1337; x += 42; x *= 3; cmp x, 0x7e``, gcc even at
   -O0 lowers ``x *= 3`` as ``edx = x; eax = x; eax += eax; eax += edx`` (a
   double-and-add-the-saved-copy strength reduction, not an ``imul``) - two
   register-register adds with no immediate, so the old code dropped the
   multiply entirely and z3 "solved" for the two-op chain instead, landing on
   ``0x1363`` instead of the real ``0x1337``. Fixed by replaying the block as
   a real register/stack-slot dataflow simulation instead of one accumulator.
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


# x86 sub-register spellings that name the same architectural register, so
# `mov edx, eax` / `add eax, eax` / `add eax, edx` thread one value through a
# register rather than each spelling getting its own untracked slot.
_X86_REG_FAMILY = {
    "al": "a",
    "ah": "a",
    "ax": "a",
    "eax": "a",
    "rax": "a",
    "bl": "b",
    "bh": "b",
    "bx": "b",
    "ebx": "b",
    "rbx": "b",
    "cl": "c",
    "ch": "c",
    "cx": "c",
    "ecx": "c",
    "rcx": "c",
    "dl": "d",
    "dh": "d",
    "dx": "d",
    "edx": "d",
    "rdx": "d",
    "sil": "si",
    "si": "si",
    "esi": "si",
    "rsi": "si",
    "dil": "di",
    "di": "di",
    "edi": "di",
    "rdi": "di",
    "bpl": "bp",
    "bp": "bp",
    "ebp": "bp",
    "rbp": "bp",
    "spl": "sp",
    "sp": "sp",
    "esp": "sp",
    "rsp": "sp",
}
for _n in range(8, 16):
    for _suf in ("", "d", "w", "b"):
        _X86_REG_FAMILY[f"r{_n}{_suf}"] = f"r{_n}"
del _n, _suf


def _model_guard_block(z3, insns, guard_addr, bits):
    """Return ``f(inp_bitvec) -> bitvec`` replaying the basic block that ends
    at ``guard_addr`` as a real register/stack-slot dataflow simulation (not
    a single accumulator - see the module docstring's bug #2 for why that
    silently dropped operations like the `eax += edx` half of a compiler's
    `x*3 = x+x+x` strength reduction). The *first* register or memory slot
    read before ever being written becomes the symbolic input; anything else
    read-before-written is assumed unrelated setup state and starts at 0."""
    log: list[str] = []
    idx = next((i for i, ins in enumerate(insns) if ins.address == guard_addr), None)
    if idx is None:  # pragma: no cover - guard addr always came from this list
        return (lambda x: x), log
    start = idx
    while start > 0 and insns[start - 1].mnemonic.lower() not in ("call", "ret", "jmp", "retq", "callq"):
        start -= 1
    block = insns[start:idx]
    cmp_parts = [p.strip() for p in insns[idx].op_str.split(",")] if insns[idx].op_str else []
    cmp_dst = cmp_parts[0] if cmp_parts else None

    trace = [f"{i.mnemonic} {i.op_str}" for i in block if i.mnemonic.lower() in (*_ARITH, "mov")]
    if trace:
        log.append("z3 model trace: " + " ; ".join(trace))

    def f(x):
        mask = z3.BitVecVal((1 << bits) - 1, bits)
        regs: dict[str, object] = {}
        mem: dict[str, object] = {}
        seeded = False

        def read(tok: str):
            nonlocal seeded
            tok = tok.strip()
            imm = _imm_from_op(tok)
            if imm is not None:
                return z3.BitVecVal(imm & ((1 << bits) - 1), bits)
            key = _X86_REG_FAMILY.get(tok, tok)
            table = regs if tok in _X86_REG_FAMILY else mem
            if key not in table:
                table[key] = x if not seeded else z3.BitVecVal(0, bits)
                seeded = True
            return table[key]

        def write(tok: str, v):
            tok = tok.strip()
            key = _X86_REG_FAMILY.get(tok, tok)
            (regs if tok in _X86_REG_FAMILY else mem)[key] = v & mask

        for ins in block:
            m = ins.mnemonic.lower()
            if not ins.op_str:
                continue
            parts = [p.strip() for p in ins.op_str.split(",")]
            dst = parts[0]
            if m == "mov" and len(parts) == 2:
                write(dst, read(parts[1]))
            elif m in ("imul", "mul") and len(parts) == 3:
                write(dst, read(parts[1]) * read(parts[2]))
            elif m in ("neg", "not"):
                cur = read(dst)
                write(dst, -cur if m == "neg" else ~cur)
            elif m in ("inc", "dec"):
                write(dst, read(dst) + (1 if m == "inc" else -1))
            elif m in _ARITH and len(parts) >= 2:
                cur, rhs = read(dst), read(parts[-1])
                if m == "add":
                    res = cur + rhs
                elif m == "sub":
                    res = cur - rhs
                elif m == "xor":
                    res = cur ^ rhs
                elif m == "and":
                    res = cur & rhs
                elif m == "or":
                    res = cur | rhs
                elif m in ("imul", "mul"):
                    res = cur * rhs
                elif m in ("shl", "sal"):
                    res = cur << rhs
                elif m in ("shr", "sar"):
                    res = z3.LShR(cur, rhs)
                elif m == "rol":
                    res = z3.RotateLeft(cur, rhs)
                else:  # ror
                    res = z3.RotateRight(cur, rhs)
                write(dst, res)

        if cmp_dst is not None:
            key = _X86_REG_FAMILY.get(cmp_dst, cmp_dst)
            table = regs if cmp_dst in _X86_REG_FAMILY else mem
            if key in table:
                return table[key] & mask
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
