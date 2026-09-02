"""Correctness tests for conditional-branch p-code semantics (DEC-01).

Every assertion inspects PcodeOp/Varnode structure or SSA graph state.
None assert on ``decompile_with_pcode()`` rendered C -- end-to-end ``if``
rendering is Phase 5 (wire ``CFGStructurer``).
"""

from __future__ import annotations

import pytest

from triage_web.cfg import CFGBuilder
from triage_web.pcode import OpCode, Translator, Varnode
from triage_web.ssa_engine import build_ssa

_EFLAGS_OFFSET = 0x0100


def _insns(*rows):
    """Build dict-form Capstone-ish instructions the Translator accepts."""
    return [{"address": addr, "mnemonic": mnem, "op_str": op_str, "size": size} for (addr, mnem, op_str, size) in rows]


def _find_cbranch(ops):
    return next(op for op in ops if op.opcode == OpCode.CBRANCH)


def _defining_op(ops, vn):
    return next(op for op in ops if op.output is vn)


def test_je_cbranch_carries_real_int_equal_predicate():
    ops = Translator().translate(
        _insns(
            (0x1000, "cmp", "eax, 5", 3),
            (0x1003, "je", "0x1006", 3),
            (0x1006, "ret", "", 1),
        )
    )
    cbranch = _find_cbranch(ops)
    cond = cbranch.inputs[0]

    # (a) the condition is NOT the old always-true constant
    assert not cond.is_constant()
    assert cond != Varnode.const(1, 8)

    # (b) the op defining the condition is INT_EQUAL over eax and 5
    pred = _defining_op(ops, cond)
    assert pred.opcode == OpCode.INT_EQUAL
    assert pred.inputs[0].is_register()
    assert pred.inputs[1].is_constant()
    assert pred.inputs[1].offset == 5

    # the branch-target constant is still the CBRANCH's second input
    assert cbranch.inputs[1].is_constant()
    assert cbranch.inputs[1].offset == 0x1006


def test_je_slice_survives_build_ssa_with_condition_reaching_dataflow():
    ops = Translator().translate(
        _insns(
            (0x1000, "cmp", "eax, 5", 3),
            (0x1003, "je", "0x1006", 3),
            (0x1006, "ret", "", 1),
        )
    )
    cbranch = _find_cbranch(ops)
    cond = cbranch.inputs[0]

    graph = CFGBuilder().build(ops, base_addr=0x1000)
    build_ssa(graph)  # must not raise

    # the CBRANCH condition varnode reached the SSA data-flow graph
    assert cond.def_op is not None
    assert cond.def_op.opcode == OpCode.INT_EQUAL


def test_conditional_jump_without_preceding_compare_uses_eflags_not_constant():
    ops = Translator().translate(
        _insns(
            (0x2000, "je", "0x2006", 3),
            (0x2006, "ret", "", 1),
        )
    )
    cond = _find_cbranch(ops).inputs[0]
    assert not cond.is_constant()
    assert cond.is_register()  # honest eflags fallback, never a constant


# ── Task 2: full relational coverage, single-flag routing, data-flow ──


@pytest.mark.parametrize(
    ("mnem", "opcode", "swapped"),
    [
        ("je", OpCode.INT_EQUAL, False),
        ("jne", OpCode.INT_NOTEQUAL, False),
        ("jl", OpCode.INT_SLESS, False),
        ("jb", OpCode.INT_LESS, False),
        ("jg", OpCode.INT_SLESS, True),
        ("ja", OpCode.INT_LESS, True),
    ],
)
def test_cmp_then_jump_recovers_condition_opcode(mnem, opcode, swapped):
    ops = Translator().translate(
        _insns(
            (0x1000, "cmp", "eax, 5", 3),
            (0x1003, mnem, "0x1006", 3),
            (0x1006, "ret", "", 1),
        )
    )
    pred = _defining_op(ops, _find_cbranch(ops).inputs[0])
    assert pred.opcode == opcode
    # `cmp X, Y` is X - Y; swapped jumps synthesize the predicate over (Y, X)
    reg_i, const_i = (1, 0) if swapped else (0, 1)
    assert pred.inputs[reg_i].is_register()
    assert pred.inputs[const_i].is_constant()
    assert pred.inputs[const_i].offset == 5


@pytest.mark.parametrize(("mnem", "opcode"), [("je", OpCode.INT_EQUAL), ("jne", OpCode.INT_NOTEQUAL)])
def test_test_then_eq_jump_compares_and_result_against_zero(mnem, opcode):
    ops = Translator().translate(
        _insns(
            (0x1000, "test", "eax, eax", 2),
            (0x1002, mnem, "0x1006", 4),
            (0x1006, "ret", "", 1),
        )
    )
    pred = _defining_op(ops, _find_cbranch(ops).inputs[0])
    assert pred.opcode == opcode
    assert pred.inputs[0].is_unique()  # the `test` AND-result temp
    assert pred.inputs[1].is_constant()
    assert pred.inputs[1].offset == 0


def test_single_flag_jump_routes_to_eflags_and_is_not_skipped():
    ops = Translator().translate(
        _insns(
            (0x1000, "cmp", "eax, 5", 3),
            (0x1003, "js", "0x1006", 3),
            (0x1006, "ret", "", 1),
        )
    )
    cbranches = [op for op in ops if op.opcode == OpCode.CBRANCH]
    assert len(cbranches) == 1  # routed, not dropped
    cond = cbranches[0].inputs[0]
    assert cond.is_register()
    assert cond.offset == _EFLAGS_OFFSET
    assert not cond.is_constant()
    # no comparison op was synthesized for the single-flag jump
    assert not any(op.output is cond for op in ops)


def test_compare_constant_reaches_ssa_dataflow_from_cbranch_condition():
    ops = Translator().translate(
        _insns(
            (0x1000, "cmp", "eax, 5", 3),
            (0x1003, "jl", "0x1006", 3),
            (0x1006, "ret", "", 1),
        )
    )
    cond = _find_cbranch(ops).inputs[0]
    graph = CFGBuilder().build(ops, base_addr=0x1000)
    build_ssa(graph)
    pred = cond.def_op
    assert pred is not None
    assert any(v.is_constant() and v.offset == 5 for v in pred.inputs)


# ── Task 3: regression gate — the always-true placeholder is gone ─────


def test_translate_cond_jump_no_longer_emits_always_true_constant():
    import inspect

    src = inspect.getsource(Translator._translate_cond_jump)
    code = "".join(line for line in src.splitlines(keepends=True) if not line.lstrip().startswith("#"))
    squashed = code.replace(" ", "")
    # ROADMAP criterion 4: the size-8 constant-one condition is removed …
    assert "Varnode.const(1,8)" not in squashed
    # … while the branch-target constant is still built.
    assert "Varnode.const(target_addr,8)" in squashed
