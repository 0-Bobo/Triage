"""Regression tests for wiring CFGStructurer into the p-code decompile path
(Phase 5: if/no-else in 05-01, extended to if/else in 05-02).

Covers three separate defects that together block conditional structuring:
  A. CFGBuilder._find_boundaries/_connect mixed raw addresses into an
     op-list-index domain, so branch targets never became real boundaries
     and unconditional BRANCH edges never connected.
  B. CFGStructurer._detect_if_else only recognized the two-body merge shape
     (`t.succs & f.succs`), missing the if/no-else case where the
     branch-taken arm IS the merge block.
  C. emit_c never rendered anything for a CBRANCH-terminated block, and even
     if it had, _build_condition named the (never-declared) condition
     varnode instead of inlining its comparison.

Test D (05-02) extends coverage to the classic two-armed if/else shape,
where both branch arms carry real, distinct content and the then-body ends
in an unconditional jump that skips over the else-body.
"""

from __future__ import annotations

from triage_web.cfg import BlockType, CFGBuilder, CFGStructurer, DominatorTree
from triage_web.decompile_actions import default_pipeline
from triage_web.engine import Disassembler
from triage_web.pcode import Translator
from triage_web.ssa_engine import build_ssa

# Shared fixture: cmp+jne-skip if/no-else diamond at realistic, non-zero,
# multi-byte addresses (mirrors tests/test_pcode_branch.py's `_insns` helper).
#   0x1000: cmp eax, 5        -- comparison
#   0x1003: jne 0x100A        -- CBRANCH: taken arm skips straight to merge
#   0x1006: mov [ebx], eax    -- then-body (only arm with real content)
#   0x100A: mov [ecx], eax    -- merge/after
#   0x100E: ret
#
# The then-body and merge-body use memory stores (not register moves) on
# purpose: a `mov reg, imm` whose destination register is never read again
# is legitimately dead code that DeadCodeElimination (Phase 1 of
# default_pipeline) would strip regardless of the CFG-structuring fix this
# plan targets, which would make this fixture unable to demonstrate body
# survival. A STORE op always has `output=None`, so DCE's removal check
# (`if op.output and op.output not in necessary`) never fires for it --
# the store's presence in the graph is unconditional, only its *rendering*
# depends on the fixes under test.
_FIXTURE = [
    (0x1000, "cmp", "eax, 5", 3),
    (0x1003, "jne", "0x100A", 3),
    (0x1006, "mov", "[ebx], eax", 4),
    (0x100A, "mov", "[ecx], eax", 4),
    (0x100E, "ret", "", 1),
]


def _insns(rows):
    return [{"address": addr, "mnemonic": mnem, "op_str": op_str, "size": size} for (addr, mnem, op_str, size) in rows]


def _build_graph():
    ops = Translator().translate(_insns(_FIXTURE), base_addr=0x1000)
    return CFGBuilder().build(ops, base_addr=0x1000)


# ── Test A: boundary/connect bug ───────────────────────────────────────


def test_boundary_and_connect_produce_three_blocks_with_real_addr_targets():
    graph = _build_graph()

    assert graph.num_blocks == 3

    branch_block = graph.blocks[0]
    assert len(branch_block.succs) == 2
    assert branch_block.succs[0].ops[0].addr == 0x100A  # CBRANCH target (merge)
    assert branch_block.succs[1].ops[0].addr == 0x1006  # fallthrough (then-body)


# ── Test B: no-else merge-detection bug ────────────────────────────────


def test_no_else_diamond_is_recognized_as_condition():
    graph = _build_graph()
    ctx = build_ssa(graph)
    default_pipeline().run(ctx)

    domtree = DominatorTree(ctx.graph)
    domtree.compute()
    CFGStructurer(ctx.graph, domtree).structure()

    branch_block = ctx.graph.blocks[0]
    assert branch_block.block_type == BlockType.CONDITION


# ── Test C: end-to-end rendering (the literal ROADMAP criterion) ───────


def test_decompile_with_pcode_renders_natural_if_no_else():
    analysis = {"address": 0x1000, "insns": _insns(_FIXTURE)}
    code = Disassembler().decompile_with_pcode(analysis)

    assert "// no C code generated" not in code
    assert "if (1)" not in code
    assert "tmp_" not in code
    assert "goto" not in code
    assert "else" not in code

    assert "if (" in code
    # Natural polarity: the CBRANCH's own predicate is INT_NOTEQUAL (jne),
    # but its taken arm IS the merge -- so the rendered condition must be
    # the *negation* (INT_EQUAL) to guard entry into the real body.
    assert "==" in code
    assert "5" in code

    assert "rbx" in code  # then-body store target ([ebx] -> canonical rbx alias)
    assert "rcx" in code  # merge-body store target ([ecx] -> canonical rcx alias)
    # merge body must appear exactly once (not duplicated by both the
    # condition-merge lookup AND the plain post-block emission)
    assert code.count("rcx") == 1


# ── Test D: two-armed if/else rendering (05-02) ─────────────────────────

# Classic if/else diamond: the then-body ends in an unconditional jmp that
# skips over the else-body, and both arms have real, distinct content
# (memory stores, for the same DCE-survival reason documented above).
#   0x2000: cmp eax, 5        -- comparison
#   0x2003: jne 0x200D        -- CBRANCH: taken arm is the else-body
#   0x2006: mov [ebx], eax    -- then-body (fallthrough arm)
#   0x200A: jmp 0x2011        -- skip-else, unconditional branch to merge
#   0x200D: mov [ecx], eax    -- else-body (taken arm)
#   0x2011: ret               -- merge (no content of its own)
_FIXTURE_IFELSE = [
    (0x2000, "cmp", "eax, 5", 3),
    (0x2003, "jne", "0x200D", 3),
    (0x2006, "mov", "[ebx], eax", 4),
    (0x200A, "jmp", "0x2011", 3),
    (0x200D, "mov", "[ecx], eax", 4),
    (0x2011, "ret", "", 1),
]


def test_decompile_with_pcode_renders_two_armed_if_else():
    analysis = {"address": 0x2000, "insns": _insns(_FIXTURE_IFELSE)}
    code = Disassembler().decompile_with_pcode(analysis)

    assert "// no C code generated" not in code
    assert "goto" not in code

    assert "if (" in code
    assert code.count("else {") == 1

    # Condition compares eax (canonical rax alias) and 5.
    assert "rax" in code
    assert "5" in code

    # Both bodies present, each exactly once (no duplicated merge/arm content).
    assert "rbx" in code  # then-body store target ([ebx] -> canonical rbx alias)
    assert "rcx" in code  # else-body store target ([ecx] -> canonical rcx alias)
    assert code.count("rbx") == 1
    assert code.count("rcx") == 1
