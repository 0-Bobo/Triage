"""Decompiler Action Pipeline — transformation passes on p-code SSA form.

Inspired by Ghidra's coreaction.hh (63 core actions) and ruleaction.hh (133 rules).

Each Action is a single transformation pass. Actions are grouped into phases
and applied in sequence. Some actions repeat until no more changes (fixed point).

Pipeline phases:
  Phase 1: First-pass simplification (DCE, constprop, cpyprop, trivial reductions)
  Phase 2: Control flow cleanup (unreachable elimination, block merging)
  Phase 3: Type recovery (type inference, cast insertion)
  Phase 4: Variable naming and final cleanup
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Tuple

from .pcode import OpCode, PcodeOp, Varnode
from .cfg import BasicBlock
from .ssa_engine import SSAContext, _varname_key


# ── Action Base Class ─────────────────────────────────────────────────

class Action(ABC):
    """Base class for all decompiler transformation passes.

    Mirrors Ghidra's Action class (action.hh).
    """

    def __init__(self, name: str, repeat: bool = False):
        self.name = name
        self.repeat = repeat  # Whether to repeat until no change
        self._count = 0       # Number of changes made

    @abstractmethod
    def apply(self, ctx: SSAContext) -> bool:
        """Apply the action. Returns True if changes were made."""
        ...

    def run(self, ctx: SSAContext) -> bool:
        """Run the action (handles repeat logic)."""
        changed = self.apply(ctx)
        if changed:
            self._count += 1
        if self.repeat and changed:
            while self.apply(ctx):
                self._count += 1
        return changed


# ── Action Pipeline ───────────────────────────────────────────────────

class ActionPipeline:
    """Sequenced pipeline of transformation actions.

    Usage:
        pipeline = ActionPipeline()
        pipeline.add_phase('simplify', [
            DeadCodeElimination(),
            CopyPropagation(),
            ConstantPropagation(),
        ])
        pipeline.run(ctx)
    """

    def __init__(self):
        self.phases: List[Tuple[str, List[Action]]] = []

    def add_phase(self, name: str, actions: List[Action]):
        self.phases.append((name, actions))

    def run(self, ctx: SSAContext):
        for name, actions in self.phases:
            for action in actions:
                action.run(ctx)

    def print_stats(self):
        for name, actions in self.phases:
            for a in actions:
                print(f'  {a.name}: {a._count} changes')


# ══════════════════════════════════════════════════════════════════════
# Phase 1: First-Pass Simplification
# ══════════════════════════════════════════════════════════════════════

class DeadCodeElimination(Action):
    """Remove ops whose outputs have no consumers.

    Mirrors Ghidra's ActionDeadCode.
    Backward reachability from essential ops (stores, branches, returns, calls).
    """

    def __init__(self):
        super().__init__('dead_code_elimination', repeat=True)

    def apply(self, ctx: SSAContext) -> bool:
        necessary: Set[Varnode] = set()

        def mark(vn: Varnode):
            if vn in necessary or vn.is_constant():
                return
            necessary.add(vn)
            if vn.def_op:
                for inp in vn.def_op.inputs:
                    mark(inp)

        # Seed: any op that has a side effect
        for block in ctx.graph.blocks:
            for op in block.ops:
                if op.is_store or op.is_branch or op.is_return or op.is_call:
                    for inp in op.inputs:
                        mark(inp)
                if op.is_store:
                    for inp in op.inputs:
                        mark(inp)

        # Remove unmarked
        changed = False
        for block in ctx.graph.blocks:
            new_ops = []
            for op in block.ops:
                if op.output and op.output not in necessary:
                    if not op.is_store and not op.is_call and not op.is_branch:
                        changed = True
                        continue
                new_ops.append(op)
            block.ops = new_ops

        return changed


class CopyPropagation(Action):
    """Replace uses of COPY outputs with their source.

    Mirrors Ghidra's RulePropagateCopy / ActionCopyPropagate.
    COPY rdx ← rax → all future uses of rdx become uses of rax.
    """

    def __init__(self):
        super().__init__('copy_propagation', repeat=True)

    def apply(self, ctx: SSAContext) -> bool:
        changed = False
        for block in ctx.graph.blocks:
            for op in block.ops:
                if op.is_copy and op.output and op.inputs:
                    src = op.inputs[0]
                    dst = op.output
                    if not dst.uses:
                        continue
                    # Replace all uses of dst with src
                    for use_op in list(dst.uses):
                        for i, inp in enumerate(use_op.inputs):
                            if inp is dst:
                                use_op.inputs[i] = src
                    dst.uses.clear()
                    changed = True
        return changed


class ConstantPropagation(Action):
    """Forward propagate constants through the SSA graph.

    For each op where all inputs are constant → evaluate and replace output.
    Mirrors Ghidra's constant propagation passes.
    """

    def __init__(self):
        super().__init__('constant_propagation', repeat=True)
        self._lattice: Dict[str, Optional[int]] = {}

    def apply(self, ctx: SSAContext) -> bool:
        changed = False

        # Initialize with existing constants
        for block in ctx.graph.blocks:
            for op in block.ops:
                if op.output and op.output.is_constant():
                    self._lattice[_varname_key(op.output)] = op.output.offset

        for block in ctx.graph.blocks:
            for op in block.ops:
                if op.output and op.is_phi:
                    continue
                if op.output and _varname_key(op.output) not in self._lattice:
                    all_const = True
                    vals = []
                    for inp in op.inputs:
                        vn = _varname_key(inp)
                        if vn in self._lattice:
                            vals.append(self._lattice[vn])
                        elif inp.is_constant():
                            vals.append(inp.offset)
                        else:
                            all_const = False
                            break
                    if all_const and vals:
                        result = self._eval_op(op.opcode, vals)
                        if result is not None:
                            self._lattice[_varname_key(op.output)] = result
                            changed = True

        return changed

    def _eval_op(self, opcode: OpCode, vals: List[int]) -> Optional[int]:
        """Evaluate p-code op with constant inputs."""
        ops = {
            OpCode.INT_ADD: lambda v: v[0] + v[1],
            OpCode.INT_SUB: lambda v: v[0] - v[1],
            OpCode.INT_MULT: lambda v: v[0] * v[1],
            OpCode.INT_AND: lambda v: v[0] & v[1],
            OpCode.INT_OR: lambda v: v[0] | v[1],
            OpCode.INT_XOR: lambda v: v[0] ^ v[1],
            OpCode.INT_LEFT: lambda v: v[0] << v[1],
            OpCode.INT_RIGHT: lambda v: v[0] >> v[1],
            OpCode.INT_NEGATE: lambda v: ~v[0],
            OpCode.INT_2COMP: lambda v: -v[0],
            OpCode.COPY: lambda v: v[0],
            OpCode.INT_SRIGHT: lambda v: (v[0] >> v[1]) if v[0] >= 0
                                 else (v[0] >> v[1]) | (~0 << (64 - v[1])),
        }
        fn = ops.get(opcode)
        if fn and len(vals) >= 2:
            return fn(vals[:2])
        elif fn and len(vals) == 1:
            return fn(vals)
        return None


class TrivialArithElimination(Action):
    """Eliminate trivial arithmetic: x + 0, x * 1, x & x, etc.

    Mirrors Ghidra's RuleTrivialArith.
    """

    def __init__(self):
        super().__init__('trivial_arith_elim', repeat=True)

    def apply(self, ctx: SSAContext) -> bool:
        changed = False
        for block in ctx.graph.blocks:
            new_ops = []
            for op in block.ops:
                # x + 0 → x   (INT_ADD with const 0)
                if op.opcode == OpCode.INT_ADD and len(op.inputs) >= 2:
                    if op.inputs[1].is_constant() and op.inputs[1].offset == 0:
                        # Replace with COPY
                        new_op = PcodeOp(OpCode.COPY, op.output,
                                        [op.inputs[0]], addr=op.addr)
                        new_ops.append(new_op)
                        changed = True
                        continue
                # x - 0 → x
                if op.opcode == OpCode.INT_SUB and len(op.inputs) >= 2:
                    if op.inputs[1].is_constant() and op.inputs[1].offset == 0:
                        new_op = PcodeOp(OpCode.COPY, op.output,
                                        [op.inputs[0]], addr=op.addr)
                        new_ops.append(new_op)
                        changed = True
                        continue
                # x * 1 → x
                if op.opcode == OpCode.INT_MULT and len(op.inputs) >= 2:
                    if op.inputs[1].is_constant() and op.inputs[1].offset == 1:
                        new_op = PcodeOp(OpCode.COPY, op.output,
                                        [op.inputs[0]], addr=op.addr)
                        new_ops.append(new_op)
                        changed = True
                        continue
                # x & x → x
                if op.opcode == OpCode.INT_AND and len(op.inputs) >= 2:
                    if op.inputs[0] is op.inputs[1]:
                        new_op = PcodeOp(OpCode.COPY, op.output,
                                        [op.inputs[0]], addr=op.addr)
                        new_ops.append(new_op)
                        changed = True
                        continue
                # x | x → x
                if op.opcode == OpCode.INT_OR and len(op.inputs) >= 2:
                    if op.inputs[0] is op.inputs[1]:
                        new_op = PcodeOp(OpCode.COPY, op.output,
                                        [op.inputs[0]], addr=op.addr)
                        new_ops.append(new_op)
                        changed = True
                        continue
                # x ^ x → 0
                if op.opcode == OpCode.INT_XOR and len(op.inputs) >= 2:
                    if op.inputs[0] is op.inputs[1]:
                        new_op = PcodeOp(OpCode.COPY, op.output,
                                        [Varnode.const(0)], addr=op.addr)
                        new_ops.append(new_op)
                        changed = True
                        continue
                new_ops.append(op)
            block.ops = new_ops
        return changed


class SubvariableReduction(Action):
    """Reduce SUBPIECE/ZEXT/SEXT cascades.

    Mirrors Ghidra's rules: RulePiece2Zext, RulePiece2Sext, RuleZextEliminate.
    SUBPIECE(SUBPIECE(x, 0), 0) → SUBPIECE(x, 0)
    ZEXT(SUBPIECE(x, 0)) → clean up
    """

    def __init__(self):
        super().__init__('subvariable_reduction', repeat=True)

    def apply(self, ctx: SSAContext) -> bool:
        changed = False
        for block in ctx.graph.blocks:
            new_ops = []
            for op in block.ops:
                # SUBPIECE(SUBPIECE(x,a), b) → SUBPIECE(x, a+b)
                if op.opcode == OpCode.SUBPIECE and op.inputs:
                    src = op.inputs[0]
                    if src.def_op and src.def_op.opcode == OpCode.SUBPIECE:
                        inner_a = src.def_op.inputs[1].offset if len(src.def_op.inputs) >= 2 else 0
                        outer_b = op.inputs[1].offset if len(op.inputs) >= 2 else 0
                        total = inner_a + outer_b
                        new_op = PcodeOp(OpCode.SUBPIECE, op.output,
                                        [src.def_op.inputs[0],
                                         Varnode.const(total)], addr=op.addr)
                        new_ops.append(new_op)
                        changed = True
                        continue
                new_ops.append(op)
            block.ops = new_ops
        return changed


# ══════════════════════════════════════════════════════════════════════
# Phase 2: Control Flow Cleanup
# ══════════════════════════════════════════════════════════════════════

class UnreachableBlockElimination(Action):
    """Remove blocks not reachable from the entry point.

    Mirrors Ghidra's ActionUnreachable.
    """

    def __init__(self):
        super().__init__('unreachable_block_elim', repeat=True)

    def apply(self, ctx: SSAContext) -> bool:
        # Mark reachable from entry
        reachable: Set[BasicBlock] = set()
        work = [ctx.graph.entry] if ctx.graph.entry else []

        while work:
            b = work.pop()
            if b in reachable:
                continue
            reachable.add(b)
            for s in b.succs:
                if s not in reachable:
                    work.append(s)

        # Remove unreachable blocks
        changed = False
        ctx.graph.blocks = [b for b in ctx.graph.blocks if b in reachable]
        if len(ctx.graph.blocks) < len(reachable):
            changed = True
        return changed


class BlockMerge(Action):
    """Merge consecutive blocks where there's a single entry/exit.

    Mirrors Ghidra's action to merge straight-line blocks.
    A → B where A has 1 succ (B) and B has 1 pred (A) → merge into one block.
    """

    def __init__(self):
        super().__init__('block_merge', repeat=True)

    def apply(self, ctx: SSAContext) -> bool:
        changed = False
        i = 0
        while i < len(ctx.graph.blocks) - 1:
            a = ctx.graph.blocks[i]
            b = ctx.graph.blocks[i + 1]
            # Check if A→B is straight-line (A has 1 succ, B has 1 pred)
            if len(a.succs) == 1 and a.succs[0] is b and len(b.preds) == 1:
                # Merge B's ops into A
                a.ops.extend(b.ops)
                a.succs = b.succs
                # Update successor preds
                for s in b.succs:
                    s.preds = [a if p is b else p for p in s.preds]
                # Remove B
                ctx.graph.blocks.pop(i + 1)
                changed = True
            else:
                i += 1
        return changed


# ══════════════════════════════════════════════════════════════════════
# Phase 3: Type Recovery (stub)
# ══════════════════════════════════════════════════════════════════════

class TypeRecovery(Action):
    """Incremental type inference through the SSA graph.

    Mirrors Ghidra's ActionInferTypes.
    Assigns types to varnodes based on:
    - Size (1=char, 2=short, 4=int, 8=long/pointer)
    - Use patterns (pointer arithmetic → pointer type)
    - Call conventions (function signatures)
    """

    SIMPLE_TYPES = {1: 'char', 2: 'short', 4: 'int', 8: 'long'}

    def __init__(self):
        super().__init__('type_recovery', repeat=False)
        self.types: Dict[str, str] = {}  # varname → type string

    def apply(self, ctx: SSAContext) -> bool:
        changed = False
        for block in ctx.graph.blocks:
            for op in block.ops:
                if not op.output:
                    continue
                varname = _varname_key(op.output)
                if varname in self.types:
                    continue

                # Basic type from size
                t = self.SIMPLE_TYPES.get(op.output.size, f'uint{op.output.size * 8}_t')
                self.types[varname] = t
                changed = True

                # PTRADD → pointer type
                if op.opcode == OpCode.PTRADD and op.inputs:
                    pointee_type = self.types.get(_varname_key(op.inputs[0]), 'int')
                    self.types[varname] = f'{pointee_type}*'
                    changed = True

                # LOAD result → pointer element
                # if op.opcode == OpCode.LOAD and op.inputs:
                #     ptr_varname = _varname_key(op.inputs[1])
                #     if ptr_varname in self.types:
                #         ptr_type = self.types[ptr_varname]
                #         # Strip one * to get element type
                #         if ptr_type.endswith('*'):
                #             self.types[varname] = ptr_type[:-1].strip()
                #             changed = True

        return changed


# ── Default Pipeline Builder ──────────────────────────────────────────

def default_pipeline() -> ActionPipeline:
    """Create the default decompiler action pipeline."""
    pipeline = ActionPipeline()

    # Phase 1: First-pass simplification
    pipeline.add_phase('simplify', [
        DeadCodeElimination(),
        CopyPropagation(),
        TrivialArithElimination(),
        ConstantPropagation(),
        SubvariableReduction(),
    ])

    # Phase 2: Control flow cleanup
    pipeline.add_phase('cf_cleanup', [
        UnreachableBlockElimination(),
        BlockMerge(),
    ])

    # Phase 3: Type recovery
    pipeline.add_phase('type_recovery', [
        TypeRecovery(),
    ])

    return pipeline
