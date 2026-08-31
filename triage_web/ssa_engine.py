"""SSA (Static Single Assignment) Construction Engine.

Builds proper SSA form from p-code ops using dominance frontiers
(phi placement) and variable renaming.

Based on Ghidra's heritage algorithm (ActionHeritage in coreaction.hh)
and standard SSA construction (Cytron et al., 1991).

Pipeline:
  1. Collect def-sites: which varname is defined in which block
  2. Place φ-nodes (CPUI_MULTIEQUAL) using dominance frontier criterion
  3. Rename variables via dominator-tree walk (assign versions)
"""

from __future__ import annotations
from collections import defaultdict
from typing import Dict, List, Optional, Set, DefaultDict

from .pcode import OpCode, PcodeOp, Varnode, AddressSpace
from .cfg import BasicBlock, BlockGraph, DominatorTree


class SSAContext:
    """Contains the full SSA state for a function.

    After construction:
    - All varnodes have unique SSA versions
    - φ-nodes (MULTIEQUAL) are inserted at merge points
    - The def-use chains are populated
    """

    def __init__(self, graph: BlockGraph):
        self.graph = graph
        # All varnodes in the function
        self.varnodes: List[Varnode] = []
        # Varnode version tracking
        self._next_version: DefaultDict[str, int] = defaultdict(int)
        # Stack of current version per varname during renaming
        self._version_stack: DefaultDict[str, List[int]] = defaultdict(list)

    def reset(self):
        self.varnodes.clear()
        self._next_version.clear()
        self._version_stack.clear()


def build_ssa(graph: BlockGraph) -> SSAContext:
    """Build SSA form for a BlockGraph.

    Returns an SSAContext with all varnodes versioned and φ-nodes placed.
    """
    ctx = SSAContext(graph)
    domtree = DominatorTree(graph)
    domtree.compute()

    # Step 1: Collect def-sites (which block defines which varname)
    defsites: DefaultDict[str, Set[BasicBlock]] = defaultdict(set)
    for block in graph.blocks:
        for op in block.ops:
            if op.output:
                varname = _varname_key(op.output)
                defsites[varname].add(block)

    # Step 2: Place φ-nodes at dominance frontiers
    phi_blocks: DefaultDict[str, Set[BasicBlock]] = _place_phi_nodes(
        defsites, domtree)

    # Step 3: Insert φ-nodes into blocks
    _insert_phi_nodes(graph, phi_blocks)

    # Step 4: Rename variables
    _rename_variables(graph, domtree, ctx)

    # Step 5: Build def-use chains
    _build_def_use(ctx)

    return ctx


def _varname_key(vn: Varnode) -> str:
    """Get a canonical name string for a varnode (space+offset)."""
    return f'{vn.space.name}:{vn.offset}:{vn.size}'


def _place_phi_nodes(
    defsites: Dict[str, Set[BasicBlock]],
    domtree: DominatorTree
) -> DefaultDict[str, Set[BasicBlock]]:
    """Place φ-nodes using the dominance frontier criterion.

    For each varname, a φ-node is needed at every block in the
    dominance frontier of any block that defines that varname.
    """
    phi_blocks: DefaultDict[str, Set[BasicBlock]] = defaultdict(set)

    for varname, defblocks in defsites.items():
        # Skip constant varnames — never need φ
        if varname.startswith('const:'):
            continue

        work = list(defblocks)
        processed = set()

        while work:
            b = work.pop()
            for df_block in domtree.dominance_frontier.get(b, set()):
                if df_block not in processed:
                    phi_blocks[varname].add(df_block)
                    processed.add(df_block)
                    if df_block not in defsites.get(varname, set()):
                        work.append(df_block)

    return phi_blocks


def _insert_phi_nodes(graph: BlockGraph,
                       phi_blocks: Dict[str, Set[BasicBlock]]):
    """Insert CPUI_MULTIEQUAL (φ) ops at the start of each relevant block."""
    for block in graph.blocks:
        varnames = [v for v, blocks in phi_blocks.items() if block in blocks]
        if not varnames:
            continue

        phi_ops = []
        for varname in varnames:
            # Parse space, offset, size from varname key
            parts = varname.split(':')
            space_name = parts[0]
            offset = int(parts[1]) if parts[1] else 0
            size = int(parts[2]) if len(parts) > 2 else 8

            space = AddressSpace.get(space_name)
            output = Varnode(space, offset, size)

            # φ takes one input per predecessor
            inputs = [Varnode(space, offset, size) for _ in block.preds]
            phi_op = PcodeOp(OpCode.MULTIEQUAL, output, inputs)
            phi_ops.append(phi_op)

        # Insert φ ops at beginning of block
        block.ops = phi_ops + block.ops


def _rename_variables(graph: BlockGraph, domtree: DominatorTree,
                      ctx: SSAContext):
    """Rename varnodes via dominator tree walk.

    Each varnode gets a unique SSA version number.
    Uses the standard stack-based algorithm:
    - Walk in dominator-tree preorder
    - When encountering a def: push new version, assign to def
    - When encountering a use: peek current version from stack
    - Pop versions when leaving a block
    """
    def rename(block: BasicBlock):
        # Track which varnames we pushed in this block (for cleanup)
        pushed: List[str] = []

        # Rename φ outputs first
        for op in block.ops:
            if op.is_phi and op.output:
                varname = _varname_key(op.output)
                ver = ctx._next_version[varname]
                ctx._next_version[varname] += 1
                op.output.version = ver
                ctx._version_stack[varname].append(ver)
                pushed.append(varname)
                ctx.varnodes.append(op.output)

        # Then rename all other ops
        for op in block.ops:
            if op.is_phi:
                continue

            # Rename inputs (uses)
            for i, inp in enumerate(op.inputs):
                if inp.is_constant():
                    continue
                varname = _varname_key(inp)
                if ctx._version_stack[varname]:
                    inp.version = ctx._version_stack[varname][-1]

            # Rename output (def)
            if op.output:
                varname = _varname_key(op.output)
                ver = ctx._next_version[varname]
                ctx._next_version[varname] += 1
                op.output.version = ver
                ctx._version_stack[varname].append(ver)
                pushed.append(varname)
                ctx.varnodes.append(op.output)

        # Recurse to children in dominator tree
        children = [b for b in graph.blocks if b.idom is block]
        for child in children:
            rename(child)

        # Pop versions we pushed
        for varname in pushed:
            ctx._version_stack[varname].pop()

    if graph.entry:
        rename(graph.entry)


def _build_def_use(ctx: SSAContext):
    """Build def-use chains for all varnodes.

    For each op: output.def_op = op (definition site)
    For each use: op.inputs[i].uses.append(op) (use site)
    """
    for block in ctx.graph.blocks:
        for op in block.ops:
            # Record definition
            if op.output:
                op.output.def_op = op

            # Record uses
            for inp in op.inputs:
                if not inp.is_constant():
                    inp.uses.append(op)


# ── SSA Simplification Passes ─────────────────────────────────────────

class SSASimplifier:
    """Run SSA simplification passes on the constructed SSA form.

    Mirrors Ghidra's early-coreaction passes:
    - Dead code elimination
    - Copy propagation
    - Constant propagation
    """

    def __init__(self, ctx: SSAContext):
        self.ctx = ctx
        self.graph = ctx.graph

    def run_all(self):
        """Run all simplification passes to fixed point."""
        changed = True
        max_iter = 10
        while changed and max_iter > 0:
            changed = False
            changed |= self.dead_code_elimination()
            changed |= self.copy_propagation()
            max_iter -= 1

    def dead_code_elimination(self) -> bool:
        """Remove ops whose outputs have no uses.

        Algorithm: backward from essential ops (stores, branches, returns,
        calls), mark all reaching varnodes as necessary. Remove the rest.
        """
        necessary: Set[Varnode] = set()

        def mark(vn: Varnode):
            if vn in necessary or vn.is_constant():
                return
            necessary.add(vn)
            if vn.def_op:
                for inp in vn.def_op.inputs:
                    mark(inp)

        # Seed with essential ops
        for block in self.graph.blocks:
            for op in block.ops:
                if op.is_store or op.is_branch or op.is_return or op.is_call:
                    for inp in op.inputs:
                        mark(inp)
                if op.is_call and op.output:
                    mark(op.output)

        # Remove unmarked ops
        changed = False
        for block in self.graph.blocks:
            new_ops = []
            for op in block.ops:
                if op.output and op.output not in necessary and not op.is_store:
                    changed = True
                    continue  # Remove this dead op
                new_ops.append(op)
            block.ops = new_ops

        return changed

    def copy_propagation(self) -> bool:
        """Replace all uses of COPY outputs with their inputs.

        COPY rax ← rbx → replace all uses of rax with rbx.
        """
        changed = False
        for block in self.graph.blocks:
            for op in block.ops:
                if op.is_copy:
                    src = op.inputs[0]
                    dst = op.output
                    if dst and dst.uses:
                        # Replace dst with src in all use sites
                        for use_op in dst.uses:
                            for i, inp in enumerate(use_op.inputs):
                                if inp is dst:
                                    use_op.inputs[i] = src
                        changed = True
                        dst.uses.clear()
        return changed

    def constant_propagation(self, lattice: Dict[str, Optional[int]] = None) -> bool:
        """Forward constant propagation using a lattice.

        For each op where all inputs are constant → compute constant output.
        """
        if lattice is None:
            lattice = {}

        # Initialize lattice
        for block in self.graph.blocks:
            for op in block.ops:
                if op.output and op.output.is_constant():
                    varname = _varname_key(op.output)
                    lattice[varname] = op.output.offset

        changed = False
        for block in self.graph.blocks:
            for op in block.ops:
                if op.output and _varname_key(op.output) not in lattice:
                    # Check if all inputs are constant
                    all_const = True
                    input_vals = []
                    for inp in op.inputs:
                        varname = _varname_key(inp)
                        if varname in lattice:
                            input_vals.append(lattice[varname])
                        elif inp.is_constant():
                            input_vals.append(inp.offset)
                        else:
                            all_const = False
                            break

                    if all_const:
                        result = self._eval_op(op.opcode, input_vals)
                        if result is not None:
                            lattice[_varname_key(op.output)] = result
                            changed = True

        return changed

    def _eval_op(self, opcode: OpCode, inputs: List[int]) -> Optional[int]:
        """Evaluate a p-code op with constant inputs."""
        if opcode == OpCode.INT_ADD:
            return inputs[0] + inputs[1] if len(inputs) >= 2 else None
        elif opcode == OpCode.INT_SUB:
            return inputs[0] - inputs[1] if len(inputs) >= 2 else None
        elif opcode == OpCode.INT_MULT:
            return inputs[0] * inputs[1] if len(inputs) >= 2 else None
        elif opcode == OpCode.INT_AND:
            return inputs[0] & inputs[1] if len(inputs) >= 2 else None
        elif opcode == OpCode.INT_OR:
            return inputs[0] | inputs[1] if len(inputs) >= 2 else None
        elif opcode == OpCode.INT_XOR:
            return inputs[0] ^ inputs[1] if len(inputs) >= 2 else None
        elif opcode == OpCode.INT_LEFT:
            return inputs[0] << inputs[1] if len(inputs) >= 2 else None
        elif opcode == OpCode.INT_RIGHT:
            return inputs[0] >> inputs[1] if len(inputs) >= 2 else None
        elif opcode == OpCode.INT_SRIGHT:
            # Arithmetic right shift
            val = inputs[0]
            shift = inputs[1]
            if val < 0:
                return (val >> shift) | (~0 << (64 - shift))
            return val >> shift
        elif opcode == OpCode.INT_NEGATE:
            return ~inputs[0]
        elif opcode == OpCode.INT_2COMP:
            return -inputs[0]
        elif opcode == OpCode.COPY:
            return inputs[0] if inputs else None
        elif opcode == OpCode.INT_ZEXT:
            return inputs[0] & 0xFFFFFFFF  # 32-bit zero extend
        elif opcode == OpCode.INT_SEXT:
            # Sign extension from 32-bit
            val = inputs[0] & 0xFFFFFFFF
            if val & 0x80000000:
                return val | ~0xFFFFFFFF
            return val
        return None


# ── Backward-compatible SSAMemory for legacy decompiler ─────────────────

class SSAMemory:
    """Store-forwarding cache used by engine.py's legacy decompiler.

    Maps stack slot expressions (e.g. [rbp-8]) to the Expr value
    written there, so that a subsequent reload returns the original
    expression tree rather than a raw variable name.
    """

    def __init__(self):
        self._cache: dict = {}

    def store(self, dst: str, src: str, regs: dict) -> None:
        """Record that `src` (a register name) was stored to `dst` (a stack slot)."""
        if src in regs and hasattr(regs[src], 'op'):
            self._cache[dst.lower()] = regs[src]
        else:
            self._cache.pop(dst.lower(), None)

    def load(self, op: str):
        """Look up a cached expression for a memory operand.

        Returns the stored Expr if found, or None if no matching store
        has been recorded.
        """
        return self._cache.get(op.lower())
