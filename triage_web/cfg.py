"""Control Flow Graph — basic blocks, dominance analysis, and structured control flow.

Inspired by Ghidra's block.hh / blockaction.hh:
- BasicBlock: linear sequence of p-code ops
- BlockGraph: container with successors/predecessors
- Dominator analysis: Lengauer-Tarjan algorithm
- Block structuring: goto elimination into if/else/while/switch
"""

from __future__ import annotations

from collections import defaultdict
from enum import IntEnum

from .pcode import OpCode, PcodeOp

# ── Structured Block Types ────────────────────────────────────────────


class BlockType(IntEnum):
    PLAIN = 0  # Straight-line code
    GOTO = 1  # Unconditional jump
    CONDITION = 2  # Conditional branch (if/else)
    LIST = 3  # Ordered sequence of sub-blocks
    IF = 4  # If/else structure
    WHILE = 5  # While loop
    INFWHILE = 6  # Infinite loop (while true)
    FOR = 7  # For loop
    SWITCH = 8  # Switch/case


# ── BasicBlock ────────────────────────────────────────────────────────


class BasicBlock:
    """A basic block — a maximal-length straight-line sequence of p-code ops.

    - Entry: first p-code op in the block
    - Exit: last p-code op (branch, return, or fall-through)
    """

    def __init__(self, index: int = 0, name: str = ""):
        self.index = index
        self.name = name or f"B{index}"
        self.ops: list[PcodeOp] = []
        self.succs: list[BasicBlock] = []
        self.preds: list[BasicBlock] = []

        # Dominator info (filled by DominatorTree)
        self.idom: BasicBlock | None = None  # Immediate dominator
        self.dominance_frontier: set[BasicBlock] = set()
        self.depth: int = 0

        # For structuring
        self.block_type: BlockType = BlockType.PLAIN
        self.children: list[BasicBlock] = []
        self.loop_header: bool = False
        self.loop_body: set[BasicBlock] = set()
        self.switch_cases: dict[int, BasicBlock] = {}

    def add_op(self, op: PcodeOp):
        self.ops.append(op)

    @property
    def last_op(self) -> PcodeOp | None:
        return self.ops[-1] if self.ops else None

    @property
    def is_entry(self) -> bool:
        return len(self.preds) == 0

    @property
    def is_exit(self) -> bool:
        return len(self.succs) == 0

    @property
    def has_call(self) -> bool:
        return any(op.is_call for op in self.ops)

    @property
    def has_return(self) -> bool:
        return any(op.is_return for op in self.ops)

    def __repr__(self):
        return f"<{self.name} ops={len(self.ops)} succs={len(self.succs)}>"

    def __hash__(self):
        return hash(self.index)

    def __eq__(self, other):
        if not isinstance(other, BasicBlock):
            return NotImplemented
        return self.index == other.index


# ── BlockGraph (CFG container) ────────────────────────────────────────


class BlockGraph:
    """Container for the full control flow graph."""

    def __init__(self):
        self.blocks: list[BasicBlock] = []
        self.entry: BasicBlock | None = None
        self.exit: BasicBlock | None = None
        self._block_by_addr: dict[int, BasicBlock] = {}

    def add_block(self, block: BasicBlock):
        self.blocks.append(block)
        if block.is_entry:
            self.entry = block

    def get_block(self, index: int) -> BasicBlock | None:
        for b in self.blocks:
            if b.index == index:
                return b
        return None

    @property
    def num_blocks(self) -> int:
        return len(self.blocks)

    def rpo(self) -> list[BasicBlock]:
        """Reverse post-order (topological order for CFG traversal)."""
        visited = set()
        order = []

        def dfs(b: BasicBlock):
            if b in visited:
                return
            visited.add(b)
            for s in b.succs:
                dfs(s)
            order.append(b)

        if self.entry:
            dfs(self.entry)
        return list(reversed(order))

    def __repr__(self):
        return f"<BlockGraph {len(self.blocks)} blocks>"


def _branch_target_addr(op: PcodeOp) -> int | None:
    """Resolve a branch op's target address, in the same domain as `op.addr`.

    `BRANCH`'s `.addr` holds its *target* (not its own source address --
    see `Translator._translate_jump`), so it is returned directly.
    `CBRANCH`'s target is the constant input wider than 4 bytes (the
    existing matching rule, centralized here instead of duplicated between
    `_find_boundaries` and `_connect`). Anything else (`BRANCHIND`, or no
    match) has no statically-resolvable target.
    """
    if op.opcode is OpCode.BRANCH:
        return op.addr
    if op.opcode is OpCode.CBRANCH:
        for inp in op.inputs:
            if inp.is_constant() and inp.size > 4:
                return inp.offset
        return None
    return None


def find_if_merge(t: BasicBlock, f: BasicBlock) -> BasicBlock | None:
    """Find where a two-way branch's arms (`t`, `f`) reconverge, if at all.

    Handles both the classic if/else shape (both arms are separate body
    blocks that flow into a third merge block) and the if/no-else shape
    (one arm IS the merge block directly, with no separate body on that
    arm) -- shared by `CFGStructurer._detect_if_else` and
    `emit_c._emit_condition` so both agree on the same reconvergence point.
    """
    if t is f:
        return None
    common = set(t.succs) & set(f.succs)
    if common:
        return next(iter(common))
    if t in f.succs:
        return t
    if f in t.succs:
        return f
    return None


# ── CFG Builder ───────────────────────────────────────────────────────


class CFGBuilder:
    """Build a BlockGraph from a list of p-code ops.

    ʃ Steps:
    1. Scan ops for branch targets → block boundary markers
    2. Linear pass to partition ops into blocks
    3. Connect blocks via successors/predecessors
    """

    def build(self, pcode_ops: list[PcodeOp], base_addr: int = 0) -> BlockGraph:
        """Build complete CFG from p-code ops."""
        if not pcode_ops:
            return BlockGraph()

        # Step 1: Find all block boundaries
        boundaries = self._find_boundaries(pcode_ops)

        # Step 2: Partition into basic blocks
        blocks = self._partition(pcode_ops, boundaries)

        # Step 3: Connect edges
        graph = self._connect(blocks, pcode_ops)

        return graph

    def _find_boundaries(self, ops: list[PcodeOp]) -> set[int]:
        """Find all indices that are block boundaries (entry points)."""
        boundaries = {0}  # First op is always a boundary

        # Address → op-list index, so branch targets (addresses) can be
        # translated into the same index domain `_partition` compares
        # against. `BRANCH` is excluded from contributing entries: its
        # `.addr` holds a *target* address, not its own position, and if a
        # `BRANCH` op were scanned before the real instruction starting at
        # that same address, its (wrong) index would win the first-write-
        # wins dict below and never get corrected.
        addr_to_idx: dict[int, int] = {}
        for i, op in enumerate(ops):
            if op.addr not in addr_to_idx and op.opcode is not OpCode.BRANCH:
                addr_to_idx[op.addr] = i

        for i, op in enumerate(ops):
            if op.is_branch or op.is_return:
                # After a branch → new block
                if i + 1 < len(ops):
                    boundaries.add(i + 1)
                # Branch targets → new blocks
                target = _branch_target_addr(op)
                if target is not None:
                    idx = addr_to_idx.get(target)
                    if idx is not None:
                        boundaries.add(idx)
            if op.is_call:
                # After any call → could be a boundary if tail call
                pass

        return boundaries

    def _partition(self, ops: list[PcodeOp], boundaries: set[int]) -> list[BasicBlock]:
        """Partition ops into BasicBlocks at boundary points."""
        blocks = []
        current = BasicBlock(len(blocks))

        for i, op in enumerate(ops):
            if i in boundaries and current.ops:
                blocks.append(current)
                current = BasicBlock(len(blocks))
            current.add_op(op)

        if current.ops:
            blocks.append(current)

        return blocks

    def _connect(self, blocks: list[BasicBlock], ops: list[PcodeOp]) -> BlockGraph:
        """Connect blocks via successors/predecessors."""
        graph = BlockGraph()

        # Build address → block map
        addr_map: dict[int, BasicBlock] = {}
        for b in blocks:
            if b.ops:
                addr_map[b.ops[0].addr] = b

        for i, block in enumerate(blocks):
            graph.add_block(block)
            last_op = block.last_op
            if not last_op:
                continue

            if last_op.is_branch:
                if last_op.opcode == OpCode.BRANCH:
                    # Unconditional branch → connect to target
                    target_addr = _branch_target_addr(last_op)
                    if target_addr is not None:
                        target = addr_map.get(target_addr)
                        if target and target not in block.succs:
                            block.succs.append(target)
                            target.preds.append(block)
                elif last_op.opcode == OpCode.CBRANCH:
                    # Conditional branch → true path + fall-through
                    if last_op.inputs:
                        # Find branch target from inputs (simplified)
                        for inp in last_op.inputs:
                            if inp.is_constant() and inp.size > 4:
                                target = addr_map.get(inp.offset)
                                if target and target not in block.succs:
                                    block.succs.append(target)
                                    target.preds.append(block)
                    # Fall-through to next block
                    if i + 1 < len(blocks):
                        next_block = blocks[i + 1]
                        if next_block not in block.succs:
                            block.succs.append(next_block)
                            next_block.preds.append(block)
                elif last_op.opcode == OpCode.BRANCHIND:
                    # Indirect branch — can't resolve statically
                    pass
            elif last_op.is_return:
                # Return — no successors
                pass
            elif last_op.is_call:
                # Call → falls through (unless no-return)
                if i + 1 < len(blocks):
                    next_block = blocks[i + 1]
                    block.succs.append(next_block)
                    next_block.preds.append(block)
            else:
                # Fall-through to next block
                if i + 1 < len(blocks):
                    next_block = blocks[i + 1]
                    block.succs.append(next_block)
                    next_block.preds.append(block)

        if blocks:
            graph.entry = blocks[0]
            graph.exit = blocks[-1]

        return graph


# ── Dominator Tree (Lengauer-Tarjan) ──────────────────────────────────


class DominatorTree:
    """Compute immediate dominators and dominance frontiers using Lengauer-Tarjan.

    Reference: Lengauer & Tarjan, "A Fast Algorithm for Finding Dominators
    in a Flow Graph" (TOPLAS 1979).
    """

    def __init__(self, graph: BlockGraph):
        self.graph = graph
        self._idom: dict[BasicBlock, BasicBlock] = {}
        self._df: dict[BasicBlock, set[BasicBlock]] = defaultdict(set)

    def compute(self):
        """Compute all dominator info."""
        self._compute_idoms()
        self._compute_dominance_frontiers()
        self._assign_loop_depths()

    def _compute_idoms(self):
        """Lengauer-Tarjan dominator computation.

        Simplified: uses iterative data-flow algorithm for correctness.
        (RTO: O(n²) worst-case, fine for CTF binaries.)
        """
        blocks = self.graph.rpo()
        if not blocks:
            return

        # Entry's idom = None
        entry = blocks[0]
        self._idom[entry] = entry

        # Initialize all others to None
        for b in blocks[1:]:
            self._idom[b] = None

        # Iterative data-flow
        changed = True
        while changed:
            changed = False
            for b in blocks[1:]:
                if not b.preds:
                    continue
                # First processed predecessor
                new_idom = None
                for p in b.preds:
                    if self._idom.get(p) is not None:
                        new_idom = p
                        break
                if new_idom is None:
                    continue
                # Intersect with other reachable predecessors
                for p in b.preds:
                    if p is new_idom:
                        continue
                    if self._idom.get(p) is not None:
                        new_idom = self._intersect(p, new_idom)
                if self._idom[b] is not new_idom:
                    self._idom[b] = new_idom
                    changed = True

        self._idom[entry] = None  # Entry has no idom

        # Store idom on blocks
        for b, idom in self._idom.items():
            b.idom = idom

    def _intersect(self, b1: BasicBlock, b2: BasicBlock) -> BasicBlock:
        """Find the first common ancestor in the dominator tree."""
        finger1 = b1
        finger2 = b2
        blocks = self.graph.rpo()
        rank = {b: i for i, b in enumerate(blocks)}

        while finger1 is not finger2:
            while rank.get(finger1, 0) > rank.get(finger2, 0):
                finger1 = self._idom.get(finger1) or finger1
            while rank.get(finger2, 0) > rank.get(finger1, 0):
                finger2 = self._idom.get(finger2) or finger2
        return finger1

    def _compute_dominance_frontiers(self):
        """DF(b) = {x | b dom pred(x) but not b dom x}."""
        blocks = self.graph.rpo()
        for b in blocks:
            self._df[b] = set()

        if not blocks:
            return

        for b in blocks:
            if len(b.preds) < 2:
                continue
            for p in b.preds:
                runner = p
                while runner is not self._idom.get(b):
                    self._df[runner].add(b)
                    runner = self._idom.get(runner)
                    if runner is None:
                        break

        # Store on blocks
        for b, df in self._df.items():
            b.dominance_frontier = df

    def _assign_loop_depths(self):
        """Assign loop depth based on back-edges in the dominator tree."""
        blocks = self.graph.rpo()
        for b in blocks:
            for s in b.succs:
                # Back-edge: successor dominates predecessor → loop
                if self._dominates(s, b):
                    s.loop_header = True

    def _dominates(self, dom: BasicBlock, b: BasicBlock) -> bool:
        """Check if `dom` dominates `b`."""
        if dom is b:
            return True
        current = self._idom.get(b)
        while current is not None:
            if current is dom:
                return True
            current = self._idom.get(current)
        return False

    @property
    def idom(self) -> dict[BasicBlock, BasicBlock]:
        return self._idom

    @property
    def dominance_frontier(self) -> dict[BasicBlock, set[BasicBlock]]:
        return self._df


# ── CFG Structuring ────────────────────────────────────────────────────


class CFGStructurer:
    """Convert flat CFG with gotos to structured control flow.

    Successively applies pattern-matching rules:
    1. If-then-else (two-way branch that merges)
    2. While loop (back-edge to header with condition)
    3. Infinite loop (back-edge with no condition)
    4. Switch (multi-way branch from jump table)
    """

    def __init__(self, graph: BlockGraph, domtree: DominatorTree):
        self.graph = graph
        self.domtree = domtree

    def structure(self) -> BlockGraph:
        """Run all structuring passes."""
        self._detect_if_else()
        self._detect_loops()
        self._detect_switch()
        return self.graph

    def _detect_if_else(self):
        """Detect if/else patterns.

        Pattern: block B with two successors (T and F)
        where T and F merge at block M.
        """
        for block in self.graph.blocks:
            if len(block.succs) == 2:
                t = block.succs[0]
                f = block.succs[1]
                # Find merge point (block reachable from both paths, incl.
                # the no-else/asymmetric shape where one arm IS the merge)
                merge = find_if_merge(t, f)
                if merge is not None:
                    block.block_type = BlockType.CONDITION
                    merge.preds = [p for p in merge.preds if p is not t or p is not f]

    def _detect_loops(self):
        """Detect while/do-while loops from back-edges."""
        for block in self.graph.blocks:
            if block.loop_header:
                for s in block.succs:
                    if self.domtree._dominates(block, s):
                        # Back-edge found → loop body
                        block.block_type = BlockType.WHILE
                        block.loop_body = self._collect_loop_body(block, s)

    def _collect_loop_body(self, header: BasicBlock, back_edge: BasicBlock) -> set[BasicBlock]:
        """Collect all blocks in the loop body reachable from the back-edge."""
        body = set()
        work = [back_edge]
        while work:
            b = work.pop()
            if b is header or b in body:
                continue
            body.add(b)
            for s in b.succs:
                if s not in body:
                    work.append(s)
        return body

    def _detect_switch(self):
        """Detect switch/case patterns from BRANCHIND / jump table."""
        for block in self.graph.blocks:
            last = block.last_op
            if last and last.opcode == OpCode.BRANCHIND:
                # Potential switch — look for jump table pattern
                block.block_type = BlockType.SWITCH
