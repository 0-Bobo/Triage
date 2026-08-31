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
from typing import Dict, List, Optional, Set

from .pcode import OpCode, PcodeOp


# ── Structured Block Types ────────────────────────────────────────────

class BlockType(IntEnum):
    PLAIN     = 0   # Straight-line code
    GOTO      = 1   # Unconditional jump
    CONDITION = 2   # Conditional branch (if/else)
    LIST      = 3   # Ordered sequence of sub-blocks
    IF        = 4   # If/else structure
    WHILE     = 5   # While loop
    INFWHILE  = 6   # Infinite loop (while true)
    FOR       = 7   # For loop
    SWITCH    = 8   # Switch/case


# ── BasicBlock ────────────────────────────────────────────────────────

class BasicBlock:
    """A basic block — a maximal-length straight-line sequence of p-code ops.

    - Entry: first p-code op in the block
    - Exit: last p-code op (branch, return, or fall-through)
    """

    def __init__(self, index: int = 0, name: str = ''):
        self.index = index
        self.name = name or f'B{index}'
        self.ops: List[PcodeOp] = []
        self.succs: List[BasicBlock] = []
        self.preds: List[BasicBlock] = []

        # Dominator info (filled by DominatorTree)
        self.idom: Optional[BasicBlock] = None  # Immediate dominator
        self.dominance_frontier: Set[BasicBlock] = set()
        self.depth: int = 0

        # For structuring
        self.block_type: BlockType = BlockType.PLAIN
        self.children: List[BasicBlock] = []
        self.loop_header: bool = False
        self.loop_body: Set[BasicBlock] = set()
        self.switch_cases: Dict[int, BasicBlock] = {}

    def add_op(self, op: PcodeOp):
        self.ops.append(op)

    @property
    def last_op(self) -> Optional[PcodeOp]:
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
        return f'<{self.name} ops={len(self.ops)} succs={len(self.succs)}>'

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
        self.blocks: List[BasicBlock] = []
        self.entry: Optional[BasicBlock] = None
        self.exit: Optional[BasicBlock] = None
        self._block_by_addr: Dict[int, BasicBlock] = {}

    def add_block(self, block: BasicBlock):
        self.blocks.append(block)
        if block.is_entry:
            self.entry = block

    def get_block(self, index: int) -> Optional[BasicBlock]:
        for b in self.blocks:
            if b.index == index:
                return b
        return None

    @property
    def num_blocks(self) -> int:
        return len(self.blocks)

    def rpo(self) -> List[BasicBlock]:
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
        return f'<BlockGraph {len(self.blocks)} blocks>'


# ── CFG Builder ───────────────────────────────────────────────────────

class CFGBuilder:
    """Build a BlockGraph from a list of p-code ops.

    ʃ Steps:
    1. Scan ops for branch targets → block boundary markers
    2. Linear pass to partition ops into blocks
    3. Connect blocks via successors/predecessors
    """

    def build(self, pcode_ops: List[PcodeOp], base_addr: int = 0) -> BlockGraph:
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

    def _find_boundaries(self, ops: List[PcodeOp]) -> Set[int]:
        """Find all indices that are block boundaries (entry points)."""
        boundaries = {0}  # First op is always a boundary

        for i, op in enumerate(ops):
            if op.is_branch or op.is_return:
                # After a branch → new block
                if i + 1 < len(ops):
                    boundaries.add(i + 1)
                # Branch targets → new blocks
                # In p-code, branch targets are constants
                for inp in op.inputs:
                    if inp.is_constant():
                        boundaries.add(inp.offset)  # Simplified
            if op.is_call:
                # After any call → could be a boundary if tail call
                pass

        return boundaries

    def _partition(self, ops: List[PcodeOp], boundaries: Set[int]) -> List[BasicBlock]:
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

    def _connect(self, blocks: List[BasicBlock],
                 ops: List[PcodeOp]) -> BlockGraph:
        """Connect blocks via successors/predecessors."""
        graph = BlockGraph()

        # Build address → block map
        addr_map: Dict[int, BasicBlock] = {}
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
                    if last_op.inputs and last_op.inputs[0].is_constant():
                        target_addr = last_op.inputs[0].offset
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
        self._idom: Dict[BasicBlock, BasicBlock] = {}
        self._df: Dict[BasicBlock, Set[BasicBlock]] = defaultdict(set)

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
    def idom(self) -> Dict[BasicBlock, BasicBlock]:
        return self._idom

    @property
    def dominance_frontier(self) -> Dict[BasicBlock, Set[BasicBlock]]:
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
                # Find merge point (block reachable from both paths)
                t_succs = set(t.succs)
                f_succs = set(f.succs)
                merge = t_succs & f_succs
                if merge:
                    block.block_type = BlockType.CONDITION
                    for m in merge:
                        m.preds = [p for p in m.preds
                                  if p is not t or p is not f]

    def _detect_loops(self):
        """Detect while/do-while loops from back-edges."""
        for block in self.graph.blocks:
            if block.loop_header:
                for s in block.succs:
                    if self.domtree._dominates(block, s):
                        # Back-edge found → loop body
                        block.block_type = BlockType.WHILE
                        block.loop_body = self._collect_loop_body(block, s)

    def _collect_loop_body(self, header: BasicBlock,
                           back_edge: BasicBlock) -> Set[BasicBlock]:
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
