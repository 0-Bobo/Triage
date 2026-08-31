"""Cross-reference database and basic block model.

Extracted from engine.py during modular refactoring.
"""
from collections import defaultdict
from typing import Dict, List, Tuple


class BasicBlock:
    """A basic block in the control-flow graph."""
    def __init__(self, addr: int):
        self.addr = addr
        self.instructions: List[dict] = []
        self.successors: List[Tuple[int, str]] = []
        self.predecessors: List[Tuple[int, str]] = []
        self.x = self.y = self.width = self.height = 0


class XRefDB:
    """Cross-reference database — tracks who calls/jumps where."""
    def __init__(self):
        self.xrefs_to:   Dict[int, List[Tuple[int, str]]] = defaultdict(list)
        self.xrefs_from: Dict[int, List[Tuple[int, str]]] = defaultdict(list)

    def add(self, frm: int, to: int, typ: str = 'call'):
        if (frm, typ) not in self.xrefs_to[to]:
            self.xrefs_to[to].append((frm, typ))
        if (to, typ) not in self.xrefs_from[frm]:
            self.xrefs_from[frm].append((to, typ))

    def build_from_insns(self, insns: List[dict]):
        for insn in insns:
            mn = insn['mnemonic'].lower()
            if mn in ('call', 'callq') or mn.startswith('j'):
                try:
                    t = int(insn['op_str'].strip(), 16)
                    self.add(insn['address'], t, 'call' if 'call' in mn else 'jump')
                except ValueError:
                    pass

    def get_callers(self, addr: int) -> List[Tuple[int, str]]:
        return self.xrefs_to.get(addr, [])

    def get_callees(self, addr: int) -> List[Tuple[int, str]]:
        return self.xrefs_from.get(addr, [])
