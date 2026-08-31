"""Cross-reference database and basic block model.

Extracted from engine.py during modular refactoring.
"""

from collections import defaultdict


class BasicBlock:
    """A basic block in the control-flow graph."""

    def __init__(self, addr: int):
        self.addr = addr
        self.instructions: list[dict] = []
        self.successors: list[tuple[int, str]] = []
        self.predecessors: list[tuple[int, str]] = []
        self.x = self.y = self.width = self.height = 0


class XRefDB:
    """Cross-reference database — tracks who calls/jumps where."""

    def __init__(self):
        self.xrefs_to: dict[int, list[tuple[int, str]]] = defaultdict(list)
        self.xrefs_from: dict[int, list[tuple[int, str]]] = defaultdict(list)

    def add(self, frm: int, to: int, typ: str = "call"):
        if (frm, typ) not in self.xrefs_to[to]:
            self.xrefs_to[to].append((frm, typ))
        if (to, typ) not in self.xrefs_from[frm]:
            self.xrefs_from[frm].append((to, typ))

    def build_from_insns(self, insns: list[dict]):
        for insn in insns:
            mn = insn["mnemonic"].lower()
            if mn in ("call", "callq") or mn.startswith("j"):
                try:
                    t = int(insn["op_str"].strip(), 16)
                    self.add(insn["address"], t, "call" if "call" in mn else "jump")
                except ValueError:
                    pass

    def get_callers(self, addr: int) -> list[tuple[int, str]]:
        return self.xrefs_to.get(addr, [])

    def get_callees(self, addr: int) -> list[tuple[int, str]]:
        return self.xrefs_from.get(addr, [])
