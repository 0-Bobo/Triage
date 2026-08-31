"""ROP gadget scanner.

Extracted from engine.py during modular refactoring.
"""
import re
from collections import defaultdict
from typing import Dict, List

HAS_CAPSTONE = True
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
except ImportError:
    HAS_CAPSTONE = False


class ROPGadget:
    """A single ROP gadget, consisting of 1+ instructions ending in ret."""
    CLASSES = {
        'pop_rdi': r'pop\s+rdi\s*;\s*ret',
        'pop_rsi': r'pop\s+rsi\s*;\s*ret',
        'pop_rdx': r'pop\s+rdx\s*;\s*ret',
        'pop_rax': r'pop\s+rax\s*;\s*ret',
        'pop_rbp': r'pop\s+rbp\s*;\s*ret',
        'pop_rcx': r'pop\s+rcx\s*;\s*ret',
        'syscall': r'syscall',
        'int_80': r'int\s+0x80',
        'ret': r'^ret$',
        'leave_ret': r'leave\s*;\s*ret',
        'jmp_rsp': r'jmp\s+rsp',
        'call_rsp': r'call\s+rsp',
        'mov_rdi': r'mov\s+rdi\s*,',
        'mov_rax': r'mov\s+rax\s*,\s*(?:0x3b|59)\b',
        'xor_rdi': r'xor\s+rdi\s*,\s*rdi',
        'xor_rsi': r'xor\s+rsi\s*,\s*rsi',
        'xor_rdx': r'xor\s+rdx\s*,\s*rdx',
        'mov_mem': r'mov\s+\[r\w+\]\s*,\s*r\w+',
        'add_rsp': r'add\s+rsp\s*,\s*0x[0-9a-f]+\s*;\s*ret',
    }

    def __init__(self, addr: int, insns: List[dict]):
        self.addr = addr
        self.insns = insns
        self.text = ' ; '.join(f'{i["mnemonic"]} {i["op_str"]}'.strip() for i in insns)
        self.classes = [cls for cls, pat in self.CLASSES.items() if re.search(pat, self.text, re.IGNORECASE)]


class ROPEngine:
    """Scans a binary for ROP gadgets using capstone."""
    MAX_GADGET_SIZE = 8
    MAX_SCAN_BYTES = 2 * 1024 * 1024
    _md_cache: Dict[str, 'Cs'] = {}

    def __init__(self, loader: 'BinaryLoader'):  # noqa: F821
        self.loader = loader
        self.gadgets: List[ROPGadget] = []
        self._by_class: Dict[str, List[ROPGadget]] = defaultdict(list)
        self._scanned = False

    def _get_md(self):
        key = f'{self.loader.arch}_{self.loader.bits}'
        if key not in self._md_cache:
            m = {'x86_64': (CS_ARCH_X86, CS_MODE_64), 'x86': (CS_ARCH_X86, CS_MODE_32)}
            arch, mode = m.get(key.split('_')[0], (CS_ARCH_X86, CS_MODE_64 if self.loader.bits == 64 else CS_MODE_32))
            md = Cs(arch, mode)
            md.detail = True
            self._md_cache[key] = md
        return self._md_cache[key]

    def scan(self) -> int:
        if not HAS_CAPSTONE:
            return 0
        self.gadgets.clear()
        self._by_class.clear()
        code, base = self.loader._get_text_section()
        if len(code) > self.MAX_SCAN_BYTES:
            code = code[:self.MAX_SCAN_BYTES]
        md = self._get_md()
        ret_offsets = [i for i, b in enumerate(code)
                       if b == 0xC3 or (b == 0xC2 and i + 2 < len(code))]
        seen_addrs: set = set()
        for ret_off in ret_offsets:
            for start in range(max(0, ret_off - self.MAX_GADGET_SIZE * 8), ret_off + 1):
                start_va = base + start
                if start_va in seen_addrs:
                    continue
                insns = []
                try:
                    for i in md.disasm(code[start:ret_off + 1], start_va):
                        insns.append({'address': i.address, 'mnemonic': i.mnemonic,
                                      'op_str': i.op_str, 'size': i.size})
                        if i.mnemonic.lower() in ('ret', 'retq', 'retn'):
                            break
                        if len(insns) > self.MAX_GADGET_SIZE:
                            break
                except Exception:
                    continue
                if not insns:
                    continue
                if insns[-1]['mnemonic'].lower() not in ('ret', 'retq', 'retn'):
                    continue
                gadget = ROPGadget(start_va, insns)
                if gadget.addr not in seen_addrs:
                    seen_addrs.add(gadget.addr)
                    self.gadgets.append(gadget)
                    for cls in gadget.classes:
                        self._by_class[cls].append(gadget)
        self._scanned = True
        return len(self.gadgets)

    def search(self, query: str = '', semantic_cls: str = '') -> List[dict]:
        results = self.gadgets
        if semantic_cls and semantic_cls in self._by_class:
            results = self._by_class[semantic_cls]
        if query:
            try:
                pat = re.compile(query, re.IGNORECASE)
                results = [g for g in results if pat.search(g.text)]
            except re.error:
                pass
        return [{'addr': hex(g.addr), 'text': g.text, 'classes': g.classes}
                for g in results[:500]]

    def get_summary(self) -> dict:
        return {
            'total': len(self.gadgets),
            'classes': {k: len(v) for k, v in sorted(self._by_class.items(), key=lambda x: -len(x[1]))},
        }
