"""Analysis engine: disassembler, ROP gadgets, cross-references, basic blocks."""

import re
import logging
from typing import List, Dict

log = logging.getLogger('triage-web')

_REG_ALIAS = {
    'rax': 'eax', 'rbx': 'ebx', 'rcx': 'ecx', 'rdx': 'edx',
    'rsi': 'esi', 'rdi': 'edi', 'rsp': 'esp', 'rbp': 'ebp',
    'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
    'esi': 'rsi', 'edi': 'rdi', 'esp': 'rsp', 'ebp': 'rbp',
}
_SIZE_PREFIX = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8}
_MEM_REF_RE = re.compile(r'\[([a-z]+)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]', re.IGNORECASE)
_SIMPLE_MEM_RE = re.compile(r'\[\s*([a-z0-9]+)\s*\]', re.IGNORECASE)


class Expr:
    """Expression tree node for register value tracking.
    Preserves operation structure so the emitter can produce proper C expressions
    instead of line-by-line assembly translation."""
    __slots__ = ('op', 'args')
    OPS = {'var', 'const', 'add', 'sub', 'mul', 'neg', 'not_', 'and_', 'or_'}

    def __init__(self, op: str, *args):
        assert op in self.OPS, f'unknown Expr op: {op}'
        self.op = op
        self.args = args

    @staticmethod
    def var(name: str): return Expr('var', name)

    @staticmethod
    def const(val: int): return Expr('const', val)

    @staticmethod
    def add(a, b):
        # const folding
        if isinstance(a, Expr) and a.op == 'const' and isinstance(b, Expr) and b.op == 'const':
            return Expr('const', a.args[0] + b.args[0])
        # x + 0 → x
        if isinstance(b, Expr) and b.op == 'const' and b.args[0] == 0:
            return a
        if isinstance(a, Expr) and a.op == 'const' and a.args[0] == 0:
            return b
        # (a + C1) + C2 → a + (C1 + C2)
        if isinstance(a, Expr) and a.op == 'add' and isinstance(b, Expr) and b.op == 'const':
            if isinstance(a.args[1], Expr) and a.args[1].op == 'const':
                return Expr.add(a.args[0], Expr.const(a.args[1].args[0] + b.args[0]))
        return Expr('add', a, b)

    @staticmethod
    def sub(a, b):
        if isinstance(a, Expr) and a.op == 'const' and isinstance(b, Expr) and b.op == 'const':
            return Expr('const', a.args[0] - b.args[0])
        # x - 0 → x
        if isinstance(b, Expr) and b.op == 'const' and b.args[0] == 0:
            return a
        return Expr('sub', a, b)

    @staticmethod
    def mul(a, b):
        if isinstance(a, Expr) and a.op == 'const' and isinstance(b, Expr) and b.op == 'const':
            return Expr('const', a.args[0] * b.args[0])
        if isinstance(b, Expr) and b.op == 'const' and b.args[0] == 1:
            return a
        if isinstance(a, Expr) and a.op == 'const' and a.args[0] == 1:
            return b
        if isinstance(b, Expr) and b.op == 'const' and b.args[0] == 0:
            return Expr.const(0)
        return Expr('mul', a, b)

    @staticmethod
    def neg(v): return Expr('neg', v)
    @staticmethod
    def not_(v): return Expr('not_', v)
    @staticmethod
    def and_(a, b): return Expr('and_', a, b)
    @staticmethod
    def or_(a, b): return Expr('or_', a, b)


def _is_const_int(e, v=None):
    """Check if e is a constant (optionally equal to v)."""
    return isinstance(e, Expr) and e.op == 'const' and (v is None or e.args[0] == v)


def _expr_str(e: Expr, wrap_parens=True) -> str:
    """Format an expression tree into a C expression string.
    Detects pointer+offset → array subscript notation."""
    if not isinstance(e, Expr):
        return str(e)
    if e.op == 'var':
        return e.args[0]
    if e.op == 'const':
        v = e.args[0]
        return str(v) if -256 < v < 256 else hex(v)
    if e.op == 'neg':
        return f'-{_expr_str(e.args[0])}'
    if e.op == 'not_':
        return f'~{_expr_str(e.args[0])}'
    if e.op == 'and_':
        return f'{_expr_str(e.args[0])} & {_expr_str(e.args[1])}'
    if e.op == 'or_':
        return f'{_expr_str(e.args[0])} | {_expr_str(e.args[1])}'

    left, right = e.args[0], e.args[1]
    sym = {'add': '+', 'sub': '-', 'mul': '*'}[e.op]
    # Detect base_ptr + const → ptr+offset notation
    if e.op == 'add' and isinstance(right, Expr) and right.op == 'const':
        rv = right.args[0]
        l_str = _expr_str(left, wrap_parens=False)
        if rv == 0:
            return l_str
        if rv > 0:
            body = f'{l_str} + {rv}'
        else:
            body = f'{l_str} - {-rv}'
    else:
        body = f'{_expr_str(left)} {sym} {_expr_str(right)}'
    return f'({body})' if wrap_parens else body


def _reg_lookup(name: str, regs: dict):
    """Look up a register value, trying both 64-bit and 32-bit names."""
    val = regs.get(name)
    if val is not None:
        return _expr_str(val) if isinstance(val, Expr) else val
    alias = _REG_ALIAS.get(name)
    if alias:
        val = regs.get(alias)
        return _expr_str(val) if isinstance(val, Expr) else val
    return None


def _expr_to_base_offset(e: 'Expr') -> tuple | None:
    """Walk an Expr tree to extract (base_var_name, total_offset) from var+const chains.

    Returns None if the expression doesn't resolve to a simple var[+const] pattern.
    Handles: var, var+const, (var+const)+const, var*const (scaled index).
    """
    if not isinstance(e, Expr):
        return None
    if e.op == 'var':
        name = e.args[0]
        for prefix in ('var_', 'reg_'):
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        return (name, 0)
    if e.op == 'const':
        return None
    if e.op == 'add' and len(e.args) == 2:
        base = _expr_to_base_offset(e.args[0])
        if base is not None and isinstance(e.args[1], Expr) and e.args[1].op == 'const':
            return (base[0], base[1] + e.args[1].args[0])
        return base
    if e.op == 'sub' and len(e.args) == 2:
        base = _expr_to_base_offset(e.args[0])
        if base is not None and isinstance(e.args[1], Expr) and e.args[1].op == 'const':
            return (base[0], base[1] - e.args[1].args[0])
        return None
    if e.op == 'mul' and len(e.args) == 2:
        base = _expr_to_base_offset(e.args[0])
        if base is not None and isinstance(e.args[1], Expr) and e.args[1].op == 'const':
            return (base[0], base[1] * e.args[1].args[0])
        return None
    return None


def _resolve_alias_from_reg(reg_name: str, regs: dict) -> tuple | None:
    """Resolve a register to (base_var_name, total_offset) via its expression tree.

    Works with both 64-bit and 32-bit register aliases.
    """
    val = regs.get(reg_name)
    if val is None:
        alias = _REG_ALIAS.get(reg_name)
        if alias:
            val = regs.get(alias)
    if isinstance(val, Expr):
        return _expr_to_base_offset(val)
    return None


def _resolve_mem_ref(expr: str, var_by_off: dict) -> str | None:
    """Resolve a memory reference like [rbp-0x10] to a variable name.
    Returns the variable name or None if not resolvable."""
    m = _MEM_REF_RE.search(expr)
    if not m:
        return None
    sign = 1 if m.group(2) == '+' else -1
    off_str = m.group(3)
    off_val = _parse_hex(off_str) if off_str.startswith('0x') else int(off_str)
    if off_val is None and not off_str.startswith('0x'):
        return None
    off = off_val * sign
    vinfo = var_by_off.get(off)
    if vinfo:
        return vinfo.get('suggested', vinfo['name'])
    return None


def _parse_hex(s: str) -> int | None:
    """Parse an integer from a hex string. Returns None on failure."""
    try:
        return int(s, 16)
    except (ValueError, TypeError):
        return None


# SSA memory tracking (backward-compat store-forwarding for legacy decompiler)
try:
    from triage_web.ssa_engine import SSAMemory
except ImportError:
    try:
        from ssa_engine import SSAMemory  # noqa: F401
    except ImportError:
        class SSAMemory:  # fallback no-op
            def store(self, dst, src, regs): pass
            def load(self, op): return None

# Try optional deps
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


class Disassembler:
    """capstone-based instruction disassembler."""
    BRANCH_MNEMONICS = {
        'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
        'ja', 'jae', 'jb', 'jbe', 'js', 'jns', 'jo', 'jno', 'jp', 'loop',
    }
    RET_MNEMONICS = {'ret', 'retq', 'retn', 'retf', 'iret', 'iretd', 'iretq', 'hlt'}

    def __init__(self, arch='x86_64', bits=64):
        if not HAS_CAPSTONE:
            raise RuntimeError('capstone not installed')
        m = {
            'x86_64': (CS_ARCH_X86, CS_MODE_64),
            'x86': (CS_ARCH_X86, CS_MODE_32),
            'ARM': (CS_ARCH_ARM, CS_MODE_ARM),
            'AArch64': (CS_ARCH_ARM64, CS_MODE_ARM),
        }
        arch_mode = m.get(arch, (CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32))
        self.md = Cs(*arch_mode)
        self.md.detail = True

    def disassemble(self, code: bytes, base: int, max_insns=0) -> List[dict]:
        insns = []
        for i in self.md.disasm(code, base):
            insns.append({
                'address': i.address,
                'size': i.size,
                'mnemonic': i.mnemonic,
                'op_str': i.op_str,
                'bytes': i.bytes.hex(),
            })
            if max_insns and len(insns) >= max_insns:
                break
        return insns

    def analyze_function(self, code: bytes, base: int, known_calls: Dict[int, str] = None) -> dict:
        """Disassemble a function range and return structured analysis.

        Returns dict with:
          - address, size: range info
          - insns: full instruction list
          - stack_frame: detected stack size from prologue
          - stack_vars: list of detected stack variable offsets with heuristics
          - calls: call instructions with resolved target names
          - prologue, epilogue: detected address range
          - basic_blocks: list of [start_addr, end_addr]
        """
        if known_calls is None:
            known_calls = {}
        insns = []
        stack_vars = {}
        calls = []
        blocks = []
        prev_addr = base
        prologue = None
        epilogue = None
        stack_frame = 0

        for i in self.md.disasm(code, base):
            insn = {
                'address': i.address,
                'size': i.size,
                'mnemonic': i.mnemonic,
                'op_str': i.op_str,
                'bytes': i.bytes.hex(),
            }
            insns.append(insn)

            # Prologue detection: push ebp/rbp ; mov ebp/rbp, esp
            if i.mnemonic in ('push', 'pushq') and i.op_str in ('rbp', 'ebp'):
                prologue = i.address

            # Stack frame: sub esp/rsp, N
            if i.mnemonic in ('sub', 'subq') and i.op_str.split(',')[0].strip() in ('esp', 'rsp'):
                try:
                    imm = int(i.op_str.split(',')[1].strip().lstrip('$'), 16)
                    if imm > 0 and imm <= 0x100000:
                        stack_frame = imm
                except (ValueError, IndexError):
                    pass

            # Detect stack variables: [ebp-N] / [rbp-N] / [esp+N] / [rsp+N]
            for tok in i.op_str.split(','):
                tok = tok.strip()
                m = re.search(r'\[(e?bp|rbp|e?sp|rsp)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]', tok, re.IGNORECASE)
                if m:
                    sign = m.group(2)
                    off_str = m.group(3)
                    try:
                        off = int(off_str, 16) if off_str.startswith('0x') else int(off_str)
                        if sign == '-':
                            off = -off
                    except ValueError:
                        continue
                    # [esp/rsp+N] = local; [ebp/rbp-N] = local; [ebp/rbp+N] = param
                    base_reg = m.group(1).lower()
                    is_local = (base_reg in ('esp', 'rsp', 'sp')) or (off < 0)
                    if is_local:
                        var_key = f'local_{(~off + 1) if off < 0 else off:x}'
                        if var_key not in stack_vars:
                            stack_vars[var_key] = {
                                'offset': off,
                                'name': var_key,
                                'accesses': [],
                                'used_by_funcs': set(),
                            }
                        stack_vars[var_key]['accesses'].append({
                            'at': i.address,
                            'mnemonic': i.mnemonic,
                            'context': f'{i.mnemonic} {i.op_str}',
                        })
                        # Heuristic: is this the result of a recent call?
                        # Only set on first detection (subsequent overwrites are wrong)
                        if 'result_of' not in stack_vars[var_key]:
                            target = None
                            if insns and len(insns) >= 2:
                                prev2 = insns[-2] if len(insns) >= 2 else None
                                if prev2 and prev2['mnemonic'] in ('call', 'callq'):
                                    target = _parse_hex(prev2['op_str'].strip())
                                if target is not None:
                                    resolved = known_calls.get(target, '')
                                    if resolved and 'stdout' not in resolved:
                                        stack_vars[var_key]['result_of'] = resolved
                        # Heuristic: what function does it get passed to?
                        for j in range(len(insns) - 1, max(-1, len(insns) - 6), -1):
                            prev = insns[j]
                            if prev['mnemonic'] in ('call', 'callq'):
                                target = _parse_hex(prev['op_str'].strip())
                                if target is not None:
                                    resolved = known_calls.get(target, hex(target))
                                    stack_vars[var_key]['used_by_funcs'].add(resolved)
            # Call detection with target resolution
            if i.mnemonic in ('call', 'callq'):
                target = _parse_hex(i.op_str.strip())
                if target is not None:
                    name = known_calls.get(target, '')
                    calls.append({
                        'from': i.address,
                        'to': target,
                        'name': name,
                        'type': 'call',
                    })

            # Basic block detection
            if i.mnemonic.lower() in self.BRANCH_MNEMONICS | self.RET_MNEMONICS:
                blocks.append([prev_addr, i.address + i.size])
                if i.mnemonic.lower() not in self.RET_MNEMONICS:
                    # Branch target is fall-through for next block
                    next_addr = i.address + i.size
                    if next_addr <= base + len(code):
                        blocks.append([next_addr, next_addr])
                        prev_addr = next_addr
                else:
                    prev_addr = i.address + i.size

        # Epilogue detection (last ret)
        for insn in reversed(insns):
            if insn['mnemonic'].lower() in self.RET_MNEMONICS:
                epilogue = insn['address']
                break

        self._suggest_var_names(stack_vars)

        return {
            'address': base,
            'size': len(code),
            'insns': insns,
            'stack_frame': stack_frame,
            'stack_vars': sorted(
                [{'offset': v['offset'], 'name': v['name'],
                  'suggested': v.get('suggested', v['name']),
                  'accesses': v['accesses'][:20],
                  'used_by_funcs': sorted(v['used_by_funcs'])[:10]}
                 for v in stack_vars.values()],
                key=lambda x: x['offset'],
            ),
            'calls': calls,
            'prologue': prologue,
            'epilogue': epilogue,
            'basic_blocks': blocks,
        }

    # ── Pseudo-C decompiler ──────────────────────────────────────────────

    def decompile_function(self, analysis: dict, known_calls: Dict[int, str] = None,
                           string_map: Dict[int, str] = None,
                           func_name: str = None) -> str:
        if known_calls is None:
            known_calls = {}
        if string_map is None:
            string_map = {}

        insns = analysis.get('insns', [])
        sv_raw = {v['offset']: v for v in analysis.get('stack_vars', [])}
        calls_list = analysis.get('calls', [])
        stack_frame = analysis.get('stack_frame', 0)
        address = analysis.get('address', 0)

        call_map = {c['from']: c.get('name', '') for c in calls_list}

        # Detect 32 vs 64 bit from register names in first 20 insns
        ops20 = ''.join(i['op_str'] for i in insns[:20])
        is_64 = 'rsp' in ops20 or 'rbp' in ops20

        # Build var-by-name lookup: name -> var for variable references
        var_by_name = {}
        for v in analysis.get('stack_vars', []):
            var_by_name[v['name']] = v.get('suggested', v['name'])
            var_by_name[v.get('suggested', v['name'])] = v.get('suggested', v['name'])

        # Build stack variable map for resolving register offsets to names
        # Key = offset (positive for esp-relative, negative for ebp-relative)
        var_by_off = {}
        for v in analysis.get('stack_vars', []):
            var_by_off[v['offset']] = v

        # Collect jump targets
        jump_targets = set()
        for insn in insns:
            try:
                tok = insn['op_str'].strip()
                # Only treat hex-looking operands as addresses
                if tok.startswith('0x') or tok.startswith('-0x'):
                    target = int(tok, 16)
                    if insn['mnemonic'].lower() in self.BRANCH_MNEMONICS | {'jmp'}:
                        jump_targets.add(target)
            except (ValueError, AttributeError):
                pass

        func_name = func_name or f'func_{address:x}'
        lines = []

        # ── Function signature ──
        params = self._detect_params(insns, sv_raw, is_64)
        lines.append(f'// {func_name} @ {hex(address)}')
        if stack_frame:
            lines.append(f'// Stack frame: {stack_frame} bytes')
        # Detect return type: look for mov eax, X or xor eax,eax before ret
        has_retval = False
        for i in insns:
            if i['mnemonic'].lower() in ('mov', 'movabs') and ',' in i['op_str']:
                dst = i['op_str'].split(',')[0].strip().lower()
                if dst in ('eax', 'rax'):
                    has_retval = True
        # Also handle xor eax,eax (common return 0)
        if not has_retval:
            for i in insns:
                if i['mnemonic'].lower() == 'xor' and ',' in i['op_str']:
                    parts = [p.strip().lower() for p in i['op_str'].split(',')]
                    if len(parts) == 2 and parts[0] == parts[1] and parts[0] in ('eax', 'rax'):
                        has_retval = True
                        break
        ret_type = 'int' if has_retval else 'void'
        # If returning via a pointer-typed stack variable, use that type
        if has_retval:
            for i in reversed(insns):
                mn = i['mnemonic'].lower()
                if mn in ('ret', 'retq', 'retn', 'retf', 'leave', 'leaveq', 'nop', 'endbr64', 'endbr32'):
                    continue
                if mn == 'call':
                    break  # rax from callee, keep default
                if mn in ('mov', 'movabs') and ',' in i['op_str']:
                    dst = i['op_str'].split(',')[0].strip().lower()
                    if dst in ('rax', 'eax'):
                        src = i['op_str'].split(',', 1)[1].strip()
                        m = re.match(r'\[rbp\s*-\s*(0x[0-9a-fA-F]+|\d+)\]', src, re.IGNORECASE)
                        if m:
                            try:
                                off_str = m.group(1)
                                off = -int(off_str, 16) if off_str.startswith('0x') else -int(off_str)
                                v = sv_raw.get(off)
                                if v:
                                    ctype = self._guess_var_type(v, insns)
                                    if ctype != 'int':
                                        ret_type = ctype
                            except ValueError:
                                pass
                        break  # last rax write found
                break  # unknown instruction modifying rax
        if params:
            lines.append(f'{ret_type} {func_name}({params})')
        else:
            lines.append(f'{ret_type} {func_name}(void)')
        lines.append('{')

        # ── Local variable declarations ──
        if analysis.get('stack_vars'):
            lines.append('')
            for v in sorted(analysis['stack_vars'], key=lambda x: x['offset']):
                ctype = self._guess_var_type(v, insns)
                vname = v.get('suggested', v['name'])
                if vname != v['name']:
                    lines.append(f'    {ctype} {vname};    // {v["name"]}')
                else:
                    lines.append(f'    {ctype} {vname};')
            lines.append('')

        # ── Register state tracking ──
        regs: Dict[str, str] = {}
        mem_state = SSAMemory()

        def _resolve_op(op: str, width_hint: str = '') -> str:
            op = op.strip()
            rv = _reg_lookup(op, regs)
            if rv is not None:
                return rv
            vname = _resolve_mem_ref(op, var_by_off)
            if vname is not None:
                return vname
            if op.startswith('0x'):
                val = _parse_hex(op)
                if val is not None:
                    if val in string_map:
                        return string_map[val]
                    return str(val) if val < 256 else hex(val)
            return op

        # ── Walk instructions ──
        # First pass: collect argument-setup instruction ranges so we can skip them
        call_arg_ranges = set()  # indices of insns consumed as call args
        arg_reg_names = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9',
                         'edi', 'esi', 'edx', 'ecx', 'r8d', 'r9d')
        for idx in range(len(insns)):
            if insns[idx]['mnemonic'].lower() in ('call', 'callq'):
                start = max(0, idx - 15)
                for j in range(start, idx):
                    jmn = insns[j]['mnemonic'].lower()
                    jops = insns[j]['op_str']
                    if jmn in ('push', 'xor', 'lea'):
                        call_arg_ranges.add(j)
                    elif jmn == 'mov' and ',' in jops:
                        dst = jops.split(',')[0].strip().lower()
                        # Mark movs to arg registers (64-bit ABI) OR stack pointers (32-bit cdecl)
                        is_arg_reg = any(dst.startswith(a) for a in arg_reg_names)
                        is_stack = bool(re.search(r'\[e?sp|rsp|e?bp|rbp\]', dst))
                        if is_arg_reg or is_stack:
                            call_arg_ranges.add(j)

        # Second pass: translate
        prologue_skip = 0
        for insn in insns[:6]:
            mn_l = insn['mnemonic'].lower()
            ops = insn['op_str'].strip()
            if mn_l in ('push', 'nop') and ops in ('ebp', 'rbp', 'edi', 'rdi'):
                prologue_skip += 1
            elif mn_l == 'mov' and (ops.startswith('rbp, rsp') or ops.startswith('ebp, esp')):
                prologue_skip += 1
            elif mn_l in ('sub', 'subq') and (ops.startswith('esp,') or ops.startswith('rsp,')):
                prologue_skip += 1
            elif mn_l in ('and', 'andq') and (ops.startswith('esp,') or ops.startswith('rsp,')):
                prologue_skip += 1
            elif mn_l in ('endbr64', 'endbr32'):
                prologue_skip += 1
            else:
                break

        idx = 0
        while idx < len(insns):
            insn = insns[idx]
            addr = insn['address']
            mn = insn['mnemonic'].lower()
            ops = insn['op_str']

            # Skip prologue
            if idx < prologue_skip:
                self._update_reg_state(insn, regs, var_by_off, is_64, mem_state)
                idx += 1
                continue

            # Skip argument-setup instructions (already collected into calls)
            if idx in call_arg_ranges:
                # But still update register state
                self._update_reg_state(insn, regs, var_by_off, is_64, mem_state)
                idx += 1
                continue

            # Label for jump targets
            if addr in jump_targets:
                lines.append('')
                lines.append(f'  L_{addr:x}:')

            # Call instruction
            if mn in ('call', 'callq'):
                target_name = call_map.get(addr, '')
                if not target_name:
                    try:
                        t = int(ops.strip(), 16)
                        target_name = known_calls.get(t, f'sub_{t:x}')
                    except ValueError:
                        target_name = ops
                # Strip version suffixes like @GLIBC_2.0 or @@GLIBC_2.0
                if '@@' in target_name:
                    target_name = target_name.split('@@')[0]
                elif '@' in target_name:
                    target_name = target_name.split('@')[0]
                args = self._get_call_args(insns, regs, var_by_off, _resolve_op, idx)
                # Try to inline return value: if next insn stores eax/rax to a variable
                ret_var = ''
                if idx + 1 < len(insns):
                    next_insn = insns[idx + 1]
                    nm = next_insn['mnemonic'].lower()
                    if nm == 'mov' and ',' in next_insn['op_str']:
                        parts = [p.strip() for p in next_insn['op_str'].split(',', 1)]
                        src = parts[1].lower()
                        if src in ('eax', 'rax'):
                            m = re.search(r'\[(e?bp|rbp|e?sp|rsp)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]', parts[0], re.IGNORECASE)
                            if m:
                                base = m.group(1).lower()
                                sign = 1 if m.group(2) == '+' else -1
                                try:
                                    off_str = m.group(3)
                                    off = sign * (int(off_str, 16) if off_str.startswith('0x') else int(off_str))
                                except ValueError:
                                    off = 0
                                if base in ('rsp', 'esp', 'rbp', 'ebp', 'sp', 'bp'):
                                    vinfo = var_by_off.get(off)
                                    if vinfo:
                                        ret_var = vinfo.get('suggested', vinfo['name'])
                if ret_var:
                    if args:
                        lines.append(f'    {ret_var} = {target_name}({", ".join(args)});')
                    else:
                        lines.append(f'    {ret_var} = {target_name}();')
                    # Set rax to the return value expression before processing the next
                    # instruction so the SSA memory cache can capture it on store.
                    regs['rax'] = Expr.var(ret_var)
                    # Skip the store instruction too
                    self._update_reg_state(next_insn, regs, var_by_off, is_64, mem_state)
                    idx += 2
                else:
                    if args:
                        lines.append(f'    {target_name}({", ".join(args)});')
                    else:
                        lines.append(f'    {target_name}();')
                    idx += 1
                if target_name:
                    lines.append('')
                self._clear_caller_regs(regs, is_64)
                continue

            # Return — also function boundary: stop processing adjacent code
            if mn in self.RET_MNEMONICS:
                ret_val = regs.get('eax') or regs.get('rax', '')
                if ret_val:
                    if isinstance(ret_val, Expr):
                        ret_val = _expr_str(ret_val)
                    lines.append(f'    return {ret_val};')
                else:
                    lines.append('    return;')
                break

            # Conditional jump → if/else style
            if mn in self.BRANCH_MNEMONICS and mn != 'jmp':
                try:
                    target = int(ops.strip(), 16)
                    # Look back for a cmp/test instruction
                    cond = ''
                    for j in range(max(0, idx - 4), idx):
                        jmn = insns[j]['mnemonic'].lower()
                        if jmn in ('cmp', 'test', 'cmpq', 'testq'):
                            cond = insns[j]['op_str']
                            break
                    op_l = _resolve_op(cond.split(',')[0].strip(), '') if cond and ',' in cond else ''
                    op_r = _resolve_op(cond.split(',')[1].strip(), '') if cond and ',' in cond else ''
                    c_op_map = {'je': '==', 'jz': '==', 'jne': '!=', 'jnz': '!=',
                                'jg': '>', 'jge': '>=', 'jl': '<', 'jle': '<=',
                                'ja': '>', 'jae': '>=', 'jb': '<', 'jbe': '<=',
                                'js': '< 0', 'jns': '>= 0'}
                    # Inverted operators for branch inversion
                    inv_c_op = {'==': '!=', '!=': '==', '>': '<=', '>=': '<',
                                '<': '>=', '<=': '>', '< 0': '>= 0', '>= 0': '< 0'}
                    c_op = c_op_map.get(mn, '')
                    # Branch inversion: if followed by jmp, invert condition
                    inverted = False
                    next_idx = idx + 1
                    skipped_reg_setup = []
                    # Skip interruptible instructions between cond jump and jmp
                    while next_idx < len(insns):
                        nxt = insns[next_idx]
                        nxt_mn = nxt['mnemonic'].lower()
                        nxt_ops = nxt['op_str']
                        if nxt_mn in ('nop', 'endbr64', 'endbr32'):
                            next_idx += 1
                            continue
                        # Skip register-setup instructions (mov/xor to reg, not memory)
                        if nxt_mn in ('mov', 'movabs', 'xor') and ',' in nxt_ops:
                            dst = nxt_ops.split(',')[0].strip().lower()
                            if re.match(r'^[er]?[a-z0-9]+$', dst, re.IGNORECASE):
                                skipped_reg_setup.append(nxt)
                                next_idx += 1
                                continue
                        break
                    if (next_idx < len(insns) and insns[next_idx]['mnemonic'].lower() == 'jmp'
                            and c_op and inv_c_op.get(c_op)):
                        try:
                            jmp_target = int(insns[next_idx]['op_str'].strip(), 16)
                            inv_op = inv_c_op[c_op]
                            lines.append(f'    if ({op_l} {inv_op} {op_r}) goto L_{jmp_target:x};')
                            inverted = True
                            # Track register state for skipped setup instructions
                            for si in skipped_reg_setup:
                                self._update_reg_state(si, regs, var_by_off, is_64, mem_state)
                            idx = next_idx + 1  # skip the jmp too
                        except ValueError:
                            pass
                    if not inverted:
                        if cond and c_op:
                            lines.append(f'    if ({op_l} {c_op} {op_r}) goto L_{target:x};')
                        else:
                            lines.append(f'    if (unlikely) goto L_{target:x};')
                except ValueError:
                    lines.append(f'    /* {insn["mnemonic"]} {ops} */')
                idx += 1
                continue

            # Unconditional jump (suppress if target is next line's label)
            if mn == 'jmp':
                try:
                    target = int(ops.strip(), 16)
                    # Check if the very next thing is our target label (fall-through)
                    is_fallthrough = (
                        idx + 1 < len(insns)
                        and insns[idx + 1]['address'] == target
                    )
                    if not is_fallthrough:
                        lines.append(f'    goto L_{target:x};')
                except ValueError:
                    lines.append(f'    /* jmp {ops} */')
                idx += 1
                continue

            # Skip irrelevant or already-consumed instructions
            if mn in ('nop', 'nopq', 'leave', 'leaveq', 'endbr64', 'endbr32', 'cmp', 'cmpq', 'test', 'testq'):
                self._update_reg_state(insn, regs, var_by_off, is_64, mem_state)
                idx += 1
                continue

            # Multi-instruction idiom detection
            idiom = self._match_strlen_idiom(insns, idx)
            if idiom:
                skip, c_code = idiom
                lines.append(f'    {c_code};')
                for k in range(idx, min(idx + skip, len(insns))):
                    self._update_reg_state(insns[k], regs, var_by_off, is_64, mem_state)
                idx += skip
                continue

            # Regular instruction → C statement
            c_line = self._insn_to_c(insn, regs, var_by_name, var_by_off, is_64, string_map)
            if c_line:
                lines.append(f'    {c_line};')

            # Update register state
            self._update_reg_state(insn, regs, var_by_off, is_64, mem_state)
            idx += 1

        lines.append('}')

        # Post-processing: suppress unused variable declarations
        body = '\n'.join(lines)
        import re as _re
        # Match full declaration line: "    type name;    // comment"
        for m in _re.finditer(r'^(\s{4}\w+\s+\w+;\s*(?://.*)?)$', body, _re.MULTILINE):
            decl_line = m.group(1)
            body_without_decl = body.replace(decl_line, '', 1)
            # Remove the blank line that preceded the declaration (if any)
            body_without_decl = body_without_decl.replace('\n\n\n', '\n\n')
            decl_name = decl_line.split()[1].rstrip(';')
            if decl_name not in body_without_decl:
                body = body_without_decl
        # Normalize blank lines after declaration cleanup
        body = body.replace('{\n\n', '{\n').replace('\n\n\n', '\n\n')

        return body

    # ── Decompiler helpers ───────────────────────────────────────────────

    def _get_call_args(self, insns: list, regs: dict, var_by_off: dict,
                       resolve_op, idx: int) -> list:
        args = []
        arg_regs_64 = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        arg_regs_32 = ['edi', 'esi', 'edx', 'ecx', 'r8d', 'r9d']
        reg32_to_64 = dict(zip(arg_regs_32, arg_regs_64))
        arg_vals = {}
        for j in range(idx - 1, max(0, idx - 12) - 1, -1):
            jmn = insns[j]['mnemonic'].lower()
            jops = insns[j]['op_str']
            if jmn in ('call', 'callq'):
                break
            if jmn == 'mov' and ',' in jops:
                parts = [p.strip() for p in jops.split(',', 1)]
                dst = parts[0].lower()
                if not (dst.startswith('r') or dst.startswith('e')):
                    continue
                dst64 = reg32_to_64.get(dst, dst)
                if dst64 in arg_regs_64 and dst64 not in arg_vals:
                    arg_vals[dst64] = resolve_op(parts[1], dst)
        for j in range(idx - 1, max(0, idx - 12) - 1, -1):
            if insns[j]['mnemonic'].lower() in ('call', 'callq'):
                break
            if insns[j]['mnemonic'].lower() == 'xor' and ',' in insns[j]['op_str']:
                parts = [p.strip().lower() for p in insns[j]['op_str'].split(',')]
                if len(parts) == 2 and parts[0] == parts[1]:
                    r = parts[0]
                    r64 = reg32_to_64.get(r, r)
                    if r64 in arg_regs_64 and r64 not in arg_vals:
                        arg_vals[r64] = '0'
        if arg_vals:
            for r in arg_regs_64:
                if r in arg_vals:
                    args.append(arg_vals[r])
                elif r in regs:
                    rv = regs[r]
                    if isinstance(rv, Expr):
                        rv = _expr_str(rv)
                    args.append(rv)
                else:
                    r32 = [k for k, v in reg32_to_64.items() if v == r]
                    if r32 and r32[0] in regs:
                        rv = regs[r32[0]]
                        if isinstance(rv, Expr):
                            rv = _expr_str(rv)
                        args.append(rv)
                    else:
                        break
        write_order = []
        stack_args = {}
        for j in range(idx - 1, max(0, idx - 6) - 1, -1):
            jmn = insns[j]['mnemonic'].lower()
            jops = insns[j]['op_str']
            if jmn in ('call', 'callq'):
                break
            if jmn == 'push':
                push_val = jops.strip()
                if push_val in ('ebp', 'rbp', 'r15', 'r14', 'r13', 'r12', 'rbx', 'edi', 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'):
                    continue
                arg_idx = len(stack_args)
                val = resolve_op(push_val, 'stack')
                if arg_idx not in stack_args:
                    write_order.append(arg_idx)
                stack_args[arg_idx] = val
            elif jmn == 'mov' and ',' in jops:
                parts = [p.strip() for p in jops.split(',', 1)]
                dst = parts[0]
                m = re.search(r'\[(e?sp|rsp)(?:\s*\+\s*(0x[0-9a-fA-F]+|\d+))?\]', dst, re.IGNORECASE)
                if m:
                    off_str = m.group(2)
                    if off_str is None:
                        off_val = 0
                    elif off_str.startswith('0x'):
                        off_val = _parse_hex(off_str)
                        if off_val is None:
                            continue
                    else:
                        off_val = int(off_str)
                    if off_val > 20:
                        continue
                    arg_idx = off_val // 4
                    val = resolve_op(parts[1], 'stack')
                    if arg_idx not in stack_args:
                        write_order.append(arg_idx)
                    stack_args[arg_idx] = val
        if not args and stack_args:
            # Heuristic: if [rsp+0] was written before positive offsets in the
            # backward scan (execution order: later), it's likely stale from a
            # previous call setup. Remove it.
            if 0 in stack_args and any(k > 0 for k in stack_args):
                try:
                    pos_0 = write_order.index(0)
                    pos_pos = next(i for i, k in enumerate(write_order) if k > 0)
                    if pos_0 > pos_pos:
                        del stack_args[0]
                except (ValueError, StopIteration):
                    pass
            max_idx = max(stack_args.keys()) + 1 if stack_args else 0
            for k in range(max_idx):
                if k in stack_args:
                    args.append(stack_args[k])
        return args

    def _suggest_var_names(self, stack_vars: dict):
        # Deterministic order so repeated runs / collisions are stable.
        taken = set()
        for key in sorted(stack_vars, key=lambda k: (str(stack_vars[k].get('offset', 0)), str(k))):
            var = stack_vars[key]
            funcs = var.get('used_by_funcs', set())
            result_of = var.get('result_of', '')
            suggested = key
            if 'malloc' in result_of or 'calloc' in result_of or 'realloc' in result_of:
                suggested = 'heap_ptr'
            elif result_of:
                suggested = result_of.split('@@')[0].lower() + '_res'
            elif any('scanf' in f or 'gets' in f or 'read' in f for f in funcs):
                suggested = 'input_buf'
            elif any('printf' in f for f in funcs):
                suggested = 'print_arg'
            elif any('strcpy' in f or 'memcpy' in f for f in funcs):
                suggested = 'src_buf' if 'src' in key else 'dst_buf'
            elif any('system' in f or 'exec' in f for f in funcs):
                suggested = 'cmd_str'
            elif any('malloc' in f for f in funcs):
                suggested = 'size_arg'
            elif any('free' in f for f in funcs):
                suggested = 'heap_ptr'
            # Never emit the same identifier twice — that produces invalid C.
            if suggested != key and suggested in taken:
                n = 2
                while f'{suggested}_{n}' in taken:
                    n += 1
                suggested = f'{suggested}_{n}'
            taken.add(suggested)
            var['suggested'] = suggested

    @staticmethod
    def _detect_params(insns: list, stack_vars: dict, is_64: bool) -> str:
        params = []
        if not is_64:
            seen = set()
            for insn in insns:
                ops = insn['op_str']
                m = re.findall(r'\[ebp\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]', ops, re.IGNORECASE)
                for off_str in m:
                    if off_str not in seen:
                        seen.add(off_str)
                        off = int(off_str, 16) if off_str.startswith('0x') else int(off_str)
                        idx = (off - 4) // 4
                        params.append((idx, f'arg_{idx}'))
        if params:
            params.sort()
            return ', '.join(f'int arg_{p[0]}' for p in params)
        return ''

    @staticmethod
    def _guess_var_type(var: dict, insns: list) -> str:
        """Guess variable type from usage patterns."""
        suggested = var.get('suggested', var['name'])
        accesses = var.get('accesses', [])
        used_by = var.get('used_by_funcs', set())
        # Check by function argument type
        func_type_map = {
            'strlen': 'char*', 'strcpy': 'char*', 'strcat': 'char*',
            'printf': 'char*', 'puts': 'char*', 'gets': 'char*',
            'fgets': 'char*', 'read': 'char*', 'write': 'char*',
            'send': 'char*', 'recv': 'char*',
            'free': 'void*', 'malloc': 'size_t',
            'memcpy': 'void*', 'memset': 'void*', 'memmove': 'void*',
            'open': 'char*', 'fopen': 'char*',
        }
        for func_key, ftype in func_type_map.items():
            if any(func_key in f for f in used_by):
                return ftype
        # lea → pointer (usually char*)
        for a in accesses:
            if a.get('mnemonic', '').lower() == 'lea':
                return 'char*'
        # Check access width from instruction context
        access_sizes = set()
        for a in accesses:
            ctx = a.get('context', '')
            if 'dword ptr' in ctx:
                access_sizes.add(8)
            elif 'qword ptr' in ctx:
                access_sizes.add(64)
            elif 'word ptr' in ctx:
                access_sizes.add(16)
            elif 'byte ptr' in ctx:
                access_sizes.add(8)
        if 64 in access_sizes:
            return 'long'
        # Pointer-like name heuristic
        if any(kw in suggested for kw in ('ptr', 'buf', 'str', 'arg', 'src', 'dst')):
            return 'char*'
        # Default
        return 'int'

    @staticmethod
    def _insn_to_c(insn: dict, regs: dict, var_by_name: dict,
                   var_by_off: dict, is_64: bool,
                   string_map: dict = None) -> str:
        if string_map is None:
            string_map = {}
        mn = insn['mnemonic'].lower()
        ops = insn['op_str']

        def _r(op: str) -> str:
            op = op.strip()
            rv = _reg_lookup(op, regs)
            if rv is not None:
                return rv
            vname = _resolve_mem_ref(op, var_by_off)
            if vname is not None:
                return vname
            m = _SIMPLE_MEM_RE.search(op)
            if m:
                inner = m.group(1)
                rv = _reg_lookup(inner, regs)
                if rv is not None:
                    return f'*({rv})'
                return f'*{inner}'
            if op.startswith('0x'):
                val = _parse_hex(op)
                if val is not None:
                    if val in string_map:
                        return string_map[val]
                    return str(val) if val < 256 else hex(val)
            return op

        def _access_width(dst_op: str) -> int:
            """Extract memory access width in bytes from destination operand."""
            m = re.match(r'\s*(byte|word|dword|qword)\s+ptr\s+', dst_op, re.IGNORECASE)
            return _SIZE_PREFIX.get(m.group(1).lower(), 0) if m else 0

        def _fmt_val(val_str: str, width: int) -> str:
            """Format a constant as a char literal when stored as a byte."""
            if width == 1:
                try:
                    v = int(val_str)
                    if 32 <= v < 127:
                        return repr(chr(v))
                except (ValueError, TypeError):
                    pass
            return val_str

        # movsxd dst, src — sign-extend, same tracking as mov
        if mn == 'movsxd' and ',' in ops:
            parts = [p.strip() for p in ops.split(',', 1)]
            dst = parts[0]
            src = parts[1]
            if re.match(r'^[er]?[a-z0-9]+$', dst, re.IGNORECASE):
                return ''                   # register-to-register, suppressed

        # mov / movabs dst, src
        if mn in ('mov', 'movabs') and ',' in ops:
            parts = [p.strip() for p in ops.split(',', 1)]
            dst = parts[0]
            src = parts[1]
            aw = _access_width(dst)
            # Check if dst is a memory write via pointer: *ptr = src
            m_ptr = re.search(r'\[([a-z0-9]+(?:\s*\+\s*[a-z0-9]+)?)\]\s*$', dst, re.IGNORECASE)
            m_off = re.search(r'\[([a-z]+)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]', dst, re.IGNORECASE)
            if m_off:
                base = m_off.group(1).lower()
                sign = 1 if m_off.group(2) == '+' else -1
                try:
                    off_str = m_off.group(3)
                    off = sign * (int(off_str, 16) if off_str.startswith('0x') else int(off_str))
                except ValueError:
                    return f'memory[{dst}] = {_fmt_val(_r(src), aw)}'
                # Only resolve to stack variable if base is a stack pointer
                if base in ('rsp', 'esp', 'rbp', 'ebp', 'sp', 'bp'):
                    vinfo = var_by_off.get(off)
                    if vinfo:
                        vname = vinfo.get('suggested', vinfo['name'])
                        rv = _r(src)
                        # Suppress no-op store: heap_ptr = heap_ptr (same var on both sides)
                        if rv == vname:
                            return ''
                        return f'{vname} = {_fmt_val(rv, aw)}'
                    return f'STACK_{hex(off)} = {_fmt_val(_r(src), aw)}'
                alias = _resolve_alias_from_reg(base, regs)
                if alias is not None:
                    alias_name, alias_off = alias
                    merged_off = alias_off + off
                    if alias_name in ('rbp', 'rsp', 'ebp', 'esp', 'bp', 'sp'):
                        vinfo = var_by_off.get(merged_off)
                        if vinfo:
                            vname = vinfo.get('suggested', vinfo['name'])
                            return f'{vname} = {_fmt_val(_r(src), aw)}'
                    return f'{alias_name}[{merged_off}] = {_fmt_val(_r(src), aw)}'
                rv = _reg_lookup(base, regs)
                ptr_name = rv if rv is not None else base
                return f'{ptr_name}[{off}] = {_fmt_val(_r(src), aw)}'
            if m_ptr:
                ptr_raw = m_ptr.group(1).strip()
                alias = _resolve_alias_from_reg(ptr_raw, regs)
                if alias is not None:
                    alias_name, alias_off = alias
                    if alias_name in ('rbp', 'rsp', 'ebp', 'esp', 'bp', 'sp'):
                        vinfo = var_by_off.get(alias_off)
                        if vinfo:
                            vname = vinfo.get('suggested', vinfo['name'])
                            return f'{vname} = {_fmt_val(_r(src), aw)}'
                    return f'{alias_name}[{alias_off}] = {_fmt_val(_r(src), aw)}'
                if ptr_raw in regs and isinstance(regs[ptr_raw], Expr):
                    ptr_expr = _expr_str(regs[ptr_raw])
                else:
                    rv = _reg_lookup(ptr_raw, regs)
                    ptr_expr = rv if rv is not None else ptr_raw
                return f'*{ptr_expr} = {_fmt_val(_r(src), aw)}'
            # Check if dst is a register
            if dst in regs or re.match(r'^[er]?[a-z0-9]+$', dst, re.IGNORECASE):
                # mov reg, X → just track in regs, no C line needed
                return ''
            return f'{dst} = {_fmt_val(_r(src), aw)}'

        # lea reg, [mem]
        if mn == 'lea' and ',' in ops:
            parts = [p.strip() for p in ops.split(',', 1)]
            dst = parts[0]
            src = parts[1]
            if src in regs:
                return f'{dst} = {regs[src]}'
            # [ebp-N] or [esp+N] → &var
            m = re.search(r'\[([a-z]+)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]', src, re.IGNORECASE)
            if m:
                base = m.group(1).lower()
                sign = 1 if m.group(2) == '+' else -1
                try:
                    off_str = m.group(3)
                    off = sign * (int(off_str, 16) if off_str.startswith('0x') else int(off_str))
                except ValueError:
                    return f'{dst} = &({src})'
                vinfo = var_by_off.get(off)
                if vinfo:
                    vname = vinfo.get('suggested', vinfo['name'])
                    return f'{dst} = &{vname}'
            return f'{dst} = {src}'

        # xor reg, reg → reg = 0
        if mn == 'xor' and ',' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts) == 2 and parts[0] == parts[1]:
                return f'{parts[0]} = 0'

        # add/sub on register — expression tracking handles it
        if mn in ('add', 'sub') and ',' in ops:
            parts = [p.strip() for p in ops.split(',', 1)]
            if re.match(r'^[er]?[a-z0-9]+$', parts[0], re.IGNORECASE):
                return ''
            op = '+=' if mn == 'add' else '-='
            return f'{parts[0]} {op} {_r(parts[1])}'

        # inc/dec on registers — expression tracking handles it
        if mn == 'inc' and re.match(r'^[er]?[a-z0-9]+$', ops.strip(), re.IGNORECASE):
            return ''
        if mn == 'dec' and re.match(r'^[er]?[a-z0-9]+$', ops.strip(), re.IGNORECASE):
            return ''
        if mn == 'inc':
            return f'{_r(ops)}++'
        if mn == 'dec':
            return f'{_r(ops)}--'

        # neg/not on registers — expression tracking handles it
        if mn == 'neg' and re.match(r'^[er]?[a-z0-9]+$', ops.strip(), re.IGNORECASE):
            return ''
        if mn == 'not' and re.match(r'^[er]?[a-z0-9]+$', ops.strip(), re.IGNORECASE):
            return ''

        if mn in ('and', 'or') and ',' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts) == 2 and parts[0] == parts[1] and re.match(r'^[er]?[a-z0-9]+$', parts[0], re.IGNORECASE):
                return ''
            op_sym = '&=' if mn == 'and' else '|='
            return f'{parts[0]} {op_sym} {_r(parts[1])}'

        if mn in ('shl', 'sal') and ',' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts) == 2 and re.match(r'^[er]?[a-z0-9]+$', parts[0], re.IGNORECASE):
                return f'{parts[0]} <<= {_r(parts[1])}'

        if mn in ('shr', 'sar') and ',' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts) == 2 and re.match(r'^[er]?[a-z0-9]+$', parts[0], re.IGNORECASE):
                return f'{parts[0]} >>= {_r(parts[1])}'

        if mn == 'push':
            return ''
        if mn == 'pop':
            return f'{ops} = pop()'

        # nop, and other no-ops
        if mn == 'nop':
            return ''

        # Everything else → comment
        return f'/* {insn["mnemonic"]} {ops} */'

    @staticmethod
    def _update_reg_state(insn: dict, regs: dict, var_by_off: dict, is_64: bool,
                          mem_state: 'SSAMemory | None' = None):
        """Track register values as expression trees."""
        mn = insn['mnemonic'].lower()
        ops = insn['op_str']

        def _op_expr(op: str):
            """Convert an operand string to an Expr."""
            op = op.strip()
            # Check SSA memory cache first (preserves expression trees through stack save/restore)
            if mem_state is not None:
                cached = mem_state.load(op)
                if cached is not None:
                    return cached
            vname = _resolve_mem_ref(op, var_by_off)
            if vname is not None:
                return Expr.var(vname)
            if op in regs and isinstance(regs[op], Expr):
                return regs[op]
            alias = _REG_ALIAS.get(op)
            if alias and alias in regs and isinstance(regs[alias], Expr):
                return regs[alias]
            # Must check numeric constants before register-name pattern
            if op.startswith('0x'):
                val = _parse_hex(op)
                if val is not None:
                    return Expr.const(val)
            try:
                return Expr.const(int(op, 0))
            except (ValueError, TypeError):
                pass
            # Register name (must have at least one letter to distinguish from pure numbers)
            if re.match(r'^[er]?[a-z][a-z0-9]*$', op, re.IGNORECASE):
                return Expr.var(op)
            return Expr.var(op)

        if mn in ('mov', 'movabs', 'movsxd') and ',' in ops:
            parts = [p.strip() for p in ops.split(',', 1)]
            dst = parts[0]
            src = parts[1]
            # Record stores to stack slots in the SSA memory cache
            if mem_state is not None:
                mem_state.store(dst, src if re.match(r'^[er]?[a-z0-9]+$', src, re.IGNORECASE) else '', regs)
            if re.match(r'^[er]?[a-z0-9]+$', dst, re.IGNORECASE) and not dst.startswith('['):
                regs[dst] = _op_expr(src)
                return

        if mn == 'lea' and ',' in ops:
            parts = [p.strip() for p in ops.split(',', 1)]
            dst = parts[0]
            if re.match(r'^[er]?[a-z0-9]+$', dst, re.IGNORECASE):
                regs[dst] = _op_expr(parts[1])
                return

        if mn == 'xor' and ',' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts) == 2 and parts[0] == parts[1] and re.match(r'^[er]?[a-z0-9]+$', parts[0], re.IGNORECASE):
                regs[parts[0]] = Expr.const(0)
                return

        if mn in ('add', 'sub') and ',' in ops:
            parts = [p.strip() for p in ops.split(',', 1)]
            dst = parts[0]
            if re.match(r'^[er]?[a-z0-9]+$', dst, re.IGNORECASE):
                old = regs.get(dst)
                if isinstance(old, Expr):
                    src_expr = _op_expr(parts[1])
                    regs[dst] = Expr.add(old, src_expr) if mn == 'add' else Expr.sub(old, src_expr)
                else:
                    regs.pop(dst, None)
                return
            regs.pop(dst, None)
            return

        if mn == 'inc':
            dst = ops.strip()
            if re.match(r'^[er]?[a-z0-9]+$', dst, re.IGNORECASE):
                old = regs.get(dst)
                if isinstance(old, Expr):
                    regs[dst] = Expr.add(old, Expr.const(1))
                else:
                    regs.pop(dst, None)
            return

        if mn == 'dec':
            dst = ops.strip()
            if re.match(r'^[er]?[a-z0-9]+$', dst, re.IGNORECASE):
                old = regs.get(dst)
                if isinstance(old, Expr):
                    regs[dst] = Expr.sub(old, Expr.const(1))
                else:
                    regs.pop(dst, None)
            return

        if mn in ('shl', 'sal') and ',' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts) == 2 and re.match(r'^[er]?[a-z0-9]+$', parts[0], re.IGNORECASE):
                dst = parts[0]
                shift_val = _parse_hex(parts[1])
                if shift_val is not None:
                    old = regs.get(dst)
                    if isinstance(old, Expr):
                        regs[dst] = Expr.mul(old, Expr.const(1 << shift_val))
                        return
                regs.pop(dst, None)
            return

        if mn in ('shr', 'sar') and ',' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts) == 2 and re.match(r'^[er]?[a-z0-9]+$', parts[0], re.IGNORECASE):
                regs.pop(parts[0], None)
            return

        # Clear destination reg for operations that modify regs
        if mn in ('and', 'or', 'mul', 'imul', 'div', 'idiv') and ',' in ops:
            dst = ops.split(',')[0].strip()
            if re.match(r'^[er]?[a-z0-9]+$', dst, re.IGNORECASE):
                regs.pop(dst, None)

        if mn in ('pop',):
            dst = ops.strip()
            if re.match(r'^[er]?[a-z0-9]+$', dst, re.IGNORECASE):
                regs.pop(dst, None)

    @staticmethod
    def _clear_caller_regs(regs: dict, is_64: bool):
        """After a call, caller-saved registers are clobbered."""
        caller_saved = ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']
        # Also their 32-bit variants that capstone may use (edi, esi, r8d, ...)
        ext_variants = ['eax', 'ecx', 'edx', 'esi', 'edi',
                        'r8d', 'r9d', 'r10d', 'r11d']
        all_clear = set(caller_saved + ext_variants)
        for r in list(regs.keys()):
            if r.lower() in all_clear:
                regs.pop(r, None)

    @staticmethod
    def _match_strlen_idiom(insns: list, idx: int) -> tuple | None:
        """Check if instructions at idx start a repne scasb strlen idiom.
        Returns (skip_count, c_code) or None."""
        if idx + 4 >= len(insns):
            return None
        i0 = insns[idx]
        i1 = insns[idx + 1]
        i2 = insns[idx + 2]
        # Pattern: repne scasb; not r; dec r (or lea r, [r-1])
        # capstone may split 'repne scasb' as mn='repne'/'repnz' op='scasb ...'
        # OR combine as mn='scasb' op='byte ptr [rdi]' with repne prefix
        m0 = i0['mnemonic'].lower()
        o0 = i0['op_str'].lower()
        is_scas = (m0 == 'scasb' or m0 == 'scasw' or m0 == 'scasd' or m0 == 'scasq'
                   or 'scasb' in o0 or 'scasw' in o0 or 'scasd' in o0 or 'scasq' in o0)
        if not (m0 in ('repne', 'repnz', 'repe', 'repz') and is_scas):
            return None
        # i1: not ecx/not rcx
        m1 = i1['mnemonic'].lower()
        o1 = i1['op_str'].strip().lower()
        if not (m1 == 'not' and o1 in ('ecx', 'rcx')):
            return None
        # i2: dec ecx/rcx or lea edx/rdx,[ecx/rcx-1]
        m2 = i2['mnemonic'].lower()
        o2 = i2['op_str'].strip().lower()
        skip = 3
        if m2 == 'dec' and o2 in ('ecx', 'rcx'):
            pass
        elif m2 == 'lea' and ',' in i2['op_str']:
            lea_src = i2['op_str'].split(',')[1].strip().lower()
            if lea_src in ('[ecx - 1]', '[rcx - 1]', '[ecx-1]', '[rcx-1]', '[ecx-0x1]', '[rcx-0x1]'):
                skip = 3
            else:
                return None
        else:
            return None
        # Determine the pointer register (rdi/edi) from the scasb operand
        ptr_reg = 'rdi'  # default
        return (skip, f'strlen({ptr_reg})')


    # ── Ghidra-style p-code decompilation pipeline ────────────────────

    def decompile_with_pcode(self, analysis: dict, known_calls=None,
                              string_map=None, func_name='sub_%x') -> str:
        """Decompile using the full Ghidra-style p-code pipeline.

        Pipeline:
          1. Capstone → p-code ops (via pcode.Translator)
          2. p-code ops → CFG (via cfg.CFGBuilder)
          3. CFG → SSA form (via ssa_engine.build_ssa)
          4. SSA → simplify actions (via decompile_actions.default_pipeline)
          5. SSA → C code (via emit_c.CCodeGenerator)

        This mirrors Ghidra's decompiler pipeline exactly.
        """
        try:
            from .pcode import Translator
            from .cfg import CFGBuilder
            from .ssa_engine import build_ssa
            from .decompile_actions import default_pipeline
            from .emit_c import CCodeGenerator

            insns = analysis.get('insns', [])
            if not insns:
                return '// no instructions'

            # Step 1: Capstone → p-code
            translator = Translator()
            pcode_ops = translator.translate(insns, base_addr=analysis.get('address', 0))

            if not pcode_ops:
                return '// p-code translation produced no ops'

            # Step 2: p-code → CFG
            builder = CFGBuilder()
            graph = builder.build(pcode_ops, base_addr=analysis.get('address', 0))

            if not graph.blocks:
                return '// CFG construction produced no blocks'

            # Step 3: CFG → SSA
            ctx = build_ssa(graph)

            # Step 4: SSA simplification actions
            pipeline = default_pipeline()
            pipeline.run(ctx)

            # Step 5: SSA → C code
            generator = CCodeGenerator(ctx)
            code = generator.emit()

            if not code.strip():
                return '// no C code generated'

            return code

        except ImportError as e:
            log.warning(f'p-code modules not available: {e}')
            return self.decompile_function(analysis, known_calls, string_map, func_name)
        except Exception as e:
            log.error(f'p-code decompilation failed: {e}')
            import traceback
            log.error(traceback.format_exc())
            return f'// p-code error: {e}'

    def decompile_with_pcode_demo(self, analysis: dict,
                                   known_calls=None, string_map=None,
                                   func_name='sub_%x') -> str:
        """Run BOTH decompilation methods and return comparison output."""
        old = self.decompile_function(analysis, known_calls, string_map, func_name)
        new = self.decompile_with_pcode(analysis, known_calls, string_map, func_name)
        return (
            '/* ============ LEGACY DECOMPILER ============ */\n'
            f'{old}\n\n'
            '/* ============ P-CODE DECOMPILER ============ */\n'
            f'{new}\n'
        )


# ── Backward-compatible re-exports from extracted modules ──
try:
    from triage_web.xref import BasicBlock, XRefDB          # noqa: F401
    from triage_web.rop import ROPGadget, ROPEngine          # noqa: F401
except ImportError:
    from xref import BasicBlock, XRefDB                      # noqa: F401
    from rop import ROPGadget, ROPEngine                      # noqa: F401
