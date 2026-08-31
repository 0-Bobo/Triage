"""p-code Intermediate Representation — Ghidra-inspired portable code layer.

Translates architecture-specific machine code (via Capstone) into a
generic p-code IR that all decompiler passes operate on.

p-code opcodes mirror Ghidra's CPUI_* enumeration (1–74).
"""
from __future__ import annotations
from enum import IntEnum
from typing import Dict, List, Optional


# ── p-code Opcodes (mirrors Ghidra's CPUI_* from opcodes.hh) ──────────

class OpCode(IntEnum):
    COPY        = 1    # Copy one operand to another
    LOAD        = 2    # Load from pointer in address space
    STORE       = 3    # Store at pointer in address space
    BRANCH      = 4    # Always branch
    CBRANCH     = 5    # Conditional branch
    BRANCHIND   = 6    # Indirect branch (jumptable)
    CALL        = 7    # Call absolute address
    CALLIND     = 8    # Call indirect
    CALLOTHER   = 9    # User-defined operation
    RETURN      = 10   # Return from subroutine
    INT_EQUAL   = 11   # Integer comparison, equality (==)
    INT_NOTEQUAL= 12   # Integer comparison, inequality (!=)
    INT_SLESS   = 13   # Integer comparison, signed less (<)
    INT_SLESSEQUAL=14  # Integer comparison, signed less-or-equal (<=)
    INT_LESS    = 15   # Integer comparison, unsigned less (<)
    INT_LESSEQUAL=16   # Integer comparison, unsigned less-or-equal (<=)
    INT_ZEXT    = 17   # Zero extension
    INT_SEXT    = 18   # Sign extension
    INT_ADD     = 19   # Addition (+)
    INT_SUB     = 20   # Subtraction (-)
    INT_CARRY   = 21   # Test for unsigned carry
    INT_SCARRY  = 22   # Test for signed carry
    INT_SBORROW = 23   # Test for signed borrow
    INT_2COMP   = 24   # Two's complement (negation)
    INT_NEGATE  = 25   # Bitwise NOT (~)
    INT_XOR     = 26   # Bitwise XOR (^)
    INT_AND     = 27   # Bitwise AND (&)
    INT_OR      = 28   # Bitwise OR (|)
    INT_LEFT    = 29   # Left shift (<<)
    INT_RIGHT   = 30   # Logical right shift (>>)
    INT_SRIGHT  = 31   # Arithmetic right shift (>>)
    INT_MULT    = 32   # Multiplication (*)
    INT_DIV     = 33   # Unsigned division (/)
    INT_SDIV    = 34   # Signed division (/)
    INT_REM     = 35   # Unsigned remainder (%)
    INT_SREM    = 36   # Signed remainder (%)
    BOOL_NEGATE = 37   # Boolean NOT (!)
    BOOL_XOR    = 38   # Boolean XOR (^^)
    BOOL_AND    = 39   # Boolean AND (&&)
    BOOL_OR     = 40   # Boolean OR (||)
    # Float ops (41-59) — skipped for MVP
    FLOAT_EQUAL  = 41  # Floating-point equality
    FLOAT_NOTEQUAL=42  # Floating-point inequality
    FLOAT_LESS   = 43  # Floating-point less
    FLOAT_LESSEQUAL=44 # Floating-point less-or-equal
    FLOAT_NAN    = 46  # Not-a-number test
    FLOAT_ADD    = 47  # Floating-point addition
    FLOAT_DIV    = 48  # Floating-point division
    FLOAT_MULT   = 49  # Floating-point multiplication
    FLOAT_SUB    = 50  # Floating-point subtraction
    FLOAT_NEG    = 51  # Floating-point negation
    FLOAT_ABS    = 52  # Floating-point absolute value
    FLOAT_SQRT   = 53  # Floating-point square root
    FLOAT_INT2FLOAT  = 54  # Integer → float
    FLOAT_FLOAT2FLOAT= 55  # Float size conversion
    FLOAT_TRUNC  = 56  # Round toward zero
    FLOAT_CEIL   = 57  # Round toward +inf
    FLOAT_FLOOR  = 58  # Round toward -inf
    FLOAT_ROUND  = 59  # Round toward nearest
    # Data-flow internal opcodes
    MULTIEQUAL   = 60  # Phi-node operator
    INDIRECT     = 61  # Copy with indirect effect
    PIECE        = 62  # Concatenate two values
    SUBPIECE     = 63  # Truncate (extract sub-piece)
    CAST         = 64  # Type cast
    PTRADD       = 65  # Array indexing (base + index * sizeof)
    PTRSUB       = 66  # Structure field access (base + offset)
    SEGMENTOP    = 67  # Segmented address lookup
    CPOOLREF     = 68  # Constant pool reference
    NEW          = 69  # Object allocation (new)
    INSERT       = 70  # Insert bit-range
    ZPULL        = 71  # Extract unsigned bit-range
    POPCOUNT     = 72  # Count 1-bits
    LZCOUNT      = 73  # Count leading 0-bits
    SPULL        = 74  # Extract signed bit-range


# ── Address Spaces ────────────────────────────────────────────────────

class AddressSpace:
    """p-code memory/register/constant space.

    Ghidra's p-code addresses data through named spaces:
    - ram:     The main memory space (virtual address)
    - register: The register file
    - const:   Constant values
    - stack:   Stack-local memory (offset from sp)
    - unique:  Temporary variables
    """
    RAM      = 'ram'
    REGISTER = 'register'
    CONST    = 'const'
    STACK    = 'stack'
    UNIQUE   = 'unique'

    _ALL_SPACES = {}

    def __init__(self, name: str, base: int = 0, size: int = 0):
        self.name = name
        self.base = base
        self.size = size  # 0 = unlimited
        AddressSpace._ALL_SPACES[name] = self

    def __repr__(self):
        return f'<Space {self.name}>'

    @staticmethod
    def get(name: str) -> 'AddressSpace':
        if name not in AddressSpace._ALL_SPACES:
            AddressSpace(name)
        return AddressSpace._ALL_SPACES[name]


# Initialize standard spaces
RAM      = AddressSpace.get('ram')
REGISTER = AddressSpace.get('register')
CONST    = AddressSpace.get('const')
STACK    = AddressSpace.get('stack')
UNIQUE   = AddressSpace.get('unique')


# ── Varnode (p-code variable node) ────────────────────────────────────

class Varnode:
    """A p-code variable node — (address_space, offset, size, version).

    Mirrors Ghidra's Varnode concept: uniquely identifies a value location
    in a specific address space with a specific size.
    """

    __slots__ = ('space', 'offset', 'size', 'version', 'def_op', 'uses')

    def __init__(self, space: AddressSpace, offset: int, size: int,
                 version: int = 0):
        self.space = space
        self.offset = offset
        self.size = size
        self.version = version
        self.def_op: Optional['PcodeOp'] = None  # The op that defines this varnode
        self.uses: List['PcodeOp'] = []           # Ops that use this varnode as input

    def copy(self, version: int = 0) -> 'Varnode':
        """Create a shallow copy with optional version bump."""
        v = Varnode(self.space, self.offset, self.size, version)
        return v

    @staticmethod
    def const(value: int, size: int = 8) -> 'Varnode':
        """Create a constant varnode."""
        return Varnode(CONST, value, size)

    @staticmethod
    def var(name: str, size: int = 8) -> 'Varnode':
        """Create a register varnode from a named register reference."""
        # offset = hash(name) & 0xFFFF (simplified — real Ghidra maps to register file)
        offset = sum(ord(c) * (31 ** i) for i, c in enumerate(name)) & 0xFFFF
        return Varnode(REGISTER, offset, size)

    def is_constant(self) -> bool:
        return self.space is CONST

    def is_register(self) -> bool:
        return self.space is REGISTER

    def is_memory(self) -> bool:
        return self.space in (RAM, STACK)

    def is_unique(self) -> bool:
        return self.space is UNIQUE

    @property
    def varnode_id(self) -> tuple:
        """Unique identifier for this varnode instance."""
        return (self.space.name, self.offset, self.size, self.version)

    def __repr__(self):
        if self.space is CONST:
            return f'#{self.offset}:{self.size}'
        if self.space is REGISTER:
            return f'reg[{self.offset:x}]:{self.size}'
        return f'{self.space.name}[{self.offset:x}]:{self.size}'

    def __hash__(self):
        return hash(self.varnode_id)

    def __eq__(self, other):
        if not isinstance(other, Varnode):
            return NotImplemented
        return self.varnode_id == other.varnode_id


# ── PcodeOp (p-code operation) ────────────────────────────────────────

class PcodeOp:
    """A single p-code operation in the data-flow graph.

    Each op has:
    - opcode: The operation type (from OpCode enum)
    - output: The varnode being defined (or None for STORE/BRANCH)
    - inputs: List of input varnodes
    - addr:   The original machine code address (for debug/error reporting)
    """

    __slots__ = ('opcode', 'output', 'inputs', 'addr')

    def __init__(self, opcode: OpCode, output: Optional[Varnode] = None,
                 inputs: Optional[List[Varnode]] = None, addr: int = 0):
        self.opcode = opcode
        self.output = output
        self.inputs = inputs or []
        self.addr = addr

    def __repr__(self):
        out = str(self.output) if self.output else '_'
        ins = ', '.join(str(v) for v in self.inputs)
        opname = self.opcode.name
        return f'{opname}({ins}) → {out}'

    @property
    def is_phi(self) -> bool:
        return self.opcode == OpCode.MULTIEQUAL

    @property
    def is_branch(self) -> bool:
        return self.opcode in (OpCode.BRANCH, OpCode.CBRANCH, OpCode.BRANCHIND)

    @property
    def is_call(self) -> bool:
        return self.opcode in (OpCode.CALL, OpCode.CALLIND)

    @property
    def is_return(self) -> bool:
        return self.opcode == OpCode.RETURN

    @property
    def is_load(self) -> bool:
        return self.opcode == OpCode.LOAD

    @property
    def is_store(self) -> bool:
        return self.opcode == OpCode.STORE

    @property
    def is_copy(self) -> bool:
        return self.opcode == OpCode.COPY


# ── Guard utilities ────────────────────────────────────────────────────

def _const_int(vn: Varnode) -> bool:
    return vn.is_constant()

def _int_val(vn: Varnode) -> int:
    assert vn.is_constant()
    return vn.offset

def _make_op(opcode: OpCode, out: Optional[Varnode], *inputs: Varnode,
             addr: int = 0) -> PcodeOp:
    return PcodeOp(opcode, out, list(inputs), addr=addr)


# ── x86→p-code Translator ─────────────────────────────────────────────

_X86_COND_MAP = {
    'je':  OpCode.INT_EQUAL,
    'jne': OpCode.INT_NOTEQUAL,
    'jl':  OpCode.INT_SLESS,
    'jge': OpCode.INT_SLESSEQUAL,  # reversed sense
    'jg':  OpCode.INT_SLESS,       # reversed operands
    'jle': OpCode.INT_SLESSEQUAL,
    'jb':  OpCode.INT_LESS,
    'jae': OpCode.INT_LESSEQUAL,
    'ja':  OpCode.INT_LESS,        # reversed operands
    'jbe': OpCode.INT_LESSEQUAL,
    'js':  OpCode.INT_SLESS,       # sign test
    'jns': OpCode.INT_SLESS,       # not sign test
    'jo':  OpCode.INT_EQUAL,       # overflow
    'jno': OpCode.INT_NOTEQUAL,
}


class Translator:
    """Translates Capstone instructions into p-code PcodeOp sequences.

    Handles x86/x86_64 instruction → p-code mapping by pattern-matching
    mnemonics and operands.  Not exhaustive — focuses on common patterns
    that CTF binaries exhibit.
    """

    def __init__(self):
        # Build mnemonic → opcode mapping
        self._simple_ops: Dict[str, OpCode] = {
            'mov':   OpCode.COPY,
            'movzx': OpCode.INT_ZEXT,
            'movsx': OpCode.INT_SEXT,
            'movsxd': OpCode.INT_SEXT,
            'add':   OpCode.INT_ADD,
            'sub':   OpCode.INT_SUB,
            'inc':   OpCode.INT_ADD,
            'dec':   OpCode.INT_SUB,
            'imul':  OpCode.INT_MULT,
            'mul':   OpCode.INT_MULT,
            'idiv':  OpCode.INT_SDIV,
            'div':   OpCode.INT_DIV,
            'xor':   OpCode.INT_XOR,
            'and':   OpCode.INT_AND,
            'or':    OpCode.INT_OR,
            'not':   OpCode.INT_NEGATE,
            'neg':   OpCode.INT_2COMP,
            'shl':   OpCode.INT_LEFT,
            'shr':   OpCode.INT_RIGHT,
            'sar':   OpCode.INT_SRIGHT,
            'lea':   OpCode.PTRADD,
            'cmp':   OpCode.INT_SUB,  # flags implicit
            'test':  OpCode.INT_AND,  # flags implicit
            'push':  OpCode.STORE,
            'pop':   OpCode.LOAD,
            'ret':   OpCode.RETURN,
            'nop':   OpCode.COPY,
        }
        # Instructions that don't produce output (stores, branches, calls)
        self._no_output = {'push', 'stosb', 'stosd', 'stosq',
                           'repne_scasb', 'rep_stosb', 'ret', 'nop'}
        # Instructions that modify memory (output is implicit via STORE)
        self._mem_ops = {'stosb', 'stosd', 'stosq'}

    def translate(self, capstone_insns: list, loader=None,
                  base_addr: int = 0) -> List[PcodeOp]:
        """Translate a list of Capstone instructions to p-code."""
        pcode_ops = []
        # Pre-pass: map all target addresses from branches for assignment
        targets = self._collect_targets(capstone_insns, base_addr)

        for insn in capstone_insns:
            if hasattr(insn, 'address'):
                addr = insn.address or base_addr
                mnem = insn.mnemonic.lower().replace('.', '_')
                op_str = insn.op_str or ''
            else:
                addr = insn.get('address', base_addr)
                mnem = insn['mnemonic'].lower().replace('.', '_')
                op_str = insn.get('op_str', '')

            ops = self._translate_one(insn, mnem, op_str, addr, targets)
            pcode_ops.extend(ops)

        return pcode_ops

    def _collect_targets(self, insns: list, base_addr: int) -> set:
        """Collect all branch target addresses for block boundary detection."""
        targets = set()
        for insn in insns:
            if hasattr(insn, 'address'):
                addr = insn.address
                mnem = insn.mnemonic.lower()
                op_str = insn.op_str or ''
            else:
                addr = insn.get('address', 0)
                mnem = insn['mnemonic'].lower()
                op_str = insn.get('op_str', '')

            if mnem.startswith('j') and mnem != 'jmp':
                if op_str and op_str.startswith('0x'):
                    try:
                        targets.add(int(op_str, 16))
                    except ValueError:
                        pass
            elif mnem == 'jmp':
                if op_str and op_str.startswith('0x'):
                    try:
                        targets.add(int(op_str, 16))
                    except ValueError:
                        pass
            elif mnem in ('call',):
                if op_str and op_str.startswith('0x'):
                    try:
                        targets.add(int(op_str, 16))
                    except ValueError:
                        pass
        # Next instruction after branch is also a target (fall-through)
        for insn in insns:
            if hasattr(insn, 'address'):
                addr = insn.address
                mnem = insn.mnemonic.lower()
                insn_size = insn.size
            else:
                addr = insn.get('address', 0)
                mnem = insn['mnemonic'].lower()
                insn_size = insn.get('size', 1)
            if mnem in ('jmp', 'ret') or mnem.startswith('j'):
                targets.add(addr + insn_size)
        return targets

    def _translate_one(self, insn: dict, mnem: str, op_str: str,
                       addr: int, targets: set) -> List[PcodeOp]:
        """Translate a single instruction to p-code ops."""
        base_mnem = mnem.replace('.', '_')

        # CALL → CALL/CALLIND + register save/restore (simplified)
        if base_mnem == 'call':
            return self._translate_call(insn, op_str, addr)

        # JUMP → BRANCH/CBRANCH
        if base_mnem == 'jmp':
            return self._translate_jump(insn, op_str, addr, targets)

        # CONDITIONAL JUMPS → CBRANCH
        if base_mnem.startswith('j') and base_mnem in _X86_COND_MAP:
            return self._translate_cond_jump(insn, base_mnem, op_str, addr, targets)

        # RETURN
        if base_mnem == 'ret':
            return [PcodeOp(OpCode.RETURN, addr=addr)]

        # PUSH/POP
        if base_mnem == 'push':
            return self._translate_push(insn, op_str, addr)

        if base_mnem == 'pop':
            return self._translate_pop(insn, op_str, addr)

        # STOS/REP ops (string operations)
        if base_mnem in ('stosb', 'stosd', 'stosq'):
            return self._translate_stos(insn, base_mnem, addr)

        # CMP → INT_SUB with flags output (simplified: no flag tracking)
        if base_mnem == 'cmp':
            return self._translate_cmp(insn, op_str, addr)

        # TEST → INT_AND with flags output
        if base_mnem == 'test':
            return self._translate_test(insn, op_str, addr)

        # LEA → PTRADD
        if base_mnem == 'lea':
            return self._translate_lea(insn, op_str, addr)

        # Simple ALU ops: ADD, SUB, XOR, AND, OR, SHL, SHR, SAR, etc.
        if base_mnem in self._simple_ops:
            return self._translate_alu(insn, base_mnem, op_str, addr, targets)

        # NOP or unknown → skip
        return []

    def _parse_operand(self, op_str: str) -> tuple:
        """Parse a Capstone operand string into (type_str, reg_name, imm_val).

        Returns (kind, detail, size_hint) where kind is one of:
        'reg', 'imm', 'mem', 'unknown'
        """
        op_str = op_str.strip()
        if not op_str:
            return ('unknown', '', 0)

        # Memory reference [base+index*scale+disp]
        if op_str.startswith('['):
            return ('mem', op_str, 8)

        # Immediate (hex or dec) — value at index 1 to match reg name at index 1
        if op_str.startswith('0x') or op_str.startswith('-0x'):
            try:
                return ('imm', int(op_str, 16) if '0x' in op_str else int(op_str), 0)
            except ValueError:
                return ('imm', 0, 0)
        try:
            return ('imm', int(op_str), 0)
        except ValueError:
            pass

        # Register
        return ('reg', op_str.lower(), 0)

    def _parse_mem_ref(self, mem_str: str) -> dict:
        """Parse a memory reference like [rbp-8], [rax+rbx*4+0x10]."""
        import re
        parts = {'base': None, 'index': None, 'scale': 1, 'disp': 0}
        s = mem_str.strip('[]')
        # Match patterns
        m = re.match(
            r'([a-z0-9]+)(?:\s*\+\s*([a-z0-9]+)(?:\s*\*\s*(\d+))?)?'
            r'(?:\s*([+-])\s*(0x[0-9a-fA-F]+|\d+))?$',
            s, re.IGNORECASE)
        if not m:
            return parts
        groups = m.groups()
        parts['base'] = groups[0]
        idx = groups[1]
        if idx:
            parts['index'] = idx
        scale = groups[2]
        if scale:
            parts['scale'] = int(scale)
        sign = groups[3]
        disp = groups[4]
        if disp:
            v = int(disp, 16) if disp.startswith('0x') else int(disp)
            parts['disp'] = -v if sign == '-' else v
        return parts

    def _varnode_for_reg(self, reg_name: str, size: int = 8) -> Varnode:
        """Create a varnode for a register, with standard offset mapping."""
        return Varnode(REGISTER, self._reg_offset(reg_name), size)

    def _reg_offset(self, name: str) -> int:
        """Simple deterministic register offset (mirrors Ghidra register file layout)."""
        # Standard x86_64 register ordering
        REG_MAP = {
            'rax': 0x0000, 'rbx': 0x0008, 'rcx': 0x0010, 'rdx': 0x0018,
            'rsi': 0x0020, 'rdi': 0x0028, 'rbp': 0x0030, 'rsp': 0x0038,
            'r8': 0x0040,  'r9': 0x0048,  'r10': 0x0050, 'r11': 0x0058,
            'r12': 0x0060, 'r13': 0x0068, 'r14': 0x0070, 'r15': 0x0078,
            'rip': 0x0080,
            # 32-bit aliases
            'eax': 0x0000, 'ebx': 0x0008, 'ecx': 0x0010, 'edx': 0x0018,
            'esi': 0x0020, 'edi': 0x0028, 'ebp': 0x0030, 'esp': 0x0038,
            'eip': 0x0080,
            # Flags
            'eflags': 0x0100,
            # Segment registers
            'cs': 0x0200, 'ds': 0x0208, 'es': 0x0210, 'fs': 0x0218,
            'gs': 0x0220, 'ss': 0x0228,
        }
        return REG_MAP.get(name, hash(name) & 0xFFFF)

    def _translate_call(self, insn: dict, op_str: str, addr: int) -> List[PcodeOp]:
        ops = []
        target = self._parse_operand(op_str)
        if target[0] == 'imm':
            # CALL const → direct call (target addr is an attribute, not a varnode input)
            ops.append(PcodeOp(OpCode.CALL, addr=int(op_str, 16) if op_str.startswith('0x') else int(op_str)))
        else:
            # Indirect call: copy target into a temporary then CALLIND
            if target[0] == 'reg':
                target_vn = self._varnode_for_reg(target[1])
            elif target[0] == 'mem':
                target_vn = Varnode(UNIQUE, addr & 0xFFFF, 8)
                # LOAD the address from memory
                ops.append(PcodeOp(OpCode.LOAD, target_vn, [Varnode.const(0), Varnode.const(0)], addr=addr))
            else:
                target_vn = Varnode.const(0, 8)
            ops.append(PcodeOp(OpCode.CALLIND, None, [target_vn], addr=addr))
        # RAX return register is implicit in calling convention
        return ops

    def _translate_jump(self, insn: dict, op_str: str, addr: int,
                        targets: set) -> List[PcodeOp]:
        target = self._parse_operand(op_str)
        if target[0] == 'imm':
            target_addr = int(op_str, 16) if op_str.startswith('0x') else int(op_str)
            ops = [PcodeOp(OpCode.BRANCH, addr=target_addr)]
        elif target[0] == 'reg':
            ops = [PcodeOp(OpCode.BRANCHIND, None, [self._varnode_for_reg(target[1])], addr=addr)]
        elif target[0] == 'mem':
            ops = [PcodeOp(OpCode.BRANCHIND, None, [Varnode.const(0, 8)], addr=addr)]
        else:
            ops = [PcodeOp(OpCode.BRANCH, addr=addr)]
        return ops

    def _translate_cond_jump(self, insn: dict, mnem: str, op_str: str,
                              addr: int, targets: set) -> List[PcodeOp]:
        ops = []
        # CBRANCH takes (condition, target_addr) as inputs
        target_addr = int(op_str, 16) if op_str.startswith('0x') else int(op_str)
        # TODO: derive the real condition from an eflags varnode (as Ghidra does)
        # and select the comparison opcode via _X86_COND_MAP[mnem].
        cond_vn = Varnode.const(1, 8)  # placeholder condition
        # Emit the CBRANCH with target address constant as input
        ops.append(PcodeOp(OpCode.CBRANCH, None, [cond_vn, Varnode.const(target_addr, 8)], addr=addr))
        return ops

    def _translate_push(self, insn: dict, op_str: str, addr: int) -> List[PcodeOp]:
        ops = []
        rsp_vn = self._varnode_for_reg('rsp')
        new_rsp = Varnode(UNIQUE, addr & 0xFFFF, 8)
        # rsp -= 8
        ops.append(PcodeOp(OpCode.INT_SUB, new_rsp, [rsp_vn, Varnode.const(8)], addr=addr))
        # Parse the value being pushed
        val_op = self._parse_operand(op_str)
        if val_op[0] == 'reg':
            val_vn = self._varnode_for_reg(val_op[1])
        elif val_op[0] == 'imm':
            val_vn = Varnode.const(val_op[1], 8)
        else:
            val_vn = Varnode.const(0, 8)
        # STORE space=const(0), addr=new_rsp, val=val_vn
        ops.append(PcodeOp(OpCode.STORE, None, [Varnode.const(0), new_rsp, val_vn], addr=addr))
        # Write back new rsp
        ops.append(PcodeOp(OpCode.COPY, rsp_vn, [new_rsp], addr=addr))
        return ops

    def _translate_pop(self, insn: dict, op_str: str, addr: int) -> List[PcodeOp]:
        ops = []
        rsp_vn = self._varnode_for_reg('rsp')
        loaded = Varnode(UNIQUE, addr & 0xFFFF, 8)
        # loaded = LOAD(0, rsp)
        ops.append(PcodeOp(OpCode.LOAD, loaded, [Varnode.const(0), rsp_vn], addr=addr))
        # Parse destination register
        val_op = self._parse_operand(op_str)
        if val_op[0] == 'reg':
            dst_vn = self._varnode_for_reg(val_op[1])
            ops.append(PcodeOp(OpCode.COPY, dst_vn, [loaded], addr=addr))
        # rsp += 8
        new_rsp = Varnode(UNIQUE, (addr & 0xFFFF) + 100, 8)
        ops.append(PcodeOp(OpCode.INT_ADD, new_rsp, [rsp_vn, Varnode.const(8)], addr=addr))
        ops.append(PcodeOp(OpCode.COPY, rsp_vn, [new_rsp], addr=addr))
        return ops

    def _translate_stos(self, insn: dict, mnem: str, addr: int) -> List[PcodeOp]:
        ops = []
        step = 1 if 'b' in mnem else (4 if 'd' in mnem else 8)
        rdi_vn = self._varnode_for_reg('rdi')
        # STORE [rdi] = rax/al
        ax_reg = 'rax' if step == 8 else ('eax' if step == 4 else 'al')
        ax_vn = self._varnode_for_reg(ax_reg)
        ops.append(PcodeOp(OpCode.STORE, None, [Varnode.const(0), rdi_vn, ax_vn], addr=addr))
        # rdi += step
        new_rdi = Varnode(UNIQUE, addr & 0xFFFF, 8)
        ops.append(PcodeOp(OpCode.INT_ADD, new_rdi, [rdi_vn, Varnode.const(step)], addr=addr))
        ops.append(PcodeOp(OpCode.COPY, rdi_vn, [new_rdi], addr=addr))
        return ops

    def _translate_cmp(self, insn: dict, op_str: str, addr: int) -> List[PcodeOp]:
        parts = op_str.split(',', 1)
        if len(parts) == 2:
            src_op = self._parse_operand(parts[0].strip())
            dst_op = self._parse_operand(parts[1].strip())
            if src_op[0] == 'reg' and dst_op[0] == 'reg':
                return [PcodeOp(OpCode.INT_SUB, Varnode(UNIQUE, addr & 0xFFFF, 4),
                               [self._varnode_for_reg(src_op[1]),
                                self._varnode_for_reg(dst_op[1])], addr=addr)]
            if src_op[0] == 'reg' and dst_op[0] == 'imm':
                return [PcodeOp(OpCode.INT_SUB, Varnode(UNIQUE, addr & 0xFFFF, 4),
                               [self._varnode_for_reg(src_op[1]),
                                Varnode.const(dst_op[1])], addr=addr)]
            if src_op[0] == 'imm' and dst_op[0] == 'reg':
                return [PcodeOp(OpCode.INT_SUB, Varnode(UNIQUE, addr & 0xFFFF, 4),
                               [Varnode.const(src_op[1]),
                                self._varnode_for_reg(dst_op[1])], addr=addr)]
        return [PcodeOp(OpCode.INT_SUB, addr=addr)]

    def _translate_test(self, insn: dict, op_str: str, addr: int) -> List[PcodeOp]:
        parts = op_str.split(',', 1)
        if len(parts) == 2:
            src_op = self._parse_operand(parts[0].strip())
            dst_op = self._parse_operand(parts[1].strip())
            if src_op[0] == 'reg' and dst_op[0] == 'reg':
                return [PcodeOp(OpCode.INT_AND, Varnode(UNIQUE, addr & 0xFFFF, 4),
                               [self._varnode_for_reg(src_op[1]),
                                self._varnode_for_reg(dst_op[1])], addr=addr)]
            if src_op[0] == 'reg' and dst_op[0] == 'imm':
                return [PcodeOp(OpCode.INT_AND, Varnode(UNIQUE, addr & 0xFFFF, 4),
                               [self._varnode_for_reg(src_op[1]),
                                Varnode.const(dst_op[1])], addr=addr)]
        return [PcodeOp(OpCode.INT_AND, addr=addr)]

    def _translate_lea(self, insn: dict, op_str: str, addr: int) -> List[PcodeOp]:
        # LEA dest, [base+index*scale+disp] → PTRADD base, index, scale
        # Or simpler: COPY-like address calculation
        parts = op_str.split(',', 1)
        if len(parts) == 2:
            dest_reg = parts[0].strip()
            src_mem = parts[1].strip()
            mem_info = self._parse_mem_ref(src_mem)
            if mem_info['base']:
                out = self._varnode_for_reg(dest_reg)
                base_vn = self._varnode_for_reg(mem_info['base'])
                if mem_info['index']:
                    idx_vn = self._varnode_for_reg(mem_info['index'])
                    ops = [PcodeOp(OpCode.PTRADD, out, [base_vn, idx_vn,
                                   Varnode.const(mem_info['scale'])], addr=addr)]
                else:
                    # Simple: LEA dest, [base+disp]
                    ops = self._make_copy_with_offset(out, base_vn,
                                                     mem_info['disp'], addr)
                return ops
        return []

    def _make_copy_with_offset(self, dest: Varnode, base: Varnode,
                                offset: int, addr) -> List[PcodeOp]:
        """Create COPY or INT_ADD to implement LEA effectively."""
        if offset == 0:
            return [PcodeOp(OpCode.COPY, dest, [base], addr=addr)]
        const_vn = Varnode.const(offset)
        return [PcodeOp(OpCode.INT_ADD, dest, [base, const_vn], addr=addr)]

    def _translate_alu(self, insn: dict, mnem: str, op_str: str,
                       addr: int, targets: set) -> List[PcodeOp]:
        """Translate ALU operations (ADD, SUB, XOR, etc)."""
        opcode = self._simple_ops.get(mnem)
        if opcode is None:
            return []

        # Intel syntax: opcode dest, src
        # So dest = dest op src  (or in AT&T which capstone defaults: opcode src, dest)
        parts = op_str.split(',', 1)
        if len(parts) < 2:
            # Single-operand (inc, dec, not, neg)
            if len(parts) == 1 and parts[0]:
                op = self._parse_operand(parts[0])
                if op[0] == 'reg':
                    reg_vn = self._varnode_for_reg(op[1])
                    if mnem in ('inc',):
                        ops = [PcodeOp(OpCode.INT_ADD, reg_vn,
                                       [reg_vn, Varnode.const(1)], addr=addr)]
                        return ops
                    elif mnem in ('dec',):
                        ops = [PcodeOp(OpCode.INT_SUB, reg_vn,
                                       [reg_vn, Varnode.const(1)], addr=addr)]
                        return ops
                    elif mnem in ('not',):
                        return [PcodeOp(OpCode.INT_NEGATE, reg_vn,
                                       [reg_vn], addr=addr)]
                    elif mnem in ('neg',):
                        return [PcodeOp(OpCode.INT_2COMP, reg_vn,
                                       [reg_vn], addr=addr)]
            return []  # Can't translate — skip

        src_str = parts[0].strip()
        dst_str = parts[1].strip()
        # Capstone defaults to Intel syntax: opcode dest, src
        # Actually, let's assume: opcode src, dest (AT&T) since that's more common
        # For Intel: opcode dest, src
        # Let's detect: the second operand that's a register is likely dest
        src_op = self._parse_operand(src_str)
        dst_op = self._parse_operand(dst_str)

        # Determine direction (Intel: dest, src)
        # We'll parse as Intel: first is dest, second is src
        dest = src_op
        src = dst_op

        ops = []

        # Skip NOP-like ops
        if mnem == 'nop':
            return ops

        # MOV/COPY
        if mnem == 'mov':
            if dest[0] == 'reg':
                dst_vn = self._varnode_for_reg(dest[1])
                if src[0] == 'reg':
                    src_vn = self._varnode_for_reg(src[1])
                    ops.append(PcodeOp(OpCode.COPY, dst_vn, [src_vn], addr=addr))
                elif src[0] == 'imm':
                    ops.append(PcodeOp(OpCode.COPY, dst_vn,
                                     [Varnode.const(src[1])], addr=addr))
                elif src[0] == 'mem':
                    mem_info = self._parse_mem_ref(src[1])
                    # LOAD from memory
                    if mem_info['base']:
                        base_vn = self._varnode_for_reg(mem_info['base'])
                        addr_vn = base_vn
                        if mem_info['disp']:
                            # base + disp
                            addr_vn = Varnode(UNIQUE, (addr & 0xFFFF) + 1000, 8)
                            ops.append(PcodeOp(OpCode.INT_ADD, addr_vn,
                                             [base_vn, Varnode.const(mem_info['disp'])],
                                             addr=addr))
                        ops.append(PcodeOp(OpCode.LOAD, dst_vn,
                                         [Varnode.const(0), addr_vn], addr=addr))
                    else:
                        ops.append(PcodeOp(OpCode.LOAD, dst_vn,
                                         [Varnode.const(0), Varnode.const(0)],
                                         addr=addr))
            elif dest[0] == 'mem':
                # MOV [addr], reg → STORE
                src_vn = Varnode.const(0)
                if src[0] == 'reg':
                    src_vn = self._varnode_for_reg(src[1])
                mem_info = self._parse_mem_ref(dest[1])
                if mem_info['base']:
                    base_vn = self._varnode_for_reg(mem_info['base'])
                    addr_vn = base_vn
                    if mem_info['disp']:
                        addr_vn = Varnode(UNIQUE, (addr & 0xFFFF) + 2000, 8)
                        ops.append(PcodeOp(OpCode.INT_ADD, addr_vn,
                                         [base_vn, Varnode.const(mem_info['disp'])],
                                         addr=addr))
                    ops.append(PcodeOp(OpCode.STORE, None,
                                     [Varnode.const(0), addr_vn, src_vn],
                                     addr=addr))
                else:
                    ops.append(PcodeOp(OpCode.STORE, None,
                                     [Varnode.const(0), Varnode.const(0), src_vn],
                                     addr=addr))
            return ops

        # ALU with 2 operands: dest op= src
        if dest[0] == 'reg' and src[0] == 'reg':
            dst_vn = self._varnode_for_reg(dest[1])
            src_vn = self._varnode_for_reg(src[1])
            ops.append(PcodeOp(opcode, dst_vn, [dst_vn, src_vn], addr=addr))

        elif dest[0] == 'reg' and src[0] == 'imm':
            dst_vn = self._varnode_for_reg(dest[1])
            const_vn = Varnode.const(src[1])
            ops.append(PcodeOp(opcode, dst_vn, [dst_vn, const_vn], addr=addr))

        elif dest[0] == 'reg' and src[0] == 'mem':
            dst_vn = self._varnode_for_reg(dest[1])
            mem_info = self._parse_mem_ref(src[1])
            if mem_info.get('base'):
                base_vn = self._varnode_for_reg(mem_info['base'])
                addr_vn = base_vn
                if mem_info.get('disp'):
                    addr_vn = Varnode(UNIQUE, (addr & 0xFFFF) + 3000, 8)
                    ops.append(PcodeOp(OpCode.INT_ADD, addr_vn,
                                     [base_vn, Varnode.const(mem_info['disp'])],
                                     addr=addr))
                loaded = Varnode(UNIQUE, (addr & 0xFFFF) + 4000, 8)
                ops.append(PcodeOp(OpCode.LOAD, loaded,
                                 [Varnode.const(0), addr_vn], addr=addr))
                ops.append(PcodeOp(opcode, dst_vn, [dst_vn, loaded], addr=addr))

        return ops
