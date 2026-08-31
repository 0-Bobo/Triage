"""C Code Generator — emits structured C from p-code SSA form.

Inspired by Ghidra's PrintC (printc.hh) and PrettyPrint (prettyprint.hh) systems.

Pipeline:
  1. Group p-code ops by structured block regions
  2. Convert each op to C expression/statement
  3. Combine with proper indentation and braces

Handles:
  - Variable declarations (from type inference)
  - Assignment statements
  - Function calls
  - Pointer arithmetic (→ array subscript, field access)
  - Control flow (if/else, while, for, switch, goto)
"""

from __future__ import annotations

from .cfg import BasicBlock, BlockType
from .pcode import OpCode, PcodeOp, Varnode
from .ssa_engine import SSAContext


class CCodeGenerator:
    """Emits C source code from an SSA context.

    Usage:
        gen = CCodeGenerator(ctx)
        code = gen.emit()
    """

    # C operator precedence (lower number = binds tighter).
    # Prefix/unary operators ('*', '&', '-', '+') share spellings with binary
    # operators but bind differently, so they live in a separate table.
    UNARY_PREC = {
        "!": 2,
        "~": 2,
        "++": 2,
        "--": 2,
        "*": 2,
        "&": 2,
        "-": 2,
        "+": 2,
    }
    PREC = {
        "[]": 1,
        "()": 1,
        "->": 1,
        ".": 1,
        "*": 3,
        "/": 3,
        "%": 3,
        "+": 4,
        "-": 4,
        "<<": 5,
        ">>": 5,
        "<": 6,
        "<=": 6,
        ">": 6,
        ">=": 6,
        "==": 7,
        "!=": 7,
        "&": 8,
        "^": 9,
        "|": 10,
        "&&": 11,
        "||": 12,
        "=": 13,
        ",": 14,
    }

    def __init__(self, ctx: SSAContext):
        self.ctx = ctx
        self.variable_names: dict[str, str] = {}  # varname → C variable name
        self.declared_vars: set[str] = set()
        self.next_var_id: int = 0
        self.indent = 0
        self.lines: list[str] = []
        self.use_labels = False  # Set True if gotos remain

    def emit(self) -> str:
        """Emit full C function body."""
        self.lines = []
        self._emit_block_graph(self.ctx.graph.entry)
        return "\n".join(self.lines)

    def _emit_block_graph(self, block: BasicBlock | None, visited: set | None = None):
        """Recursively emit a block graph."""
        if visited is None:
            visited = set()
        if block is None or block in visited:
            return
        visited.add(block)

        # Structured blocks
        if block.block_type == BlockType.CONDITION:
            self._emit_condition(block, visited)
        elif block.block_type == BlockType.WHILE:
            self._emit_while(block, visited)
        elif block.block_type == BlockType.IF:
            self._emit_if(block, visited)
        elif block.block_type == BlockType.SWITCH:
            self._emit_switch(block, visited)
        else:
            self._emit_plain(block, visited)

    def _emit_plain(self, block: BasicBlock, visited: set):
        """Emit a plain (straight-line) block."""
        for op in block.ops:
            line = self._emit_op(op)
            if line:
                self._writeln(line)

        # Fall through to next block
        if (block.succs and not block.last_op) or not block.last_op.is_branch:
            for s in block.succs:
                self._emit_block_graph(s, visited)
        elif block.succs and block.last_op.opcode == OpCode.BRANCH:
            # Unconditional branch (goto if not last block)
            if block.succs[0] not in visited:
                label = self._block_label(block.succs[0])
                self._writeln(f"goto {label};")

    def _emit_condition(self, block: BasicBlock, visited: set):
        """Emit if/else from a conditional branch block."""
        if len(block.succs) < 2:
            self._emit_plain(block, visited)
            return

        true_block = block.succs[0]
        false_block = block.succs[1]

        # Find merge point (common successor of both branches)
        t_succs = set(true_block.succs)
        f_succs = set(false_block.succs)
        merge_blocks = t_succs & f_succs
        merge = next(iter(merge_blocks)) if merge_blocks else None

        # Build condition from the CBRANCH op
        condition = self._build_condition(block)

        self._writeln(f"if ({condition}) {{")
        self.indent += 1
        # Only emit true_block if it doesn't goto the merge point
        if true_block.succs != [merge] or len(true_block.ops) > 0:
            self._emit_block_graph(true_block, visited.copy())
        self.indent -= 1
        self._writeln("}")

        # Check if false_block has real content
        if false_block and (len(false_block.ops) > 0 or set(false_block.succs) != {merge}):
            self._writeln("else {")
            self.indent += 1
            self._emit_block_graph(false_block, visited.copy())
            self.indent -= 1
            self._writeln("}")

        # Continue at merge point
        if merge and merge not in visited:
            self._emit_block_graph(merge, visited)

    def _emit_while(self, block: BasicBlock, visited: set):
        """Emit while loop."""
        condition = self._build_condition(block) or "1"
        self._writeln(f"while ({condition}) {{")
        self.indent += 1

        # Emit loop body (successor in the loop)
        body_exit = block.succs[0] if block.succs else None
        if body_exit:
            self._emit_block_graph(body_exit, visited)

        self.indent -= 1
        self._writeln("}")

        # Emit exit successor
        if len(block.succs) > 1:
            self._emit_block_graph(block.succs[1], visited)

    def _emit_if(self, block: BasicBlock, visited: set):
        """Emit if (no else) block."""
        self._emit_condition(block, visited)

    def _emit_switch(self, block: BasicBlock, visited: set):
        """Emit switch/case block."""
        # Find the switch variable from prior analysis
        switch_var = "unknown"
        self._writeln(f"switch ({switch_var}) {{")
        self.indent += 1
        for case_val, target in block.switch_cases.items():
            self._writeln(f"case {case_val}:")
            self.indent += 1
            self._emit_block_graph(target, visited)
            self._writeln("break;")
            self.indent -= 1
        self.indent -= 1
        self._writeln("}")

    def _build_condition(self, block: BasicBlock) -> str:
        """Extract condition expression from CBRANCH ops in block."""
        for op in block.ops:
            if op.opcode == OpCode.CBRANCH and op.inputs:
                return self._varnode_expr(op.inputs[0])
        return "1"

    def _emit_op(self, op: PcodeOp) -> str:
        """Emit a single p-code op as a C statement or expression."""
        if op.is_phi:
            return ""  # φ-nodes are not emitted

        if op.is_call:
            return self._emit_call(op)

        if op.is_return:
            return self._emit_return(op)

        if op.is_store:
            return self._emit_store(op)

        if op.is_load and op.output:
            return self._declare_and_assign(op)

        if op.is_copy and op.output:
            return self._emit_copy(op)

        if op.opcode in (
            OpCode.INT_ADD,
            OpCode.INT_SUB,
            OpCode.INT_MULT,
            OpCode.INT_AND,
            OpCode.INT_OR,
            OpCode.INT_XOR,
            OpCode.INT_LEFT,
            OpCode.INT_RIGHT,
            OpCode.INT_SRIGHT,
        ):
            return self._emit_arith(op)

        if op.opcode in (OpCode.INT_NEGATE, OpCode.INT_2COMP):
            return self._emit_unary(op)

        if op.opcode in (OpCode.INT_ZEXT, OpCode.INT_SEXT):
            return self._emit_extend(op)

        if op.opcode == OpCode.PTRADD and op.output:
            return self._declare_and_assign(op)

        if op.opcode == OpCode.PTRSUB and op.output:
            return self._declare_and_assign(op)

        if not op.output and op.opcode in (OpCode.INT_SUB, OpCode.INT_AND):
            # Flag-setting ops (CMP, TEST) — typically don't emit directly
            return ""

        if op.output:
            return self._declare_and_assign(op)

        return ""

    def _emit_call(self, op: PcodeOp) -> str:
        """Emit a CALL/CALLIND op as a function call statement."""
        parts = [f"sub_{op.addr:x}"] if op.opcode == OpCode.CALL else ["(*indirect_call)"]
        args = []
        for inp in op.inputs:
            args.append(self._varnode_expr(inp))
        call_str = f"{parts[0]}({', '.join(args)})"
        if op.output:
            return self._declare_var(op.output) + " = " + call_str + ";"
        return call_str + ";"

    def _emit_return(self, op: PcodeOp) -> str:
        """Emit RETURN op as return statement."""
        if op.inputs:
            return f"return {self._varnode_expr(op.inputs[0])};"
        return "return;"

    def _emit_store(self, op: PcodeOp) -> str:
        """Emit STORE op as memory write."""
        if len(op.inputs) >= 3:
            ptr = self._varnode_expr(op.inputs[1])
            val = self._varnode_expr(op.inputs[2])
            return f"*({ptr}) = {val};"
        return ""

    def _emit_copy(self, op: PcodeOp) -> str:
        """Emit COPY op as assignment (with optional declaration)."""
        dst = self._var_name(op.output)
        src = self._varnode_expr(op.inputs[0])

        # First def → declare the variable
        if dst not in self.declared_vars:
            self.declared_vars.add(dst)
            type_str = self._var_type(op.output, op.inputs[0])
            return f"{type_str} {dst} = {src};"
        return f"{dst} = {src};"

    def _emit_arith(self, op: PcodeOp) -> str:
        """Emit arithmetic op as assignment."""
        dst = self._var_name(op.output)
        op_sym = self._op_symbol(op.opcode)

        lhs = self._varnode_expr(op.inputs[0])
        rhs = self._varnode_expr(op.inputs[1])
        expr = f"{lhs} {op_sym} {rhs}"

        if dst not in self.declared_vars:
            self.declared_vars.add(dst)
            return f"{self._var_type(op.output)} {dst} = {expr};"
        return f"{dst} = {expr};"

    def _emit_unary(self, op: PcodeOp) -> str:
        """Emit unary op (NOT, NEG)."""
        dst = self._var_name(op.output)
        op_sym = "~" if op.opcode == OpCode.INT_NEGATE else "-"
        val = self._varnode_expr(op.inputs[0])
        expr = f"{op_sym}{val}"

        if dst not in self.declared_vars:
            self.declared_vars.add(dst)
            return f"{self._var_type(op.output)} {dst} = {expr};"
        return f"{dst} = {expr};"

    def _emit_extend(self, op: PcodeOp) -> str:
        """Emit ZEXT/SEXT as cast expression."""
        dst = self._var_name(op.output)
        val = self._varnode_expr(op.inputs[0])
        cast = "(unsigned long long)" if op.opcode == OpCode.INT_ZEXT else "(long long)"
        expr = f"{cast}({val})"

        if dst not in self.declared_vars:
            self.declared_vars.add(dst)
            return f"{self._var_type(op.output)} {dst} = {expr};"
        return f"{dst} = {expr};"

    def _declare_and_assign(self, op: PcodeOp) -> str:
        """Emit declaration + assignment for an op."""
        dst = self._var_name(op.output)
        expr = self._op_expr(op)

        if dst not in self.declared_vars:
            self.declared_vars.add(dst)
            return f"{self._var_type(op.output)} {dst} = {expr};"
        return f"{dst} = {expr};"

    def _op_expr(self, op: PcodeOp) -> str:
        """Get C expression for a p-code op's result."""
        if op.is_copy or op.opcode == OpCode.LOAD:
            return self._varnode_expr(op.inputs[0]) if op.inputs else "0"

        if op.opcode == OpCode.PTRADD and len(op.inputs) >= 3:
            base = self._varnode_expr(op.inputs[0])
            idx = self._varnode_expr(op.inputs[1])
            scale = op.inputs[2].offset if op.inputs[2].is_constant() else 1
            if scale == 1:
                return f"{base}[{idx}]"
            return f"{base}[{idx} * {scale}]"

        if op.opcode == OpCode.PTRSUB and len(op.inputs) >= 2:
            base = self._varnode_expr(op.inputs[0])
            offset = self._varnode_expr(op.inputs[1])
            return f"({base} + {offset})"

        sym = self._op_symbol(op.opcode)
        if sym and len(op.inputs) >= 2:
            lhs = self._varnode_expr(op.inputs[0])
            rhs = self._varnode_expr(op.inputs[1])
            return f"({lhs} {sym} {rhs})"

        return "0"

    def _varnode_expr(self, vn: Varnode | None) -> str:
        """Convert a varnode to a C expression string."""
        if vn is None:
            return "0"
        if vn.is_constant():
            val = vn.offset
            if val < 0:
                return f"({val})"
            if val > 9999:
                return hex(val)
            return str(val)
        if vn.is_register():
            return self._register_name(vn.offset, vn.size)
        if vn.is_unique():
            return self._var_name(vn)
        if vn.is_memory():
            return self._var_name(vn)
        return "unknown"

    def _register_name(self, offset: int, size: int) -> str:
        """Map register offset back to register name."""
        rev_map = {
            0x0000: "rax",
            0x0008: "rbx",
            0x0010: "rcx",
            0x0018: "rdx",
            0x0020: "rsi",
            0x0028: "rdi",
            0x0030: "rbp",
            0x0038: "rsp",
            0x0040: "r8",
            0x0048: "r9",
            0x0050: "r10",
            0x0058: "r11",
            0x0060: "r12",
            0x0068: "r13",
            0x0070: "r14",
            0x0078: "r15",
            0x0080: "rip",
        }
        name = rev_map.get(offset, f"reg_{offset:x}")
        if size < 8:
            return f"({name} & {'0x' + 'f' * (size * 2)})"
        return name

    def _var_name(self, vn: Varnode | None) -> str:
        """Get or create a C variable name for a varnode."""
        if vn is None:
            return "void"
        key = _varnode_key(vn)
        if key in self.variable_names:
            return self.variable_names[key]

        # Assign a new name
        if vn.is_register():
            return self._register_name(vn.offset, vn.size)

        if vn.is_unique():
            # Temporary variable
            name = f"tmp_{self.next_var_id}"
            self.next_var_id += 1
        elif vn.is_memory():
            name = f"mem_{vn.offset:x}"
        else:
            name = f"v_{self.next_var_id}"
            self.next_var_id += 1

        self.variable_names[key] = name
        return name

    def _var_type(self, out: Varnode, inp: Varnode | None = None) -> str:
        """Get C type string for a varnode."""
        size = out.size
        if size == 1:
            return "char"
        elif size == 2:
            return "short"
        elif size == 4:
            return "int"
        elif size == 8:
            # Check if it looks like a pointer
            return "long"
        return f"int{size * 8}_t"

    def _op_symbol(self, opcode: OpCode) -> str:
        """Map p-code opcodes to C operator symbols."""
        return {
            OpCode.INT_ADD: "+",
            OpCode.INT_SUB: "-",
            OpCode.INT_MULT: "*",
            OpCode.INT_AND: "&",
            OpCode.INT_OR: "|",
            OpCode.INT_XOR: "^",
            OpCode.INT_LEFT: "<<",
            OpCode.INT_RIGHT: ">>",
            OpCode.INT_SRIGHT: ">>",
            OpCode.INT_EQUAL: "==",
            OpCode.INT_NOTEQUAL: "!=",
            OpCode.INT_LESS: "<",
            OpCode.INT_LESSEQUAL: "<=",
            OpCode.INT_SLESS: "<",
            OpCode.INT_SLESSEQUAL: "<=",
            OpCode.BOOL_AND: "&&",
            OpCode.BOOL_OR: "||",
            OpCode.BOOL_NEGATE: "!",
            OpCode.BOOL_XOR: "^^",
        }.get(opcode, "")

    def _block_label(self, block: BasicBlock) -> str:
        return f"LABEL_{block.name}"

    def _writeln(self, s: str = ""):
        indent = "  " * self.indent
        self.lines.append(indent + s)

    def _declare_var(self, vn: Varnode | None) -> str:
        """Declare a variable if not yet declared, return its name."""
        if vn is None:
            return "void"
        name = self._var_name(vn)
        if name not in self.declared_vars:
            self.declared_vars.add(name)
            type_str = self._var_type(vn)
            self._writeln(f"{type_str} {name};")
        return name


def _varnode_key(vn: Varnode | None) -> str:
    """Get canonical key for a varnode. Returns empty string for None."""
    if vn is None:
        return ""
    return f"{vn.space.name}:{vn.offset:x}:{vn.size}:{vn.version}"
