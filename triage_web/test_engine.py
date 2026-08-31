"""Regression tests for engine.py decompiler.
Locks current behavior before modular refactoring."""
import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from engine import Disassembler, Expr

# ── 64-bit Register ABI (real binary test) ──
BINARY_64_CODE = bytes.fromhex(
    "f30f1efa554889e54883ec10bf18000000e8f1feffff488945f8"
    "488b45f8ba18000000be000000004889c7e8c7feffff488b45f8"
    "48b9464c41472d39303448890866c740083200488b45f84889c7"
    "e894feffff488b45f84889c7e878feffffb800000000c9c3"
)
BINARY_64_CALLS = {
    0x1090: 'puts@GLIBC_2.2.5',
    0x10a0: 'memset@GLIBC_2.2.5',
    0x10b0: 'malloc@GLIBC_2.2.5',
    0x1080: 'free@GLIBC_2.2.5',
}

# ── 32-bit Stack-based (mock CTF challenge) ──
STACK_ANALYSIS = {
    'address': 0x80484ad, 'size': 200,
    'insns': [
        {'address': 0x80484ad, 'mnemonic': 'push', 'op_str': 'rbp'},
        {'address': 0x80484ae, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
        {'address': 0x80484b1, 'mnemonic': 'push', 'op_str': 'rdi'},
        {'address': 0x80484b2, 'mnemonic': 'and', 'op_str': 'rsp, 0xfffffff0'},
        {'address': 0x80484b5, 'mnemonic': 'sub', 'op_str': 'rsp, 0x30'},
        {'address': 0x80484b9, 'mnemonic': 'mov', 'op_str': 'dword ptr [rsp + 0x2c], 0'},
        {'address': 0x80484c1, 'mnemonic': 'mov', 'op_str': 'dword ptr [rsp], 0x18'},
        {'address': 0x80484c8, 'mnemonic': 'call', 'op_str': '0x8048330'},
        {'address': 0x80484cd, 'mnemonic': 'mov', 'op_str': 'dword ptr [rsp + 0x2c], eax'},
        {'address': 0x80484d1, 'mnemonic': 'mov', 'op_str': 'dword ptr [rsp + 8], 0x18'},
        {'address': 0x80484d9, 'mnemonic': 'mov', 'op_str': 'dword ptr [rsp + 4], 0'},
        {'address': 0x80484e1, 'mnemonic': 'mov', 'op_str': 'eax, dword ptr [rsp + 0x2c]'},
        {'address': 0x80484e5, 'mnemonic': 'mov', 'op_str': 'dword ptr [rsp], eax'},
        {'address': 0x80484e8, 'mnemonic': 'call', 'op_str': '0x8048370'},
        {'address': 0x80484ed, 'mnemonic': 'mov', 'op_str': 'eax, dword ptr [rsp + 0x2c]'},
        {'address': 0x80484f1, 'mnemonic': 'mov', 'op_str': 'dword ptr [rsp], eax'},
        {'address': 0x80484f4, 'mnemonic': 'mov', 'op_str': 'dword ptr [rsp + 4], 0x80485f8'},
        {'address': 0x80484fc, 'mnemonic': 'call', 'op_str': '0x8048340'},
        {'address': 0x8048501, 'mnemonic': 'mov', 'op_str': 'eax, dword ptr [rsp + 0x2c]'},
        {'address': 0x8048505, 'mnemonic': 'mov', 'op_str': 'dword ptr [rsp], eax'},
        {'address': 0x8048508, 'mnemonic': 'mov', 'op_str': 'dword ptr [rsp + 4], 0x8048608'},
        {'address': 0x8048510, 'mnemonic': 'call', 'op_str': '0x8048340'},
        {'address': 0x8048515, 'mnemonic': 'mov', 'op_str': 'eax, 0'},
        {'address': 0x804851a, 'mnemonic': 'leave', 'op_str': ''},
        {'address': 0x804851b, 'mnemonic': 'ret', 'op_str': ''},
    ],
    'stack_frame': 0x30,
    'stack_vars': [
        {'offset': 44, 'name': 'local_2c', 'suggested': 'heap_ptr',
         'used_by_funcs': ['malloc@GLIBC_2.0', 'memset@GLIBC_2.0',
                           'puts@GLIBC_2.0'], 'accesses': []},
    ],
    'calls': [
        {'from': 0x80484c8, 'to': 0x8048330, 'name': 'malloc@GLIBC_2.0', 'type': 'call'},
        {'from': 0x80484e8, 'to': 0x8048370, 'name': 'memset@GLIBC_2.0', 'type': 'call'},
        {'from': 0x80484fc, 'to': 0x8048340, 'name': 'puts@GLIBC_2.0', 'type': 'call'},
        {'from': 0x8048510, 'to': 0x8048340, 'name': 'puts@GLIBC_2.0', 'type': 'call'},
    ],
    'prologue': 0x80484ad, 'epilogue': 0x804851b,
    'basic_blocks': [[0x80484ad, 0x804851b]],
}
STACK_CALLS = {
    0x8048330: 'malloc@GLIBC_2.0', 0x8048370: 'memset@GLIBC_2.0',
    0x8048340: 'puts@GLIBC_2.0',
}

# ── strlen idiom test ──
STRLEN_ANALYSIS = {
    'address': 0x8048500, 'size': 50,
    'insns': [
        {'address': 0x8048500, 'mnemonic': 'push', 'op_str': 'rbp'},
        {'address': 0x8048501, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
        {'address': 0x8048504, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
        {'address': 0x8048508, 'mnemonic': 'xor', 'op_str': 'eax, eax'},
        {'address': 0x804850a, 'mnemonic': 'mov', 'op_str': 'ecx, 0xffffffff'},
        {'address': 0x8048510, 'mnemonic': 'repne', 'op_str': 'scasb byte ptr [rdi]'},
        {'address': 0x8048512, 'mnemonic': 'not', 'op_str': 'ecx'},
        {'address': 0x8048514, 'mnemonic': 'dec', 'op_str': 'ecx'},
        {'address': 0x8048516, 'mnemonic': 'mov', 'op_str': 'eax, ecx'},
        {'address': 0x8048518, 'mnemonic': 'mov', 'op_str': 'eax, 0'},
        {'address': 0x804851d, 'mnemonic': 'leave', 'op_str': ''},
        {'address': 0x804851e, 'mnemonic': 'ret', 'op_str': ''},
    ],
    'stack_frame': 0x10, 'stack_vars': [],
    'calls': [],
    'prologue': 0x8048500, 'epilogue': 0x804851e,
    'basic_blocks': [[0x8048500, 0x804851e]],
}

# ── Function boundary test ──
BOUNDARY_ANALYSIS = {
    'address': 0x80484ad, 'size': 60,
    'insns': [
        {'address': 0x80484ad, 'mnemonic': 'push', 'op_str': 'rbp'},
        {'address': 0x80484ae, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
        {'address': 0x80484b1, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
        {'address': 0x80484b5, 'mnemonic': 'mov', 'op_str': 'dword ptr [rsp], 0x18'},
        {'address': 0x80484bc, 'mnemonic': 'call', 'op_str': '0x8048330'},
        {'address': 0x80484c1, 'mnemonic': 'mov', 'op_str': 'eax, 0'},
        {'address': 0x80484c6, 'mnemonic': 'leave', 'op_str': ''},
        {'address': 0x80484c7, 'mnemonic': 'ret', 'op_str': ''},
        # Adjacent function — should NOT appear
        {'address': 0x80484c8, 'mnemonic': 'push', 'op_str': 'rbp'},
        {'address': 0x80484c9, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
        {'address': 0x80484cc, 'mnemonic': 'mov', 'op_str': 'eax, 0x42'},
        {'address': 0x80484d1, 'mnemonic': 'leave', 'op_str': ''},
        {'address': 0x80484d2, 'mnemonic': 'ret', 'op_str': ''},
    ],
    'stack_frame': 0x10, 'stack_vars': [],
    'calls': [{'from': 0x80484bc, 'to': 0x8048330, 'name': 'malloc@GLIBC_2.0', 'type': 'call'}],
    'prologue': 0x80484ad, 'epilogue': 0x80484c7,
    'basic_blocks': [[0x80484ad, 0x80484c7]],
}


class TestDecompiler64(unittest.TestCase):
    """64-bit Register ABI decompilation tests."""

    @classmethod
    def setUpClass(cls):
        cls.d = Disassembler()
        cls.analysis = cls.d.analyze_function(BINARY_64_CODE, 0x11a9, BINARY_64_CALLS)
        cls.code = cls.d.decompile_function(cls.analysis, BINARY_64_CALLS)

    def test_malloc_inlined(self):
        self.assertIn('heap_ptr = malloc(24)', self.code)

    def test_memset_args(self):
        self.assertIn('memset(heap_ptr, 0, 24)', self.code)

    def test_puts_call(self):
        self.assertIn('puts(heap_ptr)', self.code)

    def test_free_call(self):
        self.assertIn('free(heap_ptr)', self.code)

    def test_return_zero(self):
        self.assertIn('return 0', self.code)

    def test_no_prologue_leak(self):
        self.assertNotIn('rsp -= 16', self.code)
        self.assertNotIn('endbr64', self.code)

    def test_no_movabs_comment(self):
        self.assertNotIn('/* movabs', self.code)

    def test_var_declaration(self):
        self.assertIn('heap_ptr', self.code)

    def test_memory_write(self):
        self.assertIn('heap_ptr[0] = 0x3430392d47414c46', self.code)

    def test_array_write(self):
        self.assertIn('heap_ptr[8] = 50', self.code)

    def test_alias_merged_offset(self):
        self.assertIn('heap_ptr[8] = 50', self.code)

    def test_no_ghost_args_puts(self):
        """puts should only take 1 arg in 64-bit mode."""
        # Count commas inside puts() call
        import re
        match = re.search(r'puts\(([^)]*)\)', self.code)
        if match:
            args = match.group(1).split(',')
            self.assertLessEqual(len(args), 1)


class TestDecompiler32(unittest.TestCase):
    """32-bit Stack-based decompilation tests."""

    @classmethod
    def setUpClass(cls):
        cls.d = Disassembler()
        cls.code = cls.d.decompile_function(STACK_ANALYSIS, STACK_CALLS)

    def test_malloc_inlined(self):
        self.assertIn('heap_ptr = malloc(24)', self.code)

    def test_memset_args(self):
        self.assertIn('memset(heap_ptr, 0, 24)', self.code)

    def test_puts_args(self):
        self.assertIn('0x80485f8', self.code)
        self.assertIn('0x8048608', self.code)

    def test_return_zero(self):
        self.assertIn('return 0', self.code)

    def test_no_arg_setup_leaks(self):
        """Stack-based arg setups should be suppressed."""
        self.assertNotIn('*rsp = 24', self.code)
        self.assertNotIn('STACK_0x8 = 24', self.code)


class TestStrlenIdiom(unittest.TestCase):
    """Strlen idiom detection tests."""

    @classmethod
    def setUpClass(cls):
        cls.d = Disassembler()
        cls.code = cls.d.decompile_function(STRLEN_ANALYSIS, {})

    def test_strlen_detected(self):
        self.assertIn('strlen', self.code)

    def test_no_repne_scasb(self):
        self.assertNotIn('repne', self.code)
        self.assertNotIn('scasb', self.code)

    def test_return_zero(self):
        self.assertIn('return 0', self.code)


class TestExprFolding(unittest.TestCase):
    """Expr constant folding and simplification."""

    def test_add_const_fold(self):
        """add(const(5), const(3)) → const(8)"""
        r = Expr.add(Expr.const(5), Expr.const(3))
        self.assertEqual(r.op, 'const')
        self.assertEqual(r.args[0], 8)

    def test_add_zero_elim(self):
        """add(var('x'), const(0)) → var('x')"""
        r = Expr.add(Expr.var('x'), Expr.const(0))
        self.assertEqual(r.op, 'var')
        self.assertEqual(r.args[0], 'x')

    def test_add_chained_const(self):
        """add(add(var('x'), const(8)), const(8)) → add(var('x'), const(16))"""
        inner = Expr.add(Expr.var('x'), Expr.const(8))
        r = Expr.add(inner, Expr.const(8))
        self.assertEqual(r.op, 'add')
        self.assertEqual(r.args[0].op, 'var')
        self.assertEqual(r.args[1].op, 'const')
        self.assertEqual(r.args[1].args[0], 16)

    def test_sub_const_fold(self):
        """sub(const(10), const(3)) → const(7)"""
        r = Expr.sub(Expr.const(10), Expr.const(3))
        self.assertEqual(r.op, 'const')
        self.assertEqual(r.args[0], 7)

    def test_sub_zero_elim(self):
        """sub(var('x'), const(0)) → var('x')"""
        r = Expr.sub(Expr.var('x'), Expr.const(0))
        self.assertEqual(r.op, 'var')

    def test_mul_const_fold(self):
        """mul(const(6), const(7)) → const(42)"""
        r = Expr.mul(Expr.const(6), Expr.const(7))
        self.assertEqual(r.op, 'const')
        self.assertEqual(r.args[0], 42)

    def test_mul_one_elim(self):
        """mul(var('x'), const(1)) → var('x')"""
        r = Expr.mul(Expr.var('x'), Expr.const(1))
        self.assertEqual(r.op, 'var')

    def test_mul_zero_fold(self):
        """mul(var('x'), const(0)) → const(0)"""
        r = Expr.mul(Expr.var('x'), Expr.const(0))
        self.assertEqual(r.op, 'const')
        self.assertEqual(r.args[0], 0)

    def test_chain_folding_in_output(self):
        """Full pipeline: add-chain through SSA produces clean array subscript."""
        analysis = {
            'address': 0x1000, 'size': 60,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
                {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
                {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
                {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 0x18'},
                {'address': 0x100f, 'mnemonic': 'call', 'op_str': '0x10b0'},
                {'address': 0x1014, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
                {'address': 0x1018, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
                {'address': 0x101c, 'mnemonic': 'add', 'op_str': 'rax, 8'},
                {'address': 0x1020, 'mnemonic': 'add', 'op_str': 'rax, 8'},
                {'address': 0x1024, 'mnemonic': 'mov', 'op_str': '[rax], 0x2a'},
                {'address': 0x1028, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0x10,
            'stack_vars': [
                {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
                 'used_by_funcs': set(), 'accesses': []},
            ],
            'calls': [
                {'from': 0x100f, 'to': 0x10b0, 'name': 'malloc@GLIBC_2.0', 'type': 'call'},
            ],
            'prologue': 0x1000, 'epilogue': 0x1028,
            'basic_blocks': [[0x1000, 0x1028]],
        }
        d = Disassembler()
        code = d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        # Two consecutive adds should fold: heap_ptr + 8 + 8 → heap_ptr[16]
        self.assertIn('heap_ptr[16]', code,
            'Chained add through SSA should fold (8+8) into array subscript [16]')


class TestStaleStackArg(unittest.TestCase):
    """Stale [rsp+0] detected as extra arg in 32-bit calls."""

    def setUp(self):
        self.d = Disassembler()

    def test_puts_no_extra_arg(self):
        """puts should not get stale [rsp+0] as first arg."""
        code = self.d.decompile_function(STACK_ANALYSIS, STACK_CALLS)
        import re
        matches = re.findall(r'puts\(([^)]*)\)', code)
        for args in matches:
            parts = [a.strip() for a in args.split(',') if a.strip()]
            # puts takes 1 arg; stale [rsp+0] must be filtered
            self.assertLessEqual(len(parts), 1,
                f'puts should have ≤1 arg, got: {args}')


class TestSSAMemoryForwarding(unittest.TestCase):
    """SSA memory tracking: store-to-load forwarding through stack slots."""

    @classmethod
    def setUpClass(cls):
        cls.d = Disassembler()

    def test_memory_forward_basic(self):
        """Store then reload a register through stack preserves expression."""
        analysis = {
            'address': 0x1000, 'size': 60,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
                {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
                {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
                # rax = 42
                {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rax, 0x2a'},
                # [rbp-8] = rax   (store to stack)
                {'address': 0x100f, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
                # rax = [rbp-8]   (reload from stack)
                {'address': 0x1013, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
                # return rax
                {'address': 0x1017, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0x10,
            'stack_vars': [
                {'offset': -8, 'name': 'local_8', 'suggested': 'local_8',
                 'used_by_funcs': [], 'accesses': []},
            ],
            'calls': [],
            'prologue': 0x1000, 'epilogue': 0x1017,
            'basic_blocks': [[0x1000, 0x1017]],
        }
        code = self.d.decompile_function(analysis, {})
        self.assertIn('return 42', code,
            'Memory forwarding should preserve constant 42 through stack save/restore')
        # The store local_8 = 42 IS legitimate C for the store to stack.
        # What matters: the reload uses 42, not local_8 (variable name).
        self.assertNotIn('return local_8', code,
            'Return value must use forwarded expression, not variable name')

    def test_expression_through_stack(self):
        """Complex expression preserved through stack save/restore.

        Sequence: rax = malloc(24); [rbp-8] = rax; rax = [rbp-8]; rax += 8;
                  [rbp-8] = rax; rax = [rbp-8]; *rax = 42
        → Expected: heap_ptr + 8 is preserved, output uses proper pointer notation.
        """
        analysis = {
            'address': 0x1000, 'size': 80,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
                {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
                {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
                # rax = malloc(24)
                {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 0x18'},
                {'address': 0x100f, 'mnemonic': 'call', 'op_str': '0x10b0'},
                # [rbp-8] = rax
                {'address': 0x1014, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
                # rax = [rbp-8] → should be heap_ptr
                {'address': 0x1018, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
                # rax += 8 → should be heap_ptr + 8
                {'address': 0x101c, 'mnemonic': 'add', 'op_str': 'rax, 8'},
                # [rbp-8] = rax → cache now stores heap_ptr + 8
                {'address': 0x1020, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
                # rax = [rbp-8] → should be heap_ptr + 8, NOT just heap_ptr
                {'address': 0x1024, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
                # [rax] = 42 → should be heap_ptr[8] = 42, NOT *heap_ptr = 42
                {'address': 0x1028, 'mnemonic': 'mov', 'op_str': '[rax], 0x2a'},
                # return
                {'address': 0x102c, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0x10,
            'stack_vars': [
                {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
                 'used_by_funcs': set(), 'accesses': []},
            ],
            'calls': [
                {'from': 0x100f, 'to': 0x10b0, 'name': 'malloc@GLIBC_2.0', 'type': 'call'},
            ],
            'prologue': 0x1000, 'epilogue': 0x102c,
            'basic_blocks': [[0x1000, 0x102c]],
        }
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        # The key assertion: after add+store+reload, the expression should still include +8
        self.assertNotIn('heap_ptr[0] = 42', code,
            'Should not lose +8 offset through stack save/restore')
        self.assertIn('heap_ptr[8] = 42', code,
            'Expression heap_ptr + 8 should be preserved through stack')

    def test_noop_store_suppressed(self):
        """Store of same variable back to itself should be suppressed.

        [rbp-8] = rax where rax's expression == variable name.
        This should NOT produce 'heap_ptr = heap_ptr'.
        """
        analysis = {
            'address': 0x1000, 'size': 50,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
                {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
                {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
                {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 0x18'},
                {'address': 0x100f, 'mnemonic': 'call', 'op_str': '0x10b0'},
                # [rbp-8] = rax
                {'address': 0x1014, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
                # rax = [rbp-8]
                {'address': 0x1018, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
                # [rbp-8] = rax (store back of same value — should be suppressed)
                {'address': 0x101c, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
                {'address': 0x1020, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0x10,
            'stack_vars': [
                {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
                 'used_by_funcs': set(), 'accesses': []},
            ],
            'calls': [
                {'from': 0x100f, 'to': 0x10b0, 'name': 'malloc@GLIBC_2.0', 'type': 'call'},
            ],
            'prologue': 0x1000, 'epilogue': 0x1020,
            'basic_blocks': [[0x1000, 0x1020]],
        }
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        self.assertNotIn('heap_ptr = heap_ptr', code,
            'No-op store (same var on both sides) should be suppressed')


class TestFunctionBoundary(unittest.TestCase):
    """Function boundary detection tests."""

    @classmethod
    def setUpClass(cls):
        cls.d = Disassembler()
        cls.code = cls.d.decompile_function(BOUNDARY_ANALYSIS, {0x8048330: 'malloc@GLIBC_2.0'})

    def test_adjacent_code_suppressed(self):
        self.assertNotIn('0x42', self.code)
        self.assertNotIn('0x80484c8', self.code)

    def test_malloc_present(self):
        self.assertIn('malloc(24)', self.code)

    def test_return_zero(self):
        self.assertIn('return 0', self.code)


class TestAliasAnalysis(unittest.TestCase):
    """Alias analysis: resolve [reg+offset] through Expr trees."""

    def setUp(self):
        self.d = Disassembler()

    def _make_analysis(self, insns, stack_vars):
        return {
            'address': 0x1000, 'size': 60,
            'insns': insns,
            'stack_frame': 16,
            'stack_vars': stack_vars,
            'calls': [],
            'prologue': 0x1000, 'epilogue': 0x1020,
            'basic_blocks': [[0x1000, 0x1020]],
        }

    def test_reg_ptr_direct_store(self):
        """mov [rax], val where rax=heap_ptr → heap_ptr[0] = X"""
        analysis = self._make_analysis([
            {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
            {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
            {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
            {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 24'},
            {'address': 0x100c, 'mnemonic': 'call', 'op_str': '0x10b0'},
            {'address': 0x1011, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
            {'address': 0x1015, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
            {'address': 0x1019, 'mnemonic': 'mov', 'op_str': '[rax], 0x41'},
            {'address': 0x101c, 'mnemonic': 'ret', 'op_str': ''},
        ], [
            {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
             'used_by_funcs': {'malloc'}, 'accesses': []},
        ])
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        self.assertIn('heap_ptr[0]', code)

    def test_reg_ptr_plus_off_store(self):
        """mov [rax+8], val where rax=heap_ptr → heap_ptr[8] = X"""
        analysis = self._make_analysis([
            {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
            {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
            {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
            {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 24'},
            {'address': 0x100c, 'mnemonic': 'call', 'op_str': '0x10b0'},
            {'address': 0x1011, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
            {'address': 0x1015, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
            {'address': 0x1019, 'mnemonic': 'mov', 'op_str': '[rax+8], 50'},
            {'address': 0x101c, 'mnemonic': 'ret', 'op_str': ''},
        ], [
            {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
             'used_by_funcs': {'malloc'}, 'accesses': []},
        ])
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        self.assertIn('heap_ptr[8]', code)

    def test_merged_offset_via_reg_expr(self):
        """[rax] where rax=heap_ptr+8 → heap_ptr[8] = X"""
        analysis = self._make_analysis([
            {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
            {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
            {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
            {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 24'},
            {'address': 0x100c, 'mnemonic': 'call', 'op_str': '0x10b0'},
            {'address': 0x1011, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
            {'address': 0x1015, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
            {'address': 0x1019, 'mnemonic': 'add', 'op_str': 'rax, 8'},
            {'address': 0x101c, 'mnemonic': 'mov', 'op_str': '[rax], 50'},
            {'address': 0x101f, 'mnemonic': 'ret', 'op_str': ''},
        ], [
            {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
             'used_by_funcs': {'malloc'}, 'accesses': []},
        ])
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        self.assertIn('heap_ptr[8]', code)

    def test_merged_offset_explicit_plus_reg_expr(self):
        """[rax+8] where rax=heap_ptr+16 → heap_ptr[24] = X (offsets merge)"""
        analysis = self._make_analysis([
            {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
            {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
            {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
            {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 24'},
            {'address': 0x100c, 'mnemonic': 'call', 'op_str': '0x10b0'},
            {'address': 0x1011, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
            {'address': 0x1015, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
            {'address': 0x1019, 'mnemonic': 'add', 'op_str': 'rax, 16'},
            {'address': 0x101c, 'mnemonic': 'mov', 'op_str': '[rax+8], 67'},
            {'address': 0x101f, 'mnemonic': 'ret', 'op_str': ''},
        ], [
            {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
             'used_by_funcs': {'malloc'}, 'accesses': []},
        ])
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        self.assertIn('heap_ptr[24]', code)


class TestCharLiteral(unittest.TestCase):
    """Char literal rendering for byte-sized stores."""

    def setUp(self):
        self.d = Disassembler()

    def _make_analysis(self, insns, stack_vars):
        return {
            'address': 0x1000, 'size': 60,
            'insns': insns,
            'stack_frame': 16,
            'stack_vars': stack_vars,
            'calls': [],
            'prologue': 0x1000, 'epilogue': 0x1020,
            'basic_blocks': [[0x1000, 0x1020]],
        }

    def test_byte_store_printable(self):
        """byte ptr store of printable constant renders as char literal."""
        analysis = self._make_analysis([
            {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
            {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
            {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
            {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 24'},
            {'address': 0x100c, 'mnemonic': 'call', 'op_str': '0x10b0'},
            {'address': 0x1011, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
            {'address': 0x1015, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
            {'address': 0x1019, 'mnemonic': 'mov', 'op_str': 'byte ptr [rax], 65'},
            {'address': 0x101c, 'mnemonic': 'ret', 'op_str': ''},
        ], [
            {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
             'used_by_funcs': {'malloc'}, 'accesses': []},
        ])
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        self.assertIn("heap_ptr[0] = 'A'", code)
        self.assertNotIn('heap_ptr[0] = 65', code)

    def test_byte_store_hex(self):
        """byte ptr store of 0x41 renders as 'A' too."""
        analysis = self._make_analysis([
            {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
            {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
            {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
            {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 24'},
            {'address': 0x100c, 'mnemonic': 'call', 'op_str': '0x10b0'},
            {'address': 0x1011, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
            {'address': 0x1015, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
            {'address': 0x1019, 'mnemonic': 'mov', 'op_str': 'byte ptr [rax], 0x41'},
            {'address': 0x101c, 'mnemonic': 'ret', 'op_str': ''},
        ], [
            {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
             'used_by_funcs': {'malloc'}, 'accesses': []},
        ])
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        self.assertIn("heap_ptr[0] = 'A'", code)
        self.assertNotIn('heap_ptr[0] = 65', code)

    def test_byte_store_non_printable(self):
        """byte ptr store of non-printable stays numeric."""
        analysis = self._make_analysis([
            {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
            {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
            {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
            {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 24'},
            {'address': 0x100c, 'mnemonic': 'call', 'op_str': '0x10b0'},
            {'address': 0x1011, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
            {'address': 0x1015, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
            {'address': 0x1019, 'mnemonic': 'mov', 'op_str': 'byte ptr [rax], 0'},
            {'address': 0x101c, 'mnemonic': 'ret', 'op_str': ''},
        ], [
            {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
             'used_by_funcs': {'malloc'}, 'accesses': []},
        ])
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        self.assertIn('heap_ptr[0] = 0', code)

    def test_dword_store_not_char(self):
        """dword ptr store should stay numeric even if printable."""
        analysis = self._make_analysis([
            {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
            {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
            {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
            {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 24'},
            {'address': 0x100c, 'mnemonic': 'call', 'op_str': '0x10b0'},
            {'address': 0x1011, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
            {'address': 0x1015, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
            {'address': 0x1019, 'mnemonic': 'mov', 'op_str': 'dword ptr [rax], 65'},
            {'address': 0x101c, 'mnemonic': 'ret', 'op_str': ''},
        ], [
            {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
             'used_by_funcs': {'malloc'}, 'accesses': []},
        ])
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        self.assertIn('heap_ptr[0] = 65', code)
        self.assertNotIn("'A'", code)

    def test_byte_store_with_offset(self):
        """byte ptr [rax+16] printable renders as char with offset."""
        analysis = self._make_analysis([
            {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
            {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
            {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
            {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 24'},
            {'address': 0x100c, 'mnemonic': 'call', 'op_str': '0x10b0'},
            {'address': 0x1011, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
            {'address': 0x1015, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
            {'address': 0x1019, 'mnemonic': 'mov', 'op_str': 'byte ptr [rax+8], 0x48'},
            {'address': 0x101c, 'mnemonic': 'ret', 'op_str': ''},
        ], [
            {'offset': -8, 'name': 'local_8', 'suggested': 'heap_ptr',
             'used_by_funcs': {'malloc'}, 'accesses': []},
        ])
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        self.assertIn("heap_ptr[8] = 'H'", code)


class TestReturnType(unittest.TestCase):
    """Return type detection from pointer stack variables."""

    def setUp(self):
        self.d = Disassembler()

    def test_pointer_return_from_stack_var(self):
        """Function returning a pointer-typed stack var gets char* return type."""
        analysis = {
            'address': 0x1000, 'size': 50,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
                {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
                {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
                {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'rdi, 32'},
                {'address': 0x100c, 'mnemonic': 'call', 'op_str': '0x10b0'},
                {'address': 0x1011, 'mnemonic': 'mov', 'op_str': '[rbp-8], rax'},
                {'address': 0x1015, 'mnemonic': 'mov', 'op_str': 'rax, [rbp-8]'},
                {'address': 0x1019, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0x10,
            'stack_vars': [
                {'offset': -8, 'name': 'local_8', 'suggested': 'buf',
                 'used_by_funcs': set(), 'accesses': []},
            ],
            'calls': [
                {'from': 0x100c, 'to': 0x10b0, 'name': 'malloc@GLIBC_2.0', 'type': 'call'},
            ],
            'prologue': 0x1000, 'epilogue': 0x1019,
            'basic_blocks': [[0x1000, 0x1019]],
        }
        code = self.d.decompile_function(analysis, {0x10b0: 'malloc@GLIBC_2.0'})
        # Find the signature line (after comment lines)
        sig_line = [l for l in code.split('\n') if l.strip() and not l.startswith('//')][0]
        self.assertIn('char*', sig_line, 'Return type should be char*')
        self.assertNotIn('int ', sig_line, 'Should not be int')
        # Variable should also be char* (passed to puts/free)
        self.assertIn('char* buf', code)
        self.assertIn('return buf', code)

    def test_int_return_kept_for_constant(self):
        """Function returning a constant keeps int return type."""
        analysis = {
            'address': 0x1000, 'size': 30,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
                {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
                {'address': 0x1004, 'mnemonic': 'mov', 'op_str': 'eax, 0'},
                {'address': 0x1009, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0, 'stack_vars': [],
            'calls': [],
            'prologue': 0x1000, 'epilogue': 0x1009,
            'basic_blocks': [[0x1000, 0x1009]],
        }
        code = self.d.decompile_function(analysis, {})
        sig_line = [l for l in code.split('\n') if l.strip() and not l.startswith('//')][0]
        self.assertIn('int ', sig_line, 'Return type should be int')
        self.assertNotIn('char*', sig_line, 'Should not be char*')


class TestShiftInstructions(unittest.TestCase):
    """Shift instruction (shl/shr) decompilation output."""

    def setUp(self):
        self.d = Disassembler()

    def test_shl_immediate(self):
        """shl rax, 3 → rax <<= 3"""
        analysis = {
            'address': 0x1000, 'size': 20,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'mov', 'op_str': 'rax, 1'},
                {'address': 0x1007, 'mnemonic': 'shl', 'op_str': 'rax, 3'},
                {'address': 0x100b, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0, 'stack_vars': [],
            'calls': [],
            'prologue': 0x1000, 'epilogue': 0x100b,
            'basic_blocks': [[0x1000, 0x100b]],
        }
        code = self.d.decompile_function(analysis, {})
        self.assertIn('rax <<= 3', code)

    def test_shl_reg_expr_tracking(self):
        """shl writes to register that feeds into memory — expression tracks as mul."""
        analysis = {
            'address': 0x1000, 'size': 24,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'mov', 'op_str': 'eax, dword ptr [rbp - 8]'},
                {'address': 0x1003, 'mnemonic': 'shl', 'op_str': 'eax, 2'},
                {'address': 0x1006, 'mnemonic': 'mov', 'op_str': 'dword ptr [rbp - 8], eax'},
                {'address': 0x1009, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0x10, 'stack_vars': [{'offset': -8, 'name': 'local_8', 'size': 4}],
            'calls': [],
            'prologue': 0x1000, 'epilogue': 0x1009,
            'basic_blocks': [[0x1000, 0x1009]],
        }
        code = self.d.decompile_function(analysis, {})
        # The shl with constant is tracked as mul(*4) in expression; value stored back to var
        self.assertIn('local_8', code)

    def test_shr_immediate(self):
        """shr rax, 2 → rax >>= 2"""
        analysis = {
            'address': 0x1000, 'size': 20,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'mov', 'op_str': 'rax, 64'},
                {'address': 0x1007, 'mnemonic': 'shr', 'op_str': 'rax, 2'},
                {'address': 0x100b, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0, 'stack_vars': [],
            'calls': [],
            'prologue': 0x1000, 'epilogue': 0x100b,
            'basic_blocks': [[0x1000, 0x100b]],
        }
        code = self.d.decompile_function(analysis, {})
        self.assertIn('rax >>= 2', code)

    def test_sal_as_shl(self):
        """sal is synonymous with shl"""
        analysis = {
            'address': 0x1000, 'size': 20,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'mov', 'op_str': 'rax, 1'},
                {'address': 0x1007, 'mnemonic': 'sal', 'op_str': 'rax, 1'},
                {'address': 0x100b, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0, 'stack_vars': [],
            'calls': [],
            'prologue': 0x1000, 'epilogue': 0x100b,
            'basic_blocks': [[0x1000, 0x100b]],
        }
        code = self.d.decompile_function(analysis, {})
        self.assertIn('rax <<= 1', code)


class TestAliasStackVar(unittest.TestCase):
    """Alias through lea resolves to stack variable names."""

    def setUp(self):
        self.d = Disassembler()

    def test_lea_to_stack_var(self):
        """lea rax, [rbp-8]; mov [rax], 42 → rax = &local_8, then stores through it"""
        analysis = {
            'address': 0x1000, 'size': 24,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'lea', 'op_str': 'rax, qword ptr [rbp - 8]'},
                {'address': 0x1005, 'mnemonic': 'mov', 'op_str': 'qword ptr [rax], 42'},
                {'address': 0x1009, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0x10, 'stack_vars': [{'offset': -8, 'name': 'local_8', 'size': 8}],
            'calls': [],
            'prologue': 0x1000, 'epilogue': 0x1009,
            'basic_blocks': [[0x1000, 0x1009]],
        }
        code = self.d.decompile_function(analysis, {})
        # LEA resolves to &local_8, then [rax] store resolves through the alias
        self.assertIn('local_8', code)

    def test_lea_indirect_store(self):
        """lea rax, [rbp-4]; mov [rax+4], byte 0x41 → local_4[4] = 'A' via alias"""
        analysis = {
            'address': 0x1000, 'size': 24,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'lea', 'op_str': 'rax, qword ptr [rbp - 4]'},
                {'address': 0x1005, 'mnemonic': 'mov', 'op_str': 'byte ptr [rax + 4], 0x41'},
                {'address': 0x1009, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0x10, 'stack_vars': [
                {'offset': -4, 'name': 'local_4', 'size': 4},
                {'offset': 0, 'name': 'local_0', 'size': 4},
            ],
            'calls': [],
            'prologue': 0x1000, 'epilogue': 0x1009,
            'basic_blocks': [[0x1000, 0x1009]],
        }
        code = self.d.decompile_function(analysis, {})
        # rax resolves to local_4 (rbp-4), so [rax+4] = local_4[4]
        self.assertIn('local_4', code)
        self.assertIn('[4]', code)


class TestServerCrashRegressions(unittest.TestCase):
    """Regression tests for bugs found in server-side usage."""

    def setUp(self):
        self.d = Disassembler()

    def test_stack_var_with_non_call_preceding(self):
        """No UnboundLocalError when stack var emerges after non-call instruction."""
        analysis = {
            'address': 0x1000, 'size': 24,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'mov', 'op_str': 'rax, 42'},
                {'address': 0x1003, 'mnemonic': 'mov', 'op_str': 'dword ptr [rbp-8], eax'},
                {'address': 0x1007, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0x10, 'stack_vars': [
                {'offset': -8, 'name': 'local_8', 'size': 4,
                 'used_by_funcs': [], 'accesses': []},
            ],
            'calls': [],
            'prologue': 0x1000, 'epilogue': 0x1007,
            'basic_blocks': [[0x1000, 0x1007]],
        }
        code = self.d.decompile_function(analysis, {})
        self.assertIn('local_8', code)

    def test_call_arg_with_expr_reg(self):
        """No TypeError when function call arg is an Expr object."""
        analysis = {
            'address': 0x1000, 'size': 40,
            'insns': [
                {'address': 0x1000, 'mnemonic': 'push', 'op_str': 'rbp'},
                {'address': 0x1001, 'mnemonic': 'mov', 'op_str': 'rbp, rsp'},
                {'address': 0x1004, 'mnemonic': 'sub', 'op_str': 'rsp, 0x10'},
                {'address': 0x1008, 'mnemonic': 'mov', 'op_str': 'edi, 0x20'},
                {'address': 0x100d, 'mnemonic': 'call', 'op_str': '0x1200'},
                {'address': 0x1012, 'mnemonic': 'mov', 'op_str': 'qword ptr [rbp-8], rax'},
                {'address': 0x1016, 'mnemonic': 'mov', 'op_str': 'rdi, qword ptr [rbp-8]'},
                {'address': 0x101a, 'mnemonic': 'call', 'op_str': '0x1220'},
                {'address': 0x101f, 'mnemonic': 'ret', 'op_str': ''},
            ],
            'stack_frame': 0x10, 'stack_vars': [
                {'offset': -8, 'name': 'local_8', 'size': 8,
                 'suggested': 'buf', 'used_by_funcs': [], 'accesses': []},
            ],
            'calls': [
                {'from': 0x100d, 'to': 0x1200, 'type': 'call'},
                {'from': 0x101a, 'to': 0x1220, 'type': 'call'},
            ],
            'prologue': 0x1000, 'epilogue': 0x101f,
            'basic_blocks': [[0x1000, 0x101f]],
        }
        code = self.d.decompile_function(analysis, {0x1200: 'malloc', 0x1220: 'puts'})
        # Should not crash with TypeError. Second call should pass buffer as arg.
        self.assertIn('puts', code)


if __name__ == '__main__':
    unittest.main()
