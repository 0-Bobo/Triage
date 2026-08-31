"""Regression tests for the engine.py decompiler.

Locks current behaviour before modular refactoring.
"""

import unittest
import unittest.mock

from triage_web.engine import Disassembler, Expr

# ── 64-bit Register ABI (real binary test) ──
BINARY_64_CODE = bytes.fromhex(
    "f30f1efa554889e54883ec10bf18000000e8f1feffff488945f8"
    "488b45f8ba18000000be000000004889c7e8c7feffff488b45f8"
    "48b9464c41472d39303448890866c740083200488b45f84889c7"
    "e894feffff488b45f84889c7e878feffffb800000000c9c3"
)
BINARY_64_CALLS = {
    0x1090: "puts@GLIBC_2.2.5",
    0x10A0: "memset@GLIBC_2.2.5",
    0x10B0: "malloc@GLIBC_2.2.5",
    0x1080: "free@GLIBC_2.2.5",
}

# ── 32-bit Stack-based (mock CTF challenge) ──
STACK_ANALYSIS = {
    "address": 0x80484AD,
    "size": 200,
    "insns": [
        {"address": 0x80484AD, "mnemonic": "push", "op_str": "rbp"},
        {"address": 0x80484AE, "mnemonic": "mov", "op_str": "rbp, rsp"},
        {"address": 0x80484B1, "mnemonic": "push", "op_str": "rdi"},
        {"address": 0x80484B2, "mnemonic": "and", "op_str": "rsp, 0xfffffff0"},
        {"address": 0x80484B5, "mnemonic": "sub", "op_str": "rsp, 0x30"},
        {"address": 0x80484B9, "mnemonic": "mov", "op_str": "dword ptr [rsp + 0x2c], 0"},
        {"address": 0x80484C1, "mnemonic": "mov", "op_str": "dword ptr [rsp], 0x18"},
        {"address": 0x80484C8, "mnemonic": "call", "op_str": "0x8048330"},
        {"address": 0x80484CD, "mnemonic": "mov", "op_str": "dword ptr [rsp + 0x2c], eax"},
        {"address": 0x80484D1, "mnemonic": "mov", "op_str": "dword ptr [rsp + 8], 0x18"},
        {"address": 0x80484D9, "mnemonic": "mov", "op_str": "dword ptr [rsp + 4], 0"},
        {"address": 0x80484E1, "mnemonic": "mov", "op_str": "eax, dword ptr [rsp + 0x2c]"},
        {"address": 0x80484E5, "mnemonic": "mov", "op_str": "dword ptr [rsp], eax"},
        {"address": 0x80484E8, "mnemonic": "call", "op_str": "0x8048370"},
        {"address": 0x80484ED, "mnemonic": "mov", "op_str": "eax, dword ptr [rsp + 0x2c]"},
        {"address": 0x80484F1, "mnemonic": "mov", "op_str": "dword ptr [rsp], eax"},
        {"address": 0x80484F4, "mnemonic": "mov", "op_str": "dword ptr [rsp + 4], 0x80485f8"},
        {"address": 0x80484FC, "mnemonic": "call", "op_str": "0x8048340"},
        {"address": 0x8048501, "mnemonic": "mov", "op_str": "eax, dword ptr [rsp + 0x2c]"},
        {"address": 0x8048505, "mnemonic": "mov", "op_str": "dword ptr [rsp], eax"},
        {"address": 0x8048508, "mnemonic": "mov", "op_str": "dword ptr [rsp + 4], 0x8048608"},
        {"address": 0x8048510, "mnemonic": "call", "op_str": "0x8048340"},
        {"address": 0x8048515, "mnemonic": "mov", "op_str": "eax, 0"},
        {"address": 0x804851A, "mnemonic": "leave", "op_str": ""},
        {"address": 0x804851B, "mnemonic": "ret", "op_str": ""},
    ],
    "stack_frame": 0x30,
    "stack_vars": [
        {
            "offset": 44,
            "name": "local_2c",
            "suggested": "heap_ptr",
            "used_by_funcs": ["malloc@GLIBC_2.0", "memset@GLIBC_2.0", "puts@GLIBC_2.0"],
            "accesses": [],
        },
    ],
    "calls": [
        {"from": 0x80484C8, "to": 0x8048330, "name": "malloc@GLIBC_2.0", "type": "call"},
        {"from": 0x80484E8, "to": 0x8048370, "name": "memset@GLIBC_2.0", "type": "call"},
        {"from": 0x80484FC, "to": 0x8048340, "name": "puts@GLIBC_2.0", "type": "call"},
        {"from": 0x8048510, "to": 0x8048340, "name": "puts@GLIBC_2.0", "type": "call"},
    ],
    "prologue": 0x80484AD,
    "epilogue": 0x804851B,
    "basic_blocks": [[0x80484AD, 0x804851B]],
}
STACK_CALLS = {
    0x8048330: "malloc@GLIBC_2.0",
    0x8048370: "memset@GLIBC_2.0",
    0x8048340: "puts@GLIBC_2.0",
}

# ── strlen idiom test ──
STRLEN_ANALYSIS = {
    "address": 0x8048500,
    "size": 50,
    "insns": [
        {"address": 0x8048500, "mnemonic": "push", "op_str": "rbp"},
        {"address": 0x8048501, "mnemonic": "mov", "op_str": "rbp, rsp"},
        {"address": 0x8048504, "mnemonic": "sub", "op_str": "rsp, 0x10"},
        {"address": 0x8048508, "mnemonic": "xor", "op_str": "eax, eax"},
        {"address": 0x804850A, "mnemonic": "mov", "op_str": "ecx, 0xffffffff"},
        {"address": 0x8048510, "mnemonic": "repne", "op_str": "scasb byte ptr [rdi]"},
        {"address": 0x8048512, "mnemonic": "not", "op_str": "ecx"},
        {"address": 0x8048514, "mnemonic": "dec", "op_str": "ecx"},
        {"address": 0x8048516, "mnemonic": "mov", "op_str": "eax, ecx"},
        {"address": 0x8048518, "mnemonic": "mov", "op_str": "eax, 0"},
        {"address": 0x804851D, "mnemonic": "leave", "op_str": ""},
        {"address": 0x804851E, "mnemonic": "ret", "op_str": ""},
    ],
    "stack_frame": 0x10,
    "stack_vars": [],
    "calls": [],
    "prologue": 0x8048500,
    "epilogue": 0x804851E,
    "basic_blocks": [[0x8048500, 0x804851E]],
}

# ── Function boundary test ──
BOUNDARY_ANALYSIS = {
    "address": 0x80484AD,
    "size": 60,
    "insns": [
        {"address": 0x80484AD, "mnemonic": "push", "op_str": "rbp"},
        {"address": 0x80484AE, "mnemonic": "mov", "op_str": "rbp, rsp"},
        {"address": 0x80484B1, "mnemonic": "sub", "op_str": "rsp, 0x10"},
        {"address": 0x80484B5, "mnemonic": "mov", "op_str": "dword ptr [rsp], 0x18"},
        {"address": 0x80484BC, "mnemonic": "call", "op_str": "0x8048330"},
        {"address": 0x80484C1, "mnemonic": "mov", "op_str": "eax, 0"},
        {"address": 0x80484C6, "mnemonic": "leave", "op_str": ""},
        {"address": 0x80484C7, "mnemonic": "ret", "op_str": ""},
        # Adjacent function — should NOT appear
        {"address": 0x80484C8, "mnemonic": "push", "op_str": "rbp"},
        {"address": 0x80484C9, "mnemonic": "mov", "op_str": "rbp, rsp"},
        {"address": 0x80484CC, "mnemonic": "mov", "op_str": "eax, 0x42"},
        {"address": 0x80484D1, "mnemonic": "leave", "op_str": ""},
        {"address": 0x80484D2, "mnemonic": "ret", "op_str": ""},
    ],
    "stack_frame": 0x10,
    "stack_vars": [],
    "calls": [{"from": 0x80484BC, "to": 0x8048330, "name": "malloc@GLIBC_2.0", "type": "call"}],
    "prologue": 0x80484AD,
    "epilogue": 0x80484C7,
    "basic_blocks": [[0x80484AD, 0x80484C7]],
}


class TestDecompiler64(unittest.TestCase):
    """64-bit Register ABI decompilation tests."""

    @classmethod
    def setUpClass(cls):
        cls.d = Disassembler()
        cls.analysis = cls.d.analyze_function(BINARY_64_CODE, 0x11A9, BINARY_64_CALLS)
        cls.code = cls.d.decompile_function(cls.analysis, BINARY_64_CALLS)

    def test_malloc_inlined(self):
        self.assertIn("heap_ptr = malloc(24)", self.code)

    def test_memset_args(self):
        self.assertIn("memset(heap_ptr, 0, 24)", self.code)

    def test_puts_call(self):
        self.assertIn("puts(heap_ptr)", self.code)

    def test_free_call(self):
        self.assertIn("free(heap_ptr)", self.code)

    def test_return_zero(self):
        self.assertIn("return 0", self.code)

    def test_no_prologue_leak(self):
        self.assertNotIn("rsp -= 16", self.code)
        self.assertNotIn("endbr64", self.code)

    def test_no_movabs_comment(self):
        self.assertNotIn("/* movabs", self.code)

    def test_var_declaration(self):
        self.assertIn("heap_ptr", self.code)

    def test_memory_write(self):
        self.assertIn("heap_ptr[0] = 0x3430392d47414c46", self.code)

    def test_array_write(self):
        self.assertIn("heap_ptr[8] = 50", self.code)

    def test_alias_merged_offset(self):
        self.assertIn("heap_ptr[8] = 50", self.code)

    def test_no_ghost_args_puts(self):
        """puts should only take 1 arg in 64-bit mode."""
        # Count commas inside puts() call
        import re

        match = re.search(r"puts\(([^)]*)\)", self.code)
        if match:
            args = match.group(1).split(",")
            self.assertLessEqual(len(args), 1)


class TestDecompiler32(unittest.TestCase):
    """32-bit Stack-based decompilation tests."""

    @classmethod
    def setUpClass(cls):
        cls.d = Disassembler()
        cls.code = cls.d.decompile_function(STACK_ANALYSIS, STACK_CALLS)

    def test_malloc_inlined(self):
        self.assertIn("heap_ptr = malloc(24)", self.code)

    def test_memset_args(self):
        self.assertIn("memset(heap_ptr, 0, 24)", self.code)

    def test_puts_args(self):
        self.assertIn("0x80485f8", self.code)
        self.assertIn("0x8048608", self.code)

    def test_return_zero(self):
        self.assertIn("return 0", self.code)

    def test_no_arg_setup_leaks(self):
        """Stack-based arg setups should be suppressed."""
        self.assertNotIn("*rsp = 24", self.code)
        self.assertNotIn("STACK_0x8 = 24", self.code)


class TestStrlenIdiom(unittest.TestCase):
    """Strlen idiom detection tests."""

    @classmethod
    def setUpClass(cls):
        cls.d = Disassembler()
        cls.code = cls.d.decompile_function(STRLEN_ANALYSIS, {})

    def test_strlen_detected(self):
        self.assertIn("strlen", self.code)

    def test_no_repne_scasb(self):
        self.assertNotIn("repne", self.code)
        self.assertNotIn("scasb", self.code)

    def test_return_zero(self):
        self.assertIn("return 0", self.code)


class TestExprFolding(unittest.TestCase):
    """Expr constant folding and simplification."""

    def test_add_const_fold(self):
        """add(const(5), const(3)) → const(8)"""
        r = Expr.add(Expr.const(5), Expr.const(3))
        self.assertEqual(r.op, "const")
        self.assertEqual(r.args[0], 8)

    def test_add_zero_elim(self):
        """add(var('x'), const(0)) → var('x')"""
        r = Expr.add(Expr.var("x"), Expr.const(0))
        self.assertEqual(r.op, "var")
        self.assertEqual(r.args[0], "x")

    def test_add_chained_const(self):
        """add(add(var('x'), const(8)), const(8)) → add(var('x'), const(16))"""
        inner = Expr.add(Expr.var("x"), Expr.const(8))
        r = Expr.add(inner, Expr.const(8))
        self.assertEqual(r.op, "add")
        self.assertEqual(r.args[0].op, "var")
        self.assertEqual(r.args[1].op, "const")
        self.assertEqual(r.args[1].args[0], 16)

    def test_sub_const_fold(self):
        """sub(const(10), const(3)) → const(7)"""
        r = Expr.sub(Expr.const(10), Expr.const(3))
        self.assertEqual(r.op, "const")
        self.assertEqual(r.args[0], 7)

    def test_sub_zero_elim(self):
        """sub(var('x'), const(0)) → var('x')"""
        r = Expr.sub(Expr.var("x"), Expr.const(0))
        self.assertEqual(r.op, "var")

    def test_mul_const_fold(self):
        """mul(const(6), const(7)) → const(42)"""
        r = Expr.mul(Expr.const(6), Expr.const(7))
        self.assertEqual(r.op, "const")
        self.assertEqual(r.args[0], 42)

    def test_mul_one_elim(self):
        """mul(var('x'), const(1)) → var('x')"""
        r = Expr.mul(Expr.var("x"), Expr.const(1))
        self.assertEqual(r.op, "var")

    def test_mul_zero_fold(self):
        """mul(var('x'), const(0)) → const(0)"""
        r = Expr.mul(Expr.var("x"), Expr.const(0))
        self.assertEqual(r.op, "const")
        self.assertEqual(r.args[0], 0)

    def test_chain_folding_in_output(self):
        """Full pipeline: add-chain through SSA produces clean array subscript."""
        analysis = {
            "address": 0x1000,
            "size": 60,
            "insns": [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 0x18"},
                {"address": 0x100F, "mnemonic": "call", "op_str": "0x10b0"},
                {"address": 0x1014, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1018, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                {"address": 0x101C, "mnemonic": "add", "op_str": "rax, 8"},
                {"address": 0x1020, "mnemonic": "add", "op_str": "rax, 8"},
                {"address": 0x1024, "mnemonic": "mov", "op_str": "[rax], 0x2a"},
                {"address": 0x1028, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0x10,
            "stack_vars": [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": set(), "accesses": []},
            ],
            "calls": [
                {"from": 0x100F, "to": 0x10B0, "name": "malloc@GLIBC_2.0", "type": "call"},
            ],
            "prologue": 0x1000,
            "epilogue": 0x1028,
            "basic_blocks": [[0x1000, 0x1028]],
        }
        d = Disassembler()
        code = d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        # Two consecutive adds should fold: heap_ptr + 8 + 8 → heap_ptr[16]
        self.assertIn("heap_ptr[16]", code, "Chained add through SSA should fold (8+8) into array subscript [16]")


class TestStaleStackArg(unittest.TestCase):
    """Stale [rsp+0] detected as extra arg in 32-bit calls."""

    def setUp(self):
        self.d = Disassembler()

    def test_puts_no_extra_arg(self):
        """puts should not get stale [rsp+0] as first arg."""
        code = self.d.decompile_function(STACK_ANALYSIS, STACK_CALLS)
        import re

        matches = re.findall(r"puts\(([^)]*)\)", code)
        for args in matches:
            parts = [a.strip() for a in args.split(",") if a.strip()]
            # puts takes 1 arg; stale [rsp+0] must be filtered
            self.assertLessEqual(len(parts), 1, f"puts should have ≤1 arg, got: {args}")


class TestSSAMemoryForwarding(unittest.TestCase):
    """SSA memory tracking: store-to-load forwarding through stack slots."""

    @classmethod
    def setUpClass(cls):
        cls.d = Disassembler()

    def test_memory_forward_basic(self):
        """Store then reload a register through stack preserves expression."""
        analysis = {
            "address": 0x1000,
            "size": 60,
            "insns": [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                # rax = 42
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rax, 0x2a"},
                # [rbp-8] = rax   (store to stack)
                {"address": 0x100F, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                # rax = [rbp-8]   (reload from stack)
                {"address": 0x1013, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                # return rax
                {"address": 0x1017, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0x10,
            "stack_vars": [
                {"offset": -8, "name": "local_8", "suggested": "local_8", "used_by_funcs": [], "accesses": []},
            ],
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x1017,
            "basic_blocks": [[0x1000, 0x1017]],
        }
        code = self.d.decompile_function(analysis, {})
        self.assertIn("return 42", code, "Memory forwarding should preserve constant 42 through stack save/restore")
        # The store local_8 = 42 IS legitimate C for the store to stack.
        # What matters: the reload uses 42, not local_8 (variable name).
        self.assertNotIn("return local_8", code, "Return value must use forwarded expression, not variable name")

    def test_expression_through_stack(self):
        """Complex expression preserved through stack save/restore.

        Sequence: rax = malloc(24); [rbp-8] = rax; rax = [rbp-8]; rax += 8;
                  [rbp-8] = rax; rax = [rbp-8]; *rax = 42
        → Expected: heap_ptr + 8 is preserved, output uses proper pointer notation.
        """
        analysis = {
            "address": 0x1000,
            "size": 80,
            "insns": [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                # rax = malloc(24)
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 0x18"},
                {"address": 0x100F, "mnemonic": "call", "op_str": "0x10b0"},
                # [rbp-8] = rax
                {"address": 0x1014, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                # rax = [rbp-8] → should be heap_ptr
                {"address": 0x1018, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                # rax += 8 → should be heap_ptr + 8
                {"address": 0x101C, "mnemonic": "add", "op_str": "rax, 8"},
                # [rbp-8] = rax → cache now stores heap_ptr + 8
                {"address": 0x1020, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                # rax = [rbp-8] → should be heap_ptr + 8, NOT just heap_ptr
                {"address": 0x1024, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                # [rax] = 42 → should be heap_ptr[8] = 42, NOT *heap_ptr = 42
                {"address": 0x1028, "mnemonic": "mov", "op_str": "[rax], 0x2a"},
                # return
                {"address": 0x102C, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0x10,
            "stack_vars": [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": set(), "accesses": []},
            ],
            "calls": [
                {"from": 0x100F, "to": 0x10B0, "name": "malloc@GLIBC_2.0", "type": "call"},
            ],
            "prologue": 0x1000,
            "epilogue": 0x102C,
            "basic_blocks": [[0x1000, 0x102C]],
        }
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        # The key assertion: after add+store+reload, the expression should still include +8
        self.assertNotIn("heap_ptr[0] = 42", code, "Should not lose +8 offset through stack save/restore")
        self.assertIn("heap_ptr[8] = 42", code, "Expression heap_ptr + 8 should be preserved through stack")

    def test_noop_store_suppressed(self):
        """Store of same variable back to itself should be suppressed.

        [rbp-8] = rax where rax's expression == variable name.
        This should NOT produce 'heap_ptr = heap_ptr'.
        """
        analysis = {
            "address": 0x1000,
            "size": 50,
            "insns": [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 0x18"},
                {"address": 0x100F, "mnemonic": "call", "op_str": "0x10b0"},
                # [rbp-8] = rax
                {"address": 0x1014, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                # rax = [rbp-8]
                {"address": 0x1018, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                # [rbp-8] = rax (store back of same value — should be suppressed)
                {"address": 0x101C, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1020, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0x10,
            "stack_vars": [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": set(), "accesses": []},
            ],
            "calls": [
                {"from": 0x100F, "to": 0x10B0, "name": "malloc@GLIBC_2.0", "type": "call"},
            ],
            "prologue": 0x1000,
            "epilogue": 0x1020,
            "basic_blocks": [[0x1000, 0x1020]],
        }
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        self.assertNotIn("heap_ptr = heap_ptr", code, "No-op store (same var on both sides) should be suppressed")


class TestFunctionBoundary(unittest.TestCase):
    """Function boundary detection tests."""

    @classmethod
    def setUpClass(cls):
        cls.d = Disassembler()
        cls.code = cls.d.decompile_function(BOUNDARY_ANALYSIS, {0x8048330: "malloc@GLIBC_2.0"})

    def test_adjacent_code_suppressed(self):
        self.assertNotIn("0x42", self.code)
        self.assertNotIn("0x80484c8", self.code)

    def test_malloc_present(self):
        self.assertIn("malloc(24)", self.code)

    def test_return_zero(self):
        self.assertIn("return 0", self.code)


class TestAliasAnalysis(unittest.TestCase):
    """Alias analysis: resolve [reg+offset] through Expr trees."""

    def setUp(self):
        self.d = Disassembler()

    def _make_analysis(self, insns, stack_vars):
        return {
            "address": 0x1000,
            "size": 60,
            "insns": insns,
            "stack_frame": 16,
            "stack_vars": stack_vars,
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x1020,
            "basic_blocks": [[0x1000, 0x1020]],
        }

    def test_reg_ptr_direct_store(self):
        """mov [rax], val where rax=heap_ptr → heap_ptr[0] = X"""
        analysis = self._make_analysis(
            [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 24"},
                {"address": 0x100C, "mnemonic": "call", "op_str": "0x10b0"},
                {"address": 0x1011, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1015, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                {"address": 0x1019, "mnemonic": "mov", "op_str": "[rax], 0x41"},
                {"address": 0x101C, "mnemonic": "ret", "op_str": ""},
            ],
            [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": {"malloc"}, "accesses": []},
            ],
        )
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        self.assertIn("heap_ptr[0]", code)

    def test_reg_ptr_plus_off_store(self):
        """mov [rax+8], val where rax=heap_ptr → heap_ptr[8] = X"""
        analysis = self._make_analysis(
            [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 24"},
                {"address": 0x100C, "mnemonic": "call", "op_str": "0x10b0"},
                {"address": 0x1011, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1015, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                {"address": 0x1019, "mnemonic": "mov", "op_str": "[rax+8], 50"},
                {"address": 0x101C, "mnemonic": "ret", "op_str": ""},
            ],
            [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": {"malloc"}, "accesses": []},
            ],
        )
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        self.assertIn("heap_ptr[8]", code)

    def test_merged_offset_via_reg_expr(self):
        """[rax] where rax=heap_ptr+8 → heap_ptr[8] = X"""
        analysis = self._make_analysis(
            [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 24"},
                {"address": 0x100C, "mnemonic": "call", "op_str": "0x10b0"},
                {"address": 0x1011, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1015, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                {"address": 0x1019, "mnemonic": "add", "op_str": "rax, 8"},
                {"address": 0x101C, "mnemonic": "mov", "op_str": "[rax], 50"},
                {"address": 0x101F, "mnemonic": "ret", "op_str": ""},
            ],
            [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": {"malloc"}, "accesses": []},
            ],
        )
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        self.assertIn("heap_ptr[8]", code)

    def test_merged_offset_explicit_plus_reg_expr(self):
        """[rax+8] where rax=heap_ptr+16 → heap_ptr[24] = X (offsets merge)"""
        analysis = self._make_analysis(
            [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 24"},
                {"address": 0x100C, "mnemonic": "call", "op_str": "0x10b0"},
                {"address": 0x1011, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1015, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                {"address": 0x1019, "mnemonic": "add", "op_str": "rax, 16"},
                {"address": 0x101C, "mnemonic": "mov", "op_str": "[rax+8], 67"},
                {"address": 0x101F, "mnemonic": "ret", "op_str": ""},
            ],
            [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": {"malloc"}, "accesses": []},
            ],
        )
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        self.assertIn("heap_ptr[24]", code)


class TestCharLiteral(unittest.TestCase):
    """Char literal rendering for byte-sized stores."""

    def setUp(self):
        self.d = Disassembler()

    def _make_analysis(self, insns, stack_vars):
        return {
            "address": 0x1000,
            "size": 60,
            "insns": insns,
            "stack_frame": 16,
            "stack_vars": stack_vars,
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x1020,
            "basic_blocks": [[0x1000, 0x1020]],
        }

    def test_byte_store_printable(self):
        """byte ptr store of printable constant renders as char literal."""
        analysis = self._make_analysis(
            [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 24"},
                {"address": 0x100C, "mnemonic": "call", "op_str": "0x10b0"},
                {"address": 0x1011, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1015, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                {"address": 0x1019, "mnemonic": "mov", "op_str": "byte ptr [rax], 65"},
                {"address": 0x101C, "mnemonic": "ret", "op_str": ""},
            ],
            [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": {"malloc"}, "accesses": []},
            ],
        )
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        self.assertIn("heap_ptr[0] = 'A'", code)
        self.assertNotIn("heap_ptr[0] = 65", code)

    def test_byte_store_hex(self):
        """byte ptr store of 0x41 renders as 'A' too."""
        analysis = self._make_analysis(
            [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 24"},
                {"address": 0x100C, "mnemonic": "call", "op_str": "0x10b0"},
                {"address": 0x1011, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1015, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                {"address": 0x1019, "mnemonic": "mov", "op_str": "byte ptr [rax], 0x41"},
                {"address": 0x101C, "mnemonic": "ret", "op_str": ""},
            ],
            [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": {"malloc"}, "accesses": []},
            ],
        )
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        self.assertIn("heap_ptr[0] = 'A'", code)
        self.assertNotIn("heap_ptr[0] = 65", code)

    def test_byte_store_non_printable(self):
        """byte ptr store of non-printable stays numeric."""
        analysis = self._make_analysis(
            [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 24"},
                {"address": 0x100C, "mnemonic": "call", "op_str": "0x10b0"},
                {"address": 0x1011, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1015, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                {"address": 0x1019, "mnemonic": "mov", "op_str": "byte ptr [rax], 0"},
                {"address": 0x101C, "mnemonic": "ret", "op_str": ""},
            ],
            [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": {"malloc"}, "accesses": []},
            ],
        )
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        self.assertIn("heap_ptr[0] = 0", code)

    def test_dword_store_not_char(self):
        """dword ptr store should stay numeric even if printable."""
        analysis = self._make_analysis(
            [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 24"},
                {"address": 0x100C, "mnemonic": "call", "op_str": "0x10b0"},
                {"address": 0x1011, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1015, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                {"address": 0x1019, "mnemonic": "mov", "op_str": "dword ptr [rax], 65"},
                {"address": 0x101C, "mnemonic": "ret", "op_str": ""},
            ],
            [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": {"malloc"}, "accesses": []},
            ],
        )
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        self.assertIn("heap_ptr[0] = 65", code)
        self.assertNotIn("'A'", code)

    def test_byte_store_with_offset(self):
        """byte ptr [rax+16] printable renders as char with offset."""
        analysis = self._make_analysis(
            [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 24"},
                {"address": 0x100C, "mnemonic": "call", "op_str": "0x10b0"},
                {"address": 0x1011, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1015, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                {"address": 0x1019, "mnemonic": "mov", "op_str": "byte ptr [rax+8], 0x48"},
                {"address": 0x101C, "mnemonic": "ret", "op_str": ""},
            ],
            [
                {"offset": -8, "name": "local_8", "suggested": "heap_ptr", "used_by_funcs": {"malloc"}, "accesses": []},
            ],
        )
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        self.assertIn("heap_ptr[8] = 'H'", code)


class TestReturnType(unittest.TestCase):
    """Return type detection from pointer stack variables."""

    def setUp(self):
        self.d = Disassembler()

    def test_pointer_return_from_stack_var(self):
        """Function returning a pointer-typed stack var gets char* return type."""
        analysis = {
            "address": 0x1000,
            "size": 50,
            "insns": [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "rdi, 32"},
                {"address": 0x100C, "mnemonic": "call", "op_str": "0x10b0"},
                {"address": 0x1011, "mnemonic": "mov", "op_str": "[rbp-8], rax"},
                {"address": 0x1015, "mnemonic": "mov", "op_str": "rax, [rbp-8]"},
                {"address": 0x1019, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0x10,
            "stack_vars": [
                {"offset": -8, "name": "local_8", "suggested": "buf", "used_by_funcs": set(), "accesses": []},
            ],
            "calls": [
                {"from": 0x100C, "to": 0x10B0, "name": "malloc@GLIBC_2.0", "type": "call"},
            ],
            "prologue": 0x1000,
            "epilogue": 0x1019,
            "basic_blocks": [[0x1000, 0x1019]],
        }
        code = self.d.decompile_function(analysis, {0x10B0: "malloc@GLIBC_2.0"})
        # Find the signature line (after comment lines)
        sig_line = next(ln for ln in code.split("\n") if ln.strip() and not ln.startswith("//"))
        self.assertIn("char*", sig_line, "Return type should be char*")
        self.assertNotIn("int ", sig_line, "Should not be int")
        # Variable should also be char* (passed to puts/free)
        self.assertIn("char* buf", code)
        self.assertIn("return buf", code)

    def test_int_return_kept_for_constant(self):
        """Function returning a constant keeps int return type."""
        analysis = {
            "address": 0x1000,
            "size": 30,
            "insns": [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "mov", "op_str": "eax, 0"},
                {"address": 0x1009, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0,
            "stack_vars": [],
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x1009,
            "basic_blocks": [[0x1000, 0x1009]],
        }
        code = self.d.decompile_function(analysis, {})
        sig_line = next(ln for ln in code.split("\n") if ln.strip() and not ln.startswith("//"))
        self.assertIn("int ", sig_line, "Return type should be int")
        self.assertNotIn("char*", sig_line, "Should not be char*")


class TestShiftInstructions(unittest.TestCase):
    """Shift instruction (shl/shr) decompilation output."""

    def setUp(self):
        self.d = Disassembler()

    def test_shl_immediate(self):
        """shl rax, 3 → rax <<= 3"""
        analysis = {
            "address": 0x1000,
            "size": 20,
            "insns": [
                {"address": 0x1000, "mnemonic": "mov", "op_str": "rax, 1"},
                {"address": 0x1007, "mnemonic": "shl", "op_str": "rax, 3"},
                {"address": 0x100B, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0,
            "stack_vars": [],
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x100B,
            "basic_blocks": [[0x1000, 0x100B]],
        }
        code = self.d.decompile_function(analysis, {})
        self.assertIn("rax <<= 3", code)

    def test_shl_reg_expr_tracking(self):
        """shl writes to register that feeds into memory — expression tracks as mul."""
        analysis = {
            "address": 0x1000,
            "size": 24,
            "insns": [
                {"address": 0x1000, "mnemonic": "mov", "op_str": "eax, dword ptr [rbp - 8]"},
                {"address": 0x1003, "mnemonic": "shl", "op_str": "eax, 2"},
                {"address": 0x1006, "mnemonic": "mov", "op_str": "dword ptr [rbp - 8], eax"},
                {"address": 0x1009, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0x10,
            "stack_vars": [{"offset": -8, "name": "local_8", "size": 4}],
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x1009,
            "basic_blocks": [[0x1000, 0x1009]],
        }
        code = self.d.decompile_function(analysis, {})
        # The shl with constant is tracked as mul(*4) in expression; value stored back to var
        self.assertIn("local_8", code)

    def test_shr_immediate(self):
        """shr rax, 2 → rax >>= 2"""
        analysis = {
            "address": 0x1000,
            "size": 20,
            "insns": [
                {"address": 0x1000, "mnemonic": "mov", "op_str": "rax, 64"},
                {"address": 0x1007, "mnemonic": "shr", "op_str": "rax, 2"},
                {"address": 0x100B, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0,
            "stack_vars": [],
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x100B,
            "basic_blocks": [[0x1000, 0x100B]],
        }
        code = self.d.decompile_function(analysis, {})
        self.assertIn("rax >>= 2", code)

    def test_sal_as_shl(self):
        """sal is synonymous with shl"""
        analysis = {
            "address": 0x1000,
            "size": 20,
            "insns": [
                {"address": 0x1000, "mnemonic": "mov", "op_str": "rax, 1"},
                {"address": 0x1007, "mnemonic": "sal", "op_str": "rax, 1"},
                {"address": 0x100B, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0,
            "stack_vars": [],
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x100B,
            "basic_blocks": [[0x1000, 0x100B]],
        }
        code = self.d.decompile_function(analysis, {})
        self.assertIn("rax <<= 1", code)


class TestAliasStackVar(unittest.TestCase):
    """Alias through lea resolves to stack variable names."""

    def setUp(self):
        self.d = Disassembler()

    def test_lea_to_stack_var(self):
        """lea rax, [rbp-8]; mov [rax], 42 → rax = &local_8, then stores through it"""
        analysis = {
            "address": 0x1000,
            "size": 24,
            "insns": [
                {"address": 0x1000, "mnemonic": "lea", "op_str": "rax, qword ptr [rbp - 8]"},
                {"address": 0x1005, "mnemonic": "mov", "op_str": "qword ptr [rax], 42"},
                {"address": 0x1009, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0x10,
            "stack_vars": [{"offset": -8, "name": "local_8", "size": 8}],
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x1009,
            "basic_blocks": [[0x1000, 0x1009]],
        }
        code = self.d.decompile_function(analysis, {})
        # LEA resolves to &local_8, then [rax] store resolves through the alias
        self.assertIn("local_8", code)

    def test_lea_indirect_store(self):
        """lea rax, [rbp-4]; mov [rax+4], byte 0x41 → local_4[4] = 'A' via alias"""
        analysis = {
            "address": 0x1000,
            "size": 24,
            "insns": [
                {"address": 0x1000, "mnemonic": "lea", "op_str": "rax, qword ptr [rbp - 4]"},
                {"address": 0x1005, "mnemonic": "mov", "op_str": "byte ptr [rax + 4], 0x41"},
                {"address": 0x1009, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0x10,
            "stack_vars": [
                {"offset": -4, "name": "local_4", "size": 4},
                {"offset": 0, "name": "local_0", "size": 4},
            ],
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x1009,
            "basic_blocks": [[0x1000, 0x1009]],
        }
        code = self.d.decompile_function(analysis, {})
        # rax resolves to local_4 (rbp-4), so [rax+4] = local_4[4]
        self.assertIn("local_4", code)
        self.assertIn("[4]", code)


class TestServerCrashRegressions(unittest.TestCase):
    """Regression tests for bugs found in server-side usage."""

    def setUp(self):
        self.d = Disassembler()

    def test_stack_var_with_non_call_preceding(self):
        """No UnboundLocalError when stack var emerges after non-call instruction."""
        analysis = {
            "address": 0x1000,
            "size": 24,
            "insns": [
                {"address": 0x1000, "mnemonic": "mov", "op_str": "rax, 42"},
                {"address": 0x1003, "mnemonic": "mov", "op_str": "dword ptr [rbp-8], eax"},
                {"address": 0x1007, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0x10,
            "stack_vars": [
                {"offset": -8, "name": "local_8", "size": 4, "used_by_funcs": [], "accesses": []},
            ],
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x1007,
            "basic_blocks": [[0x1000, 0x1007]],
        }
        code = self.d.decompile_function(analysis, {})
        self.assertIn("local_8", code)

    def test_call_arg_with_expr_reg(self):
        """No TypeError when function call arg is an Expr object."""
        analysis = {
            "address": 0x1000,
            "size": 40,
            "insns": [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x1004, "mnemonic": "sub", "op_str": "rsp, 0x10"},
                {"address": 0x1008, "mnemonic": "mov", "op_str": "edi, 0x20"},
                {"address": 0x100D, "mnemonic": "call", "op_str": "0x1200"},
                {"address": 0x1012, "mnemonic": "mov", "op_str": "qword ptr [rbp-8], rax"},
                {"address": 0x1016, "mnemonic": "mov", "op_str": "rdi, qword ptr [rbp-8]"},
                {"address": 0x101A, "mnemonic": "call", "op_str": "0x1220"},
                {"address": 0x101F, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0x10,
            "stack_vars": [
                {"offset": -8, "name": "local_8", "size": 8, "suggested": "buf", "used_by_funcs": [], "accesses": []},
            ],
            "calls": [
                {"from": 0x100D, "to": 0x1200, "type": "call"},
                {"from": 0x101A, "to": 0x1220, "type": "call"},
            ],
            "prologue": 0x1000,
            "epilogue": 0x101F,
            "basic_blocks": [[0x1000, 0x101F]],
        }
        code = self.d.decompile_function(analysis, {0x1200: "malloc", 0x1220: "puts"})
        # Should not crash with TypeError. Second call should pass buffer as arg.
        self.assertIn("puts", code)


class TestConditionalControlFlow(unittest.TestCase):
    """The cmp/test + Jcc -> `if (...) goto L_x;` branch of decompile_function."""

    @classmethod
    def setUpClass(cls):
        cls.d = Disassembler()
        insns = [
            {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
            {"address": 0x1001, "mnemonic": "mov", "op_str": "rbp, rsp"},
            {"address": 0x1004, "mnemonic": "mov", "op_str": "dword ptr [rbp - 4], edi"},
            {"address": 0x1007, "mnemonic": "cmp", "op_str": "dword ptr [rbp - 4], 0"},
            {"address": 0x100B, "mnemonic": "je", "op_str": "0x1016"},
            {"address": 0x100D, "mnemonic": "mov", "op_str": "eax, 1"},
            {"address": 0x1012, "mnemonic": "jmp", "op_str": "0x101B"},
            {"address": 0x1016, "mnemonic": "mov", "op_str": "eax, 0"},
            {"address": 0x101B, "mnemonic": "jg", "op_str": "0x1020"},
            {"address": 0x101E, "mnemonic": "nop", "op_str": ""},
            {"address": 0x1020, "mnemonic": "leave", "op_str": ""},
            {"address": 0x1021, "mnemonic": "ret", "op_str": ""},
        ]
        cls.analysis = {
            "address": 0x1000,
            "size": 0x22,
            "insns": insns,
            "stack_frame": 0x10,
            "stack_vars": [],
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x1021,
            "basic_blocks": [[0x1000, 0x1021]],
        }
        cls.code = cls.d.decompile_function(cls.analysis, {})

    def test_emits_goto(self):
        self.assertIn("goto L_", self.code)

    def test_inverted_branch_uses_the_jmp_target(self):
        # je (==) inverted to != when followed by jmp; target is the jmp's 0x101b
        self.assertIn("if (", self.code)
        self.assertIn("goto L_101b;", self.code)

    def test_plain_conditional_branch(self):
        self.assertTrue("goto L_1020;" in self.code or "if (unlikely)" in self.code)


class TestDecompilerBadOperands(unittest.TestCase):
    """Non-hex jump operands hit the `except ValueError` comment fallbacks."""

    def test_indirect_jump_operand_is_commented(self):
        d = Disassembler()
        analysis = {
            "address": 0x2000,
            "size": 8,
            "insns": [
                {"address": 0x2000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x2001, "mnemonic": "jne", "op_str": "rax"},
                {"address": 0x2003, "mnemonic": "jmp", "op_str": "rdx"},
                {"address": 0x2005, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0,
            "stack_vars": [],
            "calls": [],
            "prologue": 0x2000,
            "epilogue": 0x2005,
            "basic_blocks": [[0x2000, 0x2005]],
        }
        code = d.decompile_function(analysis, {})
        assert "/*" in code


class TestExprHelpers(unittest.TestCase):
    """Direct coverage of the module-level expression helpers."""

    def test_expr_to_base_offset_add_sub_mul_chains(self):
        from triage_web.engine import _expr_to_base_offset

        base = Expr.var("reg_heap_ptr")  # prefix is stripped
        self.assertEqual(_expr_to_base_offset(base), ("heap_ptr", 0))

        added = Expr.add(Expr.var("var_buf"), Expr.const(16))
        self.assertEqual(_expr_to_base_offset(added), ("buf", 16))

        subbed = Expr.sub(Expr.var("p"), Expr.const(4))
        self.assertEqual(_expr_to_base_offset(subbed), ("p", -4))

        scaled = Expr.mul(Expr.var("i"), Expr.const(8))
        self.assertEqual(_expr_to_base_offset(scaled), ("i", 0))

    def test_expr_to_base_offset_rejects_non_var_shapes(self):
        from triage_web.engine import _expr_to_base_offset

        self.assertIsNone(_expr_to_base_offset("not-an-expr"))
        self.assertIsNone(_expr_to_base_offset(Expr.const(5)))
        # sub / mul whose right side is not a plain const → None
        self.assertIsNone(_expr_to_base_offset(Expr.sub(Expr.var("x"), Expr.var("y"))))
        self.assertIsNone(_expr_to_base_offset(Expr.mul(Expr.var("x"), Expr.var("y"))))

    def test_reg_lookup_follows_register_aliases(self):
        from triage_web.engine import _reg_lookup

        regs = {"rax": Expr.const(0x140)}
        self.assertEqual(_reg_lookup("eax", regs), "0x140")  # eax → rax alias
        self.assertIsNone(_reg_lookup("rbx", regs))

    def test_resolve_mem_ref_and_parse_hex_failure_paths(self):
        from triage_web.engine import _parse_hex, _resolve_mem_ref

        self.assertIsNone(_parse_hex("zzz"))
        self.assertIsNone(_parse_hex(None))
        # a well-formed ref to an offset with no known variable → None
        self.assertIsNone(_resolve_mem_ref("[rbp - 0x8]", {}))
        # not a memory reference at all → None
        self.assertIsNone(_resolve_mem_ref("rax", {-8: {"name": "v"}}))


class TestGuessVarType(unittest.TestCase):
    """Disassembler._guess_var_type usage-pattern heuristics."""

    def test_type_from_library_function_argument(self):
        v = {"name": "local_10", "used_by_funcs": {"strcpy@GLIBC"}, "accesses": []}
        self.assertEqual(Disassembler._guess_var_type(v, []), "char*")

    def test_type_from_lea_access_is_pointer(self):
        v = {"name": "local_10", "used_by_funcs": set(), "accesses": [{"mnemonic": "lea"}]}
        self.assertEqual(Disassembler._guess_var_type(v, []), "char*")

    def test_qword_access_width_is_long(self):
        v = {
            "name": "local_10",
            "used_by_funcs": set(),
            "accesses": [{"mnemonic": "mov", "context": "qword ptr [rbp - 0x10]"}],
        }
        self.assertEqual(Disassembler._guess_var_type(v, []), "long")

    def test_name_heuristic_then_int_default(self):
        ptr = {"name": "local_10", "suggested": "src_buf", "used_by_funcs": set(), "accesses": []}
        self.assertEqual(Disassembler._guess_var_type(ptr, []), "char*")
        plain = {"name": "local_10", "suggested": "local_10", "used_by_funcs": set(), "accesses": []}
        self.assertEqual(Disassembler._guess_var_type(plain, []), "int")


class TestDetectParams(unittest.TestCase):
    """Disassembler._detect_params recovers 32-bit [ebp+N] arguments."""

    def test_thirtytwo_bit_args_are_indexed(self):
        insns = [
            {"op_str": "eax, dword ptr [ebp + 8]"},
            {"op_str": "edx, dword ptr [ebp + 0xc]"},
            {"op_str": "eax, dword ptr [ebp + 8]"},  # dup — collapsed
        ]
        sig = Disassembler._detect_params(insns, {}, is_64=False)
        self.assertEqual(sig, "int arg_1, int arg_2")

    def test_sixtyfour_bit_returns_empty(self):
        insns = [{"op_str": "rax, qword ptr [rbp - 8]"}]
        self.assertEqual(Disassembler._detect_params(insns, {}, is_64=True), "")


class TestSuggestVarNames(unittest.TestCase):
    """Disassembler._suggest_var_names collision-suffixes duplicate identifiers."""

    def test_two_free_vars_do_not_collide(self):
        d = Disassembler()
        stack_vars = {
            "local_8": {"offset": -8, "used_by_funcs": {"free@GLIBC"}},
            "local_10": {"offset": -16, "used_by_funcs": {"free@GLIBC"}},
        }
        d._suggest_var_names(stack_vars)
        names = {v["suggested"] for v in stack_vars.values()}
        self.assertEqual(names, {"heap_ptr", "heap_ptr_2"})

    def test_result_of_malloc_and_scanf_names(self):
        d = Disassembler()
        stack_vars = {
            "a": {"offset": -8, "result_of": "malloc@@plt"},
            "b": {"offset": -16, "used_by_funcs": {"__isoc99_scanf"}},
            "c": {"offset": -24, "result_of": "getenv@@plt"},
        }
        d._suggest_var_names(stack_vars)
        self.assertEqual(stack_vars["a"]["suggested"], "heap_ptr")
        self.assertEqual(stack_vars["b"]["suggested"], "input_buf")
        self.assertEqual(stack_vars["c"]["suggested"], "getenv_res")


class TestInsnToC(unittest.TestCase):
    """Disassembler._insn_to_c operand-shape coverage."""

    @staticmethod
    def _c(mnemonic, op_str, *, regs=None, var_by_off=None, is_64=True, string_map=None):
        insn = {"mnemonic": mnemonic, "op_str": op_str}
        return Disassembler._insn_to_c(insn, regs or {}, {}, var_by_off or {}, is_64, string_map)

    def test_push_pop_nop_and_unknown(self):
        self.assertEqual(self._c("push", "rbp"), "")
        self.assertEqual(self._c("pop", "rbx"), "rbx = pop()")
        self.assertEqual(self._c("nop", ""), "")
        self.assertEqual(self._c("cpuid", ""), "/* cpuid  */")

    def test_inc_dec_on_memory_operand(self):
        self.assertEqual(self._c("inc", "dword ptr [rip + 0x2000]"), "dword ptr [rip + 0x2000]++")
        self.assertEqual(self._c("dec", "dword ptr [rip + 0x2000]"), "dword ptr [rip + 0x2000]--")

    def test_and_or_two_operands(self):
        self.assertEqual(self._c("and", "eax, ebx"), "eax &= ebx")
        self.assertEqual(self._c("or", "eax, 0xff"), "eax |= 255")

    def test_shift_on_register(self):
        self.assertEqual(self._c("shl", "eax, 4"), "eax <<= 4")
        self.assertEqual(self._c("sar", "edx, 2"), "edx >>= 2")

    def test_movsxd_register_to_register_is_suppressed(self):
        self.assertEqual(self._c("movsxd", "rax, eax"), "")

    def test_mov_through_pointer_writes_deref(self):
        out = self._c("mov", "qword ptr [rcx], rax")
        self.assertEqual(out, "*rcx = rax")

    def test_mov_stack_slot_resolves_named_var(self):
        var_by_off = {-8: {"name": "local_8", "suggested": "heap_ptr"}}
        out = self._c("mov", "qword ptr [rbp - 8], rax", var_by_off=var_by_off)
        self.assertEqual(out, "heap_ptr = rax")

    def test_mov_byte_store_becomes_char_literal(self):
        out = self._c("mov", "byte ptr [rbp - 8], 0x41", var_by_off={-8: {"name": "c"}})
        self.assertIn("'A'", out)

    def test_mov_immediate_maps_through_string_map(self):
        out = self._c("mov", "rdi, 0x4006a0", string_map={0x4006A0: '"hello"'})
        # dst is a register → no C line; the string map is exercised via _r on load
        self.assertEqual(out, "")

    def test_lea_stack_var_takes_address(self):
        var_by_off = {-32: {"name": "buf", "suggested": "buf"}}
        out = self._c("lea", "rax, [rbp - 0x20]", var_by_off=var_by_off)
        self.assertEqual(out, "rax = &buf")


class TestUpdateRegState(unittest.TestCase):
    """Disassembler._update_reg_state expression-tree bookkeeping."""

    @staticmethod
    def _step(mnemonic, op_str, regs):
        Disassembler._update_reg_state({"mnemonic": mnemonic, "op_str": op_str}, regs, {}, True)
        return regs

    def test_mov_immediate_and_reg_copy(self):
        regs = self._step("mov", "rax, 0x2a", {})
        self.assertEqual(regs["rax"].op, "const")
        self._step("mov", "rbx, rax", regs)
        self.assertEqual(regs["rbx"].op, "const")  # value forwarded

    def test_add_sub_fold_and_drop(self):
        regs = {"rax": Expr.const(8)}
        self._step("add", "rax, 8", regs)
        self.assertEqual(regs["rax"].args[0], 16)  # 8+8 folded
        self._step("sub", "rax, 0x4", regs)
        self.assertEqual(regs["rax"].args[0], 12)
        # add into a register with no known Expr → forget it
        regs["rcx"] = "junk"
        self._step("add", "rcx, 1", regs)
        self.assertNotIn("rcx", regs)
        # add into a memory destination → the pop(dst) / return tail
        self.assertIsNone(self._step("add", "qword ptr [rbp - 8], rax", regs).get("[rbp"))

    def test_inc_dec_track_or_forget(self):
        regs = {"rax": Expr.const(5)}
        self._step("inc", "rax", regs)
        self.assertEqual(regs["rax"].args[0], 6)
        self._step("dec", "rax", regs)
        self.assertEqual(regs["rax"].args[0], 5)
        regs["rdx"] = "opaque"
        self._step("inc", "rdx", regs)
        self.assertNotIn("rdx", regs)

    def test_shifts_scale_or_clear(self):
        regs = {"rax": Expr.var("i")}
        self._step("shl", "rax, 3", regs)  # i << 3  →  i * 8
        self.assertEqual(regs["rax"].op, "mul")
        self.assertEqual(regs["rax"].args[1].args[0], 8)
        regs2 = {"rax": Expr.var("i")}
        self._step("sar", "rax, 1", regs2)  # arithmetic shift right → give up
        self.assertNotIn("rax", regs2)

    def test_multiplicative_and_pop_clear_dest(self):
        regs = {"rax": Expr.const(3), "rcx": Expr.const(9)}
        self._step("imul", "rax, rcx", regs)
        self.assertNotIn("rax", regs)
        self._step("pop", "rcx", regs)
        self.assertNotIn("rcx", regs)


class TestExprPrimitives(unittest.TestCase):
    """The bare Expr constructors, folds and _expr_str formatting."""

    def test_add_mul_identity_folds_on_the_left(self):
        x = Expr.var("x")
        self.assertIs(Expr.add(Expr.const(0), x), x)  # 0 + x → x
        self.assertIs(Expr.mul(Expr.const(1), x), x)  # 1 * x → x

    def test_bitwise_and_unary_constructors(self):
        v = Expr.var("v")
        self.assertEqual(Expr.neg(v).op, "neg")
        self.assertEqual(Expr.not_(v).op, "not_")
        self.assertEqual(Expr.and_(v, Expr.const(3)).op, "and_")
        self.assertEqual(Expr.or_(v, Expr.const(4)).op, "or_")

    def test_is_const_int_helper(self):
        from triage_web.engine import _is_const_int

        self.assertTrue(_is_const_int(Expr.const(5)))
        self.assertTrue(_is_const_int(Expr.const(5), 5))
        self.assertFalse(_is_const_int(Expr.const(5), 6))
        self.assertFalse(_is_const_int(Expr.var("x")))

    def test_expr_str_unary_and_bitwise(self):
        from triage_web.engine import _expr_str

        self.assertEqual(_expr_str(Expr.neg(Expr.var("a"))), "-a")
        self.assertEqual(_expr_str(Expr.not_(Expr.var("a"))), "~a")
        self.assertEqual(_expr_str(Expr.and_(Expr.var("a"), Expr.var("b"))), "a & b")
        self.assertEqual(_expr_str(Expr.or_(Expr.var("a"), Expr.var("b"))), "a | b")

    def test_expr_str_pointer_offset_notation(self):
        from triage_web.engine import _expr_str

        # built raw so the Expr.add identity fold doesn't collapse the zero
        zero = Expr("add", Expr.var("p"), Expr.const(0))
        self.assertEqual(_expr_str(zero, wrap_parens=False), "p")
        neg = Expr.add(Expr.var("p"), Expr.const(-8))
        self.assertEqual(_expr_str(neg, wrap_parens=False), "p - 8")

    def test_expr_to_base_offset_none_tails(self):
        from triage_web.engine import _expr_to_base_offset

        # sub / mul whose left side doesn't reduce to a var → None
        self.assertIsNone(_expr_to_base_offset(Expr("sub", Expr.const(3), Expr.const(1))))
        self.assertIsNone(_expr_to_base_offset(Expr("mul", Expr.const(3), Expr.const(1))))
        self.assertIsNone(_expr_to_base_offset(Expr.neg(Expr.var("x"))))
        # add with a non-const right operand → the base is returned as-is
        self.assertEqual(_expr_to_base_offset(Expr("add", Expr.var("p"), Expr.var("q"))), ("p", 0))

    def test_expr_str_passes_non_expr_through_str(self):
        from triage_web.engine import _expr_str

        self.assertEqual(_expr_str(42), "42")


class TestStrlenIdiomVariants(unittest.TestCase):
    """_match_strlen_idiom rejection paths and the lea form."""

    @staticmethod
    def _mk(i1, i2):
        base = [
            {"mnemonic": "repne", "op_str": "scasb byte ptr [rdi]"},
            i1,
            i2,
            {"mnemonic": "nop", "op_str": ""},
            {"mnemonic": "nop", "op_str": ""},
        ]
        return Disassembler._match_strlen_idiom(base, 0)

    def test_lea_minus_one_form_is_accepted(self):
        got = self._mk(
            {"mnemonic": "not", "op_str": "ecx"},
            {"mnemonic": "lea", "op_str": "edx, [ecx - 1]"},
        )
        self.assertEqual(got, (3, "strlen(rdi)"))

    def test_wrong_second_instruction_is_rejected(self):
        self.assertIsNone(
            self._mk(
                {"mnemonic": "mov", "op_str": "eax, ecx"},  # not `not ecx`
                {"mnemonic": "dec", "op_str": "ecx"},
            )
        )

    def test_wrong_third_instruction_is_rejected(self):
        self.assertIsNone(
            self._mk(
                {"mnemonic": "not", "op_str": "ecx"},
                {"mnemonic": "add", "op_str": "ecx, 1"},  # neither dec nor lea
            )
        )
        self.assertIsNone(
            self._mk(
                {"mnemonic": "not", "op_str": "ecx"},
                {"mnemonic": "lea", "op_str": "edx, [ecx + 4]"},  # wrong lea src
            )
        )


class TestGuessVarTypeAccessWidth(unittest.TestCase):
    def test_word_and_byte_contexts_do_not_force_long(self):
        for ctx in ("word ptr [rbp - 2]", "byte ptr [rbp - 1]", "dword ptr [rbp - 4]"):
            v = {"name": "v", "suggested": "v", "used_by_funcs": set(), "accesses": [{"context": ctx}]}
            self.assertEqual(Disassembler._guess_var_type(v, []), "int")


class TestInsnToCMore(unittest.TestCase):
    @staticmethod
    def _c(mn, ops, *, regs=None, var_by_off=None, string_map=None, is_64=True):
        return Disassembler._insn_to_c(
            {"mnemonic": mn, "op_str": ops}, regs or {}, {}, var_by_off or {}, is_64, string_map
        )

    def test_r_helper_resolves_mem_ref_simple_deref_and_string(self):
        self.assertEqual(self._c("inc", "dword ptr [rbp - 8]", var_by_off={-8: {"name": "x"}}), "x++")
        self.assertEqual(self._c("inc", "[rbx]"), "*rbx++")
        self.assertEqual(self._c("inc", "[rbx]", regs={"rbx": Expr.var("p")}), "*(p)++")
        # _r() routes a raw 0x-immediate through the string map
        self.assertEqual(self._c("mov", "gs:0x10, 0x1234", string_map={0x1234: '"msg"'}), 'gs:0x10 = "msg"')

    def test_byte_store_of_a_non_numeric_value_is_left_alone(self):
        out = self._c(
            "mov",
            "byte ptr [rbp - 1], eax",
            regs={"rax": Expr.add(Expr.var("i"), Expr.const(1))},
            var_by_off={-1: {"name": "c"}},
        )
        self.assertEqual(out, "c = (i + 1)")  # _fmt_val hit the ValueError branch

    def test_store_through_reg_alias_to_stack_var_and_array(self):
        rbp_minus_8 = {"rax": Expr.add(Expr.var("rbp"), Expr.const(-8))}
        self.assertEqual(
            self._c("mov", "dword ptr [rax + 0], ecx", regs=rbp_minus_8, var_by_off={-8: {"name": "v"}}),
            "v = ecx",
        )
        self.assertEqual(self._c("mov", "dword ptr [rax + 4], ecx", regs={"rax": "buf"}), "buf[4] = ecx")
        self.assertEqual(
            self._c("mov", "qword ptr [rax], rcx", regs=rbp_minus_8, var_by_off={-8: {"name": "v"}}),
            "v = rcx",
        )

    def test_store_through_a_non_offset_expr_pointer(self):
        out = self._c("mov", "qword ptr [rax], rcx", regs={"rax": Expr.neg(Expr.var("p"))})
        self.assertEqual(out, "*-p = rcx")

    def test_mov_to_a_segment_operand_is_emitted_verbatim(self):
        self.assertEqual(self._c("mov", "gs:0x10, rax"), "gs:0x10 = rax")

    def test_lea_from_register_and_unresolved_source(self):
        self.assertIn("rax = ", self._c("lea", "rax, rbx", regs={"rbx": Expr.const(5)}))
        self.assertEqual(self._c("lea", "rax, [rip + rbx]"), "rax = [rip + rbx]")

    def test_add_on_memory_dest_and_reg_noops(self):
        self.assertEqual(self._c("add", "qword ptr [rbp - 8], 1"), "qword ptr [rbp - 8] += 1")
        for mn in ("inc", "dec", "neg", "not"):
            self.assertEqual(self._c(mn, "rax"), "")
        self.assertEqual(self._c("and", "rax, rax"), "")


class TestUpdateRegStateMore(unittest.TestCase):
    @staticmethod
    def _step(mn, ops, regs):
        Disassembler._update_reg_state({"mnemonic": mn, "op_str": ops}, regs, {}, True)
        return regs

    def test_op_expr_via_32bit_alias_and_opaque_operand(self):
        regs = self._step("mov", "eax, ebx", {"rbx": Expr.const(9)})  # ebx→rbx alias, Expr
        self.assertEqual(regs["eax"].args[0], 9)
        regs = self._step("mov", "eax, gs:0x10", {})  # unparseable → Expr.var(op)
        self.assertEqual(regs["eax"].op, "var")

    def test_dec_and_shift_without_a_tracked_expr(self):
        self.assertNotIn("rdx", self._step("dec", "rdx", {"rdx": "opaque"}))
        regs = self._step("shl", "rax, nothex", {"rax": Expr.var("i")})  # unparsable shift
        self.assertNotIn("rax", regs)


class TestDecompileFunctionEdges(unittest.TestCase):
    def test_runs_with_no_known_calls_argument(self):
        d = Disassembler()
        analysis = {
            "address": 0x1000,
            "size": 8,
            "insns": [
                {"address": 0x1000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x1001, "mnemonic": "xor", "op_str": "eax, eax"},
                {"address": 0x1003, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0,
            "stack_vars": [],
            "calls": [],
            "prologue": 0x1000,
            "epilogue": 0x1003,
            "basic_blocks": [[0x1000, 0x1003]],
        }
        assert "return 0" in d.decompile_function(analysis)  # known_calls defaulted

    def test_non_hex_branch_operand_is_swallowed(self):
        d = Disassembler()
        analysis = {
            "address": 0x2000,
            "size": 8,
            "insns": [
                {"address": 0x2000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x2001, "mnemonic": "je", "op_str": "0xnothex"},
                {"address": 0x2003, "mnemonic": "ret", "op_str": ""},
            ],
            "stack_frame": 0,
            "stack_vars": [],
            "calls": [],
            "prologue": 0x2000,
            "epilogue": 0x2003,
            "basic_blocks": [[0x2000, 0x2003]],
        }
        d.decompile_function(analysis, {})  # must not raise


class TestSuggestVarNamesBranches(unittest.TestCase):
    def test_each_usage_bucket(self):
        d = Disassembler()
        sv = {
            "a": {"offset": -8, "used_by_funcs": {"printf"}},
            "src_x": {"offset": -16, "used_by_funcs": {"strcpy"}},
            "b": {"offset": -24, "used_by_funcs": {"memcpy"}},
            "c": {"offset": -32, "used_by_funcs": {"system"}},
            "d": {"offset": -40, "used_by_funcs": {"malloc"}},
        }
        d._suggest_var_names(sv)
        self.assertEqual(sv["a"]["suggested"], "print_arg")
        self.assertEqual(sv["src_x"]["suggested"], "src_buf")
        self.assertEqual(sv["b"]["suggested"], "dst_buf")
        self.assertEqual(sv["c"]["suggested"], "cmd_str")
        self.assertEqual(sv["d"]["suggested"], "size_arg")

    def test_collision_suffix_increments_past_taken(self):
        d = Disassembler()
        sv = {
            "x": {"offset": -8, "used_by_funcs": {"free"}},
            "y": {"offset": -16, "used_by_funcs": {"free"}},
            "z": {"offset": -24, "used_by_funcs": {"free"}},
        }
        d._suggest_var_names(sv)
        assert {v["suggested"] for v in sv.values()} == {"heap_ptr", "heap_ptr_2", "heap_ptr_3"}


class TestDisassemblerCore(unittest.TestCase):
    def test_requires_capstone(self):
        import triage_web.engine as eng

        with unittest.mock.patch.object(eng, "HAS_CAPSTONE", False):
            with self.assertRaises(RuntimeError):
                Disassembler()

    def test_disassemble_honours_max_insns(self):
        d = Disassembler()
        # 4x `nop` ; `ret`
        insns = d.disassemble(b"\x90\x90\x90\x90\xc3", 0x1000, max_insns=2)
        self.assertEqual(len(insns), 2)

    def test_analyze_function_defaults_known_calls_and_survives_reg_sub(self):
        d = Disassembler()
        # push rbp; mov rbp,rsp; sub rsp, rax  (49 89 e5 ... `sub rsp,rax`=48 29 c4)
        code = b"\x55\x48\x89\xe5\x48\x29\xc4\xc3"
        an = d.analyze_function(code, 0x1000)  # no known_calls
        assert an["stack_frame"] == 0  # `sub rsp, rax` → the except path, frame stays 0
        assert an["insns"][0]["mnemonic"] == "push"


class TestGetCallArgs(unittest.TestCase):
    def setUp(self):
        self.d = Disassembler()
        self.rid = lambda op, hint="": op  # identity resolve_op

    def test_xor_zeroed_arg_register(self):
        insns = [
            {"mnemonic": "xor", "op_str": "esi, esi"},
            {"mnemonic": "mov", "op_str": "edi, 1"},
            {"mnemonic": "call", "op_str": "0x40"},
        ]
        args = self.d._get_call_args(insns, {}, {}, self.rid, 2)
        self.assertEqual(args[:2], ["1", "0"])  # rdi=1, rsi=0

    def test_arg_registers_pulled_from_tracked_reg_state(self):
        insns = [
            {"mnemonic": "mov", "op_str": "rdi, 1"},
            {"mnemonic": "call", "op_str": "0x40"},
        ]
        regs = {"rsi": Expr.var("a"), "edx": Expr.const(5)}
        args = self.d._get_call_args(insns, regs, {}, self.rid, 1)
        self.assertEqual(args, ["1", "a", "5"])  # rdi arg_val, rsi Expr, rdx via 32-bit alias

    def test_pushed_stack_arguments(self):
        insns = [
            {"mnemonic": "push", "op_str": "0x2"},
            {"mnemonic": "push", "op_str": "0x1"},
            {"mnemonic": "call", "op_str": "0x40"},
        ]
        args = self.d._get_call_args(insns, {}, {}, self.rid, 2)
        self.assertEqual(set(args), {"0x1", "0x2"})

    def test_stale_rsp0_write_is_dropped(self):
        insns = [
            {"mnemonic": "mov", "op_str": "dword ptr [rsp], 0x9"},  # stale (written later in prog)
            {"mnemonic": "mov", "op_str": "dword ptr [rsp + 4], 0x1"},
            {"mnemonic": "call", "op_str": "0x40"},
        ]
        args = self.d._get_call_args(insns, {}, {}, self.rid, 2)
        self.assertEqual(args, ["0x1"])  # [rsp+0] pruned as stale


class TestDecompileCallAndJumpForms(unittest.TestCase):
    @staticmethod
    def _an(insns, **kw):
        base = {
            "address": insns[0]["address"],
            "size": 64,
            "stack_frame": 0,
            "stack_vars": [],
            "calls": [],
            "prologue": insns[0]["address"],
            "epilogue": insns[-1]["address"],
            "basic_blocks": [[insns[0]["address"], insns[-1]["address"]]],
        }
        base.update(kw)
        base["insns"] = insns
        return base

    def test_bare_call_and_indirect_call_target(self):
        d = Disassembler()
        an = self._an(
            [
                {"address": 0x10, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x11, "mnemonic": "call", "op_str": "rax"},  # non-hex → ops verbatim
                {"address": 0x13, "mnemonic": "call", "op_str": "0x2000"},  # bare, no args
                {"address": 0x18, "mnemonic": "ret", "op_str": ""},
            ]
        )
        code = d.decompile_function(an, {0x2000: "helper@@GLIBC_2.2.5"})
        self.assertIn("rax();", code)
        self.assertIn("helper();", code)  # @@ suffix stripped

    def test_call_return_value_inlined_into_a_stack_var(self):
        d = Disassembler()
        an = self._an(
            [
                {"address": 0x10, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x11, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x14, "mnemonic": "call", "op_str": "0x2000"},
                {"address": 0x19, "mnemonic": "mov", "op_str": "qword ptr [rbp - 8], rax"},
                {"address": 0x1D, "mnemonic": "ret", "op_str": ""},
            ],
            stack_vars=[{"offset": -8, "name": "local_8", "suggested": "r", "used_by_funcs": set(), "accesses": []}],
        )
        code = d.decompile_function(an, {0x2000: "getpid"})
        self.assertIn("r = getpid();", code)

    def test_plain_conditional_branch_without_a_trailing_jmp(self):
        d = Disassembler()
        an = self._an(
            [
                {"address": 0x10, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x11, "mnemonic": "cmp", "op_str": "eax, 0"},
                {"address": 0x14, "mnemonic": "je", "op_str": "0x20"},
                {"address": 0x16, "mnemonic": "mov", "op_str": "eax, 1"},
                {"address": 0x20, "mnemonic": "ret", "op_str": ""},
            ]
        )
        code = d.decompile_function(an, {})
        self.assertIn("if (eax == 0) goto L_20;", code)

    def test_branch_inversion_with_a_non_hex_jmp_target_is_swallowed(self):
        d = Disassembler()
        an = self._an(
            [
                {"address": 0x10, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x11, "mnemonic": "cmp", "op_str": "eax, ebx"},
                {"address": 0x14, "mnemonic": "je", "op_str": "0x30"},
                {"address": 0x16, "mnemonic": "jmp", "op_str": "rax"},  # non-hex → inversion aborts
                {"address": 0x30, "mnemonic": "ret", "op_str": ""},
            ]
        )
        code = d.decompile_function(an, {})  # must not raise
        self.assertIn("goto L_30;", code)

    def test_unconditional_jump_to_a_hex_target(self):
        d = Disassembler()
        an = self._an(
            [
                {"address": 0x10, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x11, "mnemonic": "jmp", "op_str": "0x40"},
                {"address": 0x13, "mnemonic": "mov", "op_str": "eax, 2"},
                {"address": 0x40, "mnemonic": "ret", "op_str": ""},
            ]
        )
        code = d.decompile_function(an, {})
        self.assertIn("goto L_40;", code)

    def test_pointer_return_type_is_dropped_when_rax_comes_from_a_call(self):
        d = Disassembler()
        an = self._an(
            [
                {"address": 0x10, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x11, "mnemonic": "mov", "op_str": "eax, 1"},  # has_retval
                {"address": 0x16, "mnemonic": "call", "op_str": "0x2000"},  # last rax writer → break
                {"address": 0x1B, "mnemonic": "ret", "op_str": ""},
            ]
        )
        code = d.decompile_function(an, {0x2000: "f"})
        self.assertIn("int func_10(void)", code)  # rax from callee → ret type stays int

    def test_thirtytwo_bit_signature_gets_detected_params(self):
        d = Disassembler()
        an = self._an(
            [
                {"address": 0x10, "mnemonic": "push", "op_str": "ebp"},
                {"address": 0x11, "mnemonic": "mov", "op_str": "ebp, esp"},
                {"address": 0x13, "mnemonic": "mov", "op_str": "eax, dword ptr [ebp + 8]"},
                {"address": 0x16, "mnemonic": "ret", "op_str": ""},
            ]
        )
        code = d.decompile_function(an, {})
        self.assertIn("int arg_1", code)

    def test_string_map_resolves_a_pointer_argument(self):
        d = Disassembler()
        an = self._an(
            [
                {"address": 0x10, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x11, "mnemonic": "mov", "op_str": "rdi, 0x4006a0"},
                {"address": 0x18, "mnemonic": "call", "op_str": "0x2000"},
                {"address": 0x1D, "mnemonic": "ret", "op_str": ""},
            ]
        )
        code = d.decompile_function(an, {0x2000: "puts"}, string_map={0x4006A0: '"hello"'})
        self.assertIn('puts("hello")', code)


if __name__ == "__main__":
    unittest.main()
