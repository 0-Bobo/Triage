"""Tests for triage_web.solvers.

Every generator must emit syntactically valid Python, and the
static-string reconstructor must actually recover an immediate-write
string from raw machine code.
"""

from __future__ import annotations

import ast

import pytest

from triage_web import solvers


def test_solver_list_matches_generators() -> None:
    listed = {s["id"] for s in solvers.get_solver_list()}
    assert listed == set(solvers.SOLVER_GENERATORS)


@pytest.mark.parametrize("solver_id", sorted(solvers.SOLVER_GENERATORS))
@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("recovered", [(None, None), (0x401234, 40)], ids=["unrecovered", "recovered"])
def test_generated_script_is_valid_python(solver_id: str, bits: int, recovered: tuple[int | None, int | None]) -> None:
    pop_rdi, overflow_offset = recovered
    src = solvers.generate_solver(
        solver_id,
        "./target.bin",
        "x86_64" if bits == 64 else "x86",
        bits,
        pop_rdi=pop_rdi,
        overflow_offset=overflow_offset,
    )
    ast.parse(src)
    compile(src, f"<{solver_id}:{bits}:{recovered}>", "exec")
    assert "BINARY = './target.bin'" in src


def test_generate_solver_rejects_unknown_type() -> None:
    with pytest.raises(ValueError, match="Unknown solver type"):
        solvers.generate_solver("does_not_exist", "./x.bin", "x86", 64)


# ── ret2libc: real pop_rdi / overflow_offset wiring ─────────────────────


def test_ret2libc_bakes_a_real_pop_rdi_and_offset() -> None:
    src = solvers.generate_solver("ret2libc", "./target.bin", "x86_64", 64, pop_rdi=0x401234, overflow_offset=40)
    ast.parse(src)
    compile(src, "<ret2libc:known>", "exec")
    assert "POP_RDI = 0x401234" in src
    assert "OFFSET  = 40" in src
    assert "POP_RDI = 0x0" not in src


def test_ret2libc_falls_back_to_runtime_gadget_search_when_pop_rdi_unknown() -> None:
    src = solvers.generate_solver("ret2libc", "./target.bin", "x86_64", 64)
    ast.parse(src)
    compile(src, "<ret2libc:unknown>", "exec")
    assert "POP_RDI = 0x0" not in src
    assert 'rop.find_gadget(["pop rdi", "ret"])' in src
    assert "OFFSET  = 64" in src


# ── one_gadget_rce: real pop_rdi / overflow_offset wiring ───────────────


def test_one_gadget_rce_bakes_a_real_pop_rdi_and_offset() -> None:
    src = solvers.generate_solver("one_gadget_rce", "./target.bin", "x86_64", 64, pop_rdi=0x401234, overflow_offset=40)
    ast.parse(src)
    compile(src, "<one_gadget_rce:known>", "exec")
    assert "POP_RDI = 0x401234" in src
    assert "OFFSET  = 40" in src
    assert "POP_RDI = 0x0" not in src


def test_one_gadget_rce_falls_back_to_runtime_gadget_search_when_pop_rdi_unknown() -> None:
    src = solvers.generate_solver("one_gadget_rce", "./target.bin", "x86_64", 64)
    ast.parse(src)
    compile(src, "<one_gadget_rce:unknown>", "exec")
    assert "POP_RDI = 0x0" not in src
    assert 'rop.find_gadget(["pop rdi", "ret"])' in src
    assert "OFFSET  = 64" in src


def test_other_generators_unaffected_by_the_new_trailing_kwargs() -> None:
    for solver_id in sorted(solvers.SOLVER_GENERATORS):
        src = solvers.generate_solver(solver_id, "./target.bin", "x86_64", 64)
        ast.parse(src)
        compile(src, f"<{solver_id}>", "exec")


# ── shellcode_exploit: real offset + named BUF_ADDR ─────────────────────


def test_shellcode_exploit_bakes_a_real_offset() -> None:
    src = solvers.generate_solver("shellcode_exploit", "./target.bin", "x86_64", 64, overflow_offset=88)
    ast.parse(src)
    compile(src, "<shellcode:known>", "exec")
    assert "OFFSET  = 88" in src


def test_shellcode_exploit_keeps_the_documented_fallback_offset() -> None:
    src = solvers.generate_solver("shellcode_exploit", "./target.bin", "x86_64", 64)
    ast.parse(src)
    compile(src, "<shellcode:unknown>", "exec")
    assert "OFFSET  = 64" in src


def test_shellcode_exploit_exposes_buf_addr_as_a_named_constant() -> None:
    src = solvers.generate_solver("shellcode_exploit", "./target.bin", "x86_64", 64)
    ast.parse(src)
    compile(src, "<shellcode:buf_addr>", "exec")
    assert "BUF_ADDR = 0xdeadbeef" in src
    assert "p64(BUF_ADDR)" in src
    assert "p64(0xdeadbeef)" not in src


def test_shellcode_exploit_relies_on_elf_auto_detected_arch() -> None:
    """A 64-bit target must not have its architecture overwritten with an
    invalid, truncated value (e.g. "x86" instead of pwntools' "amd64") -
    the ELF-context binding already sets it correctly."""
    src = solvers.generate_solver("shellcode_exploit", "./target.bin", "x86_64", 64)
    ast.parse(src)
    compile(src, "<shellcode:arch>", "exec")
    assert 'context.arch  = "x86"' not in src
    assert "context.binary = ELF(BINARY" in src


# ── unicorn_emulate_func: named INPUT_BYTES ─────────────────────────────


def test_unicorn_emulate_func_declares_input_bytes_as_a_named_constant() -> None:
    src = solvers.generate_solver("unicorn_emulate_func", "./target.bin", "x86_64", 64)
    ast.parse(src)
    compile(src, "<unicorn:input_bytes>", "exec")
    assert 'INPUT_BYTES = b"INPUT-GOES-HERE\\x00"' in src
    assert "uc.mem_write(ARG1, INPUT_BYTES)" in src
    assert 'uc.mem_write(ARG1, b"INPUT-GOES-HERE' not in src


# 32-bit machine code that builds "FLAG-4092" via immediate MOV writes:
#   mov  dword [eax],     0x47414c46   ; "FLAG"
#   mov  dword [eax + 4], 0x3930342d   ; "-409"
#   mov  word  [eax + 8], 0x32         ; "2"
#   ret
_FLAG_BUILDER = bytes.fromhex("c700464c4147c740042d34303966c740083200c3")


def test_static_string_reconstruct_recovers_the_flag(tmp_path) -> None:
    blob = tmp_path / "builder.bin"
    blob.write_bytes(_FLAG_BUILDER)

    src = solvers.generate_solver("static_string_reconstruct", str(blob), "x86", 32)
    result = solvers.execute_solver(src)

    assert result["returncode"] == 0, result["stderr"]
    assert "FLAG-4092" in result["stdout"]
    assert "looks like a flag" in result["stdout"]


def test_static_string_reconstruct_on_a_real_elf(crackme_path) -> None:
    src = solvers.generate_solver("static_string_reconstruct", str(crackme_path), "x86_64", 64)
    result = solvers.execute_solver(src)

    assert result["returncode"] == 0, result["stderr"]
    assert "FLAG{ok}" in result["stdout"]


@pytest.mark.parametrize("code", ["", "   \n\t"])
def test_execute_solver_rejects_empty_code(code: str) -> None:
    r = solvers.execute_solver(code)
    assert r == {"stdout": "", "stderr": "No code provided", "returncode": -1}


def test_execute_solver_reports_a_nonzero_exit() -> None:
    r = solvers.execute_solver("import sys; sys.exit(3)")
    assert r["returncode"] == 3


def test_execute_solver_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(solvers, "SOLVER_TIMEOUT", 1)
    r = solvers.execute_solver("import time; time.sleep(30)")
    assert r["returncode"] == -1
    assert "timed out" in r["stderr"]


def test_execute_solver_wraps_unexpected_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a, **_k):
        raise RuntimeError("subprocess exploded")

    monkeypatch.setattr(solvers.subprocess, "run", boom)
    r = solvers.execute_solver("print('hi')")
    assert r["returncode"] == -1
    assert "subprocess exploded" in r["stderr"]


def test_execute_solver_survives_a_cleanup_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_unlink(_path):
        raise OSError("held open")

    monkeypatch.setattr(solvers.os, "unlink", no_unlink)
    r = solvers.execute_solver("print('ok')")
    assert r["returncode"] == 0 and r["stdout"].strip() == "ok"
