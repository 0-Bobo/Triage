"""Tests for triage_web.solvers.

Every generator must emit syntactically valid Python, and the
static-string reconstructor must actually recover an immediate-write
string from raw machine code.
"""

from __future__ import annotations

import pytest

from triage_web import solvers


def test_solver_list_matches_generators() -> None:
    listed = {s["id"] for s in solvers.get_solver_list()}
    assert listed == set(solvers.SOLVER_GENERATORS)


@pytest.mark.parametrize("solver_id", sorted(solvers.SOLVER_GENERATORS))
@pytest.mark.parametrize("bits", [32, 64])
def test_generated_script_is_valid_python(solver_id: str, bits: int) -> None:
    src = solvers.generate_solver(solver_id, "./target.bin", "x86_64" if bits == 64 else "x86", bits)
    compile(src, f"<{solver_id}:{bits}>", "exec")
    assert "BINARY = './target.bin'" in src


def test_generate_solver_rejects_unknown_type() -> None:
    with pytest.raises(ValueError, match="Unknown solver type"):
        solvers.generate_solver("does_not_exist", "./x.bin", "x86", 64)


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
