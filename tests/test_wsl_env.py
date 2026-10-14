"""Tests for ``triage_web.autopwn.wsl_env`` — WSL + pwn-venv detection."""

from __future__ import annotations

import pytest

from triage_web.autopwn import runner
from triage_web.autopwn.runner import ProcResult
from triage_web.autopwn.wsl_env import _PROBE, _SETUP_SCRIPT, detect, main, run_setup


def _result(text: str, *, runnable: bool = True, timed_out: bool = False, returncode: int | None = 0) -> ProcResult:
    return ProcResult(
        returncode=returncode,
        stdout=text.encode(),
        stderr=b"",
        timed_out=timed_out,
        seconds=0.1,
        cmd="wsl",
        runnable=runnable,
    )


# ── Task 1: end-to-end chain ─────────────────────────────────────────


def test_detect_reports_wsl_missing(monkeypatch):
    monkeypatch.setattr(runner, "have_wsl", lambda: False)
    status = detect()
    assert status.wsl_installed is False
    assert status.distro_running is False
    assert status.venv_exists is False
    assert status.pwntools_ok is False
    assert status.triton_ok is False
    assert status.z3_ok is False
    assert status.angr_ok is False
    assert status.unicorn_ok is False
    assert not status.usable
    assert "WSL not installed" in status.detail


def test_detect_reports_distro_not_responding(monkeypatch):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(runner, "_wsl_bash", lambda *_a: _result("some garbage, no tokens here"))
    status = detect()
    assert status.wsl_installed is True
    assert status.distro_running is False
    assert status.venv_exists is False
    assert status.pwntools_ok is False
    assert status.triton_ok is False
    assert status.z3_ok is False
    assert status.angr_ok is False
    assert status.unicorn_ok is False
    assert not status.usable


def test_detect_venv_only_no_imports(monkeypatch):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(runner, "_wsl_bash", lambda *_a: _result("VENV_OK\nPWNTOOLS_MISSING\nTRITON_MISSING\n"))
    status = detect()
    assert status.wsl_installed is True
    assert status.distro_running is True
    assert status.venv_exists is True
    assert status.pwntools_ok is False
    assert status.triton_ok is False
    assert status.z3_ok is False
    assert status.angr_ok is False
    assert status.unicorn_ok is False
    assert not status.usable


def test_detect_fully_usable(monkeypatch):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(
        runner, "_wsl_bash", lambda *_a: _result("VENV_OK\nPWNTOOLS_OK\nTRITON_OK\nZ3_OK\nANGR_OK\nUNICORN_OK\n")
    )
    status = detect()
    assert status.wsl_installed is True
    assert status.distro_running is True
    assert status.venv_exists is True
    assert status.pwntools_ok is True
    assert status.triton_ok is True
    assert status.z3_ok is True
    assert status.angr_ok is True
    assert status.unicorn_ok is True
    assert status.usable


def test_main_prints_pass_lines_and_returns_zero_when_usable(monkeypatch, capsys):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(
        runner, "_wsl_bash", lambda *_a: _result("VENV_OK\nPWNTOOLS_OK\nTRITON_OK\nZ3_OK\nANGR_OK\nUNICORN_OK\n")
    )
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.count("[PASS]") == 8
    assert "usable: True" in out


# ── Task 2: remaining branch coverage ─────────────────────────────────


def test_detect_handles_a_timed_out_probe_without_raising(monkeypatch):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    timed_out = ProcResult(
        returncode=None, stdout=b"", stderr=b"", timed_out=True, seconds=15.0, cmd="wsl", runnable=True
    )
    monkeypatch.setattr(runner, "_wsl_bash", lambda *_a: timed_out)
    status = detect()
    assert status.distro_running is False
    assert status.venv_exists is False
    assert status.pwntools_ok is False
    assert status.triton_ok is False
    assert status.z3_ok is False
    assert status.angr_ok is False
    assert status.unicorn_ok is False
    assert status.detail.strip() == ""  # empty text -> empty detail, no index error


def test_detect_tracks_pwntools_and_triton_independently(monkeypatch):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(runner, "_wsl_bash", lambda *_a: _result("VENV_OK\nPWNTOOLS_OK\nTRITON_MISSING\n"))
    status = detect()
    assert status.venv_exists is True
    assert status.pwntools_ok is True
    assert status.triton_ok is False
    assert not status.usable  # triton missing alone is enough to make it unusable


def test_main_reports_a_distinct_line_per_field_when_mixed(monkeypatch, capsys):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(runner, "_wsl_bash", lambda *_a: _result("VENV_OK\nPWNTOOLS_OK\nTRITON_MISSING\n"))
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 1
    lines = [line for line in out.splitlines() if line.startswith(("[PASS]", "[FAIL]"))]
    assert len(lines) == 8
    assert "[PASS] wsl_installed" in lines
    assert "[PASS] distro_running" in lines
    assert "[PASS] venv_exists" in lines
    assert "[PASS] pwntools_ok" in lines
    assert "[FAIL] triton_ok" in lines
    assert "[FAIL] z3_ok" in lines
    assert "[FAIL] angr_ok" in lines
    assert "[FAIL] unicorn_ok" in lines


def test_detect_tracks_z3_angr_unicorn_independently(monkeypatch):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(
        runner, "_wsl_bash", lambda *_a: _result("VENV_OK\nPWNTOOLS_OK\nTRITON_OK\nZ3_OK\nANGR_MISSING\nUNICORN_OK\n")
    )
    status = detect()
    assert status.angr_ok is False
    assert status.pwntools_ok is True
    assert status.triton_ok is True
    assert status.z3_ok is True
    assert status.unicorn_ok is True
    assert status.usable  # a missing angr alone does not change usable


def test_detect_keeps_earlier_results_when_the_probe_times_out_during_angr(monkeypatch):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    timed_out = ProcResult(
        returncode=None,
        stdout=b"VENV_OK\nPWNTOOLS_OK\nTRITON_OK\nZ3_OK\nUNICORN_OK\n",
        stderr=b"",
        timed_out=True,
        seconds=15.0,
        cmd="wsl",
        runnable=True,
    )
    monkeypatch.setattr(runner, "_wsl_bash", lambda *_a: timed_out)
    status = detect()
    assert status.angr_ok is False
    assert status.wsl_installed is True
    assert status.distro_running is True
    assert status.venv_exists is True
    assert status.pwntools_ok is True
    assert status.triton_ok is True
    assert status.z3_ok is True
    assert status.unicorn_ok is True


def test_probe_imports_angr_last():
    assert "import pwn" in _PROBE
    assert "import triton" in _PROBE
    assert "import z3" in _PROBE
    assert "import unicorn" in _PROBE
    assert "import angr" in _PROBE
    assert _PROBE.rindex("import ") == _PROBE.index("import angr")


def test_main_prints_detail_line_when_distro_is_unresponsive(monkeypatch, capsys):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(runner, "_wsl_bash", lambda *_a: _result("no tokens at all"))
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 1
    assert "detail:" in out
    assert "no tokens at all" in out


def test_main_rejects_an_unrecognized_flag():
    with pytest.raises(SystemExit) as exc_info:
        main(["--bogus"])
    assert exc_info.value.code == 2


# ── Task 2: run_setup() branches ────────────────────────────────────


def test_run_setup_on_linux_runs_script_directly(monkeypatch):
    calls = []

    def fake_popen(cmd, stdin, timeout):
        calls.append((cmd, stdin, timeout))
        return _result("ok")

    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runner, "_popen", fake_popen)
    result = run_setup(timeout=42.0)
    assert result.text.startswith("ok")
    assert calls == [(["bash", str(_SETUP_SCRIPT)], b"", 42.0)]


def test_run_setup_on_windows_without_wsl_does_not_shell_out(monkeypatch):
    monkeypatch.setattr(runner.platform, "system", lambda: "Windows")
    monkeypatch.setattr(runner, "have_wsl", lambda: False)
    monkeypatch.setattr(runner, "_popen", lambda *_a: pytest.fail("should not shell out"))
    monkeypatch.setattr(runner, "_wsl_bash", lambda *_a: pytest.fail("should not shell out"))
    result = run_setup()
    assert result.runnable is False
    assert "WSL not installed" in result.text


def test_run_setup_on_windows_with_wsl_drives_through_wsl_bash(monkeypatch):
    calls = []

    def fake_wsl_bash(script, stdin, timeout):
        calls.append((script, stdin, timeout))
        return _result("done")

    monkeypatch.setattr(runner.platform, "system", lambda: "Windows")
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(runner, "_wsl_bash", fake_wsl_bash)
    result = run_setup(timeout=99.0)
    assert result.text.startswith("done")
    assert len(calls) == 1
    script, stdin, timeout = calls[0]
    assert script.startswith("bash ")
    assert runner.to_wsl(_SETUP_SCRIPT) in script
    assert stdin == b""
    assert timeout == 99.0


def test_main_setup_flag_calls_run_setup_and_returns_zero_on_success(monkeypatch, capsys):
    monkeypatch.setattr(
        "triage_web.autopwn.wsl_env.run_setup", lambda *, timeout: _result("[PASS] pwntools\n==> all checks passed")
    )
    rc = main(["--setup"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[PASS] pwntools" in out


def test_main_setup_flag_returns_one_on_failure(monkeypatch, capsys):
    monkeypatch.setattr(
        "triage_web.autopwn.wsl_env.run_setup",
        lambda *, timeout: _result("[FAIL] triton-library: boom", returncode=1),
    )
    rc = main(["--setup"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "[FAIL] triton-library: boom" in out


def test_main_setup_flag_passes_through_custom_timeout(monkeypatch):
    seen = {}

    def fake_run_setup(*, timeout):
        seen["timeout"] = timeout
        return _result("ok")

    monkeypatch.setattr("triage_web.autopwn.wsl_env.run_setup", fake_run_setup)
    main(["--setup", "--timeout", "5"])
    assert seen["timeout"] == 5.0
