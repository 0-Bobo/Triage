"""Tests for ``triage_web.autopwn.wsl_env`` — WSL + pwn-venv detection."""

from __future__ import annotations

import pytest

from triage_web.autopwn import runner
from triage_web.autopwn.runner import ProcResult
from triage_web.autopwn.wsl_env import detect, main


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
    assert not status.usable


def test_detect_fully_usable(monkeypatch):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(runner, "_wsl_bash", lambda *_a: _result("VENV_OK\nPWNTOOLS_OK\nTRITON_OK\n"))
    status = detect()
    assert status.wsl_installed is True
    assert status.distro_running is True
    assert status.venv_exists is True
    assert status.pwntools_ok is True
    assert status.triton_ok is True
    assert status.usable


def test_main_prints_pass_lines_and_returns_zero_when_usable(monkeypatch, capsys):
    monkeypatch.setattr(runner, "have_wsl", lambda: True)
    monkeypatch.setattr(runner, "_wsl_bash", lambda *_a: _result("VENV_OK\nPWNTOOLS_OK\nTRITON_OK\n"))
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.count("[PASS]") == 5
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
    assert len(lines) == 5
    assert "[PASS] wsl_installed" in lines
    assert "[PASS] distro_running" in lines
    assert "[PASS] venv_exists" in lines
    assert "[PASS] pwntools_ok" in lines
    assert "[FAIL] triton_ok" in lines


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
