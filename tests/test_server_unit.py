"""Unit / error-path tests for triage_web.server that don't fit the
happy-path smoke suite."""

from __future__ import annotations

import os
import threading

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from triage_web import server
from triage_web.server import Session


@pytest.fixture(autouse=True)
def _fresh_session(monkeypatch):
    """Every test in this module starts with an empty session; any binary
    it loads is closed before the session object is discarded."""
    s = Session()
    monkeypatch.setattr(server, "_session", s)
    yield
    if s.loader is not None:
        s.loader.close()


@pytest.fixture
def app_client() -> TestClient:
    return TestClient(server.app)


# ── Session accessors ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("method", "word"),
    [
        ("require_loader", "No binary loaded"),
        ("require_disasm", "Disassembler not initialized"),
        ("require_rop", "ROP engine not initialized"),
        ("require_xrefs", "XRefs not initialized"),
    ],
)
def test_session_require_raises_400_when_empty(method: str, word: str) -> None:
    with pytest.raises(HTTPException) as exc:
        getattr(Session(), method)()
    assert exc.value.status_code == 400
    assert word in exc.value.detail


def test_session_reset_closes_the_previous_loader() -> None:
    closed = []
    s = Session()
    s.loader = type("L", (), {"close": lambda self: closed.append(True)})()
    s.reset(loader=None, disasm=None, rop=None, xrefs=None, path=None, filename=None)
    assert closed == [True]
    assert s.loader is None and s.filename is None


def test_session_reset_is_lock_guarded_against_concurrent_readers() -> None:
    """One thread hammers reset() with distinct sentinel loader/disasm
    objects per call while another thread reads loader/disasm together.
    Without the lock, a reader can catch reset()'s field-by-field setattr
    loop mid-flight and observe a pair mixing objects from two different
    calls; with the lock, every observed pair is either the untouched
    initial state or a pair some single reset() call actually wrote."""
    s = Session()
    iterations = 100
    expected_pairs = {(None, None)}
    observed_pairs = []
    stop = threading.Event()

    def make_loader():
        return type("StubLoader", (), {"close": lambda self: None})()

    def resetter():
        for _ in range(iterations):
            loader, disasm = make_loader(), object()
            expected_pairs.add((loader, disasm))
            s.reset(loader=loader, disasm=disasm, rop=None, xrefs=None, path=None, filename=None)
        stop.set()

    def reader():
        while not stop.is_set():
            observed_pairs.append((s.loader, s.disasm))

    t_read = threading.Thread(target=reader)
    t_reset = threading.Thread(target=resetter)
    t_read.start()
    t_reset.start()
    t_reset.join()
    t_read.join()

    assert observed_pairs  # sanity: the reader actually observed something
    assert all(pair in expected_pairs for pair in observed_pairs)


# ── /api/load ─────────────────────────────────────────────────────────


def test_load_requires_path_or_file(app_client: TestClient) -> None:
    r = app_client.post("/api/load", data={})
    assert r.status_code == 400
    assert "Provide path or upload" in r.json()["detail"]


def test_load_missing_path_is_400(app_client: TestClient) -> None:
    r = app_client.post("/api/load", data={"path": "/no/such/binary"})
    assert r.status_code == 400
    assert "File not found" in r.json()["detail"]


def test_load_via_file_upload(app_client: TestClient, sample_path) -> None:
    with open(sample_path, "rb") as fh:
        r = app_client.post("/api/load", files={"file": ("upload.bin", fh, "application/octet-stream")})
    assert r.status_code == 200
    assert r.json()["filename"] == "upload.bin"
    assert server._session.loader is not None


# ── /api/unload ───────────────────────────────────────────────────────


def test_unload_clears_the_session(app_client: TestClient, sample_path) -> None:
    with open(sample_path, "rb") as fh:
        app_client.post("/api/load", files={"file": ("upload.bin", fh, "application/octet-stream")})
    assert server._session.loader is not None

    r = app_client.post("/api/unload")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert server._session.loader is None

    r = app_client.get("/api/info")
    assert r.status_code == 400


def test_unload_with_nothing_loaded_is_a_no_op(app_client: TestClient) -> None:
    r = app_client.post("/api/unload")
    assert r.status_code == 200
    assert server._session.loader is None


def test_load_wraps_a_loader_failure_as_500(app_client: TestClient, monkeypatch, tmp_path) -> None:
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x7fELF...")

    def boom(_path):
        raise RuntimeError("parse blew up")

    monkeypatch.setattr(server, "BinaryLoader", boom)
    r = app_client.post("/api/load", data={"path": str(f)})
    assert r.status_code == 500
    assert "Load failed" in r.json()["detail"]


@pytest.mark.filterwarnings("ignore::ResourceWarning")
@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_load_without_capstone_keeps_the_400(app_client: TestClient, monkeypatch, sample_path) -> None:
    # pyelftools can leave a handle for the GC on this early-exit path
    monkeypatch.setattr(server, "HAS_CAPSTONE", False)
    r = app_client.post("/api/load", data={"path": str(sample_path)})
    assert r.status_code == 400
    assert "capstone is required" in r.json()["detail"]


# ── misc ──────────────────────────────────────────────────────────────


def test_favicon_is_svg(app_client: TestClient) -> None:
    r = app_client.get("/favicon.ico")
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/svg+xml"
    assert b"<svg" in r.content


def test_hex_search_empty_needle(app_client: TestClient, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    body = app_client.get("/api/hex/search", params={"q": "", "kind": "hex"}).json()
    assert body["hits"] == [] and body["needle_len"] == 0


def test_hex_search_odd_length_hex_query_is_rejected(app_client: TestClient, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    r = app_client.get("/api/hex/search", params={"q": "abc", "kind": "hex"})
    assert r.status_code == 400
    assert "abc" in r.json()["detail"]


def test_hex_search_even_length_hex_query_is_unchanged(app_client: TestClient, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    r = app_client.get("/api/hex/search", params={"q": "abcd", "kind": "hex"})
    assert r.status_code == 200
    assert r.json()["needle_len"] == 2


def test_sections_entropy_failure_is_swallowed(app_client, monkeypatch, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})

    def boom(_data):
        raise ValueError("entropy blew up")

    monkeypatch.setattr(server._session.loader, "compute_entropy", boom)
    secs = app_client.get("/api/sections").json()
    assert secs and all(s["entropy"] == 0.0 for s in secs)

    # same swallow in the /api/memory-map section loop
    mm = app_client.get("/api/memory-map").json()
    assert all(s["entropy"] == 0.0 for s in mm["sections"])


def test_upload_staging_failure_falls_back_to_temp(app_client, monkeypatch, sample_path) -> None:
    import shutil as _shutil

    monkeypatch.setattr(_shutil, "copy2", lambda *a, **k: (_ for _ in ()).throw(OSError("no space")))
    with open(sample_path, "rb") as fh:
        r = app_client.post("/api/load", files={"file": ("x.bin", fh, "application/octet-stream")})
    assert r.status_code == 200  # still loads from the NamedTemporaryFile path


def test_upload_traversal_filename_is_sanitized_to_temp_basename(app_client, sample_path) -> None:
    import tempfile
    from pathlib import Path

    staged = Path(tempfile.gettempdir()) / "triage_evil.bin"
    staged.unlink(missing_ok=True)
    try:
        with open(sample_path, "rb") as fh:
            r = app_client.post("/api/load", files={"file": ("../../../evil.bin", fh, "application/octet-stream")})
        assert r.status_code == 200
        assert staged.is_file()
    finally:
        # release the mmap'd handle on the staged file before unlinking (Windows)
        if server._session.loader is not None:
            server._session.loader.close()
        staged.unlink(missing_ok=True)


def test_safe_staged_upload_path_neutralizes_shell_metacharacters() -> None:
    import re as _re

    dest = server._safe_staged_upload_path("poc'; touch pwned; echo '.elf")
    assert dest is not None
    basename = os.path.basename(dest)
    assert _re.fullmatch(r"[A-Za-z0-9._-]+", basename)


def test_safe_staged_upload_path_is_unchanged_for_a_normal_filename() -> None:
    import tempfile as _tempfile

    assert server._safe_staged_upload_path("upload.bin") == os.path.join(_tempfile.gettempdir(), "triage_upload.bin")


def test_safe_staged_upload_path_resolves_a_traversal_name_inside_tempdir() -> None:
    import tempfile
    from pathlib import Path

    dest = server._safe_staged_upload_path("../../../evil.bin")
    assert dest is not None
    tempdir = Path(tempfile.gettempdir()).resolve()
    assert Path(dest).resolve().is_relative_to(tempdir)


def test_safe_staged_upload_path_rejects_a_bypassed_basename(monkeypatch) -> None:
    import os as _os

    # Three ".." segments: one is absorbed by the "triage_" prefix on the first
    # joined component, the other two pop back past the temp directory itself —
    # proving the resolve-based guard independently blocks the escape even if
    # os.path.basename AND the metacharacter-sanitization regex were both
    # ever bypassed by a future refactor. The regex bypass is needed here
    # because sanitization also neutralizes the path separators this escape
    # relies on, so without it the escape would already be defused upstream.
    escape = _os.sep.join([".."] * 3) + _os.sep + "evil.bin"
    monkeypatch.setattr(_os.path, "basename", lambda _p: escape)
    monkeypatch.setattr(server.re, "sub", lambda _pattern, _repl, s: s)
    assert server._safe_staged_upload_path("evil.bin") is None


def test_load_skips_staged_copy_when_helper_rejects_the_filename(app_client, monkeypatch, sample_path) -> None:
    monkeypatch.setattr(server, "_safe_staged_upload_path", lambda _filename: None)
    with open(sample_path, "rb") as fh:
        r = app_client.post("/api/load", files={"file": ("upload.bin", fh, "application/octet-stream")})
    assert r.status_code == 200
    assert server._session.loader is not None


# ── CORS ──────────────────────────────────────────────────────────────


def test_cors_preflight_from_a_disallowed_origin_is_rejected(app_client: TestClient) -> None:
    r = app_client.options(
        "/api/health",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert r.status_code == 400
    assert "access-control-allow-origin" not in r.headers


def test_cors_preflight_from_the_default_localhost_origin_is_allowed(app_client: TestClient) -> None:
    r = app_client.options(
        "/api/health",
        headers={"Origin": "http://localhost:8888", "Access-Control-Request-Method": "GET"},
    )
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "http://localhost:8888"


def test_cors_origins_defaults_to_localhost_when_env_unset(monkeypatch) -> None:
    monkeypatch.delenv("TRIAGE_CORS_ORIGINS", raising=False)
    assert server._cors_origins() == server._DEFAULT_CORS_ORIGINS


def test_cors_origins_honors_the_env_override(monkeypatch) -> None:
    monkeypatch.setenv("TRIAGE_CORS_ORIGINS", "https://a.example, https://b.example")
    assert server._cors_origins() == ["https://a.example", "https://b.example"]


# ── CSRF / Origin protection ─────────────────────────────────────────
#
# CORS above blocks a cross-origin script from *reading* a response, not
# from *sending* a request — a plain HTML <form> POST needs no preflight
# and reaches the handler regardless. /api/unload stands in for every
# mutating route (/api/shutdown, /api/load, /api/autopwn): the middleware
# is method-based, not route-specific, so proving it here proves the same
# code path protects the others. /api/shutdown itself is untestable — it
# calls os._exit and would kill the test runner.


def test_foreign_origin_mutation_is_rejected_with_no_side_effect(app_client: TestClient, sample_path) -> None:
    with open(sample_path, "rb") as fh:
        app_client.post("/api/load", files={"file": ("upload.bin", fh, "application/octet-stream")})
    assert server._session.loader is not None

    r = app_client.post("/api/unload", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert server._session.loader is not None  # rejected before the handler ran


def test_default_allowed_origin_mutation_still_works(app_client: TestClient, sample_path) -> None:
    with open(sample_path, "rb") as fh:
        app_client.post("/api/load", files={"file": ("upload.bin", fh, "application/octet-stream")})

    r = app_client.post("/api/unload", headers={"Origin": "http://localhost:8888"})
    assert r.status_code == 200
    assert server._session.loader is None


def test_mutation_with_no_origin_header_is_unaffected(app_client: TestClient, sample_path) -> None:
    """No existing test sets an Origin header (curl/requests behave the
    same way) — proving the middleware doesn't regress non-browser
    clients."""
    with open(sample_path, "rb") as fh:
        app_client.post("/api/load", files={"file": ("upload.bin", fh, "application/octet-stream")})

    r = app_client.post("/api/unload")
    assert r.status_code == 200
    assert server._session.loader is None


def test_wildcard_cors_origins_opt_in_allows_a_foreign_origin_mutation(
    app_client: TestClient, monkeypatch, sample_path
) -> None:
    monkeypatch.setenv("TRIAGE_CORS_ORIGINS", "*")
    with open(sample_path, "rb") as fh:
        app_client.post("/api/load", files={"file": ("upload.bin", fh, "application/octet-stream")})

    r = app_client.post("/api/unload", headers={"Origin": "https://evil.example"})
    assert r.status_code == 200
    assert server._session.loader is None


# ── Upload size limit ─────────────────────────────────────────────────


def test_upload_under_the_limit_still_loads(app_client, sample_path) -> None:
    with open(sample_path, "rb") as fh:
        r = app_client.post("/api/load", files={"file": ("upload.bin", fh, "application/octet-stream")})
    assert r.status_code == 200


def test_upload_over_the_limit_is_rejected_with_413(app_client, monkeypatch, sample_path) -> None:
    monkeypatch.setattr(server, "_MAX_UPLOAD_BYTES", 16)
    with open(sample_path, "rb") as fh:
        r = app_client.post("/api/load", files={"file": ("upload.bin", fh, "application/octet-stream")})
    assert r.status_code == 413
    assert "16" in r.json()["detail"]


def test_exploit_techniques_maps_pe_imports(app_client, pe_path) -> None:
    app_client.post("/api/load", data={"path": str(pe_path)})
    body = app_client.get("/api/exploit-techniques").json()
    assert body["count"] == len(body["techniques"])
    assert all("technique" in t for t in body["techniques"])


def test_exploit_techniques_swallows_a_section_read_failure(app_client, monkeypatch, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    monkeypatch.setattr(
        server._session.loader,
        "get_sections",
        lambda: (_ for _ in ()).throw(RuntimeError("section table gone")),
    )
    body = app_client.get("/api/exploit-techniques").json()
    assert body["count"] == len(body["techniques"])  # inner except → keeps going


def test_exploit_techniques_nx_off_when_text_is_not_executable(app_client, monkeypatch, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    # a .text section with no SHF_EXECINSTR bit → the other has_nx=False branch
    monkeypatch.setattr(server._session.loader, "get_sections", lambda: [{"name": ".text", "flags": 0x2}])
    techs = app_client.get("/api/exploit-techniques").json()["techniques"]
    t = next(x for x in techs if x["mitre_id"] == "T1059.006")
    assert t["nx_status"] == "disabled"


def test_entropy_result_is_cached_between_requests(app_client, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    first = app_client.get("/api/entropy").json()
    assert server._session.loader._entropy_cache is not None
    second = app_client.get("/api/entropy").json()  # served from the cache branch
    assert first == second


def test_entropy_and_hex_search_operate_on_the_raw_buffer_directly(app_client, sample_path) -> None:
    """Proves the copy-elision (operating on loader._raw, a bytearray,
    instead of a throwaway bytes() copy) is output-preserving."""
    app_client.post("/api/load", data={"path": str(sample_path)})

    entropy = app_client.get("/api/entropy").json()
    assert entropy["total_bytes"] == len(server._session.loader._raw)

    hits = app_client.get("/api/hex/search", params={"q": "7f454c46", "kind": "hex"}).json()
    assert hits["needle_len"] == 4
    assert 0 in hits["hits"]  # ELF magic at offset 0
    assert hits["total"] == len(server._session.loader._raw)


def test_vuln_hints_skips_non_exploitation_imports(app_client, vuln_samples) -> None:
    # vuln_execstack imports open()/write() — in VULN_PATTERNS but not the
    # exploitation-relevant subset → the `continue` at the top of the loop
    app_client.post("/api/load", data={"path": str(vuln_samples["vuln_execstack"])})
    body = app_client.get("/api/vuln-hints").json()
    vf = {v["name"] for v in body["vulnerable_functions"]}
    assert "open" not in vf and "write" not in vf
    assert "strcpy" in vf  # the BOF sink is still reported


# ── /api/capa rule-resolution guards ─────────────────────────────────


@pytest.mark.filterwarnings("ignore::ResourceWarning")
@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_capa_reports_missing_rules(app_client, monkeypatch, crackme_path) -> None:
    import pathlib

    pytest.importorskip("capa.rules")
    app_client.post("/api/load", data={"path": str(crackme_path)})
    monkeypatch.setattr(pathlib.Path, "is_dir", lambda self: False)
    r = app_client.post("/api/capa")
    assert r.status_code == 400
    assert "CAPA rules not found" in r.json()["detail"]


@pytest.mark.filterwarnings("ignore::ResourceWarning")
@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_capa_wraps_an_analysis_failure_as_500(app_client, monkeypatch, crackme_path) -> None:
    capa = pytest.importorskip("capa.rules")
    app_client.post("/api/load", data={"path": str(crackme_path)})

    def boom(*_a, **_k):
        raise RuntimeError("vivisect exploded")

    monkeypatch.setattr(capa, "get_rules", boom)
    r = app_client.post("/api/capa")
    assert r.status_code == 500
    assert "CAPA analysis failed" in r.json()["detail"]


# ── Hex-param validation / min_len clamp ─────────────────────────────


def test_malformed_hex_vaddr_is_400_not_500(app_client, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    r = app_client.get("/api/disasm", params={"vaddr": "not-hex"})
    assert r.status_code == 400
    assert "vaddr" in r.json()["detail"]


def test_malformed_hex_off_on_hex_window_is_400(app_client, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    r = app_client.get("/api/hex", params={"off": "zz"})
    assert r.status_code == 400
    assert "off" in r.json()["detail"]


def test_out_of_range_min_len_does_not_500(app_client, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    r = app_client.get("/api/strings", params={"min_len": -5})
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ── Solver endpoints ──────────────────────────────────────────────────


def test_unknown_solver_type_is_400_not_500(app_client, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    r = app_client.get("/api/solver", params={"solver_type": "not_a_real_solver"})
    assert r.status_code == 400
    assert "not_a_real_solver" in r.json()["detail"]


def test_solver_execute_rejects_non_string_code(app_client) -> None:
    r = app_client.post("/api/solver/execute", json={"code": None})
    assert r.status_code == 400
    assert "code" in r.json()["detail"]


def test_solver_execute_runs_a_valid_string(app_client) -> None:
    r = app_client.post("/api/solver/execute", json={"code": ""})
    assert r.status_code == 200
    assert r.json()["stderr"] == "No code provided"


# ── Exploit-techniques narrow catch ───────────────────────────────────


def test_exploit_techniques_no_binary_still_returns_fallback(app_client) -> None:
    r = app_client.get("/api/exploit-techniques")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == len(body["techniques"])


def test_exploit_techniques_real_error_is_not_masked_as_fallback(app_client, monkeypatch, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    monkeypatch.setattr(
        server._session.loader,
        "get_imports",
        lambda: (_ for _ in ()).throw(RuntimeError("import table gone")),
    )
    with pytest.raises(RuntimeError):
        app_client.get("/api/exploit-techniques")


# ── Upload temp-file cleanup ──────────────────────────────────────────


def test_successful_upload_removes_the_pre_copy_temp_file(app_client, monkeypatch, sample_path) -> None:
    seen = {}
    real_unlink = server.os.unlink

    def tracking_unlink(path, *a, **k):
        seen["unlinked"] = path
        return real_unlink(path, *a, **k)

    monkeypatch.setattr(server.os, "unlink", tracking_unlink)
    with open(sample_path, "rb") as fh:
        r = app_client.post("/api/load", files={"file": ("upload.bin", fh, "application/octet-stream")})
    assert r.status_code == 200
    assert "unlinked" in seen
    assert not os.path.exists(seen["unlinked"])


def test_upload_cleanup_survives_an_unlink_failure(app_client, monkeypatch, sample_path) -> None:
    """If the pre-copy temp file can't be removed (permissions, already
    gone, ...), the load still succeeds — the cleanup failure is logged,
    not raised."""

    def failing_unlink(path, *a, **k):
        raise OSError("permission denied")

    monkeypatch.setattr(server.os, "unlink", failing_unlink)
    with open(sample_path, "rb") as fh:
        r = app_client.post("/api/load", files={"file": ("upload.bin", fh, "application/octet-stream")})
    assert r.status_code == 200


def test_get_overflow_sites_degrades_to_empty_list_without_disasm() -> None:
    assert Session().get_overflow_sites() == []


# ── Per-binary analysis cache ────────────────────────────────────────


def test_known_calls_and_overflow_sites_are_cached_per_binary(app_client, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    session = server._session

    known_calls_first = session.get_known_calls()
    assert session.get_known_calls() is known_calls_first  # served from the cache

    overflow_sites_first = session.get_overflow_sites()
    assert session.get_overflow_sites() is overflow_sites_first  # served from the cache

    # A fresh load resets the session — the reset() field list picks up the
    # new cache fields automatically, so a reload must produce fresh objects.
    app_client.post("/api/load", data={"path": str(sample_path)})
    session = server._session
    assert session.get_known_calls() is not known_calls_first
    assert session.get_overflow_sites() is not overflow_sites_first


# ── Renamed names (readability findings 13, 19, 20) ──────────────────


def test_disasm_functions_exposes_the_renamed_binary_wide_field(app_client, sample_path) -> None:
    app_client.post("/api/load", data={"path": str(sample_path)})
    funcs = app_client.get("/api/disasm/functions").json()["functions"]
    assert funcs
    assert all("binary_has_vuln_calls" in f for f in funcs)
    assert all("is_vulnerable" not in f for f in funcs)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_confirm_non_loopback_host_allows_loopback_without_the_ack_flag(host: str) -> None:
    server._confirm_non_loopback_host(host, confirmed=False)  # no SystemExit


def test_confirm_non_loopback_host_allows_a_wide_host_when_acknowledged() -> None:
    server._confirm_non_loopback_host("0.0.0.0", confirmed=True)  # noqa: S104 - no SystemExit


def test_confirm_non_loopback_host_refuses_a_wide_host_without_the_ack_flag() -> None:
    with pytest.raises(SystemExit):
        server._confirm_non_loopback_host("0.0.0.0", confirmed=False)  # noqa: S104
