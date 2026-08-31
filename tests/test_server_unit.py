"""Unit / error-path tests for triage_web.server that don't fit the
happy-path smoke suite."""

from __future__ import annotations

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
