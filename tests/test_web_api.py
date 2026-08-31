"""Integration smoke tests for the FastAPI layer.

Drives ``triage_web.server.app`` through ``TestClient`` against a checked-in
sample binary. These assert request-path wiring and response shape, not
analysis quality — the decompiler's behaviour is locked by ``test_engine``.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from triage_web import server

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client(sample_path) -> TestClient:
    """A client with the sample binary already loaded into session state."""
    with TestClient(server.app) as c:
        resp = c.post("/api/load", data={"path": str(sample_path)})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "ok"
        yield c


# ── endpoints that work without a loaded binary ─────────────────────────


def test_health_reports_dependency_flags() -> None:
    body = TestClient(server.app).get("/api/health").json()
    assert body["status"] == "ok"
    assert {"pyelftools", "pefile", "capstone", "lief"} <= body["deps"].keys()


def test_index_serves_the_spa_uncached() -> None:
    resp = TestClient(server.app).get("/")
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    assert "<!DOCTYPE html>" in resp.text


def test_read_endpoint_requires_a_loaded_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server._session, "loader", None)
    resp = TestClient(server.app).get("/api/functions")
    assert resp.status_code == 400


# ── with a binary loaded ───────────────────────────────────────────────


def test_info_and_functions(client: TestClient) -> None:
    info = client.get("/api/info").json()
    assert info["arch"] and info["bits"] in (32, 64)

    funcs = client.get("/api/functions").json()
    assert isinstance(funcs, list) and funcs
    assert {"name", "address"} <= funcs[0].keys()


@pytest.mark.parametrize(
    "path",
    ["/api/imports", "/api/exports", "/api/sections", "/api/segments", "/api/symbols"],
)
def test_listing_endpoints_return_lists(client: TestClient, path: str) -> None:
    resp = client.get(path)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_hex_by_offset_and_vaddr(client: TestClient) -> None:
    by_off = client.get("/api/hex", params={"off": "0x0", "size": 64}).json()
    assert by_off["off"] == 0
    assert by_off["total"] > 0
    assert len(by_off["hex"]) == 128  # 64 bytes, hex-encoded

    entry = client.get("/api/info").json()["entry_point"]
    by_va = client.get("/api/hex", params={"vaddr": entry, "size": 32}).json()
    assert by_va["vaddr"] is not None
    assert by_va["section"]  # entry point lands in a named section


def test_hex_search_finds_the_elf_magic(client: TestClient) -> None:
    hits = client.get("/api/hex/search", params={"q": "7f454c46", "kind": "hex"}).json()
    assert hits["needle_len"] == 4
    assert 0 in hits["hits"]


def test_disasm_and_decompile_resolve_a_real_symbol(client: TestClient) -> None:
    funcs = client.get("/api/disasm/functions").json()["functions"]
    main = next((f for f in funcs if f["name"] == "main"), funcs[0])

    disasm = client.get("/api/disasm", params={"vaddr": main["address"], "size": 128}).json()
    assert disasm["count"] > 0
    assert {"address", "mnemonic", "op_str"} <= disasm["insns"][0].keys()

    dec = client.get("/api/disasm/decompile", params={"vaddr": main["address"]}).json()
    assert dec["func_name"]  # regression: was always "" before the resolver fix
    assert dec["code"].lstrip().startswith("//")


def test_vulns_and_hints(client: TestClient) -> None:
    vulns = client.get("/api/vulns").json()
    assert isinstance(vulns, list)

    hints = client.get("/api/vuln-hints").json()
    assert "protections" in hints
    assert isinstance(hints["paths"], list) and hints["paths"]

    prot = client.get("/api/protections").json()
    assert isinstance(prot, dict) and prot


@pytest.mark.parametrize(
    "path",
    [
        "/api/strings",
        "/api/crypto",
        "/api/exploit-techniques",
    ],
)
def test_misc_get_endpoints_ok(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/api/functions?search=main",
        "/api/strings?search=a",
        "/api/symbols?search=_",
    ],
)
def test_search_filters(client: TestClient, path: str) -> None:
    r = client.get(path)
    assert r.status_code == 200 and isinstance(r.json(), list)


@pytest.mark.parametrize(
    "path",
    [
        "/api/disasm?vaddr=0xfffffff0&size=64",
        "/api/disasm/function?vaddr=0xfffffff0",
        "/api/disasm/variables?vaddr=0xfffffff0",
        "/api/disasm/decompile?vaddr=0xfffffff0",
    ],
)
def test_disasm_endpoints_on_unmapped_address(client: TestClient, path: str) -> None:
    r = client.get(path)
    assert r.status_code == 200  # empty result, not an error


def test_xrefs_build_on_unmapped_address(client: TestClient) -> None:
    r = client.post("/api/xrefs/build", params={"vaddr": "0xfffffff0", "size": 64})
    assert r.json()["count"] == 0
    assert "no data" in r.json()["status"]


def test_hex_search_str_and_autodetect(client: TestClient) -> None:
    by_str = client.get("/api/hex/search", params={"q": "ELF", "kind": "str"}).json()
    assert by_str["needle_len"] == 3
    auto = client.get("/api/hex/search", params={"q": "not-hex-so-treated-as-string"}).json()
    assert auto["needle_len"] == len("not-hex-so-treated-as-string")
    # no `kind` + a valid even-length hex string → auto-detected as bytes
    auto_hex = client.get("/api/hex/search", params={"q": "7f454c46"}).json()
    assert auto_hex["needle_len"] == 4
    assert 0 in auto_hex["hits"]


def test_solver_execute_runs_code(client: TestClient) -> None:
    r = client.post("/api/solver/execute", json={"code": "print('solver-ran')"})
    assert r.status_code == 200
    assert "solver-ran" in r.json()["stdout"]


def test_vuln_hints_heap_path_for_the_malloc_free_sample(client: TestClient) -> None:
    # the module `client` fixture loads test_func_pe, which imports malloc + free
    hints = client.get("/api/vuln-hints").json()
    names = {p["name"] for p in hints["paths"]}
    assert "Heap exploitation" in names


def test_entropy_and_memory_map(client: TestClient) -> None:
    ent = client.get("/api/entropy").json()
    assert ent["block_size"] == 256
    assert ent["total_bytes"] > 0
    assert len(ent["blocks"]) == -(-ent["total_bytes"] // 256)  # ceil division

    mm = client.get("/api/memory-map").json()
    assert {"sections", "segments"} <= mm.keys()
    assert any(s["name"] == ".text" for s in mm["sections"])


def test_packer_report_shape(client: TestClient) -> None:
    body = client.get("/api/packer").json()
    assert isinstance(body, (dict, list))


def test_disasm_function_and_variables(client: TestClient) -> None:
    main = next(f for f in client.get("/api/disasm/functions").json()["functions"] if f["name"] == "main")
    fn = client.get("/api/disasm/function", params={"vaddr": main["address"]}).json()
    assert {"insns", "stack_frame", "stack_vars", "calls"} <= fn.keys()

    variables = client.get("/api/disasm/variables", params={"vaddr": main["address"]}).json()
    assert variables["address"] == main["address"]
    assert isinstance(variables["stack_vars"], list)


def test_solver_generation_and_listing(client: TestClient) -> None:
    listed = client.get("/api/solvers").json()["solvers"]
    assert any(s["id"] == "static_string_reconstruct" for s in listed)

    gen = client.get("/api/solver", params={"solver_type": "static_string_reconstruct"}).json()
    assert gen["type"] == "static_string_reconstruct"
    compile(gen["code"], "<api/solver>", "exec")


def test_rop_scan_then_search(client: TestClient) -> None:
    summary = client.post("/api/rop/scan").json()
    assert "total" in summary
    gadgets = client.get("/api/rop/gadgets", params={"cls": "ret"}).json()
    assert "gadgets" in gadgets and "total" in gadgets


def test_xrefs_build_then_query(client: TestClient) -> None:
    entry = int(client.get("/api/info").json()["entry_point"], 16)
    built = client.post("/api/xrefs/build", params={"vaddr": hex(entry), "size": 2048}).json()
    assert built["status"] == "ok"
    xr = client.get("/api/xrefs", params={"vaddr": hex(entry)}).json()
    assert {"callers", "callees"} <= xr.keys()


# Kept last: this loads a different binary into the (process-global) session.
def test_vuln_hints_builds_a_ret2win_path_for_the_crackme(crackme_path) -> None:
    c = TestClient(server.app)
    assert c.post("/api/load", data={"path": str(crackme_path)}).status_code == 200

    vulns = {v["name"] for v in c.get("/api/vulns").json()}
    assert "strcpy" in vulns

    hints = c.get("/api/vuln-hints").json()
    assert hints["summary"]["win_functions"], "the crackme has a `win` symbol"
    ret2win = next((p for p in hints["paths"] if p["name"] == "ret2win"), None)
    assert ret2win is not None
    assert ret2win["skeleton"].startswith("from pwn import *")
    assert any(s["function"] == "main" for s in hints["overflow_sites"])


@pytest.mark.parametrize(
    ("sample", "expected_path", "absent_path"),
    [
        ("vuln_pie", "ret2win", None),  # PIE branch → the "PIE is ON" step
        ("vuln_pie", "Format string", None),  # printf import + VULN_FMT
        ("vuln_canary", "Defeat the stack canary first", "Shellcode injection (NX off)"),
        ("vuln_execstack", "Shellcode injection (NX off)", "Defeat the stack canary first"),
        ("nostrings", "No obvious memory-corruption primitive", "ret2win"),
        ("vuln_rwx", "No obvious memory-corruption primitive", None),
    ],
)
def test_vuln_hints_paths_are_binary_specific(vuln_samples, sample, expected_path, absent_path) -> None:
    c = TestClient(server.app)
    assert c.post("/api/load", data={"path": str(vuln_samples[sample])}).status_code == 200
    names = {p["name"] for p in c.get("/api/vuln-hints").json()["paths"]}
    assert expected_path in names
    if absent_path:
        assert absent_path not in names


def test_vuln_hints_pie_step_and_ret2libc_family(vuln_samples) -> None:
    c = TestClient(server.app)
    c.post("/api/load", data={"path": str(vuln_samples["vuln_pie"])})
    hints = c.get("/api/vuln-hints").json()
    ret2win = next(p for p in hints["paths"] if p["name"] == "ret2win")
    assert any("PIE is ON" in s for s in ret2win["steps"])
    # NX-on + no-canary dynamically-linked ELF → the ret2libc leak path
    assert "ret2libc (leak + return)" in {p["name"] for p in hints["paths"]}


def test_exploit_techniques_without_a_binary_falls_back(monkeypatch) -> None:
    monkeypatch.setattr(server._session, "loader", None)
    body = TestClient(server.app).get("/api/exploit-techniques").json()
    assert body["count"] == len(body["techniques"])  # the bare EXPLOIT_TECHNIQUES list


def test_exploit_techniques_flags_nx_off(vuln_samples) -> None:
    # vuln_rwx has a single W+X PT_LOAD → its .text section is writable+exec
    c = TestClient(server.app)
    c.post("/api/load", data={"path": str(vuln_samples["vuln_rwx"])})
    techs = c.get("/api/exploit-techniques").json()["techniques"]
    t = next((x for x in techs if x["mitre_id"] == "T1059.006"), None)
    assert t is not None and t.get("nx_status") == "disabled"


@pytest.mark.slow
# capa's loader opens the sample without closing it; don't fail the strict
# warnings filter over a third-party ResourceWarning.
@pytest.mark.filterwarnings("ignore::ResourceWarning")
@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_capa_runs_with_the_bundled_rules(crackme_path) -> None:
    """End-to-end /api/capa: the pinned capa-rules submodule + vivisect
    extraction. Slow (~15 s) — excluded from `make test`, runs in coverage/CI."""
    c = TestClient(server.app)
    assert c.post("/api/load", data={"path": str(crackme_path)}).status_code == 200

    resp = c.post("/api/capa")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "count" in body and isinstance(body["capabilities"], list)
    if body["capabilities"]:
        assert {"rule", "namespace", "matches"} <= body["capabilities"][0].keys()
