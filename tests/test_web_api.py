"""Integration smoke tests for the FastAPI layer.

Drives ``triage_web.server.app`` through ``TestClient`` against a checked-in
sample binary. These assert request-path wiring and response shape, not
analysis quality — the decompiler's behaviour is locked by ``test_engine``.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from triage_web import analysis, server
from triage_web.loader import BinaryLoader
from triage_web.rop import ROPEngine

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


def test_status_reports_every_engine_with_a_three_way_availability() -> None:
    body = TestClient(server.app).get("/api/status").json()
    ids = {e["id"] for e in body["engines"]}
    assert {"capstone", "pyelftools", "pefile", "lief", "capa", "angr", "z3", "unicorn", "triton", "pwntools"} <= ids
    for e in body["engines"]:
        assert isinstance(e["installed"], bool)
        assert e["availability"] in {"native", "wsl", "missing"}
        assert e["installed"] == (e["availability"] != "missing")
    assert body["runtime"]["platform"]


def test_index_status_panel_renders_three_way_availability() -> None:
    resp = TestClient(server.app).get("/")
    assert '<span class="badge badge-low">Installed</span>' in resp.text
    assert '<span class="badge badge-low">Installed via WSL</span>' in resp.text
    assert '<span class="badge badge-crit">Missing</span>' in resp.text
    assert "const badge = AVAILABILITY_BADGES[e.availability] || AVAILABILITY_BADGES.missing;" in resp.text
    assert "e.installed" not in resp.text


def test_index_serves_the_spa_uncached() -> None:
    resp = TestClient(server.app).get("/")
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    assert "<!DOCTYPE html>" in resp.text


def test_index_carries_csp_and_nosniff_headers() -> None:
    resp = TestClient(server.app).get("/")
    csp = resp.headers["content-security-policy"]
    assert csp == server.CSP_POLICY
    # inline UI + data: fonts must be permitted, remote origins/plugins must not
    assert "script-src 'self' 'unsafe-inline'" in csp
    assert "font-src 'self' data:" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_index_is_self_contained_with_embedded_fonts() -> None:
    resp = TestClient(server.app).get("/")
    # Single file: styles and Geist fonts are inline, so it renders the same
    # when opened directly as a local file (file://) as when served.
    assert "<style>" in resp.text
    assert "data:font/woff2;base64," in resp.text
    assert 'rel="stylesheet"' not in resp.text


def test_index_has_accessible_labels_on_icon_only_controls() -> None:
    resp = TestClient(server.app).get("/")
    assert resp.text.count('aria-label="') == 27
    labels = (
        "Auto",
        "Info",
        "Functions",
        "Decompiled Code",
        "Disassembly",
        "Hex Viewer",
        "Data",
        "Exploit",
        "CAPA",
        "Cross References",
        "Quit",
        "Status",
        "About",
        "Toggle offset / virtual-address mode",
        "Previous page",
        "Next page",
        "Find next",
        "Find previous",
        "Search functions",
        "Address to disassemble",
        "Go to address",
        "Find hex bytes or string",
        "Search ROP gadgets",
        "Search strings",
        "Search imports",
        "Address to look up cross references",
    )
    for label in labels:
        assert f'aria-label="{label}"' in resp.text


def test_index_wires_hash_based_panel_routing() -> None:
    resp = TestClient(server.app).get("/")
    assert "function activatePanel(" in resp.text
    assert "if (!panel) return;" in resp.text
    assert "history.pushState(null, '', '#' + name);" in resp.text
    assert "addEventListener('hashchange'" in resp.text


def test_index_escapes_the_imports_library_cell() -> None:
    resp = TestClient(server.app).get("/")
    assert "'</td><td style=\"color:var(--text-dim)\">'+esc(i.library||'')+'</td>" in resp.text
    assert "'</td><td style=\"color:var(--text-dim)\">'+(i.library||'')+'</td>" not in resp.text


def test_index_escapes_the_disasm_mnemonic_cell() -> None:
    resp = TestClient(server.app).get("/")
    assert "'<td class=\"mnem\" style=\"color:'+i.color+'\">'+esc(i.mnemonic)+'</td>" in resp.text
    assert "'<td class=\"mnem\" style=\"color:'+i.color+'\">'+i.mnemonic+'</td>" not in resp.text


def test_index_jump_links_use_a_quote_safe_dataset_pattern() -> None:
    resp = TestClient(server.app).get("/")
    assert "function escAttr(s) {" in resp.text
    # Untrusted names land in a data-* attribute (escAttr), read back via
    # dataset in the handler — never string-concatenated into the inline
    # handler's JS-string literal.
    win_link = 'data-name="\'+escAttr(w.name)+\'" onclick="showCodeWithSearch(this.dataset.name);return false"'
    ovf_link = 'data-name="\'+escAttr(s.function)+\'" onclick="showCodeWithSearch(this.dataset.name);return false"'
    vuln_link = 'data-name="\'+escAttr(f.name)+\'" onclick="showCodeWithSearch(this.dataset.name);return false"'
    assert win_link in resp.text
    assert ovf_link in resp.text
    assert vuln_link in resp.text
    # The old vulnerable pattern — the untrusted name spliced straight into
    # the quoted inline-handler argument — must be gone from all 3 sites.
    assert 'onclick="showCodeWithSearch(\\\'"+esc(w.name)+"\\\');return false"' not in resp.text
    assert 'onclick="showCodeWithSearch(\\\'"+esc(s.function)+"\\\');return false"' not in resp.text
    assert 'onclick="showCodeWithSearch(\\\'"+esc(f.name)+"\\\');return false"' not in resp.text


def test_index_response_ok_guard_covers_every_load_fetcher() -> None:
    resp = TestClient(server.app).get("/")
    guard = "if(!r.ok){const e=await r.json();throw new Error(e.detail||r.statusText);}"
    # 3 pre-existing sites (capa, solver generate, solver execute) + the 10
    # fetchers this test locks: imports, strings, sections/memory-map, vulns,
    # code-functions, vuln-hints, ROP scan, ROP gadget search, xrefs lookup,
    # xrefs build.
    assert resp.text.count(guard) == 13


def test_index_search_inputs_filter_client_side_without_a_fetch() -> None:
    resp = TestClient(server.app).get("/")
    # Both search boxes drive a pure-local filter/render helper on every
    # keystroke — the network fetch happens once, on load/tab-open, not here.
    assert 'oninput="filterCodeFunctions(this.value)"' in resp.text
    assert 'oninput="filterImports()"' in resp.text
    assert "function filterCodeFunctions(query) {" in resp.text
    assert "function filterImports() {" in resp.text
    # The render helpers are reachable without an intervening fetch() call —
    # confirm neither oninput handler survives as a direct fetch trigger.
    assert 'oninput="loadCodeFunctions(this.value)"' not in resp.text
    assert 'oninput="loadImports()"' not in resp.text


def test_index_subtab_switch_uses_a_non_ambiguous_name() -> None:
    resp = TestClient(server.app).get("/")
    assert "function switchSubview(panel, name) {" in resp.text
    assert "onclick=\"switchSubview('imports','imp')\"" in resp.text
    assert "onclick=\"switchSubview('exploit','vulns')\"" in resp.text
    # the old name must not survive as a callable identifier
    assert "function sub(panel, name) {" not in resp.text
    assert 'onclick="sub(' not in resp.text


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


def test_solver_ret2libc_wiring_matches_independent_recompute(client: TestClient, sample_path) -> None:
    """/api/solver?solver_type=ret2libc bakes in the same pop_rdi ROPEngine.scan()
    independently finds for this sample, and falls back to the documented OFFSET
    constant since this sample has no BOF sink (no overflow site)."""
    resp = client.get("/api/solver", params={"solver_type": "ret2libc"})
    assert resp.status_code == 200
    code = resp.json()["code"]
    compile(code, "<api/solver:ret2libc>", "exec")

    ldr = BinaryLoader(str(sample_path))
    try:
        gadgets = analysis.scan_gadgets(ROPEngine(ldr))
    finally:
        ldr.close()

    expected_pop_rdi = int(gadgets["pop rdi; ret"], 16)
    assert f"POP_RDI = {hex(expected_pop_rdi)}" in code
    assert "OFFSET  = 64" in code


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
