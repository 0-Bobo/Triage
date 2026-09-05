"""FastAPI server application — routes, middleware, and entry point."""

import logging
import os
import re
import sys
import tempfile
from dataclasses import dataclass, fields
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from triage_web.analysis import (
    VULN_BOF,
    VULN_FMT,
    build_known_calls,
    build_string_map,
    code_example,
    find_binsh,
    find_win_functions,
    overflow_sites,
    pwntools_skeleton,
    scan_gadgets,
    section_for_offset,
)
from triage_web.config import DEFAULT_MNEMONIC_COLOR, VULN_SEVERITY_COLORS
from triage_web.config import MNEMONIC_COLORS as MNEMONIC_COLOR_MAP
from triage_web.engine import HAS_CAPSTONE, Disassembler, ROPEngine, XRefDB
from triage_web.frontend import HTML_PAGE
from triage_web.knowledge import EXPLOIT_TECHNIQUES, MITRE_VULN_MAP, VULN_PATTERNS
from triage_web.loader import BinaryLoader
from triage_web.solvers import execute_solver, generate_solver, get_solver_list

log = logging.getLogger("triage-web")

# ── FastAPI App ────────────────────────────────────────────────────────

# Localhost-only by default — this is a single-user local tool, not a
# multi-tenant service, so there's no reason any other origin should be
# able to read its API responses out of the box. Matches main()'s own
# default bind (--port 8888). Set TRIAGE_CORS_ORIGINS (comma-separated,
# or "*") to explicitly widen this for a non-default deployment.
_DEFAULT_CORS_ORIGINS = ["http://localhost:8888", "http://127.0.0.1:8888"]


def _cors_origins() -> list[str]:
    """Allowed CORS origins: TRIAGE_CORS_ORIGINS (comma-separated) if set,
    else the localhost-only default. Setting TRIAGE_CORS_ORIGINS is a
    deliberate opt-in for a wider deployment."""
    env = os.environ.get("TRIAGE_CORS_ORIGINS")
    if not env:
        return _DEFAULT_CORS_ORIGINS
    return [o.strip() for o in env.split(",") if o.strip()]


app = FastAPI(title="Triage Web", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=_cors_origins(), allow_methods=["*"], allow_headers=["*"])

# Upload limits — TRIAGE_MAX_UPLOAD_BYTES matches the documented ~500MB
# binary-size ceiling from PROJECT.md; reads happen in fixed-size chunks so
# an oversized body is rejected mid-stream instead of fully buffered first.
_MAX_UPLOAD_BYTES = int(os.environ.get("TRIAGE_MAX_UPLOAD_BYTES", str(500 * 1024 * 1024)))
_UPLOAD_CHUNK_BYTES = 1024 * 1024


@dataclass
class Session:
    """The single binary currently loaded into the server.

    One process holds one binary (the analysis backends are stateful and
    memory-heavy). The ``require_*`` accessors narrow ``None`` away and raise
    a 400 so handlers don't each repeat the "not loaded" guard.
    """

    loader: BinaryLoader | None = None
    disasm: Disassembler | None = None
    rop: ROPEngine | None = None
    xrefs: XRefDB | None = None
    path: str | None = None
    filename: str | None = None

    def reset(self, **values: object) -> None:
        """Close the previous binary and replace the whole session."""
        if self.loader is not None:
            self.loader.close()
        known = {f.name for f in fields(self)}
        for name in known:
            setattr(self, name, values.get(name))

    def require_loader(self) -> BinaryLoader:
        if self.loader is None:
            raise HTTPException(400, "No binary loaded. Load one first.")
        return self.loader

    def require_disasm(self) -> Disassembler:
        if self.disasm is None:
            raise HTTPException(400, "Disassembler not initialized — load a binary first")
        return self.disasm

    def require_rop(self) -> ROPEngine:
        if self.rop is None:
            raise HTTPException(400, "ROP engine not initialized — load a binary first")
        return self.rop

    def require_xrefs(self) -> XRefDB:
        if self.xrefs is None:
            raise HTTPException(400, "XRefs not initialized — load a binary first")
        return self.xrefs


_session = Session()


def _get_loader() -> BinaryLoader:
    return _session.require_loader()


def _size_to_next_function(loader: BinaryLoader, addr: int) -> int:
    """Byte span from ``addr`` to the next function boundary, capped at 256."""
    next_addr = addr + 256
    for _name, a2 in loader.get_functions():
        if a2 > addr:
            next_addr = min(next_addr, a2)
            break
    return next_addr - addr


def _safe_staged_upload_path(filename: str) -> str | None:
    """Build the predictable staged-copy path for an uploaded ``filename``,
    guaranteed to resolve inside ``tempfile.gettempdir()``.

    The client-supplied filename is untrusted: normalize backslashes to
    forward slashes and strip embedded NUL bytes first, so a plain
    ``os.path.basename`` (which only recognizes the current OS's separator)
    can't be defeated by a backslash-separated or NUL-embedded name on a
    POSIX host. As a final backstop, resolve the joined path and confirm it
    is still inside the temp directory — returns ``None`` if that check
    ever fails, so the caller can skip the staged copy instead of writing
    outside the intended directory.
    """
    normalized = filename.replace("\\", "/").replace("\x00", "")
    safe_name = os.path.basename(normalized) or "upload"
    dest = os.path.join(tempfile.gettempdir(), "triage_" + safe_name)
    tempdir = Path(tempfile.gettempdir()).resolve()
    resolved = Path(dest).resolve()
    if not resolved.is_relative_to(tempdir):
        return None
    return dest


# ── Health / Shutdown ─────────────────────────────────────────────────


@app.get("/api/health")
def health():
    from triage_web.loader import HAS_LIEF, HAS_PEFILE, HAS_PYELFTOOLS

    return {
        "status": "ok",
        "deps": {
            "pyelftools": HAS_PYELFTOOLS,
            "pefile": HAS_PEFILE,
            "capstone": HAS_CAPSTONE,
            "lief": HAS_LIEF,
        },
    }


@app.post("/api/shutdown")
def api_shutdown():  # pragma: no cover - calls os._exit; would kill the test runner
    import threading
    import time

    # Give the response 0.15s to flush, then exit cleanly (no traceback)
    threading.Thread(target=lambda: (time.sleep(0.15), os._exit(0)), daemon=True).start()
    return {"status": "ok", "message": "Server shutting down"}


# ── Load ──────────────────────────────────────────────────────────────


@app.post("/api/load")
async def api_load(path: str = Form(""), file: UploadFile = File(None)):
    original_name = None
    if file and file.filename:
        ext = Path(file.filename).suffix
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
        total = 0
        while chunk := await file.read(_UPLOAD_CHUNK_BYTES):
            total += len(chunk)
            if total > _MAX_UPLOAD_BYTES:
                tmp.close()
                os.unlink(tmp.name)
                raise HTTPException(413, f"Upload exceeds the {_MAX_UPLOAD_BYTES}-byte limit")
            tmp.write(chunk)
        tmp.close()
        target = tmp.name
        original_name = file.filename
        # Copy to a predictable path so solver scripts can reference the file
        dest = _safe_staged_upload_path(file.filename)
        if dest is not None:
            try:
                import shutil

                shutil.copy2(target, dest)
                target = dest
            except Exception as e:
                log.debug("could not stage upload at %s: %s — using temp path", dest, e)
        else:
            log.debug("rejected unsafe staged-upload filename: %r — using temp path", file.filename)
    elif path:
        if not os.path.isfile(path):
            raise HTTPException(400, f"File not found: {path}")
        target = path
        original_name = os.path.basename(path)
    else:
        raise HTTPException(400, "Provide path or upload a file")
    try:
        loader = BinaryLoader(target)
        if not HAS_CAPSTONE:
            loader.close()
            raise HTTPException(400, "capstone is required for analysis")
        _session.reset(
            loader=loader,
            disasm=Disassembler(loader.arch, loader.bits),
            rop=ROPEngine(loader),
            xrefs=XRefDB(),
            path=target,
            filename=original_name,
        )
        return {"status": "ok", "info": loader.get_info(), "filename": original_name}
    except HTTPException:
        raise  # deliberate 4xx — don't remap to 500
    except Exception as e:
        raise HTTPException(500, f"Load failed: {e}") from e


@app.post("/api/unload")
def api_unload():
    """Release the currently loaded binary and free its analysis backends."""
    _session.reset()
    return {"status": "ok"}


# ── Info ──────────────────────────────────────────────────────────────


@app.get("/api/info")
def api_info():
    return _get_loader().get_info()


# ── Functions ─────────────────────────────────────────────────────────


@app.get("/api/functions")
def api_functions(search: str = ""):
    loader = _get_loader()
    funcs = loader.get_functions()
    if search:
        funcs = [(n, a) for n, a in funcs if search.lower() in n.lower()]
    return [{"name": n, "address": hex(a)} for n, a in funcs]


# ── Imports ───────────────────────────────────────────────────────────


@app.get("/api/imports")
def api_imports():
    loader = _get_loader()
    return [
        {
            "name": i["name"],
            "library": i["library"],
            "vuln": list(VULN_PATTERNS.get(i["name"], ())) if i["name"] in VULN_PATTERNS else None,
        }
        for i in loader.get_imports()
    ]


# ── Exports ───────────────────────────────────────────────────────────


@app.get("/api/exports")
def api_exports():
    return _get_loader().get_exports()


# ── Sections ──────────────────────────────────────────────────────────


@app.get("/api/sections")
def api_sections():
    loader = _get_loader()
    secs = loader.get_sections()
    for s in secs:
        try:
            data = loader.read_vaddr(s["vaddr"], min(s["size"], 4096))
            s["entropy"] = round(loader.compute_entropy(data), 3)
        except Exception:
            s["entropy"] = 0.0
    return secs


# ── Segments ──────────────────────────────────────────────────────────


@app.get("/api/segments")
def api_segments():
    return _get_loader().get_segments()


# ── Strings ───────────────────────────────────────────────────────────


@app.get("/api/strings")
def api_strings(min_len: int = 4, search: str = ""):
    loader = _get_loader()
    strs = loader.get_strings(min_len=min_len)
    if search:
        strs = [s for s in strs if search.lower() in s.lower()]
    cols = ["#ff7b72", "#d29922", "#3fb950", "#58a6ff", "#bc8cff", "#f778ba", "#56d4dd"]
    return [{"text": s, "color": cols[hash(s) % len(cols)], "len": len(s)} for s in strs[:5000]]


# ── Hex ───────────────────────────────────────────────────────────────


@app.get("/api/hex")
def api_hex(off: str | None = None, vaddr: str | None = None, size: int = 512):
    """Hex window keyed by raw file offset (`off`) or virtual address (`vaddr`).
    Returns the raw bytes plus the resolved offset/vaddr, containing section,
    and total file size — the client lays out rows and handles selection."""
    loader = _get_loader()
    raw = loader._raw
    total = len(raw)
    size = max(16, min(int(size), 8192))

    if vaddr is not None:
        va = int(vaddr, 16)
        o = loader.vaddr_to_offset(va)
        base = o if o >= 0 else (va if 0 <= va < total else 0)
    else:
        base = int(off, 16) if off else 0
    base = max(0, min(base, max(0, total - 1)))

    data = bytes(raw[base : base + size])
    section, base_va = section_for_offset(loader, base)
    return {
        "off": base,
        "vaddr": base_va,
        "size": len(data),
        "total": total,
        "section": section,
        "hex": data.hex(),
    }


@app.get("/api/hex/search")
def api_hex_search(q: str, kind: str = "auto", limit: int = 500):
    """Find a byte pattern in the raw file. kind: 'hex' | 'str' | 'auto'."""
    loader = _get_loader()
    raw = bytes(loader._raw)
    if kind == "str":
        needle = q.encode("latin-1", "ignore")
    elif kind == "hex":
        hx = re.sub(r"[^0-9a-fA-F]", "", q)
        needle = bytes.fromhex(hx[:-1] if len(hx) % 2 else hx) if hx else b""
    else:
        cleaned = re.sub(r"\s+|^0x", "", q, flags=re.I)
        if cleaned and re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) % 2 == 0:
            needle = bytes.fromhex(cleaned)
        else:
            needle = q.encode("latin-1", "ignore")
    if not needle:
        return {"hits": [], "needle_len": 0, "total": len(raw)}
    hits = []
    i = raw.find(needle)
    while i != -1 and len(hits) < limit:
        hits.append(i)
        i = raw.find(needle, i + 1)
    return {"hits": hits, "needle_len": len(needle), "total": len(raw)}


# ── Disassembly ───────────────────────────────────────────────────────


@app.get("/api/disasm")
def api_disasm(vaddr: str = "0x0", size: int = 256):
    loader = _get_loader()
    disasm = _session.require_disasm()
    addr = int(vaddr, 16)
    data = loader.read_vaddr(addr, size)
    if not data:
        return {"insns": [], "address": addr, "count": 0}
    insns = disasm.disassemble(data, addr)
    result = []
    for i in insns:
        color = MNEMONIC_COLOR_MAP.get(i["mnemonic"].lower(), DEFAULT_MNEMONIC_COLOR)
        result.append(
            {
                "address": hex(i["address"]),
                "mnemonic": i["mnemonic"],
                "op_str": i["op_str"],
                "bytes": i["bytes"],
                "color": color,
            }
        )
    return {"insns": result, "address": addr, "count": len(result)}


# ── Disasm: Functions ────────────────────────────────────────────────


@app.get("/api/disasm/functions")
def api_disasm_functions():
    loader = _get_loader()
    _session.require_disasm()  # 400 if analysis isn't ready

    known_calls = build_known_calls(loader)
    funcs = loader.get_functions()
    # Binary-wide flag: does this binary import/resolve any known-vulnerable call?
    # (Per-function attribution would require disassembling every function here.)
    binary_has_vuln_calls = any(name in VULN_PATTERNS for name in known_calls.values())
    result = []
    for name, addr in funcs:
        # Compute size from next function or section end
        size = 32
        for _name, a2 in funcs:
            if a2 > addr:
                size = min(a2 - addr, 2048)
                break
        result.append(
            {
                "name": name,
                "address": hex(addr),
                "size": size,
                "is_vulnerable": binary_has_vuln_calls,
            }
        )
    return {"functions": result, "count": len(result)}


@app.get("/api/disasm/function")
def api_disasm_function(vaddr: str = "0x0", size: int = 0):
    loader = _get_loader()
    disasm = _session.require_disasm()
    addr = int(vaddr, 16)

    known_calls = build_known_calls(loader)

    # Auto-size to next function boundary if size not given
    if not size or size < 1:
        size = _size_to_next_function(loader, addr)

    data = loader.read_vaddr(addr, size)
    if not data:
        return {"insns": [], "address": hex(addr), "count": 0}
    analysis = disasm.analyze_function(data, addr, known_calls)
    return analysis


@app.get("/api/disasm/variables")
def api_disasm_variables(vaddr: str = "0x0", size: int = 0):
    loader = _get_loader()
    disasm = _session.require_disasm()
    addr = int(vaddr, 16)

    known_calls = build_known_calls(loader)

    if not size or size < 1:
        size = _size_to_next_function(loader, addr)

    data = loader.read_vaddr(addr, size)
    if not data:
        return {"stack_vars": [], "stack_frame": 0}
    analysis = disasm.analyze_function(data, addr, known_calls)
    return {
        "address": hex(addr),
        "stack_frame": analysis["stack_frame"],
        "stack_vars": analysis["stack_vars"],
        "calls": analysis["calls"],
    }


@app.get("/api/disasm/decompile")
def api_disasm_decompile(vaddr: str = "0x0"):
    """GET /api/disasm/decompile?vaddr=0x...
    Returns pseudo-C decompilation of the function at the given address."""
    loader = _get_loader()
    disasm = _session.require_disasm()
    addr = int(vaddr, 16)

    known_calls = build_known_calls(loader)

    # Auto-size to the *nearest* following function boundary
    nexts = [a2 for _, a2 in loader.get_functions() if a2 > addr]
    next_addr = min(nexts) if nexts else addr + 256
    size = min(next_addr - addr, 8192)

    data = loader.read_vaddr(addr, size)
    if not data:
        return {"code": "// no code at " + vaddr, "address": vaddr}

    analysis = disasm.analyze_function(data, addr, known_calls)
    string_map = build_string_map(loader, analysis.get("insns", []))
    # Resolve the real symbol name for this function (falls back to sub_<addr>)
    func_name = (
        known_calls.get(addr) or next((n for n, a in loader.get_functions() if a == addr), "") or f"sub_{addr:x}"
    )
    pseudo_c = disasm.decompile_function(analysis, known_calls, string_map, func_name)
    return {
        "address": vaddr,
        "code": pseudo_c,
        "func_name": func_name,
        "insn_count": len(analysis.get("insns", [])),
        "stack_frame": analysis.get("stack_frame", 0),
        "var_count": len(analysis.get("stack_vars", [])),
    }


# ── Cross-References ─────────────────────────────────────────────────


@app.get("/api/xrefs")
def api_xrefs(vaddr: str = "0x0"):
    xrefs = _session.require_xrefs()
    addr = int(vaddr, 16)
    callers = [{"from": hex(f), "type": t} for f, t in xrefs.get_callers(addr)]
    callees = [{"to": hex(t), "type": typ} for t, typ in xrefs.get_callees(addr)]
    return {"address": vaddr, "callers": callers, "callees": callees}


@app.post("/api/xrefs/build")
def api_xrefs_build(vaddr: str = "0x0", size: int = 4096):
    loader = _get_loader()
    xrefs = _session.require_xrefs()
    disasm = _session.require_disasm()
    addr = int(vaddr, 16)
    data = loader.read_vaddr(addr, size)
    if not data:
        return {"count": 0, "status": "no data at address"}
    insns = disasm.disassemble(data, addr)
    xrefs.build_from_insns(insns)
    return {"count": len(insns), "status": "ok"}


# ── Vulnerabilities ──────────────────────────────────────────────────


@app.get("/api/vulns")
def api_vulns():
    loader = _get_loader()
    vulns = []
    for imp in loader.get_imports():
        if imp["name"] in VULN_PATTERNS:
            sev, desc, fix = VULN_PATTERNS[imp["name"]]
            vulns.append(
                {
                    "name": imp["name"],
                    "address": hex(imp["address"]) if imp.get("address") else "",
                    "severity": sev,
                    "description": desc,
                    "fix": fix,
                    "exploit_path": MITRE_VULN_MAP.get(imp["name"], {}).get("exploit_path", ""),
                    "color": VULN_SEVERITY_COLORS.get(sev, "#8b949e"),
                }
            )
    return sorted(
        vulns,
        key=lambda v: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(v["severity"], 4),
    )


# ── ROP ───────────────────────────────────────────────────────────────


@app.post("/api/rop/scan")
def api_rop_scan():
    rop = _session.require_rop()
    rop.scan()
    return rop.get_summary()


@app.get("/api/rop/gadgets")
def api_rop_gadgets(query: str = "", cls: str = ""):
    rop = _session.require_rop()
    return {"gadgets": rop.search(query=query, semantic_cls=cls), "total": len(rop.gadgets)}


# ── Protections ──────────────────────────────────────────────────────


@app.get("/api/protections")
def api_protections():
    return _get_loader().protections()


# ── CAPA ──────────────────────────────────────────────────────────────


@app.post("/api/capa")
def api_capa():
    try:
        import capa
        import capa.loader as cloader
        import capa.main
        import capa.rules
        import capa.rules.cache
    except ImportError:
        raise HTTPException(400, "capa not installed — run: pip install flare-capa") from None
    import pathlib

    loader = _get_loader()
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    capa_root = pathlib.Path(capa.main.get_default_root())
    env_rules = os.environ.get("TRIAGE_CAPA_RULES")
    rules_candidates = [
        pathlib.Path(env_rules) if env_rules else None,
        repo_root / "capa-rules",  # the pinned git submodule
        capa_root / "rules",
        capa_root.parent / "rules",
        pathlib.Path("/usr/share/capa/rules"),
        pathlib.Path(os.path.expanduser("~/.capa/rules")),
    ]
    rules_dir = next(
        (p for p in rules_candidates if p and p.is_dir() and next(p.rglob("*.yml"), None)),
        None,
    )
    if not rules_dir:
        raise HTTPException(
            400,
            "CAPA rules not found. Run `git submodule update --init capa-rules`, "
            "or set TRIAGE_CAPA_RULES to a capa-rules checkout.",
        )
    try:
        rules = capa.rules.get_rules([rules_dir])
        sigpaths = capa.main.get_default_signatures()
        extractor = cloader.get_extractor(pathlib.Path(loader.path), "auto", "auto", "vivisect", sigpaths)
        result = capa.main.find_capabilities(rules, extractor, disable_progress=True)
        caps = result.matches if hasattr(result, "matches") else result
        items = []
        for rule_name, matches in caps.items():
            ns = ""
            if hasattr(matches, "__iter__") and not isinstance(matches, dict):
                ns = getattr(next(iter(matches), None), "namespace", "")
            items.append(
                {
                    "rule": rule_name,
                    "namespace": str(ns) if ns else "",
                    "matches": len(matches) if hasattr(matches, "__len__") else 0,
                }
            )
        return {"capabilities": items, "count": len(items)}
    except Exception as e:
        raise HTTPException(500, f"CAPA analysis failed: {e}") from e


# ── Solver ────────────────────────────────────────────────────────────


@app.get("/api/solver")
def api_solver(solver_type: str = "angr_find_flag"):
    loader = _get_loader()
    disasm = _session.disasm  # optional here — degrade gracefully if absent
    rop = _session.rop
    gadgets = scan_gadgets(rop)
    pop_rdi_hex = gadgets.get("pop rdi; ret")
    pop_rdi = int(pop_rdi_hex, 16) if pop_rdi_hex is not None else None
    known_calls = build_known_calls(loader) if disasm else {}
    ov_sites = overflow_sites(loader, disasm, known_calls, loader.bits == 64) if disasm else []
    overflow_offset = ov_sites[0]["est_offset_to_ret"] if ov_sites else None
    code = generate_solver(
        solver_type, loader.path, loader.arch, loader.bits, pop_rdi=pop_rdi, overflow_offset=overflow_offset
    )
    return {"code": code, "type": solver_type, "arch": loader.arch, "bits": loader.bits}


@app.post("/api/solver/execute")
def api_solver_execute(body: dict):
    code = body.get("code", "")
    result = execute_solver(code)
    return result


@app.get("/api/solvers")
def api_solvers():
    return {"solvers": get_solver_list()}


# ── Symbols ───────────────────────────────────────────────────────────


@app.get("/api/symbols")
def api_symbols(search: str = ""):
    loader = _get_loader()
    syms = loader.get_symbols()
    if search:
        syms = [s for s in syms if search.lower() in s["name"].lower()]
    return syms


# ── Crypto ────────────────────────────────────────────────────────────


@app.get("/api/crypto")
def api_crypto():
    loader = _get_loader()
    return [{"name": n, "offset": hex(o)} for n, o in loader.detect_crypto()]


# ── Packer ────────────────────────────────────────────────────────────


@app.get("/api/packer")
def api_packer():
    return _get_loader().detect_packer()


# ── Entropy ───────────────────────────────────────────────────────────


@app.get("/api/entropy")
def api_entropy():
    loader = _get_loader()
    if loader._entropy_cache is not None:
        return loader._entropy_cache
    raw = bytes(loader._raw)
    block = 256
    blocks = []
    for i in range(0, len(raw), block):
        data = raw[i : i + block]
        blocks.append(round(loader.compute_entropy(data), 3))
    loader._entropy_cache = {"blocks": blocks, "block_size": block, "total_bytes": len(raw)}
    return loader._entropy_cache


# ── Memory Map ────────────────────────────────────────────────────────


@app.get("/api/memory-map")
def api_memory_map():
    loader = _get_loader()
    secs = []
    for s in loader.get_sections():
        off = s.get("offset", 0)
        size = s.get("size", 0)
        ent = 0.0
        if off >= 0 and size > 0:
            try:
                data = bytes(loader._raw[off : off + min(size, 4096)])
                ent = round(loader.compute_entropy(data), 3)
            except Exception as e:
                log.debug("entropy for section at 0x%x failed: %s", off, e)
        secs.append(
            {
                "name": s["name"],
                "vaddr": hex(s["vaddr"]),
                "size": s["size"],
                "flags": str(s.get("flags", 0)),
                "type": s.get("type", ""),
                "entropy": ent,
                "offset": s.get("offset", -1),
            }
        )
    segs = []
    for s in loader.get_segments():
        segs.append(
            {
                "type": s["type"],
                "vaddr": hex(s["vaddr"]),
                "memsz": s["memsz"],
                "filesz": s["filesz"],
                "flags": s["flags"],
            }
        )
    return {"sections": secs, "segments": segs}


# ── Vuln Hints (MITRE ATT&CK) ────────────────────────────────────────


@app.get("/api/vuln-hints")
def api_vuln_hints():
    loader = _get_loader()
    disasm = _session.disasm  # optional here — degrade gracefully if absent
    rop = _session.rop
    is64 = loader.bits == 64
    imports = {i["name"] for i in loader.get_imports()}
    imports_by_name = {i["name"]: i for i in loader.get_imports()}
    prot = loader.protections()
    nx = "Enabled" in str(prot.get("NX (No-Execute)", ""))
    pie = "Enabled" in str(prot.get("PIE (ASLR)", ""))
    canary = "Enabled" in str(prot.get("Stack Canary", ""))
    relro = "Full" in str(prot.get("RELRO", ""))
    static = len(loader.get_imports()) == 0

    win_functions = find_win_functions(loader)
    binsh = find_binsh(loader)
    gadgets = scan_gadgets(rop)
    known_calls = build_known_calls(loader) if disasm else {}
    ov_sites = overflow_sites(loader, disasm, known_calls, is64) if disasm else []

    filename = _session.filename or "chall"
    first_off = ov_sites[0]["est_offset_to_ret"] if ov_sites else None

    # ── Per-function detail (imports that are exploitation-relevant) ──
    functions_exploit = []
    for imp_name in sorted(imports):
        if imp_name not in VULN_PATTERNS:
            continue
        if imp_name not in (
            VULN_BOF
            | VULN_FMT
            | {
                "malloc",
                "free",
                "system",
                "execve",
                "popen",
                "memcpy",
                "mprotect",
                "realloc",
                "calloc",
                "atoi",
                "strtol",
            }
        ):
            continue
        sev, desc, fix = VULN_PATTERNS[imp_name]
        info = imports_by_name.get(imp_name, {})
        address = info.get("address", None)
        functions_exploit.append(
            {
                "name": imp_name,
                "address": hex(address) if address else "",
                "severity": sev,
                "issue": desc,
                "fix": fix,
                "code": code_example(imp_name),
                "recipe": MITRE_VULN_MAP.get(imp_name, {}).get("exploit_path", ""),
            }
        )

    # ── Ranked, binary-specific attack paths ────────────────────────
    paths = []

    if ov_sites or (imports & VULN_BOF):
        off = first_off if first_off is not None else "OFFSET"
        if win_functions and nx:
            steps = [
                f"Overflow the buffer in {ov_sites[0]['function']}() — ~{off} bytes to the saved return address"
                if ov_sites
                else "Overflow a stack buffer to the saved return address",
                f"Overwrite saved RIP with {win_functions[0]['name']} @ {win_functions[0]['address']}",
                "If it crashes inside the win function, add one `ret` gadget for 16-byte stack alignment",
            ]
            if pie:
                steps.append(
                    "PIE is ON — the win address is randomized; leak the ELF base "
                    "(or use a partial overwrite of the low bytes of saved RIP)"
                )
            paths.append(
                {
                    "name": "ret2win",
                    "confidence": "medium" if (canary or pie) else "high",
                    "why": f"stack overflow primitive + win function `{win_functions[0]['name']}`"
                    + (" — stack canary present, leak it first" if canary else "")
                    + (" — PIE on, need an ELF leak" if pie else ""),
                    "steps": steps,
                    "skeleton": pwntools_skeleton(
                        "ret2win", {"filename": filename, "offset": off, "win": win_functions[0]["name"]}
                    ),
                }
            )
        if not nx:
            paths.append(
                {
                    "name": "Shellcode injection (NX off)",
                    "confidence": "high",
                    "why": "NX is disabled — the stack/bss is executable",
                    "steps": [
                        "Place shellcode in the overflowed buffer (or .bss)",
                        "Overwrite saved RIP with the address of your shellcode",
                        "Need a stack leak unless a jmp/call rsp gadget exists",
                    ],
                    "skeleton": pwntools_skeleton("shellcode", {"filename": filename, "offset": off}),
                }
            )
        if nx and not canary:
            has_syscall_chain = all(k in gadgets for k in ("pop rdi; ret",)) and (
                "syscall" in gadgets or "int 0x80" in gadgets
            )
            if "system" in imports or binsh:
                paths.append(
                    {
                        "name": "ret2system",
                        "confidence": "high" if ("system" in imports and binsh) else "medium",
                        "why": ("system@plt present" if "system" in imports else "no system@plt")
                        + (f' + "/bin/sh" @ {binsh["vaddr"] or binsh["offset"]}' if binsh else " + no /bin/sh string"),
                        "steps": [
                            f"padding = {off}",
                            f"pop rdi; ret @ {gadgets.get('pop rdi; ret', '<find one>')}",
                            f'rdi = &"/bin/sh" ({binsh["vaddr"] if binsh else "write it via read() into .bss"})',
                            "return into system@plt" + ("" if is64 else " (32-bit: arg goes on the stack, not rdi)"),
                        ],
                        "skeleton": pwntools_skeleton("ret2libc", {"filename": filename, "offset": off}),
                    }
                )
            if has_syscall_chain:
                paths.append(
                    {
                        "name": "execve syscall ROP",
                        "confidence": "medium",
                        "why": "pop-gadgets + syscall present — no libc needed",
                        "steps": [
                            'Set rdi=&"/bin/sh", rsi=0, rdx=0, rax=59, then `syscall`',
                            'Write "/bin/sh\\0" into a known writable address first (read@plt into .bss)',
                        ],
                        "skeleton": pwntools_skeleton(
                            "syscall_rop",
                            {"filename": filename, "offset": off, "binsh": binsh["vaddr"] if binsh else "0x0"},
                        ),
                    }
                )
            paths.append(
                {
                    "name": "ret2libc (leak + return)",
                    "confidence": "medium",
                    "why": "dynamically linked, NX on, no canary — classic 2-stage leak",
                    "steps": [
                        "Stage 1: leak a libc address (puts(puts@got)), return to main/vuln",
                        "Compute libc base from the leak",
                        'Stage 2: overflow again → system("/bin/sh") or a one_gadget',
                    ],
                    "skeleton": pwntools_skeleton("ret2libc", {"filename": filename, "offset": off}),
                }
            )
        if canary:
            paths.append(
                {
                    "name": "Defeat the stack canary first",
                    "confidence": "info",
                    "why": "canary present — a raw overwrite of RIP will trip __stack_chk_fail",
                    "steps": [
                        "Leak it: format string, an OOB read/print, or brute-force byte-by-byte on a forking server",
                        "Keep the leaked canary word in place in your payload, then overflow past it",
                    ],
                    "skeleton": "",
                }
            )

    if (imports & VULN_FMT) and "printf" in imports:
        paths.append(
            {
                "name": "Format string",
                "confidence": "medium",
                "why": "printf-family import present — exploitable if the format arg is user-controlled",
                "steps": [
                    "Find your arg offset: send `%p ` * 20 and count to your bytes",
                    "Leak: canary (`%N$p`), PIE/ELF base, libc (a __libc_start_main+ret on the stack)",
                    "Write: `fmtstr_payload(off, {target: value})` — "
                    + (
                        "printf@got → system@plt (partial RELRO)"
                        if not relro
                        else "__free_hook / return address (full RELRO)"
                    ),
                ],
                "skeleton": pwntools_skeleton("fmt", {"filename": filename}),
            }
        )

    if {"malloc", "free"} <= imports or {"malloc", "calloc"} & imports:
        paths.append(
            {
                "name": "Heap exploitation",
                "confidence": "medium" if {"malloc", "free"} <= imports else "low",
                "why": f"{'malloc+free' if {'malloc', 'free'} <= imports else 'allocator'} imported"
                + (" — no free(), look for a UAF via a dangling menu pointer" if "free" not in imports else ""),
                "steps": [
                    "Identify the menu: alloc / free / edit / view primitives and the max size",
                    "tcache poisoning (glibc <2.32) or safe-linking bypass (>=2.32): free two chunks, "
                    "corrupt fd, malloc back to an arbitrary address",
                    "Targets: __free_hook→system, a saved return address, a GOT entry, or FSOP on stdout",
                ],
                "skeleton": pwntools_skeleton("heap", {"filename": filename}),
            }
        )

    if not paths:
        paths.append(
            {
                "name": "No obvious memory-corruption primitive",
                "confidence": "info",
                "why": "none of the usual unsafe imports/patterns matched",
                "steps": [
                    "Run the angr solver (Solvers tab) if this is a flag-checker / crackme",
                    "Look for logic bugs: off-by-one, signed/unsigned size checks, integer overflow before malloc",
                    "Diff strings/xrefs for a hidden menu option or command",
                ],
                "skeleton": "",
            }
        )

    conf_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    paths.sort(key=lambda p: conf_rank.get(p.get("confidence"), 4))

    return {
        "protections": {
            "NX": str(prot.get("NX (No-Execute)", "?")),
            "PIE": str(prot.get("PIE (ASLR)", "?")),
            "Canary": str(prot.get("Stack Canary", "?")),
            "RELRO": str(prot.get("RELRO", "?")),
        },
        "summary": {
            "arch": f"{loader.arch} {loader.bits}-bit",
            "static": static,
            "win_functions": win_functions,
            "binsh": binsh,
            "gadgets": gadgets,
        },
        "overflow_sites": ov_sites,
        "vulnerable_functions": functions_exploit,
        "paths": paths,
    }


# ── Exploit Techniques ───────────────────────────────────────────────


@app.get("/api/exploit-techniques")
def api_exploit_techniques():
    techniques = []
    mitre_to_funcs = {}
    try:
        loader = _get_loader()
        for imp in loader.get_imports():
            fname = imp["name"]
            if fname in MITRE_VULN_MAP:
                info = MITRE_VULN_MAP[fname]
                tid = info["tid"]
                mitre_to_funcs.setdefault(tid, []).append(fname)
        has_nx = True
        is_pe = loader.fmt == loader.FMT_PE
        try:
            for s in loader.get_sections():
                fl = s.get("flags", 0) or 0
                if is_pe:  # PE section Characteristics
                    writable = bool(fl & 0x80000000)  # IMAGE_SCN_MEM_WRITE
                    executable = bool(fl & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
                else:  # ELF sh_flags
                    writable, executable = bool(fl & 0x1), bool(fl & 0x4)  # SHF_WRITE / SHF_EXECINSTR
                if ".text" in s.get("name", "") and not executable:
                    has_nx = False
                if writable and executable:
                    has_nx = False
        except Exception as e:
            log.debug("NX heuristic from section flags failed: %s", e)
    except Exception:
        return {"techniques": EXPLOIT_TECHNIQUES, "count": len(EXPLOIT_TECHNIQUES)}

    for t in EXPLOIT_TECHNIQUES:
        t_copy = dict(t)
        matched = mitre_to_funcs.get(t["mitre_id"], [])
        if matched:
            t_copy["matched_imports"] = matched
        if t["mitre_id"] == "T1059.006" and not has_nx:
            t_copy["nx_status"] = "disabled"
        techniques.append(t_copy)
    return {"techniques": techniques, "count": len(techniques)}


# ── Automated solver (autopwn) ──────────────────────────────────────


@app.get("/api/autopwn/recon")
def api_autopwn_recon(use_capa: bool = False):
    """Classify the loaded binary and rank the solver strategies."""
    _get_loader()  # 400 if nothing loaded
    from triage_web.autopwn import recon

    return recon(_session.path, use_capa=use_capa)


@app.post("/api/autopwn")
def api_autopwn(
    strategies: str | None = None,
    budget_s: float = 150.0,
    flag_pattern: str | None = None,
    use_capa: bool = False,
):
    """Run the automated solver against the loaded binary and return the
    flag plus every strategy attempt (each with its generated script)."""
    _get_loader()
    from triage_web.autopwn import solve

    only = [s.strip() for s in strategies.split(",")] if strategies else None
    budget = max(10.0, min(float(budget_s), 600.0))
    result = solve(_session.path, only=only, budget_s=budget, flag_pattern=flag_pattern, use_capa=use_capa)
    return {
        "path": result.path,
        "success": result.success,
        "flag": result.flag,
        "strategy": result.strategy,
        "seconds": result.seconds,
        "plans": result.plans,
        "attempts": result.attempts,
        "proof": result.proof,
        "notes": result.notes,
        "recon": result.recon,
    }


@app.get("/api/autopwn/stream")
def api_autopwn_stream(
    strategies: str | None = None,
    budget_s: float = 150.0,
    flag_pattern: str | None = None,
    use_capa: bool = False,
):
    """Same as ``POST /api/autopwn`` but streams progress as Server-Sent
    Events (``recon`` → ``plan`` → ``strategy_start``/``strategy_done`` … →
    ``done``) so the UI can show what the solver is doing while it runs."""
    import json
    import queue
    import threading

    from triage_web.autopwn import solve

    _get_loader()
    path = _session.path
    only = [s.strip() for s in strategies.split(",")] if strategies else None
    budget = max(10.0, min(float(budget_s), 600.0))

    events: queue.Queue = queue.Queue()
    _DONE = object()

    def _run():
        try:
            solve(path, only=only, budget_s=budget, flag_pattern=flag_pattern, use_capa=use_capa, on_event=events.put)
        except Exception as exc:  # never wedge the stream on an orchestrator bug
            events.put({"kind": "error", "message": f"{type(exc).__name__}: {exc}"})
        finally:
            events.put(_DONE)

    threading.Thread(target=_run, daemon=True).start()

    def _sse():
        while True:
            ev = events.get()
            if ev is _DONE:
                break
            yield f"data: {json.dumps(ev)}\n\n"

    return StreamingResponse(
        _sse(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Frontend ──────────────────────────────────────────────────────────


@app.get("/favicon.ico")
def favicon():
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<rect width="64" height="64" rx="8" fill="#0d1117"/>'
        '<text x="32" y="44" font-family="monospace" font-size="36" font-weight="bold" '
        'fill="#58a6ff" text-anchor="middle">T</text></svg>'
    )
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
def index():
    # no-store so a redeployed build's JS isn't served from the browser cache
    return HTMLResponse(HTML_PAGE, headers={"Cache-Control": "no-store"})


# ══════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════


def main():  # pragma: no cover - CLI entry point, starts uvicorn
    import argparse

    parser = argparse.ArgumentParser(description="Triage Web — CTF Binary Analysis Workbench")
    parser.add_argument("binary", nargs="?", help="Path to binary to load")
    # Binds all interfaces by default so a CTF team on the LAN can reach it;
    # pass --host 127.0.0.1 to restrict.
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")  # noqa: S104
    parser.add_argument("--port", type=int, default=8888, help="Port (default: 8888)")
    args = parser.parse_args()

    if args.binary:
        try:
            loader = BinaryLoader(args.binary)
            if not HAS_CAPSTONE:
                log.error("capstone is required")
                sys.exit(1)
            _session.reset(
                loader=loader,
                disasm=Disassembler(loader.arch, loader.bits),
                rop=ROPEngine(loader),
                xrefs=XRefDB(),
                path=args.binary,
                filename=os.path.basename(args.binary),
            )
            log.info(f"Pre-loaded: {args.binary}")
        except Exception as e:
            log.error(f"Failed to load {args.binary}: {e}")
            sys.exit(1)

    import uvicorn

    log.info(f"Starting server at http://{args.host}:{args.port}")
    print(f"\n  \033[1;36mTriage  http://localhost:{args.port}\033[0m\n")
    # Plain host/port bind — portable across Linux and Windows. (An earlier
    # version passed an inherited socket via uvicorn's `fd=`, which fails on
    # Windows because uvicorn resolves it with socket.AF_UNIX.)
    config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info")
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
