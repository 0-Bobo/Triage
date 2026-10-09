# Architecture

A CTF binary-analysis workbench. Load an ELF or PE, get disassembly, a
Ghidra-style pseudo-C decompilation, cross-references, ROP gadgets, vulnerability
hints, capa capabilities, and an `autopwn` subsystem that classifies the target
and runs solver strategies in priority order.

The orientation map for picking the repo up cold; read it after the README. For *what changed when*, read `CHANGELOG.md`.

---

## 1. The two pieces

| Piece | Path | Status |
|---|---|---|
| **Web app** | `triage_web/` | The shipped product. FastAPI backend + SPA (`index.html` + `style.css`, no build step). 100% line coverage on the shipped surface, 511 tests. |
| **autopwn** | `triage_web/autopwn/` | "Recon + first-move accelerator" (see §5). Importable library + `python -m triage_web.autopwn` CLI + three HTTP routes. |

`main.py` launches it; CI builds it; the tests cover it.

---

## 2. Directory map

```
main.py                     thin launcher -> triage_web.server:main
triage_web/                  the package (see §3)
  index.html                 the SPA markup + JS (~1644 lines); style.css holds the CSS
  style.css                  all page styles + @font-face (Geist Sans/Mono, static/fonts/*.woff2)
  static/fonts/              Geist Sans/Mono .woff2 files + their OFL license
  frontend.py                reads index.html/style.css once at import into HTML_PAGE/CSS_PAGE
  server.py                  FastAPI app: ~40 routes, upload handling, entry point
  analysis.py                pure domain helpers over BinaryLoader (no FastAPI)
  loader.py                  BinaryLoader — ELF/PE parse, protections, strings, hashes, arch detection
  engine.py                  Disassembler, ROP scanner, xref DB, basic blocks (Capstone)
  rop.py, xref.py            extracted from engine.py during a modular refactor
  knowledge.py               static tables: vuln patterns, crypto/packer sigs, ATT&CK
  solvers.py                 generates + executes standalone exploit scripts (pwntools/z3/angr templates)
  config.py                  colour palette + visual constants
  cfg.py pcode.py            EXPERIMENTAL Ghidra-style p-code decompiler pipeline —
  ssa_engine.py emit_c.py      reachable from no HTTP route, omitted from coverage,
  decompile_actions.py         only entered via engine.decompile_with_pcode (unused). See §4.
  autopwn/                   the accelerator (see §5)
tests/                       pytest suite (see §6)
samples/                     small purpose-built test binaries + their C source in samples/src/
samples/src/build.sh         rebuilds the sample binaries
capa-rules/                  git submodule -> github.com/mandiant/capa-rules
```

---

## 3. Request flow

```
browser (index.html)
   |  fetch /api/*
   v
server.py  --uses-->  analysis.py  --over-->  loader.BinaryLoader
   |                       |                    engine.Disassembler / rop / xref
   |                       '-- knowledge.py tables
   '-- GET /  -> frontend.HTML_PAGE  (index.html served verbatim)
```

- **`server.py`** owns HTTP only: routing, the uploaded-file lifecycle, error
  mapping. No analysis logic lives here.
- `analysis.py` is pure functions on a `BinaryLoader`, unit-tested directly
  against a sample binary with no TestClient. This is where `/api/disasm/*`
  and `/api/vuln-hints` logic actually lives.
- **`loader.py`** shells out to `strings` / `objdump` (trusted, from PATH) and
  uses `pyelftools` / `pefile` / optionally `lief`. `md5`/`sha1` here are file
  *identifiers*, not security.
- **`engine.py`** is Capstone-based. `Disassembler.disassemble(..., skip_junk=True)`
  is an anti-disassembly mode that steps over `eb 01` / `7x 01` + junk-byte
  sequences. `autopwn/strat_smc` uses it.
- Heavy backends (`angr`, `unicorn`, `lief`, `flare-capa`, `z3`, `keystone`) are
  all **runtime-optional**; modules degrade via `HAS_*` feature flags.

### Route groups (server.py)
`/api/health`, `/api/shutdown` · `/api/load` (upload) · info/functions/imports/
exports/sections/segments/symbols/strings · hex + hex/search · disasm +
disasm/functions/function/variables/decompile · xrefs (+build) · vulns +
vuln-hints · rop/scan + rop/gadgets · protections/crypto/packer/entropy ·
memory-map · capa · solver + solver/execute + solvers · exploit-techniques ·
**autopwn/recon**, **autopwn** (POST), **autopwn/stream** (SSE) · `/` (SPA).

---

## 4. The experimental p-code decompiler pipeline

`pcode.py` -> `cfg.py` -> `ssa_engine.py` -> `decompile_actions.py` -> `emit_c.py`
is a from-scratch, Ghidra-inspired decompiler (p-code IR, Lengauer–Tarjan
dominance, Cytron SSA, an action/rule pass pipeline, structured C emission).

**It is not wired to anything.** No HTTP route reaches it; the only entry point
is `engine.decompile_with_pcode`, which nothing calls. It is listed in
`[tool.coverage.run] omit` and `exclude_lines`. The shipped decompiler view uses
a simpler path in `engine.py`. Drop these from the omit list once the pipeline is
actually used and tested.

---

## 5. autopwn

The primary output is the recon: format, arch, protections, the ranked strategy plan, and per-strategy recovered parameters
(win address, overflow offset, struct size, compare key, decoded SMC image) plus
a runnable exploit *scaffold*. A recovered flag is a bonus. A *failed* solve
still returns the full picture. In docs and commit messages a strategy
surfaces, ranks, or recovers parameters; it does not "solve".

### Flow

```
recon(path, use_capa=?)              solve(path, budget_s=180, ...)
   |                                    |  emits on_event: recon->plan->
   v                                    |  strategy_start->strategy_done->done
BinaryLoader.get_info/protections       v
   |                              classify(path, capa)
   v                                    |
capa_scan.capabilities(path)  ----->  registry.build_view -> StaticView
   (optional, cached on disk at         |
    ~/.triage/capa-cache/)              v
                                  registry.plan(view)  -> ranked [StratPlan]
                                        |
                                        v  for each, in order, within budget
                                  registry.run_strategy(name, RunCtx)
                                        |      -> strat_<name>.run()
                                        v
                                  Attempt(strategy, ok, seconds, detail, flag, script)
                                        |  first ok+flag wins; else all recon kept
                                        v
                                  SolveResult  ->  JSONL telemetry row
                                                   ($TRIAGE_RESULTS or ~/.triage/results.jsonl)
```

### Module roles (`triage_web/autopwn/`)

| Module | Role |
|---|---|
| `__init__.py` | `recon()`, `solve()`, `SolveResult`, `_record()` telemetry. Public API. |
| `__main__.py` | `python -m triage_web.autopwn` CLI: `--only --budget --pattern --recon --json`. |
| `registry.py` | **The declarative core.** `Strategy(name, score(view)->(prio,why)|None, run(ctx)->Attempt)`. `STRATEGIES` list, `build_view`, `plan`, `run_strategy`. Adding a strategy = write `strat_<x>`, append one `Strategy`. |
| `classify.py` | Thin adapter: `BinaryLoader` -> `StaticView` -> `registry.plan`. Separate entry point because `recon` and tests call `classify(path)` directly. |
| `capa_scan.py` | Best-effort flare-capa pass; lowercased rule + namespace names feed `StaticView.capa` and reprioritise scores. Cached per file (path+size+mtime), in-process and on disk. |
| `runner.py` | WSL/native process bridge, flag extraction, `run_script(env=)`. Wraps every target/script run in `bwrap` -> `unshare` sandbox (`TRIAGE_SANDBOX=off`/`strict`). |
| `attempt.py` | The `Attempt` dataclass. |

### Strategy catalog

| name | score signal | what it recovers / does |
|---|---|---|
| `smc` | RWE `PT_LOAD` or trashed `e_ident`; capa `anti-analysis`/`self-modifying` | Static self-modifying-code unwrap: repairs mangled ELF header, reads the decoder stub's `mov end`/`mov count` via skip-junk disasm, brute-forces a reversible per-byte transform family (incl. the `rol1;not;rol3` involution), writes a byte-exact decoded image with `e_entry` repointed, neutralises hand-rolled `fork`/`ptrace` anti-debug (`0f 05`->`31 c0`), drops overlapping `PT_LOAD`s. |
| `keygen` | `input == CONSTANT -> win()` shape, any arch | Recovers the constant + win address; reconstructs a static flag when the win function assembles it from immediates. |
| `emulate` | small self-contained check function | Unicorn function run + memory scan. |
| `z3` | short arithmetic chain (`add/sub/xor/mul/shl/shr/rol/ror/neg/not`) before a constant compare | Models the chain, solves with z3 (`keygate` -> `0xdeadbeef`). |
| `ret2win` | BOF sink + a win function | Symbolic offset + pwntools payload + run. |
| `uaf` | dangling-callback pattern | Recon classifies how the planted callback's `arg1` is consumed — session `id` / socket `fd` / `ptr` (needs a leak, bails) — and routes the exploit accordingly. |
| `format_string` | `%p`-style user-controlled format | `%p` probe / leak script. |
| `angr` | fallback: symbolic stdin/argv -> success state | |
| `brute` | runnable checker + feedback oracle | char-by-char, then a short digit-keyspace, bounded by time + a 4000-run ceiling. |

---

## 6. Tests & the coverage contract

- `uv run pytest -q` (or `.venv/bin/python -m pytest -q`): 502 tests, ~20 s.
- `pyproject.toml` sets `fail_under = 100` for coverage, but with a large `omit`
  list: the entire p-code pipeline (§4) **and every `strat_*.py`** plus
  `capa_scan.py`. Only the autopwn *orchestration* layer (`runner`, `classify`,
  `registry`, `__init__`) is line-covered. The stated contract: the shipped web
  surface is 100%; the strategies are exercised end-to-end against `samples/`
  fixtures by `tests/test_autopwn.py` but not line-counted (unicorn is unstable
  under `sys.settrace`, and line-counting means every libc stub branch).
  `make coverage-strat` reports the strategy layer's real number with no gate
  (about 71% at the time of writing).
- Test files: `test_engine.py` (locks decompiler/engine behaviour, the big one),
  `test_autopwn.py`, `test_web_api.py` (TestClient), `test_server_unit.py`,
  `test_loader.py`, `test_analysis.py`, `test_solvers.py`, `test_rop.py`,
  `test_xref.py`, `test_config.py`, `test_golden_recon.py` (locks the
  deterministic `recon()` shape for 5 samples in `tests/golden/recon/*.json`).
  `conftest.py` builds/locates sample binaries.

---

## 7. Tooling

| Command | Purpose |
|---|---|
| `make dev` | install uv, `uv sync --all-extras --dev`, install pre-commit hooks |
| `make test` | fast pytest (skips slow capa/vivisect tests) |
| `make check` | `ruff check` + `ruff format --check` + pytest |
| `make coverage` | pytest with term/html/xml coverage, `--cov=triage_web` |
| `make coverage-strat` | report-only line coverage of the `omit`-ed `strat_*` / `capa_scan` layer (no gate) |
| `make deps-canary` | solver suite against **unpinned latest** angr/unicorn/pwntools/capstone — catch upstream breakage. Weekly in CI (`schedule:`) + on demand; never gates a PR. |
| `make autopwn BIN=path` | `python -m triage_web.autopwn` on one binary |

- **Package manager:** `uv`. `uv.lock` is committed; CI installs `--frozen`.
- **Lint:** ruff (`check` + `format --check`), line-length 120, rule sets
  `E W F I B C4 UP RUF S`. Per-file ignores in `pyproject.toml`
  (frontend/knowledge/solvers embed long strings; autopwn spawns processes on
  purpose). `samples/` and the `capa-rules` submodule are excluded wholesale
  (`extend-exclude`).
- **pre-commit:** ruff + ruff-format + whitespace/EOF/yaml; a `pre-push` hook
  runs the coverage gate.
- **CI** (`.github/workflows/ci.yml`): push/PR on `master` + `workflow_dispatch`
  + weekly `schedule:`. `test` job — matrix Python 3.12 & 3.13,
  `uv sync --all-extras --dev --frozen` -> `make lint` -> `make coverage` ->
  `pip-audit` (non-blocking) -> Codecov. `deps-canary` job — schedule /
  dispatch only, `continue-on-error`, runs `make deps-canary`.
- **Commits:** conventional (`feat: fix: docs: refactor: test: chore:`).

---

## 8. Samples & binaries

- `samples/` holds small, purpose-built binaries (`keygate`, `keycheck`,
  `ret2win`, `vuln_pie`, `vuln_canary`, `elf64_crackme`, `memflag`,
  `pe64_hello.exe`, ...) with C source in `samples/src/`; `build.sh` rebuilds
  them. These are the test fixtures.
- `Binaries/` is gitignored. Drop your own target binaries there for
  end-to-end runs; nothing in the repo depends on its contents.
- `capa-rules/` is a submodule: `git clone --recurse-submodules` or
  `git submodule update --init`.

---

## 9. Gotchas / known divergences

- The p-code decompiler pipeline is dead weight until it is wired up (§4);
  the decompiler view does not use it.
- capa needs the `capa-rules` submodule and `flare-capa`; without them
  `capa_scan` returns an empty capability set and strategy scoring silently falls
  back to static signals only.
- Sandbox: `runner` wraps execution in `bwrap` or `unshare`. On a host without
  either, set `TRIAGE_SANDBOX=off`; `=strict` refuses to run unsandboxed.
- Telemetry is best-effort and silent on failure. Every `solve()` appends a
  JSONL row to `$TRIAGE_RESULTS` or `~/.triage/results.jsonl`.
