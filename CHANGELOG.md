# Changelog

All notable changes to the web edition. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions predate the public
release.

## [Unreleased]

### Added
- **[`CONTEXT.md`](CONTEXT.md)**: newcomer-facing orientation map (what Triage is, the
  static-analysis/`autopwn` mental model, reading order, a "where to make
  a change" table, what's safe vs. load-bearing).
- **[`SECURITY.md`](SECURITY.md)**: explicit threat model (unauthenticated local file
  read + unauthenticated arbitrary code execution, by design, for a
  single-user local tool) and a private disclosure channel.
- **`.github/ISSUE_TEMPLATE/`**: bug report + feature request templates.
- **`triage_web/style.css`**: CSS split out of `index.html` into its own
  file; the five embedded base64 Geist Sans/Mono weights became real
  `.woff2` files under `triage_web/static/fonts/` (served via a
  `StaticFiles` mount), same same-origin guarantee, far smaller and more
  readable.
- **`--i-understand-the-network-risk`**: required alongside any
  non-loopback `--host`; the server now refuses to start without it
  instead of just printing a warning.
- **[`ARCHITECTURE.md`](ARCHITECTURE.md)**, cold-start orientation map: the web request flow, the
  unwired p-code decompiler pipeline, the `autopwn`
  recon → classify → registry → strategy flow, the strategy catalog, the
  coverage contract, tooling, and known gotchas.
- **`Attempt.confidence`** (`solved` / `likely` / `guess`), a strategy grades
  its own flag; the orchestrator defaults it to `solved` when a strategy
  returns a flag ungraded. Surfaced in `SolveResult.summary()`, the CLI, the
  SSE `strategy_done` event, and the telemetry row.
- **`strategy_start`** SSE event now carries `budget_remaining` (seconds), so
  the time spend is visible while a solve runs.
- **`solve(context=)`** (falls back to `$TRIAGE_CTX`), written to the
  `~/.triage/results.jsonl` telemetry row.
- **`make coverage-strat`**: report-only line coverage of the `omit`-ed
  `strat_*` / `capa_scan` layer, no gate.
- **Weekly `deps-canary` CI job**: the solver suite against unpinned-latest
  `angr` / `unicorn` / `pwntools` / `capstone`; non-gating, catches upstream
  backend breakage on a schedule.
- **`tests/test_golden_recon.py`**: locks the deterministic `recon()` shape
  (format / arch / protections / ranked plan) for five sample fixtures in the
  fast test path.

### Fixed
- **Two independent whole-repo security review passes closed 10
  findings**: unquoted/mis-quoted shell interpolation in the autopwn
  WSL/POSIX bridge (CWE-78), no CSRF/Origin check on state-mutating
  routes, `_srop_chain` crashing on every 32-bit target (plus a follow-up:
  its payload-packing line still used a fixed-width pack regardless of
  target bits), a `Session` singleton with no concurrency guard, an
  upload path that didn't reject shell metacharacters, a missing
  `Content-Security-Policy`/`X-Content-Type-Options` header, silent
  odd-length hex-search truncation, one `esc()` coverage gap on the
  disasm-table mnemonic cell, and doc drift (README port, stale test
  counts).
- **`solve_smc()` leaked a full copy of the target binary into the system
  temp directory** on every run that didn't actually decode anything;
  every binary classified as an SMC candidate that turned out not to be
  one left a permanent `triage_smc_*` file behind.
- **A stale `uv.lock` "desktop" extra** (PyQt6 and friends, left over from
  a dependency group that no longer exists in `pyproject.toml`) forced an
  unnecessary full re-resolution on `uv run`.
- **`starlette.testclient.TestClient` only worked by accident**: `httpx`
  reached the environment transitively via an optional IDA-plugin
  dependency chain, not as a declared test dependency; a fresh environment
  without that chain hit a hard `RuntimeError` at test collection. `httpx2`
  (the actually-required package) is now declared directly.
- Several frontend inconsistencies caught by a design review: 8 stray
  `border-radius` values contradicting the CSS's own sharp-corners rule,
  3 inline colors that bypassed the design tokens for raw, more-saturated
  defaults, and one full-color emoji among otherwise single-tone
  section-label glyphs.
- 24 findings from an earlier code review (2 Critical XSS, 3 High,
  6 Medium, 13 Low) across the web surface.
- **CI runs green on Linux**: the suite had only ever run on Windows. The first
  real CI run surfaced: `ruff format --check` reformatting Markdown code blocks;
  the sandbox picking `unshare` on hosts that block unprivileged user
  namespaces (`_sh_probe` now runs each tool for real and keeps it only on exit
  0, so `_sandbox_wrap` falls through to bare execution); sample ELF fixtures
  committed without the executable bit; and two `runner.py` lines only
  reachable on Windows, now covered by direct tests. `make coverage` reports
  `term-missing`.
- **`solve()` crashed on an unloadable / missing binary** instead of returning a
  result; `recon()` is guarded, but the next line re-derived the plan with an
  unguarded second `classify()` call that re-opened the file and raised straight
  out of `solve()`. It now reuses the plan `recon()` already computed.
  Regression test added.
- **`api_disasm_decompile` docstring** referenced `?addr=`; the query parameter
  is `vaddr`.
- **Asm sidebar glyph** reused the Info panel's gear icon; it is now a distinct
  glyph so the two nav entries are distinguishable.

### Changed
- **`server.py`**: extracted `_size_to_next_function()`; two byte-identical
  "size to next function boundary" blocks now call it.
- **`index.html`**: removed a dead `.tab-bar` / `.tab` CSS block + its inert
  click handler + an empty init IIFE. No visual change.
- **[`CONTRIBUTING.md`](CONTRIBUTING.md)**: `autopwn` is documented as a *recon + first-move
  accelerator*: a strategy *surfaces / ranks / recovers parameters*, it does not
  "solve end to end". A `strat_*` file joins the coverage `omit` list only
  alongside a golden-output test for it.

## [2.5.0] - Strategy registry, capa-driven selection, live solver feedback

### Added
- **Declarative strategy registry** (`triage_web/autopwn/registry.py`). Every
  solver strategy is one `Strategy(name, score(view), run(ctx))`: `score` turns
  the static `StaticView` into `(priority, rationale)` or `None`; `run` invokes
  it. `classify()` and the orchestrator iterate the list; adding a strategy is
  "write `strat_<x>`, append one `Strategy`". The old hand-written `classify`
  ladder and `__init__` if/elif dispatch are gone.
- **capa feeds strategy selection:** `capa_scan.capabilities(path)` runs a
  best-effort flare-capa pass; matched rule + namespace names land in
  `StaticView.capa` and scorers use them (an `anti-analysis` match promotes the
  SMC unwrap, an `arithmetic` match promotes the z3 modeller). Results are
  cached per file (path + size + mtime) in-process and on disk; the stream emits
  a `capa_running` event only for a real (uncached) scan.
- **`strat_z3`**: models a short arithmetic chain (`add`/`sub`/`xor`/`mul`/
  `shl`/`shr`/`rol`/`ror`/`neg`/`not`) applied to the input ahead of a
  constant-compare guard and solves it with z3.
- **`strat_uaf` routing analysis**: recon disassembles the flag function's
  callee and classifies how the planted callback's `arg1` is consumed: a
  session `id` (compared to a far struct field), a socket `fd` (passed to
  `send`/`write`), or a `ptr` (dereferenced; reported as needing a separate
  leak). The generated exploit routes accordingly.
- **`strat_brute`**: feedback-oracle key recovery against a runnable checker:
  char-by-char, then a short digit-keyspace fallback, both bounded by `timeout`
  and a run ceiling.
- **Auto Solve live progress:** `GET /api/autopwn/stream` (Server-Sent Events)
  emits `recon` → `plan` → per-strategy `strategy_start` / `strategy_done` →
  `done`. `solve()` gained an optional `on_event` callback.

### Fixed
- **Decompiler panel** rendered pseudo-C drifting right: the syntax highlighter
  re-matched the `var(` inside its own injected `style="color:var(--x)"`.
  Highlighting is now class-based (`.pc-*`) and the code column is left-aligned.
- **Stale panels:** loading a new binary left every lazily-populated panel
  showing the previous binary's results; `_load()` now calls `resetPanels()`.
- **`strat_fmt` crash** on a Linux host: `_probe_network` hardcoded a `wsl`
  spawn. It now selects the runtime like `runner` and treats a missing runtime
  as a clean "could not start the service".
- `classify` no longer silently skips a strategy for want of a scoring branch.

## [2.4.0] - Sandbox, telemetry, self-modifying-code unwrap

The auto-solver was re-scoped from "one-shot the challenge" to a **recon +
first-move accelerator**: the ranked plan and per-strategy parameters/scaffold
are the product; a recovered flag is a bonus. Every `solve()` now carries the
full static `recon` (also on failure) and the CLI prints it when no flag is
found.

### Added
- **`strat_smc`**: static self-modifying-code unwrap. Repairs a mangled ELF
  `e_ident`, recovers the exact rewrite span from the entry decoder stub
  (skip-junk disasm of its `mov end` / `mov count` immediates), brute-forces a
  reversible per-byte transform family (`xor`/`rol`/`ror`/`add`/`sub`/`not` and
  compositions) scored on structural x86 signatures and junk-mnemonic rate, then
  writes a byte-exact decoded image with `e_entry` repointed past the spent
  stub. Also neutralises hand-rolled anti-debug (`mov (r|e)ax,
  <fork|clone|ptrace>; syscall` → `... ; xor eax, eax`) and zeroes a non-primary
  `PT_LOAD` fully contained in another, so the decoded image loads cleanly in
  `cle` / angr. New `"smc"` plan when a RWE `PT_LOAD` or trashed `e_ident` is
  seen.
- **`Disassembler.disassemble(..., skip_junk=True)`**: anti-disassembly mode
  that steps over `eb 01` / `7x 01` + junk-byte sequences to the real jump
  target and resyncs on undecodable bytes.
- **Execution sandbox**: `runner` wraps every target and generated
  exploit-script run in `bwrap` (no network, ro-root, private `/tmp`) or
  `unshare` (loopback-only island for the self-tests). `TRIAGE_SANDBOX=off`
  runs bare; `=strict` refuses to run unsandboxed.
- **Telemetry**: each solve appends a JSONL row (strategy mix, timings, arch,
  outcome) to `$TRIAGE_RESULTS` or `~/.triage/results.jsonl`.
- `recon` is returned by `POST /api/autopwn`, the CLI `--json`, and printed on a
  failed solve. `make deps-canary` runs the solver suite against unpinned-latest
  backends. A `pre-push` hook runs the coverage gate.

### Changed
- CI triggers repointed to `master` (+ `workflow_dispatch`).

### Fixed
- `classify` no longer silently skips self-modifying binaries.

## [2.3.0] - More solver strategies, one-click solve, UI refresh

### Added
- **`strat_keygen`**: recovers an `input == CONSTANT → win()` gate on any
  architecture (x86 / x86-64 / SPARC / MIPS / ARM / PPC), formats the key the
  way the program reads it (`scanf %x` → hex), feeds it in, and statically
  reconstructs a flag the win function assembles from immediates.
- **`strat_uaf`**: dangling-callback use-after-free auto-exploit. Detects the
  shape (a networked service that `free()`s then `getenv()`s), auto-recovers the
  flag function, struct size, listen port, WebSocket-vs-raw framing and the
  command verbs, emits a WebSocket exploit, and self-tests it against a spawned
  instance.
- **One-click Auto Solve**, a headline panel/button in the web UI: classify →
  run every strategy → show the flag, the plan, every attempt and the winning
  script.
- CLI entry `triage-autopwn`, `make autopwn BIN=…`.

### Changed
- **Web UI redesign**: modern layered-dark palette with a single accent;
  refreshed sidebar, panels, toolbars, tabs, buttons, tables, toast. Merged
  panels: **Exploit** (Vulns / Attack Paths / ROP / Solvers) and **Data**
  (Imports / Exports / Symbols / Strings / Sections).

### Fixed
- `loader`: ELF `e_machine` now maps SPARC / MIPS / PPC / RISC-V (was silently
  reporting `x86_64` for every non-x86 target).

## [2.2.0] - Automated solver + full coverage

### Added
- **`triage_web.autopwn`**: an end-to-end auto-solver. `solve(path)` classifies
  the target and runs strategies in priority order until one yields a flag:
  **emulate** (unicorn-run a function, scan memory/output), **angr**
  (symbolic-execute to a success state), **ret2win** (symbolic saved-return
  offset → pwntools payload → run), **format_string** (`%p` stack leak / probe
  script). Exposed as `POST /api/autopwn` + `GET /api/autopwn/recon` and the
  `python -m triage_web.autopwn <bin> [--recon] [--json]` CLI.
- `runner.py` process bridge: runs ELF targets natively on Linux (or via WSL on
  Windows), PE natively / via `wine`, with flag-regex extraction.
- Solver fixtures `samples/{memflag,ret2win,keycheck}` (+ sources).

### Changed
- Test coverage of the shipped surface is now **100%** (`fail_under = 100`).
  `server.py`, `loader.py`, `engine.py`, `rop.py` went from 91–96% to 100%; the
  autopwn strategy modules are `omit`-ed from the gate (they drive
  angr/unicorn/pwntools) but covered end-to-end by `tests/test_autopwn.py`.

### Fixed
- `api_exploit_techniques` NX heuristic did substring ops on the integer
  section-flags word, threw `TypeError` every call and swallowed it; now
  decodes ELF `SHF_*` / PE `IMAGE_SCN_*` bits.
- `loader.protections()` only recognised the legacy `DT_BIND_NOW` tag, so modern
  full-RELRO binaries were reported "Partial"; now also reads `DF_BIND_NOW` /
  `DF_1_NOW`. Any `__*_chk` symbol counts as Fortify Source.

## [2.1.0] - Cross-platform + tooling

### Added
- Runs on native **Windows** and from **WSL**.
- `triage_web/analysis.py`: binary-analysis / exploit-intel helpers, extracted
  from `server.py` and unit-tested directly.
- Rebuilt **Hex tab**: offset ⇄ virtual-address modes, paging, section jump,
  hover/selection inspector (u8…u64 LE/BE), byte/string search.
- Deeper `/api/vuln-hints`: win-function detection, resolved `&"/bin/sh"`,
  ROP-staple addresses, per-function overflow-offset estimates, and ranked
  attack paths each with a ready-to-edit pwntools skeleton.
- Solver templates: `triton_solve_flag`, `unicorn_emulate_func`.
- Dev tooling: `pyproject.toml` (uv), `ruff` (E/W/F/I/B/C4/UP/RUF/S), `pytest` +
  coverage gate, `pre-commit`, `Makefile`, GitHub Actions, `pip-audit`,
  committed `uv.lock`, `.gitattributes`, Dependabot.

### Changed
- Server session state is a typed `Session` dataclass with `require_*`
  accessors (was an untyped module dict).
- The SPA moved from an inline string in `frontend.py` to
  `triage_web/index.html`.

### Fixed
- `_suggest_var_names` could emit two identically-named C variables.
- `/api/disasm/decompile` `func_name` was always empty.
- Hex tab showed nothing for unmapped / `0x0` addresses (added a file-offset
  fallback + `Cache-Control: no-store`).
- `static_string_reconstruct` decoded the whole file as code and mis-sized
  `dword` writes → garbage; now section-scoped, per-function.
- Windows startup: `fuser` / `fd=` handling, `/tmp` paths, solver temp-file
  encoding, `/api/capa` 500 → 400, `loader._clear_caches()` `AttributeError` on
  the second load.

## [2.0.0] - Pseudo-C decompiler

### Added
- `decompile_function()`: pseudo-C decompilation engine in `engine.py`, its
  `/api/disasm/decompile` HTTP endpoint, and a Code panel in the SPA with
  Pseudo-C / Asm toggles and keyword highlighting.
- Instruction → C translation: register-value tracking with stack-variable
  resolution, dual-path call-argument collection (register ABI + stack), return
  value detection, `strlen` idiom recognition (`repne scasb; not ecx; dec ecx`),
  ABI-compliant caller-register clobbering, GLIBC version-suffix stripping,
  stack-variable type inference, prologue skipping, and `leave`/`nop`/`endbr`
  suppression.

### Fixed
- Nine `[base+offset]` regexes switched `re.match` → `re.search` with flexible
  whitespace to handle capstone's `[rsp + 0x2c]` formatting.
- Call-argument collection bounded to a 6-instruction window with call-boundary
  detection, backward iteration, and 32-bit register-name mapping; prevents
  stale args spilling across calls.
- `movabs` handled alongside `mov`; register-alias propagation tries both 32-
  and 64-bit capstone names; return-value inlining after `call malloc` emits
  `heap_ptr = malloc(...);`.
