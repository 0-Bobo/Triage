# Changelog

## [Unreleased] — premortem round 2, bug fix, cleanup

### Premortem round-2 adaptations (P1–P6)
- **Wording contract (P1).** `CONTRIBUTING.md` now states autopwn is a *recon +
  first-move accelerator*: a strategy *surfaces / ranks / recovers parameters*,
  it does not "solve … end to end". New `Attempt.confidence`
  (`solved`/`likely`/`guess`) — the orchestrator defaults it to `solved` on an
  ungraded flag; surfaced in `SolveResult.summary()`, the CLI, the SSE
  `strategy_done` event, and the telemetry row. `strategy_start` now carries
  `budget_remaining` so the time spend is visible.
- **Coverage contract (P2).** `make coverage-strat` reports line coverage of the
  `omit`-ed `strat_*` / `capa_scan` layer with no gate (currently **71%**;
  `strat_brute` ~26%). Rule: a file joins `omit` only alongside a golden-output
  test for it.
- **Backend-rot canary (P3).** `ci.yml` gains a weekly `schedule:` and a
  non-gating `deps-canary` job (solver suite vs. unpinned latest angr/unicorn/
  pwntools/capstone). `tests/test_golden_recon.py` locks the deterministic
  `recon()` shape (format / arch / protections / ranked plan) for five samples
  in the fast path.
- **Desktop edition frozen (P5).** `CONTRIBUTING.md` "Editions" + a STATUS
  banner in `apps/desktop/triage.py`: not released, no new features, inlines a
  stale `BinaryLoader` — touch only to keep it launching.
- **Telemetry context (P6).** `solve(context=)` (falls back to `$TRIAGE_CTX`)
  is written to the `~/.triage/results.jsonl` row, to answer later whether the
  tool is actually opened first under time pressure.

### Fixed
- **CI now runs green on Linux** — the suite had only ever run on Windows.
  First real CI run surfaced: `ruff format --check` failing on `docs/` markdown
  code blocks and the frozen `apps/desktop/triage.py` (both now `extend-exclude`d
  from ruff); the sandbox picking `unshare` on GitHub runners where unprivileged
  user namespaces are blocked (`_sh_probe` now runs each tool for real and keeps
  it only on exit 0, so `_sandbox_wrap` falls through to bare execution); the
  sample ELF fixtures committed without the executable bit (`git update-index
  --chmod=+x`); and two `runner.py` lines (`_wsl_bash`, the `_sh_probe` spawn
  guard) only reachable on Windows, now covered by direct tests. `make coverage`
  reports `term-missing`.
- **`solve()` crashed on an unloadable / missing binary** instead of returning a
  result. `recon()` is wrapped in `try/except` to survive a mangled target, but
  the next line re-derived the plan with an *unguarded* second `classify()` call,
  which re-opens the file and raises the same exception straight out of
  `solve()` (hitting `/api/autopwn`, the SSE stream, and the CLI). The existing
  test masked it by monkeypatching the `recon` name while passing a real
  fixture. Fix: drop the redundant call — reconstruct the plan from
  `rec["plans"]` (same capa set, already computed), empty plan on a recon error.
  Regression test `test_solve_returns_cleanly_when_the_binary_cannot_be_loaded`.
- **`api_disasm_decompile` docstring** referenced `?addr=` — the query parameter
  is `vaddr`.
- **Asm sidebar glyph** reused the Info panel's gear (`⚙`); it is now `☰` so the
  two nav entries are distinguishable (avoid-ai-design re-audit — the rest of
  the industrial-readout pass holds, no rewrite).

### Changed
- **`server.py`** — extracted `_size_to_next_function()`; two byte-identical
  "size to next function boundary, capped +256" blocks in `api_disasm_function`
  and `api_disasm_variables` now call it. `api_disasm_decompile` keeps its own
  wider variant.
- **`index.html`** — removed the dead `.tab-bar` / `.tab` CSS and its inert
  "legacy" click handler (the classes appear nowhere in the markup; the live UI
  uses `.subnav`), plus an empty init IIFE. No visual change.

### Added
- **`context.md`** — cold-start orientation map for the repo: the two editions +
  autopwn, directory map, web request flow, the unwired p-code pipeline, the
  autopwn recon→classify→registry→strategy flow, strategy catalog, the coverage
  contract, tooling, and known divergences.
- **`docs/TODO.md`** — premortem round-2 backlog (P1–P6): kill the solver voice,
  split the coverage contract, put `deps-canary` in CI, land the working tree as
  focused commits, decide the desktop edition's status, instrument the "is it
  opened first" assumption in the telemetry.

_371 tests, 100% coverage on the shipped surface, ruff clean._

## [2.5.0] — 2026-09-02 — Strategy registry, capa-driven selection, live solver feedback

### Added
- **Declarative strategy registry** (`triage_web/autopwn/registry.py`). Every
  solver strategy is now one `Strategy(name, score(view), run(ctx))`:
  `score` turns the static `StaticView` into `(priority, rationale)` or
  `None`; `run` invokes it. `classify()` and the orchestrator iterate the
  list — adding a strategy is "write `strat_<x>`, append one `Strategy`",
  nothing else. The old hand-written `classify._classify` ladder and
  `__init__._run_strategy` if/elif are gone.
- **capa feeds strategy selection.** `capa_scan.capabilities(path)` runs a
  best-effort flare-capa pass; matched rule + namespace names (lowercased)
  land in `StaticView.capa`, and scorers use them — an `anti-analysis` /
  `self-modifying` match promotes the SMC unwrap, an `arithmetic` /
  `checksum` match promotes z3. `recon(path, use_capa=True)` /
  `solve(..., use_capa=True)`; the web Auto Solve panel turns it on by
  default. Previously capa ran only from its own button and fed nothing.
  Results are cached per file (path + size + mtime) in-process and on disk
  under `~/.triage/capa-cache/`, so a re-run on the same binary is instant;
  the stream emits a `capa_running` event only when a real (uncached) scan
  starts, so the UI shows "running capa…" instead of a silent stall.
- **`strat_z3`** — models a short arithmetic chain (`add`/`sub`/`xor`/`mul`/
  `shl`/`shr`/`rol`/`ror`/`neg`/`not`) applied to the input ahead of a
  constant-compare guard and solves it with z3. Solves `keygate` end to end
  (`0xdeadbeef` → `flag{keygate_static}`).
- **`strat_uaf` routing analysis** — recon disassembles the flag function's
  callee and classifies how the planted callback's `arg1` is consumed —
  session `id` (compared to a far struct field), socket `fd` (passed to
  `send`/`write`), or a `ptr` (dereferenced). The generated exploit routes
  the flag accordingly instead of assuming; a `ptr` target is reported as
  needing a separate leak rather than flailed at. Fixes `bidsniper`
  (`route=id` — `sub_404ee0` is send-to-session-by-id, not a pointer deref;
  the old code guessed a `/proc` fd). Standalone solve in
  `Writeups/bidsniper_solve.py`.
- **`strat_brute`** — feedback-oracle key recovery against a runnable
  checker: char-by-char (the classic `for i: if in[i] != key[i]` crackme)
  then a short digit-keyspace fallback, both bounded by `timeout` and a
  4000-run ceiling.
- **Auto Solve live progress.** New `GET /api/autopwn/stream` (Server-Sent
  Events) emits `recon` → `plan` → per-strategy `strategy_start` /
  `strategy_done` (running / ✓ / ✗ / seconds) → `done`. The web panel and
  the desktop `AutoSolvePanel` render it as a live log instead of a blank
  spinner; `solve()` gained an optional `on_event` callback that drives it.

### Fixed
- **Decompiler panel** rendered pseudo-C drifting to the right: the syntax
  highlighter ran regex passes that re-matched the `var(` inside their own
  injected `style="color:var(--x)"`, corrupting the markup. Highlighting is
  now class-based (`.pc-*`) and the code column is explicitly left-aligned.
- **Stale panels.** Loading a new binary left every lazily-populated panel
  (decompiler, disassembly, hex, capa, vulns, attack paths, ROP, solvers,
  xrefs, Auto Solve) showing the previous binary's results. `_load()` now
  calls `resetPanels()` first.
- **`strat_fmt` crash** `format_string: crashed: [Errno 2] No such file or
  directory: 'wsl'` on a Linux host — `_probe_network` hardcoded a `wsl`
  spawn. It now selects the runtime like `runner` (native shell on Linux)
  and treats a missing runtime as a clean "could not start the service".
- `classify` no longer silently skips a strategy for want of a scoring branch.
- **bidsniper handshake** — the server does a single `recv` + `strstr("

")`,
  so a WebSocket handshake with literal `
` (or split across sends) is
  silently dropped. The generated + standalone exploits send one request with
  real CRLF.
- **Desktop app** re-themed to match the web UI (industrial charcoal + amber,
  one mono family), **dropped the `qt-material` layer** that fought the custom
  QSS and double-decorated dock titles on Windows, opaque base `QWidget`
  background (fixes see-through windows under WSLg), and unified the app name
  to "Triage".

## [2.4.0] — 2026-09-01 — Premortem hardening: sandbox, telemetry, SMC unwrap

The auto-solver was re-scoped from "one-shots CTFs" to a **recon + first-move
accelerator**: the ranked plan and the per-strategy parameters/scaffold are the
product; a recovered flag is a bonus. Every `solve()` now carries the full
static `recon` (also on failure) and the CLI prints it when no flag is found.

### Added
- **`strat_smc`** — static self-modifying-code unwrap. Repairs a mangled ELF
  `e_ident`, recovers the exact rewrite span from the entry decoder stub
  (skip-junk disasm of its `mov end` / `mov count` immediates), brute-forces a
  reversible per-byte transform family (`xor`/`rol`/`ror`/`add`/`sub`/`not` +
  the RingZer0 *oracle* `rol1;not;rol3` involution) scored on structural x86
  signatures and junk-mnemonic rate, then writes a byte-exact decoded image
  with `e_entry` repointed past the spent stub. Also **neutralises hand-rolled
  anti-debug**: `mov (r|e)ax, <fork|clone|ptrace>; syscall` → `... ; xor eax,
  eax`, so the stub returns 0 (single-process, all anti-trace checks pass) —
  `LD_PRELOAD` can't touch a raw `syscall`, but the decoded image is on disk.
  On `oracle` the decoded region matches `Binaries/oracle_dec` exactly and the
  `fork`/`ptrace` stubs are de-fanged. Also zeroes any non-primary `PT_LOAD`
  fully contained in another (the anti-tooling overlapping-segment trick), so
  the decoded image loads cleanly in `cle` / angr. New `"smc"` plan (score 90)
  when a RWE `PT_LOAD` or trashed `e_ident` is seen.
- **`Disassembler.disassemble(..., skip_junk=True)`** — anti-disassembly mode
  that steps over `eb 01`/`7x 01` + junk-byte sequences to the real jump
  target and resyncs on undecodable bytes.
- **Execution sandbox** — `runner` wraps every ELF/target and generated
  exploit-script run in `bwrap` (no network, ro-root, private `/tmp`) or
  `unshare` (loopback-only island for the UAF/fmt self-tests).
  `TRIAGE_SANDBOX=off` runs bare; `=strict` refuses to run unsandboxed.
- **Telemetry** — each solve appends a JSONL row (strategy mix, timings, arch,
  outcome) to `$TRIAGE_RESULTS` or `~/.triage/results.jsonl`.
- `recon` is returned by `POST /api/autopwn`, the CLI `--json`, and printed on
  a failed solve. `make deps-canary` runs the solver suite against unpinned
  latest angr/unicorn/pwntools/capstone. `pre-push` hook runs the coverage gate.

### Changed
- CI triggers repointed from `main`/`develop` to `master` (+ `workflow_dispatch`).
- `apps/desktop/triage.py` carries a divergence note: its inlined
  `BinaryLoader` is the older copy; `triage_web/loader.py` is maintained.

### Fixed
- `classify` no longer silently skips self-modifying binaries.

## [2.3.0] — 2026-09-01 — More solver strategies, one-click solve, UI refresh

### Added
- **`strat_keygen`** — recovers an `input == CONSTANT → win()` gate on any
  architecture (x86/x86-64/SPARC/MIPS/ARM/PPC), formats the key the way the
  program reads it (`scanf %x` → hex), feeds it in, and statically
  reconstructs a flag the win function assembles from immediates. Solves
  `IntroToSparc` end-to-end → `FLAG-SPARC1S3XC3LL3NT`.
- **`strat_uaf`** — dangling-callback use-after-free auto-exploit. Detects the
  shape (networked service that `free()`s + `getenv()`s), auto-recovers the
  flag function, struct size, listen port, WebSocket-vs-raw and the command
  verbs, emits a WebSocket exploit, and self-tests it against a spawned
  instance (targets the server's real fd for the receiver socket via `/proc`).
- **One-click Auto Solve** — a headline panel/button in both the web UI and the
  PyQt6 desktop app: classify → run every strategy → show the flag, the plan,
  every attempt and the winning script.
- CLI entry `triage-autopwn`, `make autopwn BIN=…`.

### Changed
- **Web UI redesign** — modern layered-dark palette with a teal-green accent;
  refreshed sidebar, panels, toolbars, tabs, buttons, tables, toast. Merged
  panels: **Exploit** (Vulns / Attack Paths / ROP / Solvers) and **Data**
  (Imports / Exports / Symbols / Strings / Sections).

### Fixed
- `loader` — ELF `e_machine` now maps SPARC / MIPS / PPC / RISC-V (was
  silently reporting `x86_64` for every non-x86 target).

## [2.2.0] — 2026-08-31 — Automated solver + full coverage

### Added
- **`triage_web.autopwn`** — an end-to-end CTF auto-solver. `solve(path)`
  classifies the target and runs strategies in priority order until one
  yields a flag:
  - **emulate** — unicorn-run a function and scan memory/output for a flag
    that the program builds but never prints;
  - **angr** — symbolic-execute to a success state, recover the winning
    stdin/argv;
  - **ret2win** — find the saved-return offset symbolically, build a
    pwntools payload, run it, read the flag;
  - **format_string** — `%p` stack leak / probe script, local or over a
    service spawned in WSL.
  Exposed as `POST /api/autopwn` + `GET /api/autopwn/recon`, and the
  `python -m triage_web.autopwn <bin> [--recon] [--json]` CLI
  (`triage-autopwn` entry point, `make autopwn BIN=…`).
- `runner.py` process bridge: runs ELF targets through WSL (or natively on
  Linux), PE natively / via `wine`, with flag-regex extraction.
- Solver fixtures `samples/{memflag,ret2win,keycheck}` (+ sources).

### Changed
- Test coverage of the shipped surface is now **100%** (`fail_under = 100`),
  329 tests. `server.py`, `loader.py`, `engine.py`, `rop.py` went from
  91–96 % to 100 %; the autopwn strategy modules are `omit`-ed from the
  gate (they drive angr/unicorn/pwntools-in-WSL) but covered end-to-end by
  `tests/test_autopwn.py`.

### Fixed
- `api_exploit_techniques` NX heuristic did substring ops on the integer
  section-flags word, threw `TypeError` every call and swallowed it, so the
  "NX disabled" marker was unreachable — now decodes ELF `SHF_*` / PE
  `IMAGE_SCN_*` bits.
- `loader.protections()` only recognised the legacy `DT_BIND_NOW` tag, so
  modern full-RELRO binaries were reported "Partial"; now also reads
  `DF_BIND_NOW` / `DF_1_NOW`. Any `__*_chk` symbol counts as Fortify Source.

## [2.1.0] — 2026-08-31 — Cross-platform + tooling

### Added
- Runs on native **Windows** and from **WSL** (`wsl/` holds the shell config,
  kept on the Windows filesystem and sourced from `~/.zshrc`).
- `triage_web/analysis.py` — the binary-analysis / exploit-intel helpers,
  extracted from `server.py` and unit-tested directly.
- Rebuilt **Hex tab**: offset ⇄ virtual-address modes, paging, section jump,
  hover/selection inspector (u8…u64 LE/BE), byte/string search
  (`/api/hex`, `/api/hex/search` rewritten).
- Deeper `/api/vuln-hints`: win-function detection, resolved `&"/bin/sh"`,
  ROP-staple addresses, per-function overflow-offset estimates, and
  ranked attack paths each with a ready-to-edit pwntools skeleton.
- Solvers: `triton_solve_flag`, `unicorn_emulate_func` templates.
- Dev tooling: `pyproject.toml` (uv), `ruff` (E/W/F/I/B/C4/UP/RUF/S),
  `pytest` + coverage gate, `pre-commit`, `Makefile`, GitHub Actions,
  `pip-audit`, committed `uv.lock`, `.gitattributes`, Dependabot.
- Test suites: `tests/{test_web_api,test_analysis,test_solvers,test_xref,
  test_loader}.py` — 127 tests, ~75 % coverage of shipped code.

### Changed
- Server session state is a typed `Session` dataclass with `require_*`
  accessors (was an untyped module dict).
- The SPA moved from an inline string in `frontend.py` to
  `triage_web/index.html`.
- The desktop PyQt6 edition moved to `apps/desktop/triage.py`.

### Fixed
- `_suggest_var_names` could emit two identically-named C variables.
- `/api/disasm/decompile` `func_name` was always empty.
- Hex tab showed nothing for unmapped/`0x0` addresses (added a
  file-offset fallback + `Cache-Control: no-store`).
- `static_string_reconstruct` solver decoded the whole file as code and
  mis-sized `dword` writes → garbage; now section-scoped, per-function.
- Windows: `server.main()` `fuser`/`fd=` startup, `/tmp` paths, solver
  temp-file encoding, `/api/capa` 500 → 400, `loader._clear_caches()`
  `AttributeError` on the 2nd load.
- `_suggest_var_names` `NameError` (`var_key`), `emit_c` `PREC` dup keys.

## [Unreleased] — Pseudo-C Decompiler

### Added
- `decompile_function()` — full pseudo-C decompilation engine in `engine.py`
- `/api/disasm/decompile` HTTP endpoint in `server.py`
- Code panel UI with toggle buttons in `frontend.py`
- Syntax highlighting for pseudo-C keywords in `showCodeFunction()`
- `_get_call_args()` — dual-path argument collector (register ABI + stack-based) for call instructions
- `_update_reg_state()` — register value tracking through instructions with stack variable resolution
- `_find_ret_value()` — detects return value from eax/rax register at function exit
- `_insn_to_c()` — translates individual instructions to C-like expressions
- `_match_strlen_idiom()` — detects `repne scasb; not ecx; dec ecx` pattern → `strlen()`
- `_reg_val()` — register alias resolution (eax ↔ rax, ebx ↔ rbx, etc.) for capstone naming
- `_clear_caller_regs()` — ABI-compliant register clobbering after function calls
- Version suffix stripping (`@GLIBC_2.0`, `@@GLIBC_2.0`) from call names
- Stack variable type inference (`_guess_var_type()`)
- Prologue skipping (push rbp, mov rbp rsp, push rdi, stack alignment)
- `leave`/`nop`/`endbr64`/`endbr32` suppression in C output
- `result_of` set-once heuristic to prevent variable name overwrite from later reads

### Fixed
- **All `[base+offset]` regexes** (9 locations): switched `re.match` → `re.search` with `\s*` whitespace flexibility to handle capstone's `[rsp + 0x2c]` format
- **_get_call_args()** `is_64` branching: rewritten to try both register ABI and stack-based collection regardless of `is_64` flag
- **_get_call_args()**: reverse-order stack arg collection limited to 6 instructions with call boundary detection — prevents stale args from spilling across calls
- **_get_call_args()**: added `rdi`/`rsi`/`rdx`/`rcx`/`r8`/`r9` to push filter list to prevent prologue register saves from being treated as stack args
- **_update_reg_state()**: added base-register check before resolving `[rax + N]` to `stack_vars` (prevents `[rax+4]` from being matched to a `rsp+4` stack variable)
- **Prologue detection**: handles `push rdi` (stack alignment), `and esp, -16` (alignment), fixed operator-precedence bug in conditional chain
- **`is_local` check**: now includes `rsp`/`sp` for 64-bit register name output from capstone
- **Register alias propagation**: `_reg_val()` lookup tries both `eax` and `rax`/`ecx` and `rcx`/etc. to handle capstone's mixed 32/64-bit register naming
- **Variable naming**: `mov eax, [rsp+N]` correctly resolves to `heap_ptr` (not `puts@_res`) via `_update_reg_state`
- **_find_ret_value()** — checks both `eax` and `rax` (capstone naming inconsistency)
- **Main loop**: converted `for` → `while` loop to support multi-instruction idiom skipping (strlen pattern)
- **`_insn_to_c()`**: pointer dereferences (`*rax`, `rax[4]`) no longer wrongly map to offset-matched stack variables — base register must be `rsp`/`esp`/`rbp`/`ebp`
- **Function boundary detection**: main loop now `break`s after `ret` instruction to prevent adjacent function code from leaking into output
- **Prologue skip**: added `endbr64`/`endbr32` to recognized prologue instructions so `sub rsp, N` isn't emitted as `rsp -= N;`
- **_get_call_args() register ABI scan**: changed from forward to backward iteration, with call boundary detection — prevents register arg data from spilling across function calls
- **_get_call_args() register ABI scan**: added 32-bit register name mapping (`edi`→`rdi`, `esi`→`rsi`, `edx`→`rdx`) so both `mov edi, N` and `mov rdi, N` set up the correct arg register
- **`call_arg_ranges` first pass**: mov instructions are only marked when destination is an argument register (`rdi`/`rsi`/`rdx`/`rcx`/`r8`/`r9` or 32-bit variants) — prevents constant loads to scratch registers like `movabs rcx, 0x...` from being hidden as arg setup
- **`_clear_caller_regs()`**: now clears all 32-bit register variants (`esi`, `edi`, `r8d`, etc.) that capstone may use, not just 64-bit names — fixes ghost arg values leaking across calls
- **`_insn_to_c()` and `_update_reg_state()`**: added `movabs` alongside `mov` — `movabs rcx, 0x...` now renders as `reg = value;` instead of `/* movabs ... */`
- **Return value inlining**: after `call malloc`, if the next instruction stores `eax`/`rax` to a known stack variable, emits `heap_ptr = malloc(...);` instead of `malloc(...);` + `heap_ptr = rax;` — works for both 64-bit register ABI and 32-bit stack-based args

### Known Limitations
- Function name defaults to `func_XXXXXXXX` (needs `loader.get_functions()` integration)
- No `repne cmpsb` → `memcmp()` idiom detection yet
- Register ABI scan resolves `mov rdi, rax` to `heap_ptr` when rax holds a tracked value, but intermediate register-to-register moves are still shown (e.g. `heap_ptr = rax;` instead of `heap_ptr = malloc(24);`)
- No string literal resolution for immediate constants (e.g. `0x3430392d47414c46` shown instead of `"FLAG-904"`)
- No instruction-level comments in C output (e.g. no `// heap_ptr = malloc(24)` annotations)
