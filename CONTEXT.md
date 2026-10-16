## Context

A fast orientation for anyone new to this repo. [`README.md`](README.md)
is the pitch and quick start; [`ARCHITECTURE.md`](ARCHITECTURE.md) is the detailed technical
walkthrough. This page is the map between them: what Triage actually is,
how the pieces fit, and where to look first for a given kind of change.

## What this is, in one paragraph

Triage is a local, single-user web app for CTF reverse-engineering and pwn.
You load an ELF/PE and get the static analysis a human would normally
assemble by hand across several tools (disassembly, a pseudo-C decompiler,
ROP gadgets, protections, entropy/packer checks, capa capabilities,
vulnerability hints) in one browser tab. On top of that, `autopwn` is a
ranked-strategy auto-solver: it classifies the binary, picks and runs the
strategies most likely to work (keygen constant-compare, self-modifying-code
unwrap, format-string leak, ret2win, a z3/angr fallback, ...), and hands back
either a flag or a runnable exploit skeleton with real recovered parameters.

## The mental model

Two halves, one process:

1. **Static analysis** (`loader.py`, `engine.py`, `analysis.py`, `rop.py`,
   `xref.py`): pure, synchronous, no FastAPI imports. Given bytes, produce
   facts: sections, protections, disassembly, gadgets, xrefs. This is the
   layer every panel in the UI ultimately calls into.
2. **`autopwn`** (`triage_web/autopwn/`): a strategy registry on top of
   layer 1. `classify()` turns the static picture into a `StaticView`;
   `registry.plan()` ranks strategies against it; each strategy's `run()`
   either produces a flag or a `SolveResult` describing what it recovered.
   It's importable as a library, runnable as a CLI
   (`python -m triage_web.autopwn`), and wired into the web UI via three SSE
   routes.

`server.py` is the seam between both and the browser: ~40 routes, no
analysis logic of its own, one global `Session` holding "the currently
loaded binary." `index.html` is the entire frontend (markup, inline
styles, inline JS, embedded fonts): no build step, no bundler, no
framework; every panel is a `fetch()` to one of those routes rendered
into a DOM string. A CSS/font split was tried once and reverted (it
regressed under the page's CSP); see "Change the UI" below.

## Reading order for a newcomer

1. [`README.md`](README.md): what it does, quick start, the `autopwn` strategy table.
2. This file: the map you're reading.
3. [`ARCHITECTURE.md`](ARCHITECTURE.md): directory-by-directory detail, the request-flow
   diagram, the coverage contract, known gotchas. Read this before touching
   `server.py` or `autopwn/`.
4. [`CONTRIBUTING.md`](CONTRIBUTING.md): PR expectations, the golden-output-test rule for new
   `autopwn` strategies.
5. [`SECURITY.md`](SECURITY.md): the threat model. Read this before ever running the
   server anywhere but your own machine.
6. [`ENGINEERING.md`](ENGINEERING.md): decision-level walkthroughs of specific subsystems
   (the two decompilers, anti-disassembly handling, autopwn's strategy
   registry, the sandbox, WSL routing, a real bug and how it surfaced).
   Narrative, not a reference map; read it for *why*, not *where*.

## Where to make a change

| You want to... | Start here |
|---|---|
| Fix/extend static analysis (new protection check, new string pattern) | `triage_web/analysis.py`, `triage_web/loader.py` |
| Add a disassembly/decompiler feature | `triage_web/engine.py` (shipped decompiler); `triage_web/pcode.py` + friends is the **experimental, unwired** p-code pipeline, see [`ARCHITECTURE.md`](ARCHITECTURE.md) §4 before touching it |
| Add a new `autopwn` strategy | `triage_web/autopwn/strat_*.py` for the pattern, `registry.py` for the scoring hook, [`CONTRIBUTING.md`](CONTRIBUTING.md) for the golden-test requirement |
| Add/fix an exploit-script generator | `triage_web/solvers.py`: one `_foo(path, bits, arch, ...)` function per generator, registered in `SOLVER_GENERATORS` |
| Add an HTTP route | `triage_web/server.py`: keep it a thin seam; put logic in `analysis.py`/`loader.py`/`engine.py` and call it from the route |
| Change the UI | `triage_web/index.html`: markup, inline `<style>` (design tokens in `:root`), and inline `<script>`, no build step, so edits are live on refresh |
| Change fonts | the base64 `@font-face` data URIs at the top of `index.html`'s `<style>` block |

## What's safe to touch vs. load-bearing

- **Safe, low-blast-radius:** `triage_web/solvers.py` generators (each is
  independent), `triage_web/autopwn/strat_*.py` (same: strategies are
  deliberately decoupled, see `registry.py`), frontend copy/layout inside
  an existing panel.
- **Load-bearing, change with care + tests:** `Session` in `server.py` (one
  shared mutable object, now lock-guarded, see `Session._lock`),
  `_safe_staged_upload_path`/`_confirm_non_loopback_host` (the two places
  this app's "unauthenticated by design" threat model is actually
  enforced), anything in `triage_web/autopwn/runner.py` (the sandboxing
  layer every strategy and generated script runs through).
- **Deliberately untouched:** `triage_web/pcode.py`, `cfg.py`, `ssa_engine.py`,
  `emit_c.py`, `decompile_actions.py`: a complete, working, but unwired
  Ghidra-style decompiler pipeline (real SSA, dominance, structuring). It's
  excluded from the coverage gate on purpose. Don't delete it reflexively
  and don't wire it up casually, see [`ARCHITECTURE.md`](ARCHITECTURE.md) §4 for the actual
  trade-off.

## The non-negotiable contract

`make check` (ruff check + format + pytest) must stay green, and the web
surface (everything except the experimental decompiler and the `strat_*`
strategy files, which have their own opt-in `make coverage-strat` report)
stays at `fail_under = 100`. A new `autopwn` strategy or solver generator
ships with a test in the same commit, see [`CONTRIBUTING.md`](CONTRIBUTING.md). The frontend
stays a single static file with no build step; if a change needs a
bundler, it's the wrong change for this repo.
