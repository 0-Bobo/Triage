# Triage

[![CI](https://github.com/0-Bobo/Triage/actions/workflows/ci.yml/badge.svg)](https://github.com/0-Bobo/Triage/actions/workflows/ci.yml)
![Python 3.12+](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![Coverage 100%](https://img.shields.io/badge/coverage-100%25-brightgreen)
![License MIT](https://img.shields.io/badge/license-MIT-green)

A local binary-analysis workbench for CTF reverse-engineering and pwn. Load an
ELF or PE in the browser and get disassembly, a pseudo-C decompiler,
cross-references, ROP gadgets, entropy and packer checks,
[capa](https://github.com/mandiant/capa) capabilities, and vulnerability hints.

It also has `autopwn`: point it at a target and it classifies the binary, ranks
a handful of solver strategies, and prints their recovered parameters (win
address, overflow offset, decoded self-modifying code, the compare constant, and
so on) plus a runnable exploit skeleton. It solves the easy shapes outright; on
the harder ones the ranked plan and the parameters are the point.

The UI is `index.html` (markup/JS) + `style.css` (styles), no build step, no bundler.

## Quick start

Needs Python 3.12 or newer. [uv](https://docs.astral.sh/uv/) is the easiest way
in:

```bash
git clone --recurse-submodules https://github.com/0-Bobo/Triage
cd Triage
uv sync --extra analysis --extra exploit --dev
uv run python main.py path/to/target
```

Or with pip:

```bash
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements-web.txt
python main.py path/to/target
```

Then open <http://127.0.0.1:8888>. The heavy backends (angr, unicorn,
flare-capa, z3) are optional; each module checks for its dependency at import
and disables that feature if it is missing.

## What it does

Static analysis:

- ELF/PE loading via pyelftools/pefile (lief optional): sections, symbols,
  imports and exports, protections (NX, PIE, RELRO, canary, RWX), hashes, an
  entropy map, crypto and packer signatures.
- A Capstone disassembler with a `skip_junk` mode that steps over `eb 01` /
  `7x 01` plus junk-byte anti-disassembly and resyncs on the real jump target.
- A pseudo-C decompiler written from scratch: p-code IR, Lengauer-Tarjan
  dominance, Cytron SSA, an action/rule pass pipeline, and structured C output.
- ROP gadget scanning, a cross-reference database, a basic-block CFG, and
  vulnerability hints that map unsafe imports to fixes and MITRE ATT&CK IDs.

`autopwn`:

- A declarative strategy registry. Each strategy is one
  `Strategy(name, score(view), run(ctx))`; `score` turns the static picture into
  a priority, `run` does the work. Adding a strategy is one new module and one
  list entry.
- capa capabilities feed the scoring: an `anti-analysis` match pushes the SMC
  unwrap up the plan, an `arithmetic` match pushes the z3 modeller up.
- Strategies: `smc` (static self-modifying-code unwrap: header repair,
  stub-derived rewrite span, per-byte transform brute force, `fork`/`ptrace`
  anti-debug de-fang), `keygen`, `emulate` (unicorn), `z3`, `ret2win`, `uaf`,
  `format_string`, `angr`, `brute`.
- Every target and generated script runs inside a `bwrap` (or `unshare`)
  sandbox. `TRIAGE_SANDBOX=strict` refuses to run without one.
- Progress streams over Server-Sent Events; every run appends a JSONL telemetry
  row.

## Using autopwn

```console
$ python -m triage_web.autopwn samples/keygate
samples/keygate: x86_64 64-bit ELF
  protections: NX enabled, PIE off, no canary
  plan:
     92  keygen         input == CONSTANT -> win()
     40  emulate        small self-contained check
[+] samples/keygate: flag{keygate_static}  (via keygen, 0.4s)
```

`--recon` stops after classification. `--json` prints a machine-readable report.
`--only smc,angr` restricts the plan. `--budget 120` caps seconds per target.

The same thing runs from the web UI as a one-click "Run Recon + Solve" with a
live per-strategy log.

## How autopwn is wired

```
recon(path)                        solve(path, budget_s=180)
   |                                  |  emits recon -> plan ->
   v                                  |  strategy_start / strategy_done -> done
BinaryLoader (format, protections)    v
   |                            classify(path, capa)
   v  (capa optional, cached)         |
capa_scan.capabilities  ---------> registry.build_view -> StaticView
                                      |
                                      v  registry.plan(view) -> ranked strategies
                                      v  run each in order, within the budget
                                Attempt(ok, seconds, detail, flag, confidence)
                                      |  first flag wins; recon is kept either way
                                      v
                                SolveResult -> JSONL telemetry
```

| strategy | fires on | recovers |
|---|---|---|
| `smc` | RWE `PT_LOAD` or trashed `e_ident`; capa `anti-analysis` | a byte-exact decoded image with `e_entry` repointed and anti-debug de-fanged |
| `keygen` | `input == CONSTANT -> win()`, any arch | the constant, the win address, a static flag when the win function assembles one |
| `emulate` | small self-contained check | a unicorn run plus a memory scan |
| `z3` | arithmetic chain before a constant compare | the satisfying input |
| `ret2win` | overflow sink plus a win function | the offset, the win address, a pwntools script |
| `uaf` | dangling callback | how `arg1` is consumed (`id` / `fd` / `ptr`) and a matching exploit |
| `format_string` | user-controlled `%p` / `%n` | a leak or probe script |
| `angr` | fallback | a symbolic stdin/argv that reaches the success state |
| `brute` | runnable checker with a pass/fail oracle | the key, char by char or over a small keyspace |

## Layout

```
main.py                  launcher for triage_web.server:main
triage_web/
  server.py              FastAPI app, ~40 routes
  analysis.py            domain helpers over BinaryLoader, no FastAPI
  loader.py  engine.py   ELF/PE parsing; Capstone disasm, ROP, xrefs
  pcode.py cfg.py ...     the experimental p-code decompiler (not yet wired)
  autopwn/               the recon + strategy layer
  index.html             the whole SPA
tests/                   pytest suite plus the golden-recon fixtures
samples/                 small purpose-built test binaries and their C source
```

`ARCHITECTURE.md` has the full walkthrough.

## Development

```bash
make dev        # uv sync + install the pre-commit hooks
make check      # ruff check + ruff format --check + pytest
make coverage   # + term-missing / html / xml
```

- 377 tests. `fail_under = 100` on the shipped web surface. The solver-strategy
  layer drives angr/unicorn/pwntools, so it is exercised end to end but left out
  of the line-coverage gate; `make coverage-strat` reports its real number, and a
  module only joins that opt-out list together with a golden-output test.
- `tests/test_golden_recon.py` pins the deterministic `recon()` output (arch,
  protections, ranked plan) for five sample binaries.
- CI runs lint, tests, and coverage on Python 3.12 and 3.13, plus `pip-audit`. A
  weekly job (`make deps-canary`) reruns the solver suite against the latest
  unpinned angr/unicorn/pwntools/capstone so a breaking release shows up on a
  schedule instead of during a competition.

## Roadmap

- A "dynamic dump" mode for key-driven self-modifying code: run the de-fanged
  image under the sandbox and snapshot the region after it decrypts itself.
- A targeted angr harness for multi-process anti-analysis binaries.
- `repne cmpsb` -> `memcmp()` idiom recognition in the decompiler.

## License

MIT. See `LICENSE`.
