# Contributing

## Development setup

**Prerequisites:** Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
make dev        # installs uv (if missing), syncs deps + dev tools, installs pre-commit hooks
make check      # ruff lint + pytest — verify the setup
```

`make dev` runs `uv sync --all-extras --dev`, which pulls the heavy optional
backends (`angr`, `lief`, `PyQt6`, …). To work on the web core only:

```bash
uv sync --dev                       # runtime deps + dev tools, no extras
uv sync --extra analysis --dev      # + symbolic/CAPA backends
```

## Make targets

| target | action |
| --- | --- |
| `make sync` | sync dependencies with uv |
| `make test` | run pytest |
| `make lint` | `ruff check .` |
| `make format` | `ruff format .` |
| `make check` | lint + test |
| `make coverage` | pytest with term/html/xml coverage (`--cov=triage_web`) |
| `make clean` | remove caches and build artifacts |

## Layout

- `triage_web/` — the FastAPI web edition (`main.py` / `python -m triage_web`).
  This is the package that ships and is covered by tests.
- `apps/desktop/triage.py` — the standalone PyQt6 desktop edition (`--extra desktop`).
- `tests/` — pytest suite (`test_engine.py` locks decompiler/engine behaviour).
- `wsl/` — shell + WSL configuration for running the tool from WSL
  (see `wsl/README.md`); excluded from lint.
- `samples/` — test binaries; excluded from lint.

## Editions

- **`triage_web/`** is the maintained edition — the one that ships, the one CI
  covers.
- **`apps/desktop/triage.py`** is **frozen / best-effort**. It is not part of a
  release, it is lint-exempt, and it inlines an older copy of `BinaryLoader`
  (`triage_web/loader.py` is the source of truth). Do **not** add new features
  here — land them in `triage_web/` first. Touch this file only to keep it
  launching. Un-freezing it means first deleting the inlined loader and
  importing `triage_web.loader` (tracked as `docs/TODO.md` P5).

## Auto-solver (`autopwn`) conventions

- **Wording.** `autopwn` is a *recon + first-move accelerator*, not a solver.
  In the CHANGELOG, `docs/TODO.md`, and docstrings, a strategy **surfaces**,
  **ranks**, or **recovers parameters** — it does not "solve … end to end" or
  "land every time". A recovered flag is a bonus; the ranked plan and the
  scaffold are the product. Keep the language honest so the tool does not get
  over-trusted mid-competition.
- **Confidence.** When a strategy returns a `flag`, set `Attempt.confidence`
  (`"solved"` verified, `"likely"`, `"guess"`). The orchestrator defaults it to
  `"solved"` if unset; a guess must say so.
- **Coverage.** The shipped web surface holds `fail_under = 100`. The
  `strat_*` / `capa_scan` layer is `omit`-ed because it drives the heavy
  backends — but a file joins that `omit` list **only in the same commit that
  adds a golden-output regression test for it** (`tests/test_golden_recon.py`
  for the deterministic recon path; a checked-in fixture + expected artifact
  for strategy output). Check the real number any time with `make coverage-strat`
  (report-only, no gate). Baseline at the time of writing: **71%** of the
  strategy layer, `strat_brute` the weak point at ~26%.

## Before committing

```bash
make format
make check
```

Pre-commit hooks (ruff + ruff-format + whitespace/EOF/yaml checks) run
automatically on `git commit`. Run them by hand with:

```bash
uv run pre-commit run --all-files
```

## Dependencies

```bash
uv add <pkg>                        # runtime dependency
uv add --optional analysis <pkg>    # optional-dependency group
uv add --dev <pkg>                  # dev tool
```

`uv.lock` is committed — `uv add` / `uv lock` updates it, so commit the
change alongside the `pyproject.toml` edit. CI installs with `--frozen`.

## Commit messages

Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.

## Pull requests

CI (`.github/workflows/ci.yml`) must pass on Python 3.12 and 3.13: lint,
tests, and coverage. Keep PRs focused.
