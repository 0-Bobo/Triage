# Contributing

## Development setup

**Prerequisites:** Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
make dev        # installs uv (if missing), syncs deps + dev tools, installs pre-commit hooks
make check      # ruff lint + pytest — verify the setup
```

`make dev` runs `uv sync --all-extras --dev`, which pulls the heavy optional
backends (`angr`, `lief`, …). The `Makefile` sets `UV_PROJECT_ENVIRONMENT=.uv`, so
the uv env is `.uv`, not `.venv`; export the same variable when calling `uv`
directly. To work on the web core only:

```bash
uv sync --dev                       # runtime deps + dev tools, no extras
uv sync --extra analysis --dev      # + symbolic/CAPA backends
```

## Make targets

| target | action |
| --- | --- |
| `make sync` | sync dependencies with uv |
| `make test` | run pytest |
| `make lint` | `ruff check .` + `ruff format --check .` |
| `make format` | `ruff format .` + `ruff check --fix .` |
| `make check` | lint + test |
| `make coverage` | pytest with term/html/xml coverage (`--cov=triage_web`) |
| `make clean` | remove caches and build artifacts |

## Layout

- `triage_web/` — the FastAPI package (`main.py` / `python -m triage_web`).
  This is the package that ships and is covered by tests.
- `tests/` — pytest suite (`test_engine.py` locks decompiler/engine behaviour).
- `samples/` — test binaries; excluded from lint.

## Auto-solver (`autopwn`) conventions

- **Wording:** `autopwn` is a *recon + first-move accelerator*, not a solver.
  In the CHANGELOG and docstrings, a strategy **surfaces**, **ranks**, or
  **recovers parameters**. It does not "solve end to end" or "land every
  time". A recovered flag is a bonus; the ranked plan and the scaffold are
  the product. Keep the language honest so the tool does not get
  over-trusted mid-competition.
- **Confidence:** when a strategy returns a `flag`, set `Attempt.confidence`
  (`"solved"` verified, `"likely"`, `"guess"`). The orchestrator defaults it to
  `"solved"` if unset; a guess must say so.
- **Coverage:** the shipped web surface holds `fail_under = 100`. The
  `strat_*` / `capa_scan` layer is `omit`-ed because it drives the heavy
  backends. A file joins that `omit` list **only in the same commit that
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

`uv.lock` is committed. `uv add` / `uv lock` updates it, so commit the
change alongside the `pyproject.toml` edit. CI installs with `--frozen`.

## Commit messages

Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.

## Pull requests

CI (`.github/workflows/ci.yml`) must pass on Python 3.12 and 3.13: lint,
tests, and coverage. Keep PRs focused.
