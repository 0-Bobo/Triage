.PHONY: help install sync test lint format check coverage coverage-strat audit clean dev autopwn deps-canary

# uv env lives in .uv so .venv stays free for plain `python -m venv` + pip
export UV_PROJECT_ENVIRONMENT := .uv

help:
	@echo "Available targets:"
	@echo "  install    - Install uv if not present and sync dependencies"
	@echo "  sync       - Sync dependencies with uv"
	@echo "  test       - Run tests with pytest"
	@echo "  lint       - Run ruff linting"
	@echo "  format     - Format code with ruff"
	@echo "  check      - Run lint and tests"
	@echo "  coverage   - Run tests with coverage report"
	@echo "  coverage-strat - Report-only coverage of the omit-ed autopwn strategy layer"
	@echo "  audit      - Scan installed dependencies for known CVEs"
	@echo "  deps-canary- Re-run the autopwn suite against the LATEST angr/unicorn/pwntools/capstone"
	@echo "  clean      - Clean temporary files"
	@echo "  dev        - Setup development environment"

install:
	@if ! command -v uv >/dev/null 2>&1; then \
		echo "Installing uv..."; \
		curl -LsSf https://astral.sh/uv/install.sh | sh; \
	fi
	git submodule update --init --recursive
	$(MAKE) sync

sync:
	uv sync --all-extras --dev

test:            ## fast feedback — skips the slow (capa/vivisect) tests
	uv run pytest -m "not slow"

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff format .
	uv run ruff check --fix .

check: lint test

coverage:        ## skips slow tests too - the two that matter (uaf/brute e2e) spawn a
                 ## sandboxed server via bwrap, which GitHub-hosted runners' restricted
                 ## user namespaces don't allow; both live in strat_uaf.py/strat_brute.py,
                 ## already coverage-omit-ed below, so this doesn't touch the 100% gate.
	uv run pytest -m "not slow" --cov=triage_web --cov-report=term-missing --cov-report=html --cov-report=xml

coverage-strat:  ## report-only: how much of the omit-ed strategy layer the e2e tests actually reach (no gate)
	uv run coverage run --rcfile=/dev/null --source=triage_web/autopwn -m pytest tests/test_autopwn.py -q
	uv run coverage report --rcfile=/dev/null --include='*/autopwn/strat_*,*/autopwn/capa_scan.py'

audit:
	uv run pip-audit --skip-editable

deps-canary:     ## catch upstream breakage early: run the solver suite on unpinned latest backends
	uv run --isolated --with 'angr' --with 'unicorn' --with 'pwntools' --with 'capstone' \
		pytest tests/test_autopwn.py tests/test_solvers.py -q

autopwn:         ## auto-solve a CTF binary:  make autopwn BIN=path/to/chall
	uv run python -m triage_web.autopwn $(BIN)

clean:
	rm -rf .pytest_cache/ htmlcov/ .coverage coverage.xml .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

dev: install
	uv add --dev pytest pytest-cov ruff pre-commit pip-audit
	uv run pre-commit install
