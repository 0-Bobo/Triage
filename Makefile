.PHONY: help install sync test lint format check coverage audit clean dev

help:
	@echo "Available targets:"
	@echo "  install    - Install uv if not present and sync dependencies"
	@echo "  sync       - Sync dependencies with uv"
	@echo "  test       - Run tests with pytest"
	@echo "  lint       - Run ruff linting"
	@echo "  format     - Format code with ruff"
	@echo "  check      - Run lint and tests"
	@echo "  coverage   - Run tests with coverage report"
	@echo "  audit      - Scan installed dependencies for known CVEs"
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

coverage:
	uv run pytest --cov=triage_web --cov-report=term --cov-report=html --cov-report=xml

audit:
	uv run pip-audit --skip-editable

clean:
	rm -rf .pytest_cache/ htmlcov/ .coverage coverage.xml .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

dev: install
	uv add --dev pytest pytest-cov ruff pre-commit pip-audit
	uv run pre-commit install
