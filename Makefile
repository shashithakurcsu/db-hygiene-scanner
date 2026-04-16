.PHONY: install lint test test-cov type-check security-check format clean demo help

PYTHON := python3
PIP := $(PYTHON) -m pip

help:
	@echo "db-hygiene-scanner development commands:"
	@echo "  make install         Install development dependencies"
	@echo "  make lint            Run ruff linter"
	@echo "  make test            Run pytest"
	@echo "  make test-cov        Run pytest with coverage"
	@echo "  make type-check      Run mypy type checker"
	@echo "  make security-check  Run bandit security scanner"
	@echo "  make format          Format code with black (check mode)"
	@echo "  make clean           Remove build artifacts and cache"
	@echo "  make demo            Run demo scan pipeline"

install:
	$(PIP) install -e ".[dev]"

lint:
	ruff check src/ tests/

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=src/db_hygiene_scanner --cov-report=html --cov-report=term-missing

type-check:
	mypy src/db_hygiene_scanner --strict

security-check:
	bandit -r src/db_hygiene_scanner -ll

format:
	black --check src/ tests/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	rm -rf build/ dist/ *.egg-info .pytest_cache/ .coverage htmlcov/ .mypy_cache/

demo:
	$(PYTHON) -m db_hygiene_scanner.cli demo --repo-path ./src
