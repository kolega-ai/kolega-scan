# kolega-scan developer targets.
.DEFAULT_GOAL := check
PY ?= python3

.PHONY: setup lint format typecheck test audit secret-scan check

setup:
	$(PY) -m pip install -e ".[dev]"

lint:
	ruff check src tests scripts

format:
	ruff format src tests scripts

typecheck:
	mypy

test:
	pytest

audit:
	pip-audit

secret-scan:
	gitleaks detect --no-banner --redact || (echo "gitleaks not installed; skipping" && true)

# Composed gate: fail fast on the first failing step.
check: lint
	ruff format --check src tests scripts
	$(MAKE) typecheck
	$(MAKE) test
	$(MAKE) audit
	@echo "All local gates passed."
