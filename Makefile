# Red Team Toolkit developer tasks.
#
# Everything here is safe to run: the scan and attack targets default to
# loopback, and the test suite opens no socket beyond 127.0.0.1.

PYTHON ?= python3
VENV   ?= .venv
BIN     = $(VENV)/bin
TARGET ?= 127.0.0.1

.DEFAULT_GOAL := help
.PHONY: help venv install dev test test-fast cov lint format typecheck check clean \
        build lab lab-down scan demo report-check all

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Create the virtualenv
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip

install: ## Install the package in editable mode with dev extras
	$(BIN)/pip install -e ".[dev]"

dev: venv install ## Create the venv and install dev dependencies

test: ## Run the test suite
	$(BIN)/pytest

test-fast: ## Run the suite, stopping at the first failure
	$(BIN)/pytest -x -q

cov: ## Run the suite with a coverage report
	$(BIN)/pytest --cov=redteam_toolkit --cov-report=term-missing --cov-report=html
	@echo "open htmlcov/index.html"

lint: ## Lint and check formatting
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

format: ## Apply formatting and safe lint fixes
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

typecheck: ## Run mypy in strict mode
	$(BIN)/mypy

check: lint typecheck test ## Everything CI runs

build: ## Build the sdist and wheel
	$(BIN)/pip install --upgrade build
	$(BIN)/python -m build

lab: ## Start the deliberately vulnerable lab targets
	docker compose up -d
	@echo
	@echo "lab targets are up on 127.0.0.1:"
	@echo "  dvwa     http://127.0.0.1:8081   (admin / password)"
	@echo "  juice    http://127.0.0.1:3000"
	@echo "  nginx    http://127.0.0.1:8088   (leaks /.env and /.git/config)"
	@echo "  sshd     127.0.0.1:2222          (lab / lab)"
	@echo "  redis    127.0.0.1:6379          (no authentication)"
	@echo "  postgres 127.0.0.1:5432          (postgres / postgres)"
	@echo
	@echo "optional TLS endpoint with a self-signed, 800-day certificate:"
	@echo "  docker compose --profile tls up -d   ->  https://127.0.0.1:8443"
	@echo
	@echo "then:  make scan"

lab-down: ## Stop the lab and remove its volumes
	docker compose down -v

scan: ## Scan the local lab (start it with: make lab)
	$(BIN)/python main.py scan --target $(TARGET) --i-understand --ports 22,80,443,3000,5432,6379,8081,8088,2222,8443

demo: ## Full assessment against the local lab, all report formats
	$(BIN)/python main.py attack --target $(TARGET) --i-understand \
		--ports 22,80,443,3000,5432,6379,8081,8088,2222,8443 \
		--wordlist wordlists/creds.txt \
		--format all --output reports/

report-check: ## Verify the written reports are valid and self-contained
	@$(BIN)/python -c "$$REPORT_CHECK" 2>/dev/null || $(BIN)/python - <<'PY'
	import glob, json, pathlib
	files = glob.glob('reports/*.json') or glob.glob('/tmp/rtt/*.json')
	assert files, 'no JSON report found; run `make demo` first'
	for path in files:
	    json.loads(pathlib.Path(path).read_text())
	    print('valid JSON:', path)
	html = glob.glob('reports/*.html') or glob.glob('/tmp/rtt/*.html')
	for path in html:
	    body = pathlib.Path(path).read_text()
	    assert body.startswith('<!doctype html>')
	    assert '<script src' not in body
	    print('self-contained HTML:', path)
	PY

all: check build ## Lint, type check, test, then build

clean: ## Remove caches, build output and the venv
	rm -rf .venv build dist *.egg-info htmlcov .coverage coverage.xml .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.py[co]' -delete
