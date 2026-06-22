# SlopGuard (Hito 1) — tareas de desarrollo.
# Reproduce localmente los mismos gates que CI.

PY := .venv/bin/python
BIN := .venv/bin

.PHONY: install lint type imports test cov docs docs-docker all clean

install:  ## Crea el venv e instala el paquete en editable + dev tools
	python3.11 -m venv .venv
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e ".[dev]"

lint:  ## Ruff (lint + reglas de seguridad)
	$(BIN)/ruff check .

type:  ## Mypy estricto
	$(BIN)/mypy

imports:  ## Contratos de arquitectura (import-linter)
	$(BIN)/lint-imports

test:  ## Pruebas
	$(BIN)/pytest -q

cov:  ## Pruebas + cobertura con gate global >= 90%
	$(BIN)/pytest --cov=slopguard --cov-branch --cov-report=term-missing --cov-fail-under=90

docs:  ## Compila el documento tecnico LaTeX (requiere xelatex/latexmk o tectonic)
	cd docs && latexmk -xelatex -interaction=nonstopmode slopguard.tex

docs-docker:  ## Compila la doc via docker (sin LaTeX local)
	docker run --rm -v "$(CURDIR)/docs:/work" -w /work texlive/texlive:latest \
		latexmk -xelatex -interaction=nonstopmode slopguard.tex

all: lint type imports cov  ## Todos los gates de calidad

clean:  ## Limpia cachés y artefactos
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	cd docs && rm -f *.aux *.log *.out *.toc *.fls *.fdb_latexmk *.xdv
