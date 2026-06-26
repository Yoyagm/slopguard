# Runbook — Regeneración del dataset top-N de npm (R5.4)

Procedimiento reproducible para regenerar el corpus embebido de nombres npm que usa la
**Capa 1** (typosquatting) del adaptador npm. Es **tooling de build offline**: NO corre en
runtime ni en CI (el artefacto va embebido y se verifica con SHA-256 al arranque).

> Equivalente npm de `scripts/generate_top_n.py` (PyPI). No comparten formato de
> normalización: npm preserva el scope (`@scope/name`, sin colapso PEP 503). Ver
> [ADR-3](../specs/slopguard-hito4-npm/design.md).

## Artefactos

| Archivo | Contenido |
|---|---|
| `src/slopguard/core/dataset/npm_top_8k.json` | ~8000 nombres npm normalizados (embebido) |
| `src/slopguard/core/dataset/npm_top_8k.sha256` | digest SHA-256 del `.json`, verificado por `load_top_n_npm()` al arranque (R5.2) |

## Procedencia (de dónde salen los nombres)

1. **Baseline** (~500 nombres muy populares, conocimiento común: React, Vue, Angular,
   utilidades, build/test tooling). Garantiza que los imprescindibles estén siempre.
2. **npm registry search API** (`registry.npmjs.org/-/v1/search`): descubrimiento adicional
   por múltiples términos, ordenado por popularidad npm.
3. **npm downloads API** (`api.npmjs.org/downloads/point`, dominio público): rankea los
   candidatos **unscoped** por descargas reales en un rango de fechas fijo.

> Limitación del endpoint bulk de descargas: solo acepta paquetes **no scoped**. Los scoped
> (`@scope/name`) se incluyen por orden de descubrimiento (baseline → seed), no por descargas.

## Reproducibilidad (determinismo)

El parámetro `--week YYYY-MM-DD` fija el rango histórico de descargas: **misma fecha → mismos
datos → mismo ranking → mismo artefacto byte a byte**. El default `--week 2026-06-16` es el
usado para el artefacto embebido actual. Cambiarlo produce un dataset distinto (y un nuevo
SHA-256); hazlo de forma deliberada y registra la fecha.

## Regenerar

```bash
# Requiere RED (consulta APIs públicas de npm). NO usar en CI.
python scripts/build_npm_top_n.py            # default: --n 8000 --week 2026-06-16
# o explícito / con otra semana:
python scripts/build_npm_top_n.py --n 8000 --week 2026-06-16
```

El script reescribe el `.json` **y** el `.sha256`. Tras regenerar:

```bash
# 1) Verifica que el digest concuerda y que el runtime lo carga sin red
python -c "from slopguard.core.adapters.npm import load_top_n_npm; print(len(load_top_n_npm()), 'nombres')"

# 2) Gate completo (la carga + verificación SHA-256 se ejercita en los tests)
ruff check . && mypy && lint-imports && pytest -q
```

## Normalización (regla npm, §3.4)

`strip()` + `lower()`; `@scope/name` normaliza cada segmento y **preserva** el `/`. **Sin**
colapso PEP 503 de `._-` (eso es exclusivo de PyPI, R3.4). El script aplica exactamente la
misma `_normalize_npm_name` que el runtime, de modo que la pertenencia al top-N
(`in_top_n`) es consistente entre dataset y escaneo.

## Garantías en runtime/CI

- **Cero red**: el `.json` está embebido; `load_top_n_npm()` lo lee del paquete y compara su
  SHA-256 contra el `.sha256`. Si no concuerda → falla cerrado (no se degrada silenciosamente).
- **Cero dependencias de runtime**: el script usa solo stdlib (`urllib`); igualmente solo se
  ejecuta como herramienta de build, nunca se importa desde `src/slopguard/` en runtime.
