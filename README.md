# SlopGuard

[![CI](https://github.com/Yoyagm/slopguard/actions/workflows/slopguard-ci.yml/badge.svg)](https://github.com/Yoyagm/slopguard/actions/workflows/slopguard-ci.yml)
[![CodeQL](https://github.com/Yoyagm/slopguard/actions/workflows/codeql.yml/badge.svg)](https://github.com/Yoyagm/slopguard/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)
![Typing](https://img.shields.io/badge/mypy-strict-blue)
![Lint](https://img.shields.io/badge/lint-ruff-orange)
![Runtime deps](https://img.shields.io/badge/runtime%20deps-0-success)

> Guardián pre-instalación contra *slopsquatting*. Escanea las dependencias Python
> de un proyecto y detecta paquetes inexistentes (alucinados por LLMs), *typosquatting*
> o de metadatos sospechosos **antes** de instalarlos.

**Estado:** Hito 1 completado. 619 tests verdes, cobertura 95.3% global (≥90%), 99% en
paquetes críticos (≥95%). mypy strict, ruff, import-linter (2 contratos), CI en GitHub Actions.

---

## Qué es y qué detecta

Los asistentes de IA sugieren con frecuencia comandos `pip install` que incluyen nombres
de paquetes inexistentes. Los atacantes pre-registran esos nombres alucinados con código
malicioso —técnica conocida como *slopsquatting*— de modo que un desarrollador que copia
el comando sin verificar instala el paquete del atacante.

SlopGuard detecta tres clases de riesgo antes de la instalación, sin ejecutar ningún
código de los paquetes analizados:

| Capa | Qué evalúa | Señales emitidas |
|---|---|---|
| **Capa 0** — existencia y edad | Consulta PyPI JSON API; verifica que el paquete exista y cuántos días tiene | `NONEXISTENT` (bloqueo directo si 404), `NEW_PACKAGE` (blanda) |
| **Capa 1** — *typosquatting* | Damerau-Levenshtein + Jaro-Winkler contra el top-N de PyPI, sin red, determinista | `TYPOSQUAT` (dura), `NAME_UNTRUSTED` (nombre excesivamente largo) |
| **Capa 2** — metadatos | Señales de calidad del paquete solo desde PyPI JSON: releases, repositorio, campos de metadata | `WEAK_METADATA`, `LOW_VERIFIABILITY` (blandas, aporte acotado a 10 pts) |

**Cero dependencias de runtime** (solo stdlib). Sin LLM ni servicios de pago. Solo la
PyPI JSON API (gratuita) y un dataset embebido y verificado con SHA-256.

---

## Instalación

```bash
# Dentro del repositorio (modo editable, recomendado para desarrollo)
pip install -e .

# Con herramientas de desarrollo
pip install -e ".[dev]"
```

Requiere Python 3.11+.

---

## Uso de la CLI

### Escaneo básico

```bash
slopguard scan requirements.txt
slopguard scan pyproject.toml
pip freeze | slopguard scan -        # lee de stdin en formato pip freeze
```

### Ejemplo de salida humana

```
$ slopguard scan req.txt

SlopGuard 0.1.0 — escaneando req.txt (3 dependencias)

[BLOCK]  reqursts
         score: 75  |  sospechado: requests
         Capa 1: El nombre se parece a 'requests' (distancia Damerau-Levenshtein 1).
         Accion sugerida: verificar si quiso escribir 'requests'.

[BLOCK]  paquete-inexistente-xyz
         score: —  (override: no existe en PyPI)
         Capa 0: El paquete no existe en PyPI (404). Posible alucinacion de LLM.

[ALLOW]  boto3
         score: 3

Resumen: 1 allow · 0 warn · 2 block · 0 unverifiable
Exit code: 2
```

### Ejemplo de salida JSON

```bash
slopguard scan req.txt --format json
```

```json
{
  "schema_version": "1.0",
  "tool_version": "0.1.0",
  "ecosystem": "pypi",
  "summary": {
    "total": 3,
    "allow": 1,
    "warn": 0,
    "block": 2,
    "unverifiable": 0,
    "exit_code": 2
  },
  "error_category": null,
  "results": [
    {
      "name": "paquete-inexistente-xyz",
      "version_pin": null,
      "status": "ok",
      "verdict": "block",
      "score": null,
      "suspected_target": null,
      "error_category": null,
      "signals": [
        {
          "layer": 0,
          "code": "nonexistent",
          "weight": 0,
          "is_soft": false,
          "detail": "El paquete no existe en PyPI (404). Posible alucinacion de LLM.",
          "suspected_target": null
        }
      ]
    },
    {
      "name": "reqursts",
      "version_pin": null,
      "status": "ok",
      "verdict": "block",
      "score": 75,
      "suspected_target": "requests",
      "error_category": null,
      "signals": [
        {
          "layer": 1,
          "code": "typosquat",
          "weight": 60,
          "is_soft": false,
          "detail": "El nombre se parece a 'requests' (distancia 1).",
          "suspected_target": "requests"
        },
        {
          "layer": 0,
          "code": "new_package",
          "weight": 15,
          "is_soft": true,
          "detail": "Publicado hace 4 dias (umbral 90).",
          "suspected_target": null
        }
      ]
    },
    {
      "name": "boto3",
      "version_pin": null,
      "status": "ok",
      "verdict": "allow",
      "score": 3,
      "suspected_target": null,
      "error_category": null,
      "signals": []
    }
  ]
}
```

La salida JSON es estable, versionada (`schema_version`) y **sin marcas de tiempo**
(determinismo garantizado para CI). El campo `score` es `null` cuando el veredicto es
por override (inexistencia) o el paquete es `unverifiable`.

---

## Exit codes (R7)

| Código | Significado | Condición |
|---|---|---|
| `0` | allow | Todas las dependencias resultan `allow`; sin warn, block ni unverifiable |
| `1` | warn | Al menos 1 `warn`, sin block ni unverifiable (sin `--strict`) |
| `2` | block | Al menos 1 `block` (señal dominante); o cualquier `warn` con `--strict` |
| `3` | operacional/unverifiable | Error total (manifiesto/config/dataset) **o** ≥1 `unverifiable` sin block |

**Precedencia:** `block (2) > operacional/unverifiable (3) > warn (1) > allow (0)`.

Un `block` confirmado domina sobre una verificación incompleta. Los `unverifiable`
siempre se reportan en la salida aunque el exit code sea 2.

---

## Scoring (ADR-01)

El score es un modelo **aditivo con saturación** que separa señales duras (basadas en el
nombre) de señales blandas (corroborantes, acotadas):

```
score = min(100, dura + min(blandas, 25))
```

| Clase | Señal / condición | Peso |
|---|---|---|
| Dura | TYPOSQUAT — DL = 1 (un carácter de diferencia) | 60 |
| Dura | TYPOSQUAT — DL = 2 | 40 |
| Dura | TYPOSQUAT — Jaro-Winkler ≥ 0.95 (DL > dl_max) | 30 |
| Dura | TYPOSQUAT — 0.92 ≤ JW < 0.95 | 25 |
| Dura | NAME_UNTRUSTED — longitud > `nombre_max_chars` | 30 |
| Blanda | NEW_PACKAGE — publicado hace menos de `edad_minima_dias` | 15 |
| Blanda | Capa 2 (WEAK_METADATA + LOW_VERIFIABILITY, cap duro) | ≤ 10 |

**Invariante anti-falsos positivos:** la suma máxima de señales blandas es 25, que es
estrictamente menor que `umbral_warn` (50). Por tanto **ninguna combinación de señales
blandas por sí sola** puede producir `warn` ni `block`. Un paquete que existe y no
dispara typosquat siempre resulta `allow`.

---

## Configuración y defaults (R8)

SlopGuard carga configuración desde `[tool.slopguard]` en `pyproject.toml` o desde un
archivo `.slopguard.toml` en el directorio de trabajo. Los flags de CLI tienen precedencia
sobre el archivo, y el archivo sobre los defaults.

**Precedencia:** CLI flags > archivo de config > defaults

### Tabla de defaults

| Parámetro | Default | Descripción |
|---|---|---|
| `umbral_block` | `80` | Score mínimo para veredicto `block` |
| `umbral_warn` | `50` | Score mínimo para veredicto `warn` |
| `edad_minima_dias` | `90` | Días mínimos de antigüedad (señal `NEW_PACKAGE`) |
| `ttl_cache_horas` | `24` | Vigencia de la caché en disco |
| `concurrencia_max` | `8` | Workers de red paralelos (ThreadPoolExecutor) |
| `connect_timeout_s` | `5` | Timeout de conexión TCP (segundos) |
| `read_timeout_s` | `10` | Timeout de lectura HTTP (segundos) |
| `reintentos_red` | `2` | Reintentos ante errores transitorios (backoff 0.5s base) |
| `timeout_total_por_dep_s` | `30` | Presupuesto de tiempo total por dependencia |
| `jw_min` | `0.92` | Umbral mínimo de similaridad Jaro-Winkler |
| `dl_max` | `2` | Distancia máxima Damerau-Levenshtein para señal |
| `nombre_max_chars` | `100` | Longitud máxima de nombre antes de NAME_UNTRUSTED |
| `releases_min` | `1` | Umbral de releases escasas (Capa 2) |
| `metadata_faltantes_min` | `2` | Campos de metadata mínimos que deben faltar (Capa 2) |
| `releases_populares` | `10` | Umbral de releases para aplicar cap de Capa 2 |
| `c2_max_contrib` | `10` | Aporte máximo de Capa 2 al score |
| `max_manifest_bytes` | `5_000_000` | Tamaño máximo del manifiesto |
| `max_deps` | `5000` | Número máximo de dependencias por manifiesto |
| `max_response_bytes` | `10_000_000` | Límite de respuesta HTTP (anti-bomba) |
| `max_json_depth` | `50` | Profundidad máxima de JSON (anti JSON bomb) |
| `max_include_depth` | `10` | Profundidad máxima de includes `-r`/`-c` |

### Configurar via `pyproject.toml`

```toml
[tool.slopguard]
umbral_block = 75
umbral_warn = 45
edad_minima_dias = 60
concurrencia_max = 4
```

### Configurar via `.slopguard.toml`

```toml
umbral_block = 75
umbral_warn = 45
```

### Flags CLI principales

```
--format {human,json}       Formato de salida (default: human)
--no-cache                  Ignora la caché y no escribe en ella
--strict                    Trata cualquier warn como block (exit 2)
--config <ruta>             Ruta explícita al archivo de configuración
--manifest-type {requirements,pyproject,freeze}  Fuerza el tipo de manifiesto
--umbral-block N            Override del umbral de block
--umbral-warn N             Override del umbral de warn
--edad-minima-dias N        Override del umbral de edad
--concurrencia N            Override del número de workers
--jw-min F                  Override del umbral Jaro-Winkler
--dl-max N                  Override del umbral Damerau-Levenshtein
```

---

## Formato JSON para CI (`schema_version` 1.0)

El campo `schema_version: "1.0"` garantiza compatibilidad hacia adelante. Los campos
estables por resultado son:

```
name            string   nombre normalizado (PEP 503)
version_pin     string|null
status          "ok" | "unverifiable"
verdict         "allow" | "warn" | "block" | null  (null si unverifiable)
score           integer 0-100 | null                (null si unverifiable o inexistente)
suspected_target string|null                        (objetivo del typosquat si aplica)
error_category  string|null
signals[]       array de señales con layer/code/weight/is_soft/detail/suspected_target
```

---

## Uso como gate en pre-commit y GitHub Actions

### GitHub Actions

```yaml
- name: SlopGuard — gate de supply chain
  run: slopguard scan requirements.txt --strict --format json
  # Exit 0: todo ok. Exit 2: block (o warn con --strict). Exit 3: error operacional.
```

```yaml
- name: SlopGuard con reporte JSON
  run: |
    slopguard scan requirements.txt --format json | tee slopguard-report.json
    # El exit code del proceso es el de slopguard
```

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: slopguard
        name: SlopGuard — supply chain guard
        entry: slopguard scan
        args: [requirements.txt, --strict]
        language: python
        pass_filenames: false
        always_run: true
```

---

## Propiedades de seguridad

- **Cero ejecución de código de paquetes:** SlopGuard solo inspecciona metadatos de PyPI.
  Nunca importa, ejecuta ni evalúa el código de los paquetes analizados. Sin `eval`,
  `exec`, `pickle` ni `marshal` sobre datos externos (verificado por lint y tests AST).
- **HTTP endurecido:** solo HTTPS con verificación de certificado activa (no desactivable),
  *allowlist* de host restringida a `pypi.org`, sin redirecciones cross-scheme/cross-host,
  lectura *streaming* acotada por `max_response_bytes`, mitigación de bombas de
  descompresión y de JSON profundo (`max_json_depth`).
- **Caché segura:** JSON exclusivamente (nunca pickle), escritura atómica (`os.replace`),
  permisos 0700/0600, claves SHA-256 (anti *path traversal*), validación defensiva al leer.
- **Integridad del dataset:** el top-N embebido se verifica con SHA-256 al cargar; si
  falta o está corrupto, se aborta con `error_category=dataset_integrity` en vez de marcar
  la Capa 1 como limpia en silencio.
- **Anti-inyección de salida:** todo nombre o dato externo se sanea (ANSI CSI/SGR,
  controles C0/C1, CR/LF) en la salida humana, logs y JSON.
- **Privacidad:** nunca se envía el manifiesto a terceros. Las capas 0-2 consultan PyPI
  solo por nombre de paquete. Sin LLM ni servicios de pago.

---

## Desarrollo

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Quality gates (deben pasar todos antes de commit)
ruff check .
mypy
lint-imports
pytest --cov=slopguard --cov-branch --cov-fail-under=90
```

El CI (`.github/workflows/slopguard-ci.yml`) ejecuta los mismos gates en Python 3.11
y 3.12, más la compilación del documento técnico LaTeX a PDF.

---

## Documentación técnica

El documento técnico completo (arquitectura por capas, ADRs, modelos de datos, diagramas
de secuencia, trazabilidad EARS) se encuentra en `docs/slopguard.tex` y se compila a PDF
como artefacto del CI.
