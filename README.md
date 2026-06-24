# SlopGuard

[![CI](https://github.com/Yoyagm/slopguard/actions/workflows/slopguard-ci.yml/badge.svg)](https://github.com/Yoyagm/slopguard/actions/workflows/slopguard-ci.yml)
[![CodeQL](https://github.com/Yoyagm/slopguard/actions/workflows/codeql.yml/badge.svg)](https://github.com/Yoyagm/slopguard/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)
![Typing](https://img.shields.io/badge/mypy-strict-blue)
![Lint](https://img.shields.io/badge/lint-ruff-orange)
![Runtime deps](https://img.shields.io/badge/runtime%20deps-0-success)

> Guardián pre-instalación contra *slopsquatting*. Escanea las dependencias Python
> de un proyecto y detecta paquetes inexistentes (alucinados por LLMs), *typosquatting*,
> metadatos sospechosos o **malicia confirmada** por inteligencia de amenazas comunitaria,
> **antes** de instalarlos.

**Estado:** Hito 2 completado (v0.2.0). 1547 tests verdes, cobertura 96.23% global (≥90%),
99% en paquetes críticos (≥95%, incluye `core/threatintel`). mypy strict (82 archivos),
ruff (bandit S), import-linter (5 contratos), CI en GitHub Actions.

---

## Qué es y qué detecta

Los asistentes de IA sugieren con frecuencia comandos `pip install` que incluyen nombres
de paquetes inexistentes. Los atacantes pre-registran esos nombres alucinados con código
malicioso —técnica conocida como *slopsquatting*— de modo que un desarrollador que copia
el comando sin verificar instala el paquete del atacante.

SlopGuard detecta cuatro clases de riesgo antes de la instalación, sin ejecutar ningún
código de los paquetes analizados:

| Capa | Qué evalúa | Señales emitidas |
|---|---|---|
| **Capa 0** — existencia y edad | Consulta PyPI JSON API; verifica que el paquete exista y cuántos días tiene | `NONEXISTENT` (bloqueo directo si 404), `NEW_PACKAGE` (blanda) |
| **Capa 1** — *typosquatting* | Damerau-Levenshtein + Jaro-Winkler contra el top-N de PyPI, sin red, determinista | `TYPOSQUAT` (dura), `NAME_UNTRUSTED` (nombre excesivamente largo) |
| **Capa 2** — metadatos | Señales de calidad del paquete solo desde PyPI JSON: releases, repositorio, campos de metadata | `WEAK_METADATA`, `LOW_VERIFIABILITY` (blandas, aporte acotado a 10 pts) |
| **Capa 3** — *threat-intel* | Advisories `MAL-*` de OSV.dev (malicia confirmada) + watchlist de alucinaciones depscope (opcional) | `MALICIOUS` (override de block), `KNOWN_HALLUCINATION` (dura, peso 85), `THREATINTEL_UNVERIFIABLE` (blanda) |

**Cero dependencias de runtime** (solo stdlib). Sin LLM ni servicios de pago. PyPI JSON
API + OSV.dev (gratuitos, públicos) y un dataset embebido verificado con SHA-256.

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

## Capa 3 — Threat-intel (OSV.dev + watchlist opcional)

### Deteccion de paquetes maliciosos via OSV.dev

La Capa 3 consulta [OSV.dev](https://osv.dev) — base de datos publica y gratuita de advisories
de *open-source security* — para detectar paquetes Python **confirmados maliciosos** antes de
instalarlos. Solo se evaluan los paquetes que existen en PyPI (estado `FOUND` de la Capa 0);
los inexistentes ya tienen veredicto `block` por override y no requieren consulta de red.

**Criterio de bloqueo:** unicamente los advisories con prefijo `MAL-` (p.ej.
`MAL-2025-47868`) producen senial `MALICIOUS` y bloqueo. Los advisories de vulnerabilidad
general (`GHSA-*`, `CVE-*`, `PYSEC-*`) se **ignoran** para el veredicto — SlopGuard no es
un escaner de CVEs, es un guardian de *supply-chain*.

Una senial `MALICIOUS` fuerza `verdict=block` con `score=null` por override, con
**precedencia maxima** sobre cualquier otro veredicto de las capas 0-2. Si coexisten malicia
y typosquat, ambas seniales se reportan.

### Watchlist de alucinaciones conocidas (depscope, OPCIONAL)

La watchlist `depscope-hallucinations` es una fuente **opt-in** de nombres de paquetes
alucinados conocidos (corpus de benchmark de LLMs), disponible en
[depscope.dev](https://depscope.dev). Esta inactiva por default:

- **Con `enable_watchlist=false` (default):** no se realiza ninguna consulta a depscope.dev;
  el host no se anade al allowlist de red.
- **Con `enable_watchlist=true` o `--enable-watchlist`:** se obtiene el corpus en runtime
  (GET con TTL de cache 24h). Un match exacto produce senial `KNOWN_HALLUCINATION` (dura,
  peso 85), que produce `block` por score. **No se redistribuye ni embebe el corpus** en el
  paquete (respeto a la licencia CC-BY-NC-SA de depscope). La atribucion y la licencia del
  corpus aparecen en la salida.

### Flags de la Capa 3

```
--no-layer3              Desactiva completamente la Capa 3 (modo solo-deterministas).
                         Sin red hacia OSV ni depscope. Equivalente al comportamiento
                         del Hito 1.
--enable-watchlist       Activa la consulta opcional a depscope.dev (watchlist de
                         alucinaciones). Requiere red hacia depscope.dev.
```

Estos flags tambien son configurables via `pyproject.toml` o `.slopguard.toml`:

```toml
[tool.slopguard]
enable_layer3   = true    # default: true
enable_watchlist = false  # default: false
```

### Privacidad y transparencia (NFR-Priv.3)

SlopGuard sigue el principio de minima exposicion de datos:

| Que se envia | A que host | Cuando |
|---|---|---|
| Nombre normalizado (PEP 503) + ecosistema (`PyPI`) | `api.osv.dev` | Siempre que `enable_layer3=true` y el paquete existe en PyPI |
| Solo la peticion GET sin parametros de usuario | `depscope.dev` | Solo si `enable_watchlist=true` |

**Nunca se envia:** el contenido del manifiesto, rutas locales, versiones pinneadas
innecesariamente, identificadores del usuario ni ninguna informacion del entorno.

**Modo sin red a terceros:** usar `--no-layer3` (o `enable_layer3=false` en config)
para operar en modo solo-deterministas. Las capas 0-2 solo contactan `pypi.org`.

### Defaults de la Capa 3

| Parametro | Default | Descripcion |
|---|---|---|
| `enable_layer3` | `true` | Activa/desactiva la Capa 3 |
| `osv_host` | `api.osv.dev` | Host de la API OSV |
| `osv_ttl_cache_horas` | `6` | TTL de cache OSV en disco |
| `osv_timeout_total_por_lote_s` | `30` | Presupuesto de tiempo por lote de consulta |
| `osv_reintentos` | `2` | Reintentos ante errores transitorios (5xx/429) |
| `osv_batch_max` | `1000` | Maximo de paquetes por request a OSV |
| `enable_watchlist` | `false` | Activa la watchlist depscope (opt-in) |
| `watchlist_host` | `depscope.dev` | Host de la watchlist |
| `watchlist_ttl_cache_horas` | `24` | TTL de cache del corpus de watchlist |
| `watchlist_timeout_total_s` | `30` | Timeout para obtener el corpus |
| `threatintel_degraded_status` | `unverifiable` | Estado cuando OSV no responde (`unverifiable` o `warn`) |

### Degradacion segura

Si OSV.dev o depscope.dev no responden (timeout, 5xx, rate limit agotado), la Capa 3
**nunca produce un falso "todo limpio"**: emite senial blanda `THREATINTEL_UNVERIFIABLE`
y degrada el estado de la dependencia a `unverifiable` (exit code 3), preservando los
veredictos de las capas deterministas 0-2. Un `block` por typosquat o inexistencia
domina sobre cualquier fallo de threat-intel.

### Ejemplo de salida — bioql (MAL-2025-47868)

```
$ slopguard scan req.txt

SlopGuard 0.2.0 — escaneando req.txt (2 dependencias)

[BLOCK]  bioql
         score: —  (override: malicia confirmada por OSV)
         Capa 3: Reportado como malicioso — MAL-2025-47868
                 https://osv.dev/vulnerability/MAL-2025-47868
         Accion sugerida: no instalar; paquete reportado como malicioso.

[ALLOW]  requests
         score: 2

Resumen: 1 allow · 0 warn · 1 block · 0 unverifiable
Exit code: 2
```

### Ejemplo de salida JSON (schema_version 1.1)

```bash
slopguard scan req.txt --format json
```

```json
{
  "schema_version": "1.1",
  "tool_version": "0.2.0",
  "ecosystem": "pypi",
  "summary": {
    "total": 2,
    "allow": 1,
    "warn": 0,
    "block": 1,
    "unverifiable": 0,
    "exit_code": 2
  },
  "error_category": null,
  "results": [
    {
      "name": "bioql",
      "version_pin": null,
      "status": "ok",
      "verdict": "block",
      "score": null,
      "suspected_target": null,
      "error_category": null,
      "advisories": [
        {
          "id": "MAL-2025-47868",
          "kind": "malicious",
          "url": "https://osv.dev/vulnerability/MAL-2025-47868",
          "source": "osv"
        }
      ],
      "signals": [
        {
          "layer": 3,
          "code": "malicious",
          "weight": 0,
          "is_soft": false,
          "detail": "Reportado como malicioso por OSV (MAL-2025-47868). No instalar.",
          "suspected_target": null
        }
      ]
    },
    {
      "name": "requests",
      "version_pin": null,
      "status": "ok",
      "verdict": "allow",
      "score": 2,
      "suspected_target": null,
      "error_category": null,
      "advisories": [],
      "signals": []
    }
  ]
}
```

El campo `advisories[]` esta **siempre presente** en schema 1.1 (vacio si no hay malicia).
El cambio es **retrocompatible**: un consumidor de schema 1.0 ignora `advisories` y las
seniales de `layer:3` sin romperse.

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
--no-cache                  Ignora la cache y no escribe en ella
--strict                    Trata cualquier warn como block (exit 2)
--config <ruta>             Ruta explicita al archivo de configuracion
--manifest-type {requirements,pyproject,freeze}  Fuerza el tipo de manifiesto
--umbral-block N            Override del umbral de block
--umbral-warn N             Override del umbral de warn
--edad-minima-dias N        Override del umbral de edad
--concurrencia N            Override del numero de workers
--jw-min F                  Override del umbral Jaro-Winkler
--dl-max N                  Override del umbral Damerau-Levenshtein
--no-layer3                 Desactiva la Capa 3 (modo solo-deterministas, sin red a OSV)
--enable-watchlist          Activa la watchlist de alucinaciones depscope (opt-in)
```

---

## Formato JSON para CI (`schema_version` 1.1)

El campo `schema_version: "1.1"` garantiza compatibilidad hacia adelante. El cambio
de 1.0 a 1.1 es **estrictamente aditivo**: se anade el campo `advisories[]` (siempre
presente, vacio si no hay malicia) y seniales de `layer:3`. Los campos de 1.0 no se
modifican ni eliminan.

Los campos estables por resultado en schema 1.1 son:

```
name            string   nombre normalizado (PEP 503)
version_pin     string|null
status          "ok" | "unverifiable"
verdict         "allow" | "warn" | "block" | null  (null si unverifiable)
score           integer 0-100 | null                (null si unverifiable, inexistente o MALICIOUS)
suspected_target string|null                        (objetivo del typosquat si aplica)
error_category  string|null
advisories[]    array de advisories MAL-* (id, kind, url, source); [] si sin malicia  [NUEVO 1.1]
signals[]       array de seniales con layer/code/weight/is_soft/detail/suspected_target
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

- **Cero ejecucion de codigo de paquetes:** SlopGuard solo inspecciona metadatos de PyPI
  y advisories de OSV. Nunca importa, ejecuta ni evalua el codigo de los paquetes
  analizados. Sin `eval`, `exec`, `pickle` ni `marshal` sobre datos externos (verificado
  por lint y tests AST).
- **HTTP endurecido:** solo HTTPS con verificacion de certificado activa (no desactivable),
  *allowlist* de host ampliado a `{pypi.org, api.osv.dev}` (+ `depscope.dev` solo si
  `enable_watchlist=true`), sin redirecciones cross-scheme/cross-host — incluidas las que
  provienen de `api.osv.dev` (fix SSRF: el redirect handler valida contra el conjunto
  efectivo por-instancia), lectura *streaming* acotada por `max_response_bytes`, mitigacion
  de bombas de descompresion y de JSON profundo (`max_json_depth`).
- **Fail-closed (Capa 3):** si OSV o depscope no responden, la dependencia pasa a
  `unverifiable` (exit 3), nunca a `allow`. Un block por capas deterministas domina sobre
  cualquier fallo de threat-intel.
- **Allowlist ampliada con guardia:** `ALLOWED_HOSTS = {pypi.org}` permanece como
  constante de base verificada estaticamente; `api.osv.dev` y (si aplica) `depscope.dev`
  se anaden por-instancia, de forma explicita y acotada. El guardia estatico (test AST)
  verifica la base y el conjunto efectivo en CI.
- **Anti-envenenamiento de feed:** los IDs de advisory OSV se validan con regex
  `^MAL-[0-9A-Za-z-]+$` antes de construir cualquier URL. Los nombres se validan por
  charset antes de incluirlos en el body del POST. El corpus de watchlist se valida
  (charset, cap de tamano, schema) tanto al recibir como al leer de cache.
- **Cache segura:** JSON exclusivamente (nunca pickle), escritura atomica (`os.replace`),
  permisos 0700/0600, claves SHA-256 namespaced (anti *path traversal*), validacion
  defensiva al leer. El estado `UNVERIFIABLE` nunca se persiste en cache.
- **Integridad del dataset:** el top-N embebido se verifica con SHA-256 al cargar.
- **Anti-inyeccion de salida:** todo nombre o dato externo (incluidos IDs y resumenes de
  OSV/depscope) se sanea (ANSI CSI/SGR, controles C0/C1, CR/LF) en la salida humana,
  logs y JSON.
- **Privacidad:** solo se envia nombre normalizado + ecosistema a OSV/depscope. Nunca el
  manifiesto, rutas locales ni identificadores del usuario. Desactivable completamente con
  `--no-layer3`.

---

## Desarrollo

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Quality gates (deben pasar todos antes de commit)
ruff check .
mypy                                                     # strict, 82 archivos
lint-imports                                             # 5 contratos (core/cli, capas/scoring, source, layer3, + hito1)
pytest --cov=slopguard --cov-branch --cov-fail-under=90
```

El CI (`.github/workflows/slopguard-ci.yml`) ejecuta los mismos gates en Python 3.11
y 3.12, mas la compilacion del documento tecnico LaTeX a PDF.

---

## Documentación técnica

El documento técnico completo (arquitectura por capas, ADRs, modelos de datos, diagramas
de secuencia, trazabilidad EARS) se encuentra en `docs/slopguard.tex` y se compila a PDF
como artefacto del CI.
