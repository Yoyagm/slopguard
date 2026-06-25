# Documento de Requisitos: SlopGuard Hito 4 — Adaptador npm

## Introducción
El Hito 4 extiende el motor de detección de slopsquatting de SlopGuard al ecosistema **npm**, implementando un `EcosystemAdapter` nuevo y parametrizando por ecosistema las capas que hoy asumen PyPI (threat-intel y LLM). El objetivo es **paridad funcional con PyPI** —existencia, edad, typosquatting, threat-intel y corroborador LLM— para paquetes npm declarados en `package.json`, manteniendo el patrón core-puro-determinista + fachada, *fail-closed*, cero dependencias de runtime y las fronteras de arquitectura verificadas por import-linter, **sin tocar capas ni scoring** salvo donde el ecosistema deba parametrizarse.

## Usuarios objetivo
- **Desarrollador/CI de proyectos Node/npm:** quiere escanear `package.json` antes de instalar y recibir el mismo veredicto explicable (block/warn/clean) que ya obtiene en Python, con la garantía de que la Capa 4 nunca bloquea.
- **Mantenedor de SlopGuard:** quiere añadir npm como "un adapter nuevo" sin regresión en PyPI ni erosión de las fronteras arquitectónicas, con datasets reproducibles y verificables.

## Requisitos funcionales

### Requisito 1: Selección y registro del ecosistema npm
**Historia de usuario:** Como usuario, quiero que SlopGuard reconozca manifiestos npm y me deje forzar el ecosistema, para escanear `package.json` igual que escaneo `requirements.txt`.

**Criterios de aceptación (EARS):**
1. WHEN se invoca `get_adapter("npm", config=..., use_cache=...)` THE SYSTEM SHALL retornar un `NpmAdapter` que cumple el Protocol `EcosystemAdapter` con `ecosystem_id == "npm"`.
2. WHEN el usuario no pasa `--ecosystem` y el manifiesto se llama `package.json` THE SYSTEM SHALL auto-detectar el ecosistema `npm`; WHEN se llama `requirements*.txt`/`pyproject.toml` THE SYSTEM SHALL auto-detectar `pypi` (comportamiento del Hito 1 intacto).
3. WHEN el usuario pasa `--ecosystem {npm|pypi}` THE SYSTEM SHALL usar ese ecosistema como override de la auto-detección, incluyendo el caso de entrada por `stdin` (`-`).
4. IF se solicita un `ecosystem_id` no soportado (ni `pypi` ni `npm`) THEN THE SYSTEM SHALL terminar con error de configuración y exit code de configuración (`invalid_config`/equivalente actual), listando los ecosistemas disponibles, sin construir un adapter sin contrato.
5. IF la entrada es `stdin` y no se pasó `--ecosystem` THEN THE SYSTEM SHALL exigir `--ecosystem` explícito (no hay nombre de archivo del que inferir), con mensaje accionable, sin asumir un ecosistema por defecto silenciosamente.

### Requisito 2: Parseo de manifiestos `package.json`
**Historia de usuario:** Como usuario, quiero que SlopGuard lea los nombres de dependencias declaradas en `package.json`, para evaluarlos sin instalar nada.

**Criterios de aceptación (EARS):**
1. WHEN se parsea un `package.json` válido THE SYSTEM SHALL extraer los **nombres** de las claves de `dependencies` y `devDependencies`, ignorando los **rangos de versión** semver (los *specifiers* no-registry se tratan en R2.7).
2. WHILE parsea THE SYSTEM SHALL chequear `max_manifest_bytes` ANTES de leer el contenido completo y `max_deps` sobre el número de dependencias (mismos límites que PyPI, R1.9 del Hito 1).
3. WHEN el `package.json` no tiene `dependencies` ni `devDependencies`, o están vacíos THE SYSTEM SHALL reportar 0 dependencias y terminar con exit 0 (sin error).
4. IF el `package.json` es JSON malformado, no es un objeto, o `dependencies`/`devDependencies` no son objetos THEN THE SYSTEM SHALL lanzar `ManifestParseError` con la ruta/origen saneado (sin stacktrace crudo ni ruta absoluta), exit operativo.
5. WHEN una misma dependencia aparece en `dependencies` y `devDependencies` THE SYSTEM SHALL deduplicar por **nombre normalizado** (un único `Dependency`).
6. THE SYSTEM SHALL ignorar explícitamente `peerDependencies`, `optionalDependencies`, `bundledDependencies` y el árbol de lockfiles (fuera de alcance), sin fallar por su presencia.
7. WHEN el *specifier* (valor) de una dependencia no es un rango de versión del registry —p. ej. `file:`, `link:`, `workspace:`, `git`/`github:`/`git+…`, o un tarball `http(s)://`— THE SYSTEM SHALL **excluir esa dependencia** del análisis (no consultarla al registry como paquete publicado) y registrarla como *omitida* de forma explícita; THE SYSTEM SHALL evaluar únicamente dependencias con *specifier* de versión del registry (semver o dist-tag).

### Requisito 3: Normalización de nombres npm
**Historia de usuario:** Como motor, quiero normalizar nombres npm de forma determinista, para que las capas comparen manzanas con manzanas y los nombres maliciosos no esquiven el análisis.

**Criterios de aceptación (EARS):**
1. THE SYSTEM SHALL implementar `NpmAdapter.normalize_name` según las reglas de npm: minúsculas, soporte de paquetes *scoped* `@scope/name`, longitud máxima 214, sin colapsar el `/` del scope.
2. WHEN un nombre trae espacios/control/mayúsculas THE SYSTEM SHALL normalizarlo de forma estable e idempotente (`normalize(normalize(x)) == normalize(x)`).
3. IF un nombre es estructuralmente inválido para npm (vacío, empieza por `.`/`_`, excede 214, charset no permitido) THEN THE SYSTEM SHALL marcarlo de forma segura de modo que **nunca** produzca un veredicto CLEAN espurio (igual criterio de defensa en profundidad que PyPI): el nombre inválido no viaja a la red como "consultado limpio".
4. THE SYSTEM SHALL mantener `PypiAdapter.normalize_name` (PEP 503) **sin cambios** (cero regresión).

### Requisito 4: Existencia y metadatos npm (`NpmAdapter.fetch`)
**Historia de usuario:** Como motor, quiero una única consulta que me diga si un paquete npm existe y sus metadatos normalizados, para alimentar las capas de existencia, edad y metadata.

**Criterios de aceptación (EARS):**
1. WHEN `fetch(name)` consulta el registry npm (`registry.npmjs.org`) y la respuesta es 200 THE SYSTEM SHALL retornar `FetchOutcome(FOUND, PackageMetadata)`; WHEN es 404 THE SYSTEM SHALL retornar `FetchOutcome(NOT_FOUND)` sin lanzar; WHEN se agota el reintento transitorio (5xx/429/timeout) THE SYSTEM SHALL retornar `FetchOutcome(UNVERIFIABLE, error_category=network_unverifiable)`.
2. WHEN mapea la respuesta a `PackageMetadata` THE SYSTEM SHALL derivar: `first_release_epoch` ← `time.created`; `releases_count` ← nº de `versions`; `has_repo_url` ← presencia de `repository`; `has_description`/`has_author`/`has_license` ← presencia de esos campos; `has_classifiers` ← presencia de `keywords` (analógico npm) o `False`; `in_top_n` ← pertenencia al dataset top-N npm.
3. THE SYSTEM SHALL solicitar el **packument completo** (`Accept: application/json`) —necesario para `time.created` y los campos de metadata— aplicando el transporte endurecido existente (TLS, allowlist de host, *streaming* ≤ cap, `max_json_depth`, `safe_json` estricto sin `NaN`/`Infinity`) con un **cap de tamaño npm-específico** (mayor que el de PyPI, por el peso de los packuments). IF el packument excede el cap THEN THE SYSTEM SHALL degradar a `UNVERIFIABLE` (fail-safe), nunca CLEAN ni metadata inventada. THE SYSTEM SHALL **NO** usar el documento abreviado (`application/vnd.npm.install-v1+json`) porque omite `time`/`repository`/`description`/`author`/`license`/`keywords` y dejaría inertes las Capas 0/2.
4. IF la respuesta es anómala (no es objeto, `time`/`versions` ausentes o de tipo inesperado) THEN THE SYSTEM SHALL degradar de forma segura (campos faltantes ⇒ flags `False`/`None`, no inventar señales), tratando todo el payload como entrada NO confiable.
5. THE SYSTEM SHALL añadir `registry.npmjs.org` al allowlist de red **solo** a través del `NpmAdapter` (no global), sin que la `ANTHROPIC_API_KEY` ni ningún secreto aparezcan en la ruta del adapter.

### Requisito 5: Dataset top-N npm embebido y verificable
**Historia de usuario:** Como mantenedor, quiero un dataset reproducible de nombres npm legítimos, para que la Capa 1 detecte typosquatting de forma offline y determinista.

**Criterios de aceptación (EARS):**
1. THE SYSTEM SHALL embeber un dataset versionado de los **N≈8.000** paquetes npm más descargados, a partir de un **snapshot público pinneado**, con **procedencia documentada** (script + fuente + fecha) y reproducible.
2. WHEN `NpmAdapter.load_top_n()` carga el dataset THE SYSTEM SHALL verificar su integridad con **SHA-256**; IF falta o el checksum no coincide THEN THE SYSTEM SHALL abortar con `DatasetIntegrityError` (no operar con un corpus corrupto).
3. THE SYSTEM SHALL exponer el dataset como `TopNDataset` con el mismo contrato que PyPI, de modo que la Capa 1 lo consuma sin código por-ecosistema.
4. THE SYSTEM SHALL documentar el procedimiento de regeneración del snapshot (script/fuente/fecha) para auditoría, sin requerir red en tiempo de ejecución/CI.

### Requisito 6: Capa 1 (typosquatting) para npm
**Historia de usuario:** Como usuario, quiero detectar nombres npm tipográficamente cercanos a paquetes populares, para frenar typosquatting.

**Criterios de aceptación (EARS):**
1. WHEN un nombre npm no está en el top-N pero es cercano (Jaro-Winkler/Damerau dentro de umbral) a un nombre del top-N npm THE SYSTEM SHALL emitir la señal de similaridad existente, usando el dataset npm (no el de PyPI).
2. WHILE compara nombres *scoped* THE SYSTEM SHALL aplicar una regla determinista y documentada (definida en diseño) para `@scope/name`, sin falsos positivos triviales por el prefijo del scope.
3. THE SYSTEM SHALL reutilizar los algoritmos de similaridad del core sin duplicarlos (la Capa 1 permanece agnóstica de ecosistema; solo cambia el corpus inyectado por el adapter).

### Requisito 7: Capas 0 y 2 agnósticas operan para npm
**Historia de usuario:** Como motor, quiero que existencia/override de inexistencia (Capa 0) y señales de metadata/edad (Capa 2) funcionen para npm vía el adapter, para no reescribir lógica por ecosistema.

**Criterios de aceptación (EARS):**
1. WHEN un paquete npm no existe (`NOT_FOUND`) THE SYSTEM SHALL aplicar el override de inexistencia con la MISMA semántica de veredicto que en PyPI (sin código específico de npm en la capa).
2. WHEN evalúa edad y metadata THE SYSTEM SHALL usar exclusivamente `PackageMetadata` (agnóstico), produciendo las mismas señales blandas que en PyPI para metadatos equivalentes.

### Requisito 8: Capa 3 (threat-intel/OSV) parametrizada por ecosistema
**Historia de usuario:** Como usuario, quiero que SlopGuard consulte advisories de paquetes npm maliciosos en OSV, para bloquear paquetes confirmados como maliciosos.

**Criterios de aceptación (EARS):**
1. WHEN consulta OSV para deps npm THE SYSTEM SHALL enviar `ecosystem == "npm"` en el cuerpo del `querybatch` (constante, nunca reflejada del usuario), manteniendo `ecosystem == "PyPI"` para deps PyPI.
2. THE SYSTEM SHALL separar la caché de threat-intel por ecosistema (prefijo de clave `npm:` vs `pypi:` bajo el namespace `osv`), de modo que un blob de un ecosistema **no** sea legible como el otro, por construcción.
3. WHILE valida nombres npm antes del POST THE SYSTEM SHALL aplicar un predicado de charset propio de npm (defensa en profundidad, análogo a `_is_valid_osv_name` de PyPI): un nombre que no pase queda UNVERIFIABLE, **nunca** CLEAN, y no viaja a la red.
4. WHEN OSV devuelve un advisory `MAL-*` para un paquete npm THE SYSTEM SHALL marcarlo MALICIOUS con `Advisory` de URL reconstruida (no reflejada), igual que en PyPI (override a block, Hito 2).
5. IF la consulta OSV falla/queda desalineada/paginada THEN THE SYSTEM SHALL degradar a UNVERIFIABLE (jamás CLEAN), preservando la degradación segura del Hito 2.
6. THE SYSTEM SHALL preservar el comportamiento OSV de PyPI **idéntico** (cero regresión): la parametrización por ecosistema no altera la ruta PyPI.

### Requisito 9: Capa 4 (LLM) parametrizada por ecosistema
**Historia de usuario:** Como usuario, quiero el corroborador LLM también para nombres npm en banda gris, manteniendo la garantía de que nunca bloquea.

**Criterios de aceptación (EARS):**
1. WHEN construye el prompt para una dep npm THE SYSTEM SHALL indicar el ecosistema "npm" en el texto (taxonomía/encajonado intactos), y para PyPI SHALL mantener el texto "PyPI".
2. WHEN el texto del prompt cambia THE SYSTEM SHALL **bumpear `PROMPT_VERSION`** (o versionarlo por ecosistema), de modo que la clave de caché L4 (que incluye nombre, ecosistema, hash de contexto, modelo y `prompt_version`) no colisione entre ecosistemas ni reutilice veredictos del prompt viejo.
3. THE SYSTEM SHALL preservar el invariante anti-block del Hito 3 para npm: la señal L4 va en el canal separado acotado (`SOFT_CAP+LLM_SOFT_CAP < umbral_block`, validado por config), nunca produce `block`.
4. WHILE la Capa 4 está activa para npm THE SYSTEM SHALL conservar la degradación segura (`LLM_UNAVAILABLE` no degrada `status`/exit) y el gating de banda gris.
5. THE SYSTEM SHALL preservar el comportamiento L4 de PyPI **idéntico** salvo el `prompt_version` (cero regresión de veredictos PyPI con el mismo modelo/contexto).

### Requisito 10: Salida explicable y CLI con ecosistema
**Historia de usuario:** Como usuario, quiero ver el ecosistema en la salida y que el formato JSON siga siendo estable, para integrarlo en CI.

**Criterios de aceptación (EARS):**
1. WHEN renderiza THE SYSTEM SHALL incluir el ecosistema (`npm`/`pypi`) en la salida humana y JSON (el campo `ecosystem` ya existe en el reporte), saneado.
2. THE SYSTEM SHALL mantener `schema_version` **sin cambios** (1.2) salvo que se añadan campos nuevos de salida; IF se añade algún campo THEN THE SYSTEM SHALL bumpear `schema_version` y documentarlo.
3. WHEN se escanea un manifiesto npm THE SYSTEM SHALL devolver los mismos exit codes que PyPI según el peor veredicto (block⇒fallo, etc.).

### Requisito 11: Cero regresión en PyPI
**Historia de usuario:** Como mantenedor, quiero certeza de que añadir npm no rompe nada de PyPI.

**Criterios de aceptación (EARS):**
1. WHEN se ejecuta `--ecosystem pypi` (o auto-detección de manifiesto Python) THE SYSTEM SHALL comportarse **idéntico** al Hito 3.
2. THE SYSTEM SHALL mantener verdes TODAS las pruebas existentes de los Hitos 1–3 sin modificar su comportamiento esperado.

## Requisitos no-funcionales

### NFR-Determinismo
1. THE SYSTEM SHALL ser determinista: sin reloj de pared en la lógica de decisión; el no-determinismo del LLM queda confinado tras la caché y la salida estructurada (igual que Hito 3); el dataset npm es fijo y verificable.

### NFR-Seguridad
1. THE SYSTEM SHALL ampliar el allowlist de red a `registry.npmjs.org` **solo** vía el `NpmAdapter`, validando el host con el mismo predicado (rechazo de IP/localhost/puerto/userinfo).
2. THE SYSTEM SHALL tratar toda respuesta del registry/OSV/LLM como entrada NO confiable (saneado ANSI/C0-C1/CRLF, `safe_json` estricto, límites de tamaño/profundidad); ningún secreto ni ruta del sistema en logs/JSON/excepciones/caché.
3. THE SYSTEM SHALL separar las cachés por ecosistema (adapter, OSV `osv` con prefijo `npm:`/`pypi:`, y L4 por clave content-addressed que incluye ecosistema), de modo que no haya cruce de veredictos entre ecosistemas por construcción.
4. WHERE un nombre npm es inválido por charset THE SYSTEM SHALL excluirlo de toda consulta de red y nunca emitir CLEAN por él (fail-closed, defensa en profundidad).

### NFR-Arquitectura
1. THE SYSTEM SHALL preservar las fronteras import-linter: `core.layers`/`core.scoring` NO importan `adapters.npm`, `core.net` ni el LLM; el `NpmAdapter` (como `PypiAdapter`) puede usar `core.net`/`core.cache`. SHALL añadir/ajustar los contratos para incluir `adapters.npm` (sin romper los 7 existentes).
2. THE SYSTEM SHALL no introducir dependencias de runtime nuevas (solo stdlib + el transporte HTTPS propio).
3. THE SYSTEM SHALL pasar `mypy --strict`/`mypy` (bare, incl. `tests/`) y `ruff check .` sin errores.

### NFR-Calidad
1. THE SYSTEM SHALL mantener cobertura ≥ 90% global y ≥ 95% en paquetes críticos, con el gate de CI (mypy bare, ruff `.`, pytest `--cov`, lint-imports, CodeQL) **verde**.
2. THE SYSTEM SHALL incluir pruebas de: parser `package.json` (válido/vacío/malformado/dedup), normalización npm (scoped/inválidos/idempotencia), `fetch` (found/not_found/unverifiable/anómalo), integridad del dataset (checksum bueno/corrupto), Capa 1 npm, OSV npm (ecosistema/cache-separación/charset/MAL-/degradación), L4 npm (prompt ecosistema/anti-block/cache), auto-detección y override de `--ecosystem`, y **no-regresión PyPI**.

### NFR-Rendimiento
1. THE SYSTEM SHALL reutilizar la resolución concurrente y los presupuestos de red existentes para npm (sin un camino de concurrencia nuevo).

## Fuera de alcance
- Lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `npm-shrinkwrap.json`) y dependencias **transitivas**.
- Gestores yarn/pnpm; `workspaces`/monorepos.
- Resolución de **rangos de versión** (`^`, `~`, etc.); se escanea el nombre, no la versión resuelta.
- Registries **privados/custom** (`.npmrc`, scopes con registry propio).
- `peerDependencies`/`optionalDependencies`/`bundledDependencies`.
- Otros ecosistemas (Go, Cargo, RubyGems, etc.).
