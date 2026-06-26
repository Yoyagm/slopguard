# Changelog

Todos los cambios notables de SlopGuard se documentan aquí.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el versionado [Semantic Versioning](https://semver.org/lang/es/).

## [Unreleased]

## [0.4.0] - 2026-06-25

Cuarto hito (**Hito 4**): **adaptador npm**. SlopGuard analiza ahora `package.json` con
paridad funcional respecto a PyPI (las cuatro capas, los exit codes y el scoring se
comportan igual). El motor de capas/scoring permanece **agnóstico de ecosistema**: toda la
divergencia npm↔PyPI vive en el adaptador o tras tablas cerradas de ecosistema (cero
ramificación `if ecosystem == "npm"` en `core.layers`/`core.scoring`).

### Añadido

- **Ecosistema npm**: flag `--ecosystem {pypi,npm}` (override) y autodetección por manifiesto
  (`package.json`→npm; `requirements*.txt`/`pyproject.toml`→pypi). Por stdin `--ecosystem` es
  obligatorio (R1.5).
- **Parser `package.json`** (Forma A): `dependencies`+`devDependencies`, normalización de
  paquetes **scoped** (`@scope/name`, preserva `/`, sin colapso PEP 503), y exclusión de
  specifiers no-registro (`file:`/`link:`/`workspace:`/`git+`/`github:`/tarballs http(s), R2.7).
- **`NpmAdapter`**: allowlist `registry.npmjs.org` solo por instancia (nunca global), URL
  anti path-traversal (`quote(name, safe="")`), cap de respuesta → UNVERIFIABLE, charset
  fail-closed de un único núcleo, dataset npm top-8k embebido + verificado con SHA-256.
- **Salida JSON**: el campo raíz `ecosystem` (presente desde `schema_version` 1.0, hasta ahora
  siempre `"pypi"`) toma ahora también el valor `"npm"`. **`schema_version` permanece `1.2`**
  (introducido en el Hito 3 para `llm_assessment`): el Hito 4 no altera el esquema, solo el
  dominio de valores de un campo ya existente.
- **Threat-intel y Capa 4 por ecosistema**: OSV y watchlist aislados por **clave de caché Y
  validador de blob** (un escaneo npm jamás reutiliza un blob pypi del mismo nombre, y
  viceversa); `prompt_version` del LLM sube a `h4-v1`.
- **Docs**: [runbook de regeneración del dataset npm](docs/runbook-dataset-npm.md) (R5.4) y
  [ADR-0001](docs/adr/0001-texto-ecosistema-en-detail-capas-0-2.md).
- **CI**: el gate de cobertura crítica (≥95%) incluye ahora `core/adapters/npm.py` (100%) y
  `core/manifests/package_json.py` (98%).

### Sin cambios para PyPI (R11)

Cero regresión: el flujo PyPI es idéntico al Hito 3. El único cambio heredado es el sello
`prompt_version` (`h3-v1`→`h4-v1`), que afecta solo la clave de caché LLM y la línea de
transparencia, nunca el veredicto/score/exit code.

### Seguridad

- **Rechazo de constantes JSON no finitas en TODO fetch de registro/threat-intel**
  (H4-T40, revisión de seguridad Ola 6). `_parse_json_object` (chokepoint de `get_json`/
  `post_json`) ahora parsea con `reject_nonfinite=True`, de modo que `NaN`/`Infinity`/
  `-Infinity` en una respuesta de PyPI, npm u OSV se rechazan y degradan a UNVERIFIABLE
  (fail-closed), cumpliendo el contrato de diseño (design L510 «safe_json estricto, sin
  NaN/Infinity»). Antes solo la ruta LLM los rechazaba; el fetch los aceptaba (un futuro
  campo numérico podía provocar fail-open: `NaN<0` y `NaN>1` son ambos False). El test del
  fetch npm que «cubría» esto llamaba a `safe_json_loads` aislado (cobertura falsa-positiva);
  se reemplazó por uno integrado que ejercita el transporte real.

### Deuda técnica conocida (Known issues)

- **Texto "PyPI" en el `detail` de las señales L0/L2 para dependencias npm**
  (decisión H4-T46, vía (a); ver `docs/adr/0001-texto-ecosistema-en-detail-capas-0-2.md`).
  Las señales `NONEXISTENT` (`core/layers/layer0_existence.py`) y `LOW_VERIFIABILITY`
  (`core/layers/layer2_metadata.py`) construyen su explicación con el literal "PyPI" dentro de
  la **capa pura**; los renders solo sanean ese texto, no lo recomponen. Para una dependencia
  **npm**, el texto humano y `signals[].detail` del JSON dirán "PyPI" (defecto **cosmético**).
  El campo **estructural** `ecosystem` del reporte (JSON y cabecera) es **correcto** (`"npm"`),
  por lo que R10.1 se cumple donde importa para integración/CI. Se acepta como deuda y **no** se
  parametriza el texto por-ecosistema en la capa pura para no violar el principio rector
  ("ningún texto/lógica por-ecosistema en `core.layers`/`core.scoring`"). Pago futuro: que el
  ecosistema viaje como dato agnóstico en `FetchOutcome`/contexto (vía (b1) del ADR), en una
  tarea aparte.

## [0.3.0] - 2026-06-24

Tercer hito (**Hito 3**): **Capa 4 — superficie de alucinación con LLM**. Un evaluador LLM
(Claude `claude-opus-4-8`) clasifica nombres en *banda gris* (existen pero jóvenes o de baja
señal, sin señal dura) contra la taxonomía conflación/typo/fabricación, como **corroborador
opt-in**. La señal va en un **canal de peso separado** que puede a lo sumo elevar a `warn`,
**nunca a `block`** (garantizado por construcción). Cambios **estrictamente aditivos**; con
`--no-layer4` (default) el comportamiento es idéntico al Hito 2.

### Added

- **Capa 4 — LLM:** evaluador HTTPS crudo (cero deps de runtime) sobre
  `api.anthropic.com /v1/messages` con salida estructurada (`output_config.format`);
  *gating* de banda gris (rama "joven" `< gray_edad_max_dias` **o** señal blanda, sin señal
  dura); señales `LLM_HALLUCINATION_SURFACE` (canal separado) y `LLM_UNAVAILABLE` (abstención).
- **Opt-in:** flags `--enable-layer4` / `--no-layer4` / `--llm-model`; requiere
  `ANTHROPIC_API_KEY`. Sin clave o sin la flag, comportamiento idéntico al Hito 2.
- **Caché L4** content-addressed (`(nombre, ecosistema, contexto, modelo, prompt_version)`),
  sello `llm-1` separado de threat-intel; los aciertos no cuentan contra el presupuesto de red.
- **Salida:** `schema_version` 1.2 — bloque estable `llm_assessment`, `is_llm_channel` en
  señales y `summary.llm_unavailable`. El render humano marca el texto del LLM como *advisory,
  NO verificado* y emite un aviso agregado de indisponibilidad sin fingir "todo limpio".
- **Evaluación:** harness `eval/run_eval.py` precision/recall **pre-registrado**
  (`eval/PREREGISTRO.md`), reproducible offline, con métricas por nivel de veredicto y ablación.

### Security

- La señal L4 **nunca bloquea**: canal acotado a `LLM_SOFT_CAP=50` con `SOFT_CAP(25) +
  LLM_SOFT_CAP(50) = 75 < umbral_block(80)` y `max_hard=0` garantizado por el gating; verificado
  por test de propiedad y **7 contratos import-linter** (frontera ADR-17). **Además validado por
  configuración (R5.2):** `_validate_anti_block` aborta *fail-closed* (exit 3) cualquier config con
  `SOFT_CAP + LLM_SOFT_CAP ≥ umbral_block` o `LLM_SOFT_CAP < umbral_warn`, cerrando el bloqueo por
  L4 que era posible con `--umbral-block ≤ 75`. Los topes viven en `core.models` (hoja, fuente única).
- `ANTHROPIC_API_KEY` solo de entorno; jamás en logs, JSON, excepciones (incl. cadena
  `__cause__`) ni en la caché. Texto del LLM tratado como entrada no confiable: **saneado y
  truncado en la frontera de salida** (`sanitize_and_truncate`, R7.3/ADR-19) como defensa en
  profundidad —incluso para blobs de caché rehidratados, sin asumir que una capa previa truncó—;
  nombre encajonado en el prompt (anti prompt-injection de 1.er/2.º orden).
- `safe_json` endurecido rechaza `NaN`/`Infinity` en la salida estructurada del LLM.

### Changed

- `schema_version` del JSON `1.1` → `1.2` (aditivo, retro-compatible: ninguna clave previa se
  quita ni renombra).

## [0.2.0] - 2026-06-23

Segundo hito (**Hito 2**): Capa 3 de *threat-intel* online sobre el motor determinista
del Hito 1. Detecta paquetes confirmados maliciosos via OSV.dev y, opcionalmente,
nombres alucinados conocidos via depscope. Cambios **estrictamente aditivos**;
capas deterministas y contratos del Hito 1 intactos.

### Added

- **Capa 3 — threat-intel:** consulta [OSV.dev](https://osv.dev) `POST /v1/querybatch`
  por lotes para detectar paquetes con advisories `MAL-*` (malicia confirmada). Solo se
  consultan paquetes que existen en PyPI (`FOUND`); los inexistentes no requieren red.
- **Senial `MALICIOUS`** (dura, override de block): un advisory `MAL-*` fuerza
  `verdict=block` con `score=null`, con precedencia maxima sobre cualquier veredicto de
  las capas 0-2. Ejemplo verificado en vivo: `bioql` => `MAL-2025-47868` => block.
- **Senial `KNOWN_HALLUCINATION`** (dura, peso 85): match exacto contra el corpus de
  alucinaciones depscope produce `block` por score (`>= umbral_block`), respetando la
  invariante anti-FP (es una senial dura, no blanda).
- **Senial `THREATINTEL_UNVERIFIABLE`** (blanda, peso 0): emitida cuando OSV o depscope
  no responden; nunca produce `warn` ni `block` por si sola (invariante anti-FP intacta).
- **Watchlist depscope (opt-in):** activable con `--enable-watchlist` o
  `enable_watchlist=true`. Obtiene el corpus en runtime con cache TTL 24h. No redistribuye
  ni embebe el corpus (respeto a CC-BY-NC-SA). La atribucion y la licencia del corpus
  se incluyen en la salida JSON.
- **Flag `--no-layer3`:** desactiva completamente la Capa 3. El sistema se comporta
  identico al Hito 1 (solo capas deterministas; `api.osv.dev` no se anade al allowlist).
- **Flag `--enable-watchlist`:** activa la consulta opcional a depscope.dev.
- **JSON `schema_version` 1.1** (retrocompatible): se anade el campo `advisories[]`
  (siempre presente, vacio si sin malicia) con `{id, kind, url, source}` para cada
  advisory `MAL-*`. Las seniales de `layer:3` se incluyen en `signals[]`. Ningun campo
  de 1.0 se modifica ni elimina.
- **14 nuevos parametros de configuracion** de Capa 3 en `[tool.slopguard]` /
  `.slopguard.toml` (ver tabla de defaults en README): `enable_layer3`, `osv_host`,
  `osv_ttl_cache_horas`, `osv_timeout_total_por_lote_s`, `osv_reintentos`,
  `osv_batch_max`, `enable_watchlist`, `watchlist_host`, `watchlist_ttl_cache_horas`,
  `watchlist_timeout_total_s`, `threatintel_degraded_status`, mas reuso de
  `max_response_bytes` y `max_json_depth`.
- **Cache de threat-intel** namespaced: `get_blob`/`put_blob` JSON-only sobre
  `DiskCache`, con `cache_schema_version="ti-1"`, clave `sha256("osv:pypi:{name}")` /
  `sha256("watchlist:{host}{path}")`. El estado `UNVERIFIABLE` nunca se cachea.
- **Interfaz `ThreatIntelSource` (Protocol):** abstraccion desacoplada de la red;
  `CompositeSource` fan-out a `OsvSource` + `WatchlistSource` (si activa).
  `resolve_threatintel` gestiona chunking (<= `osv_batch_max`), dedup global y
  degradacion segura de lote.
- **3 contratos nuevos de import-linter** (5 en total): capas/scoring ✗-> threatintel+net;
  source ✗-> net; layer3 ✗-> impls concretas. Los 2 contratos del Hito 1 se mantienen.
- **1547 pruebas** (928 nuevas sobre las 619 del Hito 1): unitarias, tabla de precedencias,
  propiedad anti-FP, red con servidor local malicioso, e2e con OSV simulado.

### Security

- **Fail-closed:** si OSV o depscope no responden tras reintentos, la dependencia pasa a
  `unverifiable` (exit 3), nunca a `allow`. Un `block` de capas deterministas domina sobre
  cualquier fallo de threat-intel.
- **Allowlist ampliado con guardia:** `ALLOWED_HOSTS = {pypi.org}` permanece como
  constante base verificada estaticamente; `api.osv.dev` y (si watchlist activa)
  `depscope.dev` se anaden por-instancia mediante `extra_allowed_hosts`. El redirect
  handler valida contra el conjunto efectivo de la instancia (fix SSRF: previene
  redirecciones de `api.osv.dev` hacia hosts arbitrarios o hacia `pypi.org`).
- **Anti-envenenamiento de feed OSV:** IDs de advisory validados con
  `^MAL-[0-9A-Za-z-]+$`; nombres validados por charset antes del POST; URL de advisory
  reconstruida desde el ID validado (nunca reflejada del payload crudo).
- **Anti-envenenamiento de corpus watchlist:** charset `^[a-z0-9-]+$` + cap de tamano
  (`_WATCHLIST_MAX_NAMES`) verificados tanto al parsear la respuesta como al leer la
  cache; corpus inflado o con charset invalido => miss (refetch), no truncamiento silencioso.
- **`429` (rate limit) clasificado como transitorio:** se reintenta con backoff (igual que
  5xx); agotados los reintentos => `UNVERIFIABLE`, nunca `CLEAN`.
- **Privacidad por disenio (NFR-Priv.3):** solo nombre normalizado + ecosistema se envian
  a OSV/depscope; nunca el manifiesto, rutas locales ni identificadores del usuario.
  Completamente desactivable con `--no-layer3`.

### Notes

- **1547 pruebas**; cobertura **96.23% global / 99% en paquetes criticos**
  (incluye `core/threatintel`).
- CI: mypy `--strict` (82 archivos), ruff (incl. reglas bandit), import-linter
  (5 contratos), guardia estatico de allowlist + anti-envenenamiento, compilacion LaTeX.

## [0.1.0] - 2026-06-22

Primer hito (**Hito 1**): núcleo determinista de detección de *slopsquatting*
para dependencias Python, sin LLMs y usando solo la PyPI JSON API.

### Added
- CLI `slopguard scan <ruta|->` y `slopguard version`; lectura desde `stdin` (`pip freeze`).
- **Capa 0** — existencia y edad del paquete vía PyPI JSON API (inexistencia → `block` por override).
- **Capa 1** — *typosquatting* por Damerau-Levenshtein + Jaro-Winkler contra el top-10k de PyPI embebido; sin red y determinista.
- **Capa 2** — señales de metadatos (releases, repo enlazado, completitud) con aporte acotado.
- Scoring determinista 0-100 → veredicto `allow`/`warn`/`block`, con invariante anti-falsos-positivos (señales blandas acotadas por debajo del umbral de `warn`).
- Parseo de `requirements.txt`, `pyproject.toml` y `pip freeze`; `-r`/`-c` resueltos confinados al árbol del proyecto (detección de ciclos y profundidad máxima).
- Salida humana explicable y JSON versionado (`schema_version` 1.0); exit codes estables (`0` allow / `1` warn / `2` block / `3` operacional·unverifiable) y `--strict`.
- Caché en disco atómica y segura (TTL, JSON-only, permisos `0700`/`0600`, clave por hash).
- Configuración vía `[tool.slopguard]` en `pyproject.toml` o `.slopguard.toml` y flags CLI (precedencia CLI > archivo > defaults) con validación de rangos.
- Dataset top-10k de PyPI con procedencia documentada, verificación de integridad SHA-256 y script de generación reproducible.

### Security
- HTTPS con verificación TLS **no desactivable** y *allowlist* de host (`pypi.org`); rechazo de redirecciones cross-host/cross-scheme.
- Defensas anti JSON-bomb, anti gzip-bomb y `Content-Length` excesivo (lectura *streaming* acotada con descompresión incremental).
- **No** se ejecuta ni importa el código de ningún paquete analizado; sin `eval`/`exec`/`pickle`/`marshal` (verificado por análisis estático AST con guardias anti-vacuos).
- **Cero dependencias de runtime** (solo stdlib): superficie de *supply-chain* mínima.
- Saneo anti-inyección de terminal (ANSI/C0-C1/CRLF) en toda salida; sin fuga de rutas absolutas ni del contenido del manifiesto en errores.
- Degradación segura: ante fallo de red persistente se reporta `unverifiable` (nunca un falso "todo bien").

### Notes
- **619 pruebas**; cobertura **95.3% global / 99% en paquetes críticos**.
- CI: mypy `--strict`, ruff (incl. reglas bandit), import-linter (frontera capas/scoring ↛ red) y compilación del documento técnico LaTeX a PDF.

[Unreleased]: https://github.com/Yoyagm/slopguard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Yoyagm/slopguard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Yoyagm/slopguard/releases/tag/v0.1.0
