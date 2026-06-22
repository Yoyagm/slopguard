# Documento de Requisitos: SlopGuard (Hito 1)

## Introducción
SlopGuard es un guardián pre-instalación contra *slopsquatting*: escanea las dependencias Python de un proyecto y detecta paquetes inexistentes, alucinados por LLMs o potencialmente maliciosos **antes** de instalarlos. El Hito 1 entrega el core de scoring extensible, el adapter de PyPI y las capas deterministas 0, 1 y 2, expuestas vía CLI con salida explicable y exit codes para CI. No usa LLMs ni embeddings; solo APIs públicas gratuitas (PyPI JSON) y un dataset embebido.

> Esta versión integra los hallazgos del panel de revisión adversarial (lentes: cobertura, consistencia, testabilidad EARS, seguridad supply-chain). Las decisiones de producto tomadas durante la revisión están listadas en **§ Notas de decisión** y deben confirmarse en la Compuerta 1.

## Usuarios objetivo
- **Desarrollador Python con asistentes de IA.** Copia comandos `pip install` sugeridos por un LLM y necesita verificar, en segundos y sin fricción, que esos paquetes no sean alucinaciones o typosquatting antes de instalarlos.
- **Equipo DevSecOps.** Quiere un gate de supply-chain determinista en pre-commit/CI, con exit codes estables y salida JSON, que falle de forma explícita y nunca dé un falso "todo bien".

## Modelo de resultado (vocabulario común)
Para eliminar ambigüedad entre capas, scoring y exit codes, el sistema usa estos conceptos:
- **score**: entero 0-100 (solo para dependencias *verificables*).
- **verdict**: `allow` | `warn` | `block` (derivado del score o por override).
- **status**: `ok` (verificable, tiene verdict) | `unverifiable` (no se pudo verificar; sin score). El `status` es un campo **separado** del `verdict`.
- **error_category** (cuando aplica): `manifest_parse` | `invalid_config` | `network_unverifiable` | `dataset_integrity`.

## Requisitos funcionales

### Requisito 1: Escaneo y parseo de manifiestos
**Historia de usuario:** Como desarrollador, quiero que SlopGuard lea mis manifiestos y extraiga la lista de dependencias, para analizarlas sin trabajo manual.
**Criterios de aceptación (EARS):**
1. WHEN se invoca `slopguard scan <ruta>` sobre un `requirements.txt` válido, THE SYSTEM SHALL extraer cada dependencia con su nombre normalizado (PEP 503) y su especificador de versión si existe.
2. WHEN el manifiesto es un `pyproject.toml` con `[project].dependencies` y/o `[project.optional-dependencies]`, THE SYSTEM SHALL extraer todas esas dependencias.
3. WHEN la entrada proviene de `pip freeze` (vía archivo o stdin con `-`), THE SYSTEM SHALL parsear el formato `nombre==versión`.
4. WHERE una línea de `requirements.txt` es un comentario, línea en blanco u opción no relevante (`-e`, `--hash`, URL/VCS), THE SYSTEM SHALL ignorarla sin crashear.
5. WHEN una línea es una referencia de inclusión `-r`/`-c <ruta>`, THE SYSTEM SHALL resolverla e incluir sus dependencias **confinando la ruta resuelta al árbol del directorio del proyecto**, detectando ciclos (corte con error) y limitando la profundidad de anidamiento (default 10).
6. IF una referencia `-r`/`-c` apunta a un archivo inexistente o que escapa del árbol del proyecto (ruta absoluta o vía `../`), THEN THE SYSTEM SHALL terminar con exit code 3 (`error_category=manifest_parse`) y mensaje claro, sin leer archivos arbitrarios y sin omitir silenciosamente dependencias.
7. IF el manifiesto está vacío, THEN THE SYSTEM SHALL terminar con exit code 0 e informar "0 dependencias analizadas" (no es error).
8. IF el manifiesto está malformado o no es parseable, THEN THE SYSTEM SHALL terminar con exit code 3 (`error_category=manifest_parse`), con un mensaje que contenga la ruta del archivo y, cuando el parser exponga posición, el número de línea, sin stacktrace crudo.
9. IF el tamaño del manifiesto excede `max_manifest_bytes` o el número de dependencias excede `max_deps`, THEN THE SYSTEM SHALL terminar con exit code 3 (`error_category=manifest_parse`) en vez de cargar la entrada completa.
10. WHILE procesa el manifiesto, THE SYSTEM SHALL deduplicar dependencias repetidas por nombre normalizado.
11. WHEN una dependencia está pinneada a una versión (`==X`), THE SYSTEM SHALL evaluar existencia/edad a nivel de paquete y registrar la versión pinneada en la salida; la ausencia de pin NO altera el veredicto de Capa 0/1.

### Requisito 2: Capa 0 — existencia y edad
**Historia de usuario:** Como desarrollador, quiero saber si un paquete existe en PyPI y cuán reciente es, para detectar nombres alucinados.
**Criterios de aceptación (EARS):**
1. WHEN se evalúa una dependencia, THE SYSTEM SHALL consultar la PyPI JSON API por su existencia usando el nombre normalizado.
2. IF el paquete NO existe en PyPI (404), THEN THE SYSTEM SHALL asignar `verdict=block` por override (ver R5.2), como candidato a alucinación/slopsquatting.
3. WHEN el paquete existe, THE SYSTEM SHALL determinar su edad a partir del `upload_time` de la primera release publicada.
4. IF la edad del paquete es menor que `edad_minima_dias`, THEN THE SYSTEM SHALL emitir una señal blanda de "paquete nuevo" que contribuye al score pero NUNCA bloquea por sí sola.
5. IF la PyPI JSON API responde con error transitorio (timeout, 5xx o conexión caída), THEN THE SYSTEM SHALL reintentar hasta `reintentos_red` veces con backoff exponencial (base 0.5s) respetando `timeout_total_por_dep_s`, y al agotarlos SHALL marcar la dependencia con `status=unverifiable` (degradación segura), nunca `allow`.

### Requisito 3: Capa 1 — similaridad / typosquatting
**Historia de usuario:** Como desarrollador, quiero detectar nombres casi idénticos a paquetes populares, para atrapar typosquatting y confusiones.
**Criterios de aceptación (EARS):**
1. WHEN se evalúa el nombre de una dependencia (longitud entre 4 y `nombre_max_chars`), THE SYSTEM SHALL calcular su similaridad contra el dataset embebido del top-N de PyPI usando Damerau-Levenshtein y Jaro-Winkler.
2. IF el nombre coincide exactamente con una entrada del top-N, THEN THE SYSTEM SHALL no emitir señal de similaridad (legítimo respecto a Capa 1).
3. IF el nombre NO es idéntico pero su distancia Damerau-Levenshtein a una entrada del top-N es ≤ `dl_max` (default 2) **o** su similaridad Jaro-Winkler es ≥ `jw_min` (default 0.92), THEN THE SYSTEM SHALL emitir señal de typosquatting e identificar en la explicación el/los paquete(s) legítimo(s) sospechado(s).
4. WHEN existen múltiples candidatos cercanos, THE SYSTEM SHALL reportar el de mayor similaridad como objetivo probable.
5. WHERE el nombre del paquete tiene longitud ≤ 3 caracteres, THE SYSTEM SHALL no emitir señal de typosquatting (clase de equivalencia para evitar falsos positivos).
6. IF el nombre excede `nombre_max_chars` (default 100), THEN THE SYSTEM SHALL tratarlo como entrada no confiable, NO ejecutar los algoritmos de distancia sobre él, y emitir señal de riesgo (evita coste cuadrático no acotado).
7. WHILE evalúa la Capa 1, THE SYSTEM SHALL operar sin acceso a red (dataset local) y de forma determinista.
8. IF un nombre está en el top-N embebido PERO la Capa 0 reporta que no existe (404), THEN THE SYSTEM SHALL dar prioridad a la Capa 0 (`verdict=block`) y señalar en la explicación un posible dataset desactualizado (la existencia real es autoridad sobre la pertenencia al top-N).
9. IF el dataset top-N embebido está ausente, no es cargable o falla su verificación de integridad, THEN THE SYSTEM SHALL terminar con exit code 3 (`error_category=dataset_integrity`) en vez de marcar dependencias como limpias de Capa 1 en silencio.

### Requisito 4: Capa 2 — señales de metadatos
**Historia de usuario:** Como desarrollador, quiero que se evalúen los metadatos del paquete, para distinguir un paquete real y mantenido de uno sospechoso.
**Criterios de aceptación (EARS):**
1. WHEN el paquete existe, THE SYSTEM SHALL derivar señales de metadatos SOLO de la PyPI JSON API (fuente permitida única en Hito 1).
2. IF el número de releases es ≤ `releases_min` (default 1) Y faltan ≥ `metadata_faltantes_min` (default 2) campos del conjunto cerrado {descripción, autor, licencia, clasificadores}, THEN THE SYSTEM SHALL emitir señal de "metadatos débiles".
3. IF el paquete carece de repositorio enlazado (`project_urls`/`home_page`), THEN THE SYSTEM SHALL emitir una señal de baja verificabilidad.
4. THE SYSTEM SHALL inferir popularidad en Hito 1 mediante proxies deterministas de PyPI JSON (pertenencia al top-N, nº de releases, antigüedad); THE SYSTEM SHALL exponer un hook `downloads` reservado (NO consultado en Hito 1) y SHALL NOT interpretar la ausencia de descargas como señal de riesgo.
5. WHEN el paquete tiene ≥ `releases_populares` releases, repo enlazado y metadatos completos, THE SYSTEM SHALL limitar la contribución de Capa 2 al score a ≤ `c2_max_contrib` puntos (cota observable para no inflar falsos positivos).

### Requisito 5: Scoring y veredicto
**Historia de usuario:** Como desarrollador/DevSecOps, quiero un score 0-100 y un veredicto allow/warn/block que combine todas las señales, para decidir rápido.
**Criterios de aceptación (EARS):**
1. WHEN una dependencia es verificable y todas sus capas han evaluado, THE SYSTEM SHALL combinar sus señales en un único score entero 0-100 mediante una función determinista y documentada.
2. WHEN el paquete NO existe en PyPI, THE SYSTEM SHALL asignar `verdict=block` directamente (override de la función de scoring), independientemente del valor configurable de `umbral_block`.
3. WHEN `score ≥ umbral_block`, THE SYSTEM SHALL emitir `verdict=block`.
4. WHEN `umbral_warn ≤ score < umbral_block`, THE SYSTEM SHALL emitir `verdict=warn`.
5. WHEN `score < umbral_warn`, THE SYSTEM SHALL emitir `verdict=allow`.
6. IF un paquete es nuevo pero por lo demás legítimo (repo enlazado, metadatos completos), THEN THE SYSTEM SHALL combinar las señales de modo que NO resulte en `block` solo por novedad (regla de no-factor-único para señales blandas).
7. WHILE evalúa el lote, THE SYSTEM SHALL producir el mismo score y veredicto para la misma entrada y los mismos datos, independientemente del orden de las dependencias.
8. WHEN una dependencia no se pudo verificar, THE SYSTEM SHALL asignarle `status=unverifiable` (sin score, fuera de la escala 0-100), nunca `verdict=allow`.

### Requisito 6: Salida explicable
**Historia de usuario:** Como desarrollador, quiero entender el PORQUÉ de cada veredicto, para confiar y actuar.
**Criterios de aceptación (EARS):**
1. WHEN presenta resultados, THE SYSTEM SHALL mostrar por cada dependencia: nombre, score (o `unverifiable`), verdict/status y una explicación en lenguaje claro de las señales que contribuyeron.
2. WHERE el verdict es `warn`/`block`, THE SYSTEM SHALL incluir la razón principal y, si aplica, el paquete legítimo sospechado (typosquatting) y una acción sugerida.
3. WHEN se invoca con `--format json`, THE SYSTEM SHALL emitir un JSON estable y versionado (campo `schema_version`) apto para máquinas/CI, con campos `verdict`, `status`, `score`, `signals[]` y `error_category` cuando aplique.
4. THE SYSTEM SHALL ordenar la salida de forma determinista: primero `unverifiable`, luego `block`, luego `warn`, luego `allow`; a igualdad, por nombre normalizado ascendente.
5. WHILE muestra nombres de paquete o datos externos en CUALQUIER salida (TTY, archivos de log y JSON), THE SYSTEM SHALL neutralizar secuencias ANSI (CSI/SGR), controles C0/C1 y CR/LF (anti inyección de terminal/log/JSON), y SHALL NOT incluir rutas absolutas del sistema ni contenido del manifiesto en mensajes de error destinados a CI.

### Requisito 7: Exit codes
**Historia de usuario:** Como DevSecOps, quiero exit codes deterministas, para usar SlopGuard como gate en pre-commit/CI.
**Criterios de aceptación (EARS):**
1. WHEN todas las dependencias resultan `allow` (sin warn, block ni unverifiable), THE SYSTEM SHALL terminar con exit code 0.
2. WHEN hay al menos un `warn`, ningún `block` y ningún `unverifiable`, THE SYSTEM SHALL terminar con exit code 1.
3. WHEN hay al menos un `block`, THE SYSTEM SHALL terminar con exit code 2 (señal dominante).
4. IF ocurre un error operacional total (manifiesto ilegible, config inválida, dataset corrupto) o hay ≥1 dependencia `unverifiable` sin ningún `block`, THEN THE SYSTEM SHALL terminar con exit code 3 e incluir un `error_category` estable, distinguible de "todo allow".
5. THE SYSTEM SHALL aplicar la precedencia de exit codes: `block (2) > operacional/unverifiable (3) > warn (1) > allow (0)`.
6. WHERE el usuario activa `--strict`, THE SYSTEM SHALL tratar cualquier `warn` como fallo a efectos de exit code (warn → exit 2), manteniendo la etiqueta `warn` en la salida.

### Requisito 8: Configuración y umbrales
**Historia de usuario:** Como equipo, quiero ajustar umbrales y comportamiento, para calibrar señal/ruido a mi contexto.
**Criterios de aceptación (EARS):**
1. WHEN existe `[tool.slopguard]` en `pyproject.toml` o un `.slopguard.toml`, THE SYSTEM SHALL cargar todos los parámetros configurables (ver tabla de defaults).
2. WHEN se pasan flags por CLI, THE SYSTEM SHALL darles precedencia sobre el archivo de config, y al archivo sobre los defaults.
3. IF la configuración es inválida (tipos o rangos fuera de dominio), THEN THE SYSTEM SHALL terminar con exit code 3 (`error_category=invalid_config`) y mensaje claro, sin aplicar valores a medias.
4. WHERE no existe ningún archivo de configuración, THE SYSTEM SHALL aplicar los defaults documentados (tabla siguiente) como única fuente de verdad.

**Defaults consolidados (única fuente de verdad):**

| Parámetro | Default | Usado en |
|---|---|---|
| `umbral_block` | 80 | R5.3 |
| `umbral_warn` | 50 | R5.4 / R5.5 |
| `edad_minima_dias` | 90 | R2.4 |
| `ttl_cache_horas` | 24 | R9.1 |
| `concurrencia_max` | 8 | R9.4 |
| `connect_timeout_s` | 5 | R9.4 |
| `read_timeout_s` | 10 | R9.4 |
| `reintentos_red` | 2 | R2.5 |
| `timeout_total_por_dep_s` | 30 | R2.5 |
| `jw_min` (Jaro-Winkler) | 0.92 | R3.3 |
| `dl_max` (Damerau-Levenshtein) | 2 | R3.3 |
| `nombre_max_chars` | 100 | R1.9 / R3.6 |
| `releases_min` | 1 | R4.2 |
| `metadata_faltantes_min` | 2 | R4.2 |
| `releases_populares` | 10 | R4.5 |
| `c2_max_contrib` | 10 | R4.5 |
| `max_manifest_bytes` | 5_000_000 | R1.9 |
| `max_deps` | 5000 | R1.9 |
| `max_response_bytes` | 10_000_000 | NFR-Seguridad |
| `max_json_depth` | 50 | NFR-Seguridad |
| `max_include_depth` | 10 | R1.5 |

### Requisito 9: Caché y rendimiento
**Historia de usuario:** Como desarrollador, quiero ejecuciones rápidas y repetibles sin martillar PyPI.
**Criterios de aceptación (EARS):**
1. WHEN consulta PyPI, THE SYSTEM SHALL cachear las respuestas en disco (`~/.cache/slopguard/`) con TTL `ttl_cache_horas`.
2. WHEN existe una entrada de caché vigente (dentro del TTL), THE SYSTEM SHALL usarla sin llamar a la red.
3. WHEN se pasa `--no-cache`, THE SYSTEM SHALL ignorar la caché y no escribir en ella.
4. WHILE evalúa múltiples dependencias, THE SYSTEM SHALL paralelizar las consultas con `ThreadPoolExecutor` respetando `concurrencia_max`, `connect_timeout_s` y `read_timeout_s`.
5. IF una entrada de caché está corrupta, no es deserializable o está expirada, THEN THE SYSTEM SHALL tratarla como miss (no usarla), refrescar desde PyPI y no crashear.
6. WHILE escribe en la caché bajo concurrencia, THE SYSTEM SHALL usar escritura atómica (archivo temporal + rename) y claves saneadas (anti path traversal).
7. THE SYSTEM SHALL serializar la caché solo como JSON (nunca pickle/marshal), SHALL validar el esquema/tipos de toda entrada al leerla tratándola como entrada no confiable, y SHALL crear el directorio con permisos restrictivos (0700) y los archivos 0600.
8. WHEN escanea 30 dependencias con caché fría y PyPI disponible, THE SYSTEM SHALL completar en ≤ `T_ref` segundos (default objetivo 10s) en el hardware de referencia (Apple Silicon, conexión doméstica).

### Requisito 10: Extensibilidad (adapter de ecosistema)
**Historia de usuario:** Como mantenedor, quiero poder añadir npm más adelante sin tocar el core, para escalar el producto.
**Criterios de aceptación:**
1. THE SYSTEM SHALL definir una interfaz `EcosystemAdapter` que abstraiga existencia, metadatos y fuente del top-N, de modo que el motor de capas/scoring no dependa de PyPI directamente. *(verificable por análisis estático — § Propiedades estructurales)*
2. WHERE se añade un nuevo ecosistema en el futuro, THE SYSTEM SHALL permitirlo implementando el adapter sin modificar el motor de capas/scoring.
3. THE SYSTEM SHALL mantener el core sin dependencias de la CLI; la CLI consume solo la API pública del core. *(verificable por análisis estático)*

## Requisitos no-funcionales

### Rendimiento
1. WHEN escanea 30 dependencias con PyPI disponible y caché fría, THE SYSTEM SHALL completar en ≤ `T_ref` segundos en el hardware de referencia (criterio único; ver R9.8).
2. WHILE consulta la red, THE SYSTEM SHALL paralelizar y no consultar el mismo paquete dos veces en una corrida.

### Seguridad
1. THE SYSTEM SHALL NOT ejecutar, importar ni evaluar el código de ningún paquete analizado; solo inspecciona metadatos. *(verificable por análisis estático)*
2. THE SYSTEM SHALL NOT usar `eval`/`exec` ni deserialización insegura (pickle/marshal) sobre datos externos. *(verificable por análisis estático)*
3. WHEN consulta PyPI, THE SYSTEM SHALL usar exclusivamente HTTPS con verificación de certificado activa (sin opción para desactivar TLS), SHALL fijar el host a un allowlist y SHALL NOT seguir redirecciones a esquemas distintos de https ni a hosts fuera del allowlist; cualquier redirección anómala se trata como fallo → `status=unverifiable`.
4. WHEN lee respuestas de PyPI, THE SYSTEM SHALL acotar el cuerpo a `max_response_bytes` leyendo de forma streaming y abortando si se excede, SHALL rechazar `Content-Length` excesivo, SHALL limitar la profundidad de anidamiento JSON a `max_json_depth`, y SHALL mitigar bombas de descompresión (gzip/zip), marcando la dependencia como `unverifiable` en vez de cargar el payload completo.
5. WHEN procesa nombres o respuestas externas, THE SYSTEM SHALL validar/sanitizar la entrada, acotar la longitud del nombre antes de algoritmos de distancia (R3.6) y manejar lo malformado sin crashear ni filtrar stacktraces.
6. WHILE accede a la caché de disco, THE SYSTEM SHALL sanear las claves (anti path traversal) y validar las entradas al leerlas (R9.6, R9.7).
7. THE SYSTEM SHALL versionar el dataset top-N embebido, registrar su procedencia y fecha de generación, y verificar su integridad al cargarlo (checksum embebido), abortando con error claro si está ausente o corrupto (R3.9).

### Privacidad
1. THE SYSTEM SHALL NOT enviar el manifiesto ni su contenido a terceros; las capas 0-2 solo consultan PyPI por nombre de paquete.
2. THE SYSTEM SHALL NOT usar ningún LLM ni servicio de terceros distinto de la PyPI JSON API en el Hito 1.

### Degradación segura
1. IF PyPI no responde o falla de forma persistente, THEN THE SYSTEM SHALL fallar de forma explícita (`status=unverifiable` / exit 3) y NUNCA reportar un falso "todo bien".

### Costo cero de infraestructura
1. THE SYSTEM SHALL operar usando exclusivamente la PyPI JSON API (gratuita) y el dataset embebido, sin servicios pagos.

### Determinismo
1. WHEN se le dan la misma entrada y los mismos datos, THE SYSTEM SHALL producir idéntico resultado, con orden de evaluación de capas fijo.

### Mantenibilidad y stack
1. THE SYSTEM SHALL ejecutarse en Python 3.11+, con tipado estricto, funciones ≤50 líneas y docstrings en español. *(verificable por lint/mypy)*
2. THE SYSTEM SHALL mantener cero dependencias de runtime en las capas 0-2 (solo stdlib), reduciendo su propia superficie de supply-chain.

## Propiedades estructurales (verificación por análisis estático, no por test de comportamiento)
- `EcosystemAdapter` desacopla el core de PyPI (R10.1) → verificable con import-linter.
- Core sin dependencias de la CLI (R10.3) → import-linter.
- Ausencia de `eval`/`exec`/deserialización insegura (NFR-Seguridad.1-2) → chequeo AST / regla de lint.
- Funciones ≤50 líneas y tipado estricto (NFR-Mantenibilidad.1) → lint + mypy strict.
- Integridad/versionado del dataset top-N (NFR-Seguridad.7) → test de checksum al cargar.

## Notas de decisión (de la revisión adversarial — confirmar en Compuerta 1)
1. **Referencias `-r`/`-c`:** se **resuelven**, confinadas al árbol del proyecto, con detección de ciclos y profundidad máx. (R1.5). Alternativa descartada: tratarlas como "no soportadas" (riesgo de escanear nada → falso "todo bien").
2. **Precedencia de exit codes:** `block (2) > operacional/unverifiable (3) > warn (1) > allow (0)` (R7.5). Un `block` confirmado domina sobre una verificación incompleta; los `unverifiable` siempre se reportan en la salida.
3. **`--strict`:** eleva cualquier `warn` a fallo `exit 2` (R7.6).
4. **Override de inexistencia:** "no existe" fuerza `verdict=block` fuera de la función de scoring, independiente de `umbral_block` (R5.2).
5. **Descargas:** omitidas en Hito 1; popularidad por proxies; ausencia de descargas NO es señal de riesgo (R4.4).

## Fuera de alcance
- Análisis dinámico o ejecución/sandbox del código de los paquetes (nunca en el MVP).
- Capa 3 (threat-intel: watchlist `depscope-hallucinations` + OSV.dev) → Hito 2.
- Capa 4 (superficie de alucinación con LLM, cacheada) y evaluación precision/recall formal → Hito 3.
- Frontends pre-commit y GitHub Action → Hito 4.
- Soporte simultáneo multi-ecosistema; npm es post-MVP vía el adapter.
- Embeddings o modelos ML en cualquier capa de este hito.
- Consulta de número real de descargas (pypistats/BigQuery); solo se reserva el hook en el adapter.
