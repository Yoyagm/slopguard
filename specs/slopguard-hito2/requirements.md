# Documento de Requisitos: SlopGuard (Hito 2 — Capa 3 Threat-Intel)

## Introducción
El Hito 2 añade la **Capa 3 (threat-intel)** sobre el motor determinista del Hito 1: consulta fuentes de inteligencia de amenazas para detectar paquetes **confirmados maliciosos** y, opcionalmente, **nombres alucinados conocidos**, *antes* de instalarlos. La señal primaria es **OSV.dev** (advisories `MAL-*`, licencia permisiva); la watchlist `depscope-hallucinations` es una fuente **opcional** consultada en runtime. Capa 3 reutiliza el transporte HTTPS endurecido, la caché segura, la concurrencia y el `EcosystemAdapter` del Hito 1, manteniendo cero dependencias de runtime, degradación segura y la invariante anti-falsos-positivos.

> Decisiones de producto aprobadas en FASE 0 (Compuerta 0): (1) OSV `MAL-` como señal primaria, depscope opcional online sin redistribuir (respeta CC-BY-NC-SA); (2) `MAL-` ⇒ block por override, vulnerabilidades generales (CVE/GHSA) ignoradas para el veredicto; (3) online + caché + degradación segura; (4) alcance = solo Capa 3.

## Usuarios objetivo
- **Desarrollador con asistentes de IA.** Además de detectar inexistencia/typosquatting (Hito 1), quiere saber en segundos si un paquete sugerido está **confirmado como malicioso** por inteligencia comunitaria, antes de instalarlo.
- **Equipo DevSecOps.** Quiere un gate de supply-chain que incorpore threat-intel online de forma **determinista respecto a caché** y con **degradación segura**: si la fuente no responde, nunca reporta un falso "todo bien", y puede operar en modo "solo deterministas" (Capa 3 desactivable) para entornos sin red o con restricciones de privacidad.

## Modelo de resultado (extensiones al vocabulario del Hito 1)
Capa 3 extiende —sin romper— el modelo del Hito 1:
- **Nuevos `SignalCode`:** `MALICIOUS` (L3, dura, override de block), `KNOWN_HALLUCINATION` (L3, dura), `THREATINTEL_UNVERIFIABLE` (L3, blanda informativa: la fuente no se pudo consultar).
- **Override de malicia:** una señal `MALICIOUS` fuerza `verdict=block` con `score=None`, **fuera de la función de scoring**, igual que la inexistencia (R5.2 del Hito 1). Precedencia: si coexisten inexistencia y malicia, ambas se reportan y el resultado es `block`.
- **`schema_version` del JSON pasa a `1.1`** (campos retro-compatibles; se añaden `signals[]` de L3 y, cuando aplique, `advisories[]` con IDs `MAL-*` y enlaces).
- **`error_category`:** los fallos de transporte hacia OSV/depscope reutilizan `network_unverifiable` (por-dependencia), sin nuevas categorías operacionales totales.

## Requisitos funcionales

### Requisito 1: Capa 3 — detección de paquetes maliciosos vía OSV.dev
**Historia de usuario:** Como desarrollador, quiero saber si un paquete está reportado como malicioso por la comunidad, para bloquear su instalación aunque exista en PyPI y parezca legítimo.
**Criterios de aceptación (EARS):**
1. WHILE `enable_layer3` es verdadero, THE SYSTEM SHALL consultar OSV.dev por cada dependencia **existente** (estado `FOUND` de Capa 0) usando el nombre normalizado (PEP 503) y el ecosistema (`PyPI`), agrupando todas las consultas del escaneo en lotes vía `POST /v1/querybatch`.
2. IF OSV devuelve ≥1 advisory con ID de prefijo `MAL-` para el paquete, THEN THE SYSTEM SHALL emitir señal dura `MALICIOUS`, asignar `verdict=block` por override (independiente del score y de `umbral_block`), y registrar en la salida el/los ID(s) `MAL-*` con su enlace canónico `https://osv.dev/vulnerability/<id>`.
3. WHEN OSV devuelve únicamente advisories de vulnerabilidad general (IDs sin prefijo `MAL-`, p. ej. `GHSA-*`, `CVE-*`, `PYSEC-*`), THE SYSTEM SHALL NOT emitir señal de riesgo de slopsquatting ni alterar el veredicto (las vulnerabilidades generales se ignoran a efectos del veredicto del Hito 2).
4. WHEN OSV devuelve cero advisories para el paquete, THE SYSTEM SHALL considerar la Capa 3 evaluada y limpia para esa dependencia (sin señal L3).
5. WHERE una dependencia tiene estado `NOT_FOUND` (404) o `UNVERIFIABLE` en Capa 0, THE SYSTEM SHALL NOT consultar OSV para ella (no existe paquete real que evaluar; la inexistencia ya domina con su propio override).
6. IF la API de OSV responde con error transitorio (timeout, 5xx o conexión caída) y se agotan los reintentos dentro del presupuesto, THEN THE SYSTEM SHALL emitir señal blanda `THREATINTEL_UNVERIFIABLE` para las dependencias afectadas y degradar de forma segura su estado a `unverifiable` (nunca `allow`), salvo que Capa 0/1/2 ya hayan determinado `block` (que domina).
7. IF la respuesta de OSV es un `4xx ≠ 429` no esperado, o un `429` (rate limit) tras agotar reintentos, THEN THE SYSTEM SHALL tratarlo como anomalía no verificable (`THREATINTEL_UNVERIFIABLE`), nunca como "limpio".
8. WHILE consulta OSV, THE SYSTEM SHALL enviar **exclusivamente el nombre normalizado y el ecosistema** del paquete; SHALL NOT enviar el contenido del manifiesto, rutas locales ni versiones pinneadas sin necesidad (R-Privacidad).

### Requisito 2: Watchlist de alucinaciones conocidas (depscope, opcional)
**Historia de usuario:** Como equipo, quiero (opcionalmente) cotejar los nombres contra un corpus de paquetes alucinados conocidos, para reforzar la detección de slopsquatting.
**Criterios de aceptación (EARS):**
1. WHERE `enable_watchlist` es falso (default), THE SYSTEM SHALL NOT consultar ninguna fuente de watchlist ni añadir host alguno de watchlist al allowlist de red.
2. WHEN `enable_watchlist` es verdadero, THE SYSTEM SHALL obtener el corpus de nombres alucinados desde `watchlist_source` (default `depscope.dev`) en runtime, cacheándolo con su propio TTL, y SHALL NOT redistribuir ni embeber dicho corpus en el paquete (respeto a la licencia CC-BY-NC-SA: solo consulta y atribución).
3. IF un nombre de dependencia normalizado coincide exactamente con una entrada del corpus, THEN THE SYSTEM SHALL emitir señal dura `KNOWN_HALLUCINATION` identificando la fuente y la fecha del corpus.
4. WHEN coexisten `KNOWN_HALLUCINATION` con `NONEXISTENT` (404), THE SYSTEM SHALL dar prioridad al `block` (ambas refuerzan el bloqueo) y reportar ambas señales en la explicación.
5. IF la fuente de watchlist no responde o su carga falla la verificación, THEN THE SYSTEM SHALL emitir `THREATINTEL_UNVERIFIABLE` para la verificación de watchlist y degradar de forma segura, sin invalidar las señales de OSV ni de las capas deterministas.
6. WHILE muestra la atribución, THE SYSTEM SHALL incluir la procedencia y la licencia del corpus de watchlist en la salida (`--format json`) y en la documentación.

### Requisito 3: Scoring, veredicto y precedencia con Capa 3
**Historia de usuario:** Como desarrollador/DevSecOps, quiero que las señales de threat-intel se combinen de forma predecible con las capas deterministas, sin introducir falsos positivos.
**Criterios de aceptación (EARS):**
1. WHEN existe señal `MALICIOUS`, THE SYSTEM SHALL emitir `verdict=block` con `score=None` por override, con **precedencia máxima** sobre cualquier veredicto de Capa 0/1/2.
2. WHEN existe señal `KNOWN_HALLUCINATION` sin `MALICIOUS` ni `NONEXISTENT`, THE SYSTEM SHALL tratarla como señal **dura** que contribuye al score con peso suficiente para producir `block` por sí sola (paquete con nombre alucinado conocido y registrado es de alto riesgo), de forma documentada en el diseño (ADR).
3. THE SYSTEM SHALL preservar la **invariante anti-FP** del Hito 1: las señales blandas (incluida `THREATINTEL_UNVERIFIABLE`) por sí solas NUNCA producen `warn` ni `block`.
4. WHEN una dependencia es `block` por una capa determinista (typosquat) Y además `MALICIOUS`, THE SYSTEM SHALL reportar todas las señales contribuyentes en la explicación, manteniendo `verdict=block`.
5. WHILE evalúa el lote, THE SYSTEM SHALL producir el mismo veredicto para la misma entrada y los mismos datos de threat-intel cacheados (determinismo relativo a caché), con orden de evaluación de capas fijo (0 → 1 → 2 → 3).
6. THE SYSTEM SHALL mantener el orden de evaluación tal que Capa 3 se ejecute **después** de conocer el estado de existencia (Capa 0), para no consultar threat-intel de paquetes inexistentes (R1.5).

### Requisito 4: Exit codes con threat-intel
**Historia de usuario:** Como DevSecOps, quiero exit codes deterministas que incorporen las nuevas señales.
**Criterios de aceptación (EARS):**
1. WHEN hay al menos un `block` (incluido el override `MALICIOUS`), THE SYSTEM SHALL terminar con exit code 2 (señal dominante), manteniendo la precedencia del Hito 1: `block (2) > operacional/unverifiable (3) > warn (1) > allow (0)`.
2. IF hay ≥1 dependencia `unverifiable` por threat-intel degradado (sin ningún `block`), THEN THE SYSTEM SHALL terminar con exit code 3 e incluir el motivo, distinguible de "todo allow".
3. WHERE el usuario activa `--strict`, THE SYSTEM SHALL mantener la semántica del Hito 1 (cualquier `warn` ⇒ fallo), sin que `THREATINTEL_UNVERIFIABLE` (blanda) eleve por sí sola a `warn`.

### Requisito 5: Configuración de Capa 3
**Historia de usuario:** Como equipo, quiero ajustar el comportamiento de threat-intel, para calibrarlo a mi contexto y restricciones.
**Criterios de aceptación (EARS):**
1. WHEN existe configuración (`[tool.slopguard]` o `.slopguard.toml`), THE SYSTEM SHALL cargar todos los parámetros de Capa 3 (ver tabla de defaults) con precedencia CLI > archivo > defaults.
2. IF la configuración de Capa 3 es inválida (tipos/rangos fuera de dominio, host fuera del esquema https), THEN THE SYSTEM SHALL terminar con exit code 3 (`error_category=invalid_config`) sin aplicar valores a medias.
3. WHERE `enable_layer3` es falso, THE SYSTEM SHALL comportarse exactamente como el Hito 1 (solo capas deterministas), sin añadir hosts al allowlist ni emitir señales L3.
4. THE SYSTEM SHALL permitir configurar host, ruta, TTL de caché y timeouts de OSV y de la watchlist de forma independiente.

**Defaults consolidados de Capa 3 (única fuente de verdad):**

| Parámetro | Default | Usado en |
|---|---|---|
| `enable_layer3` | `true` | R1.1, R5.3 |
| `osv_host` | `api.osv.dev` | R1.1, NFR-Seg |
| `osv_query_path` | `/v1/querybatch` | R1.1 |
| `osv_batch_max` | 1000 | R1.1 / NFR-Rend (límite de lote OSV) |
| `osv_ttl_cache_horas` | 6 | R6 |
| `osv_timeout_total_por_lote_s` | 30 | R1.6 |
| `osv_reintentos` | 2 | R1.6 |
| `enable_watchlist` | `false` | R2.1 |
| `watchlist_host` | `depscope.dev` | R2.2 |
| `watchlist_source_path` | `/api/benchmark/hallucinations` | R2.2 |
| `watchlist_ttl_cache_horas` | 24 | R2.2 |
| `watchlist_timeout_total_s` | 30 | R2.5 |
| `threatintel_degraded_status` | `unverifiable` | R1.6 (alternativa documentada: `warn`) |
| `max_response_bytes` (reuso Hito 1) | 10_000_000 | NFR-Seg |
| `max_json_depth` (reuso Hito 1) | 50 | NFR-Seg |

### Requisito 6: Caché y rendimiento de threat-intel
**Historia de usuario:** Como desarrollador, quiero ejecuciones rápidas y repetibles sin martillar OSV/depscope.
**Criterios de aceptación (EARS):**
1. WHEN consulta OSV o la watchlist, THE SYSTEM SHALL cachear las respuestas en disco (reusando `DiskCache` seguro) con TTL `osv_ttl_cache_horas` / `watchlist_ttl_cache_horas` y claves namespaced por fuente.
2. WHEN existe una entrada de caché vigente, THE SYSTEM SHALL usarla sin llamar a la red.
3. WHEN se pasa `--no-cache`, THE SYSTEM SHALL ignorar y no escribir la caché de threat-intel.
4. WHILE consulta OSV en lote, THE SYSTEM SHALL agrupar hasta `osv_batch_max` paquetes por request, deduplicar nombres, y respetar el presupuesto de timeout por lote.
5. IF el número de dependencias excede `osv_batch_max`, THEN THE SYSTEM SHALL dividir en múltiples lotes sin exceder el límite por request.
6. THE SYSTEM SHALL NOT consultar OSV ni la watchlist más de una vez por nombre normalizado en una corrida.
7. WHEN escanea 30 dependencias con caché fría, OSV disponible y Capa 3 activa, THE SYSTEM SHALL completar en ≤ `T_ref_h2` segundos (objetivo 12s) en el hardware de referencia, dominado por la latencia de red simulada/medida (criterio no tautológico, como en Hito 1).

### Requisito 7: Salida explicable con threat-intel
**Historia de usuario:** Como desarrollador, quiero entender por qué un paquete fue marcado malicioso o alucinado, para confiar y actuar.
**Criterios de aceptación (EARS):**
1. WHERE el verdict es `block` por `MALICIOUS`, THE SYSTEM SHALL mostrar en la salida humana el/los ID(s) `MAL-*`, un resumen saneado del advisory y el enlace, además de una acción sugerida ("no instalar; reportado como malicioso").
2. WHERE el verdict involucra `KNOWN_HALLUCINATION`, THE SYSTEM SHALL indicar la fuente del corpus y su licencia/atribución.
3. WHEN se invoca con `--format json`, THE SYSTEM SHALL emitir `schema_version` `1.1`, incluyendo los `signals[]` de L3 y un bloque `advisories[]` (IDs, tipo `malicious`, enlace) cuando aplique, manteniendo orden determinista y claves estables.
4. WHILE muestra IDs, resúmenes o datos externos de OSV/depscope en CUALQUIER salida, THE SYSTEM SHALL neutralizar secuencias ANSI/C0-C1/CRLF (anti inyección de terminal/log/JSON) y SHALL NOT incluir rutas absolutas ni contenido del manifiesto.
5. THE SYSTEM SHALL mantener el orden determinista de resultados del Hito 1 (`unverifiable → block → warn → allow`, luego nombre).

### Requisito 8: Extensibilidad de fuentes de threat-intel
**Historia de usuario:** Como mantenedor, quiero poder añadir o cambiar fuentes de threat-intel sin tocar el motor de capas.
**Criterios de aceptación:**
1. THE SYSTEM SHALL definir una interfaz/abstracción de **fuente de threat-intel** (consulta de malicia por nombre y consulta de watchlist) desacoplada del motor de capas/scoring. *(verificable por análisis estático — import-linter)*
2. WHERE se añade una nueva fuente en el futuro, THE SYSTEM SHALL permitirlo implementando la interfaz sin modificar el motor de capas/scoring.
3. THE SYSTEM SHALL mantener Capa 3 (`core.layers.layer3_*`) sin importar adaptadores concretos de red directamente; la consulta de red vive tras la abstracción de fuente (consistente con la frontera R10 del Hito 1).

## Requisitos no-funcionales

### Seguridad (extiende Hito 1 a los nuevos hosts)
1. WHEN consulta OSV o la watchlist, THE SYSTEM SHALL usar exclusivamente HTTPS con verificación TLS activa (no desactivable), con el host fijado a un **allowlist ampliado** `{pypi.org, api.osv.dev}` y, solo si `enable_watchlist`, `{… , depscope.dev}`; SHALL NOT seguir redirecciones cross-scheme/cross-host (cualquier anomalía ⇒ `unverifiable`).
2. WHEN lee respuestas de OSV/depscope, THE SYSTEM SHALL reusar las defensas del Hito 1: lectura streaming acotada a `max_response_bytes`, profundidad JSON ≤ `max_json_depth`, mitigación de bombas de descompresión y `safe_json` (parseo sin `eval`/deserialización insegura).
3. THE SYSTEM SHALL NOT ejecutar, importar ni evaluar el código de ningún paquete; Capa 3 solo inspecciona metadatos de advisories y nombres. *(verificable por análisis estático)*
4. WHEN construye el cuerpo de la consulta a OSV (POST JSON), THE SYSTEM SHALL incluir solo nombres normalizados y ecosistema, validados/saneados, sin reflejar entrada no confiable cruda.

### Privacidad (ampliación deliberada y controlada)
1. THE SYSTEM SHALL enviar a OSV/depscope **solo nombres de paquete y ecosistema**, NUNCA el manifiesto, su contenido, rutas locales ni identificadores del usuario.
2. THE SYSTEM SHALL permitir desactivar toda Capa 3 (`enable_layer3=false`) para operar en modo "solo deterministas" sin contactar a terceros distintos de PyPI.
3. THE SYSTEM SHALL documentar de forma explícita qué se envía, a qué hosts y bajo qué condiciones (transparencia).

### Degradación segura
1. IF cualquier fuente de threat-intel falla de forma persistente, THEN THE SYSTEM SHALL degradar a `unverifiable` para la porción de threat-intel (nunca un falso "todo bien"), preservando los veredictos deterministas de Capa 0/1/2.

### Determinismo
1. WHEN se le dan la misma entrada y los mismos datos de threat-intel (caché vigente), THE SYSTEM SHALL producir idéntico resultado, con orden de evaluación de capas fijo (0→1→2→3).

### Costo cero y mantenibilidad
1. THE SYSTEM SHALL operar usando exclusivamente APIs públicas gratuitas (OSV.dev; depscope opcional) sin servicios pagos ni claves.
2. THE SYSTEM SHALL mantener **cero dependencias de runtime** (solo stdlib), tipado estricto, funciones ≤50 líneas y docstrings en español, igual que el Hito 1.

### Compatibilidad hacia atrás
1. THE SYSTEM SHALL mantener intactas las capas deterministas, los exit codes y el contrato JSON del Hito 1; los cambios son **aditivos** (`schema_version` 1.0 → 1.1 retro-compatible) y Capa 3 es activable/desactivable sin afectar el comportamiento determinista existente.

## Propiedades estructurales (verificación por análisis estático)
- La abstracción de fuente de threat-intel desacopla Capa 3 de la red concreta (R8.1/R8.3) → import-linter.
- Capa 3 no importa adaptadores concretos de red ni la CLI → import-linter (extiende los contratos del Hito 1).
- Ausencia de `eval`/`exec`/deserialización insegura sobre respuestas de OSV/depscope (NFR-Seg.2) → AST/lint.
- Allowlist de red acotado y verificado por test estático (extiende el guardia del Hito 1 a `{pypi.org, api.osv.dev, depscope.dev?}`).

## Fuera de alcance (Hito 2)
- Capa 4 (superficie de alucinación con LLM, cacheada) → Hito 3.
- Frontends pre-commit y GitHub Action como producto → Hito 4.
- Adaptador npm / multi-ecosistema simultáneo → post-MVP.
- Escaneo/medición de vulnerabilidades generales (CVE/GHSA) como criterio de veredicto.
- **Redistribuir o embeber** un snapshot del corpus depscope (licencia CC-BY-NC-SA): solo consulta online + atribución.
- Cualquier fuente de threat-intel de pago o con clave/API key.
