# Documento de Requisitos: SlopGuard (Hito 3 — Capa 4 Superficie de Alucinación con LLM)

## Introducción
El Hito 3 añade la **Capa 4 (superficie de alucinación con LLM)** sobre el motor del Hito 1 (deterministas) y la Capa 3 threat-intel del Hito 2. Capa 4 usa un LLM (Claude `claude-opus-4-8` por defecto) **como corroborador, con *gating***: solo se invoca para paquetes en la **banda gris** (existen, no están bloqueados, **no tienen ninguna señal dura** y resultan sospechosos por juventud o señales blandas), clasificando el *nombre* contra la taxonomía de la investigación de slopsquatting —`legitimo | conflacion | typo | fabricacion`— a partir del **contexto determinista ya computado**. La señal resultante puede a lo sumo producir `warn` (advisory), **nunca `block`**, garantizado por construcción. El transporte reutiliza el HTTPS endurecido del Hito 1 (cero dependencias de runtime). La capa es **opt-in** (`--enable-layer4` + `ANTHROPIC_API_KEY`) con **degradación segura** (abstención de peso 0). El Hito 3 entrega además una **evaluación formal precision/recall** con ablación, pre-registrada.

> **Umbrales reales del motor (única fuente de verdad, de `config.py`):** `umbral_warn = 50`, `umbral_block = 80`, `SOFT_CAP = 25`. El scorer real es `score = min(100, max_hard + min(soft_heuristico_total, SOFT_CAP))`, donde `max_hard` toma el **máximo** de las señales duras y `soft_heuristico_total` **suma** las blandas (capadas a 25). Toda la aritmética de este documento está anclada a estos valores.

> Decisiones de producto aprobadas en FASE 0 (Compuerta 0): (1) **Soft + gating**: el LLM evalúa solo la banda gris, emite señal acotada, nunca bloquea; (2) **HTTPS crudo (cero-dep)**: reusa `SecureHttpClient`, añade `api.anthropic.com` al allowlist; modelo por defecto `claude-opus-4-8`; (3) **Opt-in / OFF** por defecto, solo `nombre+ecosistema+contexto`, nunca el manifiesto; degradación segura; (4) **Benchmark + ablación** precision/recall como entregable científico. Alcance = Capa 4 + evaluación; frontends → Hito 4.

## Usuarios objetivo
- **Desarrollador con asistentes de IA.** Además de inexistencia/typosquat (H1) y malicia confirmada (H2), quiere una señal sobre nombres que *no* son typo de un paquete popular ni están en una watchlist, pero que **"huelen a confabulación de LLM"** (fabricaciones plausibles, conflaciones) — el blanco preferido del slopsquatting que las capas deterministas no ven. Quiere un *aviso*, no un bloqueo opaco.
- **Equipo DevSecOps.** Quiere activar opcionalmente una capa de juicio LLM **determinista respecto a caché**, **acotada en costo** (gating + caché + tope de llamadas) y con **degradación segura**: si no hay clave/red, o el modelo se abstiene, el veredicto determinista permanece intacto y el exit code no se degrada, pero la indisponibilidad se **reporta visiblemente** (no es un falso "todo limpio").

## Modelo de resultado (extensiones aditivas al vocabulario del Hito 1/2)
Capa 4 extiende —sin romper— el modelo existente. **Precondición de implementación:** estos enums/modelos deben añadirse en `core.models` (hoja) **antes** de cualquier emisión L4.
- **Nuevo `Layer`:** `L4 = 4`.
- **Nuevos `SignalCode`:** `LLM_HALLUCINATION_SURFACE` (L4, **canal de peso L4 separado**, escalada por confianza, acotada por `LLM_SOFT_CAP`); `LLM_UNAVAILABLE` (L4, informativa, `weight=0`: el LLM no se pudo consultar / se abstuvo).
- **Nuevo modelo de transporte `LlmAssessment`** (en `core.models`, hoja, `frozen+slots`): `clasificacion: Clasificacion` (StrEnum: `legitimo|conflacion|typo|fabricacion`), `confianza: float`, `patron: str` (saneado+truncado), `rationale: str` (saneado+truncado), `modelo: str`, `prompt_version: str`. Nunca contiene prosa cruda ni el prompt.
- **Término `score_base` (= `score_pre_L4`):** el score calculado **solo** con señales de capas 0–3. El *gating* (R1) opera sobre `score_base` y el `verdict_pre_L4` derivado; el score final reportado (R7) sí incluye el aporte L4. Esto rompe la circularidad.
- **Canal de peso L4 separado:** el aporte de `LLM_HALLUCINATION_SURFACE` **NO** entra en el `SOFT_CAP` heurístico; el scorer se extiende a `score = min(100, max_hard + min(soft_heuristico, SOFT_CAP) + min(soft_llm, LLM_SOFT_CAP))`. Como el *gating* garantiza `max_hard = 0` para toda dependencia elegible (R1.2), el score máximo con L4 es `0 + 25 + 50 = 75 < umbral_block(80)`: **L4 nunca puede bloquear**, demostrable por construcción y verificado por test de propiedad + validación de config.
- **`schema_version` del JSON pasa a `1.2`** (aditivo retro-compatible: `signals[]` de L4 y bloque `llm_assessment` cuando aplique).
- **Distinción clave vs Capa 3:** la indisponibilidad del LLM (`LLM_UNAVAILABLE`) **NO** degrada el `status` a `unverifiable` ni eleva el exit code (Capa 4 es corroborador opcional; su ausencia no abre hueco de *block*). A diferencia de `THREATINTEL_UNVERIFIABLE` (H2), que sí degradaba porque la Capa 3 podía *bloquear*. **Pero** la indisponibilidad se reporta de forma agregada y visible (R4.6/R7.6) para no fingir "todo limpio".

## Requisitos funcionales

### Requisito 1: Capa 4 — *gating* (cuándo se invoca el LLM)
**Historia de usuario:** Como equipo, quiero que el LLM se invoque solo cuando aporta valor, para acotar costo, latencia y falsos positivos.
**Criterios de aceptación (EARS):**
1. WHILE `enable_layer4` es verdadero y existe `ANTHROPIC_API_KEY`, THE SYSTEM SHALL evaluar el *predicado de banda gris* por cada dependencia tras computar `score_base`/`verdict_pre_L4` (capas 0–3), e invocar al LLM **solo** si el predicado se cumple.
2. THE SYSTEM SHALL definir **banda gris** como la conjunción de: (i) la dependencia **existe** (`status == OK` y sin señal `NONEXISTENT`); (ii) `verdict_pre_L4 != BLOCK`; (iii) **no hay ninguna señal dura** (`is_soft == False`: descarta `TYPOSQUAT`, `NAME_UNTRUSTED`, `MALICIOUS`, `KNOWN_HALLUCINATION`), garantizando `max_hard == 0`; (iv) **al menos un disparador de sospecha**: edad del paquete `< gray_edad_max_dias` (joven) **O** ≥1 señal blanda (`NEW_PACKAGE`/`WEAK_METADATA`/`LOW_VERIFIABILITY`).
3. WHERE una dependencia tiene `verdict_pre_L4 == BLOCK` o cualquier señal dura, THE SYSTEM SHALL NOT invocar al LLM (el veredicto ya está decidido; además se preserva el invariante anti-block por `max_hard == 0`).
4. WHERE una dependencia es **claramente legítima** —definida como la **negación exacta** del predicado de banda gris: existe, no bloqueada, sin señal dura, edad `>= gray_edad_max_dias` **y** sin ninguna señal blanda—, THE SYSTEM SHALL NOT invocar al LLM. (No hay zona muerta ni solape: banda-gris y claramente-legítima particionan el espacio de dependencias existentes no-bloqueadas-y-sin-dura.)
5. THE SYSTEM SHALL NOT invocar al LLM más de una vez por nombre normalizado en una corrida. THE SYSTEM SHALL respetar un tope global `llm_max_calls_por_corrida` de **llamadas de red** (los aciertos de caché **no** cuentan, R6.2); al alcanzarlo, las dependencias de banda gris **restantes en orden canónico (nombre normalizado, lexicográfico ascendente)** se marcan `LLM_UNAVAILABLE` (motivo "tope de llamadas"), sin penalizar y de forma reproducible entre corridas.
6. WHILE `enable_layer4` es falso (default) o falta `ANTHROPIC_API_KEY`, THE SYSTEM SHALL comportarse exactamente como el Hito 2 (sin Capa 4), sin añadir `api.anthropic.com` al allowlist ni emitir señales L4.

### Requisito 2: Capa 4 — clasificación LLM, salida estructurada y peso
**Historia de usuario:** Como desarrollador, quiero un juicio estructurado, determinista y resistente a inyección sobre si el nombre parece confabulado.
**Criterios de aceptación (EARS):**
1. WHEN invoca al LLM, THE SYSTEM SHALL enviar **exclusivamente** el nombre normalizado, el ecosistema y el **contexto determinista** ya computado por capas 0–2 (existencia/edad, distancia typo al vecino más cercano de top-10k, presencia de repo/metadata, señales blandas disparadas), **encajonando el nombre no confiable y el contexto dentro de delimitadores explícitos** con instrucción de tratarlos como **datos, no instrucciones** (defensa anti prompt-injection de segundo orden). SHALL solicitar salida **estructurada** vía `output_config.format` (esquema JSON: `clasificacion` enum, `confianza` número, `patron`, `rationale`), header `anthropic-version: 2023-06-01`, modelo `llm_model`, `output_config.effort = llm_effort`. (Nota: `output_config.format`/`effort` se controlan por modelo, no por el header de versión.)
2. WHEN recibe la respuesta, THE SYSTEM SHALL validar el esquema antes de usarla: `clasificacion ∈ {legitimo,conflacion,typo,fabricacion}`, `confianza` **float finito en [0,1]** (rechazar `NaN`/`Infinity`, que `safe_json` estricto debe impedir), `patron`/`rationale` texto. IF no valida, THEN THE SYSTEM SHALL tratarla como abstención (`LLM_UNAVAILABLE`, motivo "salida inválida"), **sin** intentar extracción heurística de JSON desde prosa (preserva determinismo y evita inyección).
3. IF `clasificacion ∈ {conflacion,typo,fabricacion}` y `confianza >= llm_conf_min`, THEN THE SYSTEM SHALL emitir señal `LLM_HALLUCINATION_SURFACE` con **peso determinista** `soft_llm = min(LLM_SOFT_CAP, floor(W_base[clasificacion] * confianza))`, junto al `rationale` saneado+truncado. IF `confianza < llm_conf_min`, THEN THE SYSTEM SHALL tratarla como sin-señal-de-riesgo (equivalente a `legitimo`).
4. WHEN `clasificacion == legitimo`, THE SYSTEM SHALL considerar la Capa 4 evaluada y limpia para esa dependencia (sin señal de riesgo L4). THE SYSTEM SHALL NOT eliminar, reducir ni neutralizar ninguna señal de capas 0–3: `legitimo` significa **únicamente** ausencia de señal de riesgo L4 nueva; el score/verdict deterministas permanecen intactos (consistente con R4.5).
5. THE SYSTEM SHALL fijar `llm_model` (default `claude-opus-4-8`) y una `prompt_version` versionada; ambos forman parte de la identidad del veredicto (caché y reproducibilidad, R6). El request **no** incluye parámetros de muestreo (`temperature`/`top_p` están removidos en Opus 4.8); el determinismo se confina tras la caché (R6) y la salida estructurada validada (R2.2).

**Función de peso (determinista, única fuente de verdad — ver tabla de defaults R5):**
`soft_llm = 0` si `clasificacion == legitimo` o `confianza < llm_conf_min`; en otro caso `soft_llm = min(LLM_SOFT_CAP, floor(W_base[clasificacion] * confianza))`. Con `W_base = {fabricacion: 55, conflacion: 45, typo: 40}`, `LLM_SOFT_CAP = 50`, `llm_conf_min = 0.5`. Ejemplo: `fabricacion@1.0 → min(50,55)=50 → warn` (50≥`umbral_warn`); `conflacion@0.8 → floor(36)=36`; combinado con una blanda heurística (≤25) puede llegar a `warn` pero el máximo absoluto es `0+25+50=75 < 80`.

### Requisito 3: Scoring, canal L4 separado, precedencia e invariante anti-block
**Historia de usuario:** Como desarrollador/DevSecOps, quiero que la señal del LLM se combine de forma predecible, pueda avisar pero **nunca** bloquee, y nunca introduzca falsos positivos sistémicos.
**Criterios de aceptación (EARS):**
1. THE SYSTEM SHALL extender el scorer a `score = min(100, max_hard + min(soft_heuristico, SOFT_CAP) + min(soft_llm, LLM_SOFT_CAP))`, donde `soft_llm` es exclusivamente la señal `LLM_HALLUCINATION_SURFACE` (canal separado, **fuera** del `SOFT_CAP` heurístico). El scorer permanece **función pura** (sin flags de modo).
2. THE SYSTEM SHALL garantizar como **propiedad del score final** que, en ausencia de una señal dura de block, `score_final < umbral_block`. Esto se cumple por construcción porque el *gating* (R1.2.iii) asegura `max_hard == 0` para toda dependencia con señal L4, luego `score_final <= SOFT_CAP + LLM_SOFT_CAP = 75 < 80`. Por tanto **la señal L4 nunca produce `block`** —ni sola ni combinada con blandas heurísticas— (decisión FASE 0 inmutable).
3. WHEN `soft_llm` es alto (p. ej. `fabricacion` de alta confianza), THE SYSTEM SHALL permitir que el score alcance `[umbral_warn, umbral_block)` produciendo a lo sumo `warn`. Esta es una **relajación calibrada y acotada** de la invariante de blandas del Hito 1, documentada en ADR: las blandas **heurísticas** siguen sin escalar solas (capadas a 25 < 50); solo la señal **LLM** (alta evidencia, *gated*, canal propio) puede alcanzar `warn`.
4. WHEN coexiste cualquier señal dura, THE SYSTEM SHALL dejar que domine la precedencia del Hito 1/2 (el *gating* ya evita invocar el LLM en ese caso; si una señal L4 cacheada coexistiera, no puede bajar el riesgo: R4.5).
5. THE SYSTEM SHALL implementar la **ablación** (R10.3) a nivel de **emisión de señales / pipeline** —el evaluador L4 no emite `LLM_HALLUCINATION_SURFACE`, o el runner de eval filtra esa señal de la tupla **antes** de `compute_score`—, **NUNCA** con un flag dentro del scorer puro. *(verificable por import-linter/AST: `core.scoring` no lee ningún flag de ablación.)*
6. WHILE evalúa el lote, THE SYSTEM SHALL producir el mismo veredicto para la misma entrada y el mismo veredicto LLM cacheado (determinismo relativo a caché), con orden de capas fijo (0 → 1 → 2 → 3 → 4).

### Requisito 4: Degradación segura, abstención y visibilidad
**Historia de usuario:** Como equipo, quiero que la ausencia o el fallo del LLM nunca empeore ni falsee el resultado, pero **sí** se reporte.
**Criterios de aceptación (EARS):**
1. IF falta `ANTHROPIC_API_KEY`, THEN THE SYSTEM SHALL omitir Capa 4 (no añade host al allowlist) y, si `enable_layer4` se pidió explícitamente, SHALL advertirlo una vez sin alterar veredictos.
2. IF la API responde con error transitorio (timeout, 5xx, conexión caída) tras agotar reintentos, o con `4xx`/`429` inesperado, THEN THE SYSTEM SHALL emitir `LLM_UNAVAILABLE` (weight 0) para las dependencias afectadas, **sin** degradar su `status` ni elevar el exit code.
3. WHEN la respuesta tiene `stop_reason` distinto del esperado para una salida completa (cualquier valor ≠ `end_turn` apropiado al flujo estructurado, incluidos `refusal`, `max_tokens` —salida truncada—, `pause_turn`) **o** `content` vacío, THE SYSTEM SHALL tratarla como abstención (`LLM_UNAVAILABLE`), nunca como evidencia de riesgo ni como limpio concluyente.
4. THE SYSTEM SHALL garantizar que **ninguna** ruta de error/abstención de Capa 4 pueda producir `block` ni `warn` (la abstención es siempre weight 0): el LLM solo **añade** riesgo cuando responde válidamente con una clasificación de alucinación de confianza suficiente.
5. THE SYSTEM SHALL preservar intactos los veredictos de Capa 0–3 ante cualquier resultado de Capa 4: Capa 4 **nunca puede bajar** el riesgo determinado por capas previas.
6. WHEN una corrida con `enable_layer4` deja `LLM_UNAVAILABLE` a una fracción no trivial de la banda gris, THE SYSTEM SHALL emitir una **advertencia agregada visible y determinista** ("Capa 4 activa pero N/M dependencias de banda gris no pudieron evaluarse por el LLM") y reportar el conteo en JSON (R7.6), sin elevar el exit code. Esto evita el falso "todo limpio".

### Requisito 5: Configuración y validación de Capa 4
**Historia de usuario:** Como equipo, quiero ajustar y acotar el comportamiento y el costo, con validación que proteja el invariante anti-block.
**Criterios de aceptación (EARS):**
1. WHEN existe configuración (`[tool.slopguard]` o `.slopguard.toml`), THE SYSTEM SHALL cargar los parámetros de Capa 4 con precedencia CLI > archivo > defaults; `--enable-layer4` / `--no-layer4` y `--llm-model` disponibles en CLI.
2. IF la configuración de Capa 4 es inválida, THEN THE SYSTEM SHALL terminar con exit code 3 (`error_category=invalid_config`) sin aplicar valores a medias. THE SYSTEM SHALL validar **al menos**: (a) `llm_host` es un FQDN https válido con el **mismo** predicado que los hosts de Capa 3 (rechazo de IP/localhost/puerto/userinfo); (b) el **invariante anti-block** `SOFT_CAP + LLM_SOFT_CAP < umbral_block` (con defaults: `25 + 50 = 75 < 80`); (c) `0 < llm_conf_min <= 1`, `LLM_SOFT_CAP >= umbral_warn` (para que el canal pueda alcanzar `warn`), pesos y timeouts en rango.
3. WHERE `enable_layer4` es falso, THE SYSTEM SHALL comportarse exactamente como el Hito 2.
4. THE SYSTEM SHALL permitir configurar modelo, host/versión de API, effort, timeouts, reintentos, TTL de caché, `gray_edad_max_dias`, pesos base, `LLM_SOFT_CAP`, `llm_conf_min`, `llm_max_calls_por_corrida` y `llm_max_text_chars`.

**Defaults consolidados de Capa 4 (única fuente de verdad):**

| Parámetro | Default | Usado en |
|---|---|---|
| `enable_layer4` | `false` | R1.6, R5.3 |
| `llm_host` | `api.anthropic.com` | R1.1, NFR-Seg |
| `llm_api_path` | `/v1/messages` | R2.1 |
| `llm_api_version` | `2023-06-01` | R2.1 |
| `llm_model` | `claude-opus-4-8` | R2.5 |
| `llm_effort` | `low` | R2.1 (clasificación) |
| `prompt_version` | `h3-v1` | R2.5 / R6 |
| `gray_edad_max_dias` | 365 | R1.2.iv (joven ⇒ sospechoso) |
| `W_base.fabricacion` | 55 | R2.3 (función de peso) |
| `W_base.conflacion` | 45 | R2.3 |
| `W_base.typo` | 40 | R2.3 |
| `LLM_SOFT_CAP` | 50 | R3.1 (≥ `umbral_warn`=50; con `SOFT_CAP`=25 ⇒ `75 < umbral_block`=80) |
| `llm_conf_min` | 0.5 | R2.3 |
| `llm_max_calls_por_corrida` | 50 | R1.5 |
| `llm_max_text_chars.patron` | 280 | R7.3 (truncado del texto LLM) |
| `llm_max_text_chars.rationale` | 1000 | R7.3 |
| `llm_ttl_cache_horas` | 168 | R6 |
| `llm_timeout_total_s` | 30 | R4.2 |
| `llm_reintentos` | 2 | R4.2 |
| `llm_unavailable_warn_frac` | 0.2 | R4.6 (umbral de advertencia agregada) |
| `max_response_bytes` (reuso) | 10_000_000 | NFR-Seg |
| `max_json_depth` (reuso) | 50 | NFR-Seg |

### Requisito 6: Caché y determinismo de Capa 4
**Historia de usuario:** Como desarrollador, quiero ejecuciones rápidas, baratas, repetibles y sin filtrar datos a disco.
**Criterios de aceptación (EARS):**
1. WHEN obtiene un veredicto LLM válido, THE SYSTEM SHALL cachearlo en disco (reusando `DiskCache` seguro) con clave **content-addressed** = hash de `(nombre, ecosistema, hash(contexto_determinista), llm_model, prompt_version)` y TTL `llm_ttl_cache_horas`, namespaced por fuente. THE SYSTEM SHALL almacenar en el blob **solo** el `LlmAssessment` validado (clasificación, confianza, patrón/rationale saneados+truncados, modelo, prompt_version); SHALL NOT persistir el prompt crudo, el cuerpo/headers HTTP ni la `ANTHROPIC_API_KEY`.
2. WHEN existe una entrada de caché vigente, THE SYSTEM SHALL usarla sin llamar a la red; los aciertos de caché **no** cuentan contra `llm_max_calls_por_corrida` (el tope acota llamadas de **red**, R1.5).
3. WHEN se pasa `--no-cache`, THE SYSTEM SHALL ignorar y no escribir la caché de Capa 4.
4. THE SYSTEM SHALL producir, para la misma entrada y el mismo veredicto LLM cacheado, idéntico resultado; un cambio de `llm_model` o `prompt_version` invalida la entrada (clave distinta).
5. THE SYSTEM SHALL registrar (verbose/eval) el conteo de llamadas LLM **de red** y la tasa de aciertos de caché de la corrida.

### Requisito 7: Salida explicable con Capa 4
**Historia de usuario:** Como desarrollador, quiero entender por qué el LLM marcó un nombre como sospechoso, con transparencia y sin prestarle autoridad indebida.
**Criterios de aceptación (EARS):**
1. WHERE una dependencia tiene `LLM_HALLUCINATION_SURFACE`, THE SYSTEM SHALL mostrar clasificación, confianza, `rationale` saneado y una acción sugerida ("verificar antes de instalar"), marcando explícitamente el texto como **"texto generado por LLM, no verificado"** y la señal como **advisory** (no bloqueo).
2. WHEN se invoca con `--format json`, THE SYSTEM SHALL emitir `schema_version` `1.2`, incluyendo `signals[]` de L4 y un bloque `llm_assessment` (`clasificacion`, `confianza`, `patron`, `modelo`, `prompt_version`) cuando aplique, con orden determinista y claves estables.
3. WHILE muestra CUALQUIER texto del LLM (`rationale`, `patron`) en CUALQUIER salida, THE SYSTEM SHALL **sanear** (ANSI/C0-C1/CRLF) **y truncar** a `llm_max_text_chars[campo]` (truncado con marcador), mediante una función dedicada `sanitize_and_truncate` que no contamine `sanitize_for_output`. El texto del LLM es **entrada no confiable**, también para consumidores aguas abajo del JSON.
4. THE SYSTEM SHALL indicar, cuando Capa 4 está activa, el modelo y `prompt_version` usados, y que se envió solo `nombre+ecosistema+contexto`.
5. THE SYSTEM SHALL mantener el orden determinista de resultados del Hito 1/2.
6. THE SYSTEM SHALL incluir en el JSON un conteo agregado de dependencias `LLM_UNAVAILABLE` de la corrida (soporte de la advertencia R4.6).

### Requisito 8: Privacidad y seguridad del transporte LLM
**Historia de usuario:** Como equipo con restricciones de privacidad, quiero control total sobre qué se envía y garantías de transporte y de no-fuga de la clave.
**Criterios de aceptación (EARS):**
1. WHEN consulta el LLM, THE SYSTEM SHALL usar HTTPS+TLS (no desactivable), con el host fijado al allowlist **solo si `enable_layer4`** (`{… , api.anthropic.com}`); SHALL NOT seguir redirecciones cross-scheme/cross-host.
2. THE SYSTEM SHALL enviar **solo** `nombre+ecosistema+contexto determinista`; SHALL NOT enviar el manifiesto, su contenido, rutas locales ni versiones pinneadas innecesarias.
3. THE SYSTEM SHALL transportar la `ANTHROPIC_API_KEY` extendiendo `SecureHttpClient.post_json` con un parámetro **kw-only `extra_headers`** restringido a un allowlist de nombres de cabecera (`x-api-key`, `anthropic-version`, `content-type`). THE SYSTEM SHALL leer la clave **solo** de entorno en el punto de construcción de la petición; SHALL NOT almacenarla en atributos de objetos cacheados/serializables, ni reflejarla/registrarla en mensajes de excepción, logs verbose, JSON ni en el blob de caché. El invariante "`NetworkUnverifiableError` jamás incluye cabeceras" se fija como verificable.
4. WHEN lee la respuesta del LLM, THE SYSTEM SHALL reusar las defensas del Hito 1 (lectura streaming ≤ `max_response_bytes`, profundidad JSON ≤ `max_json_depth`, `safe_json` estricto sin `eval`/deserialización insegura ni `NaN`/`Infinity`).
5. THE SYSTEM SHALL NOT ejecutar, importar ni evaluar el código de ningún paquete; Capa 4 solo razona sobre nombre+metadatos. *(estático)*

### Requisito 9: Extensibilidad y frontera arquitectónica
**Historia de usuario:** Como mantenedor, quiero cambiar de proveedor/modelo LLM sin tocar el motor de capas, con la frontera verificada en CI.
**Criterios de aceptación:**
1. THE SYSTEM SHALL definir una abstracción de **evaluador de alucinación** (consulta por nombre+contexto → `LlmAssessment`) desacoplada del motor de capas/scoring.
2. THE SYSTEM SHALL ubicar el adaptador concreto de red/LLM en `core.llm`, y los modelos de transporte (`LlmAssessment`, `Clasificacion`) en `core.models` (hoja), para no cruzar `core.layers ✗→ core.llm`.
3. THE SYSTEM SHALL añadir contratos **import-linter** explícitos (análogos a los 3 de H2): (i) `forbidden: slopguard.core.layers → slopguard.core.llm` (salvo vía la abstracción inyectada); (ii) `forbidden: slopguard.core.layers.layer4_* → ` el adaptador HTTP/LLM concreto; (iii) `forbidden: slopguard.core.scoring → ` cualquier flag de ablación (R3.5). *(verificable por import-linter/AST.)*

### Requisito 10: Evaluación formal precision/recall (entregable científico, pre-registrada)
**Historia de usuario:** Como mantenedor, quiero medir rigurosamente y sin sesgos el efecto de Capa 4, con una garantía anti-FP que pueda **fallar**.
**Criterios de aceptación (EARS):**
1. THE SYSTEM SHALL incluir un *runner* de evaluación reproducible (`eval/`) sobre un **dataset etiquetado y versionado** con **partición train/dev/test**: el prompt (`prompt_version`) y los umbrales/pesos se afinan **solo** sobre `dev`; las métricas se reportan sobre `test`, jamás usado para afinar. THE SYSTEM SHALL congelar `prompt_version` y config antes de tocar `test` (registrado en ADR).
2. THE SYSTEM SHALL construir los **positivos** (nombres alucinados) con **procedencia independiente** del juicio del modelo evaluado y de la taxonomía de prompting: nombres alucinados observados empíricamente por modelos **distintos** a `claude-opus-4-8` y/o el corpus depscope como **verdad-terreno externa efímera (consulta online, no persistida)**. THE SYSTEM SHALL prohibir que el mismo modelo/prompt evaluado participe en la selección o etiquetado del dataset. THE SYSTEM SHALL documentar la procedencia de cada positivo.
3. THE SYSTEM SHALL construir los **negativos** en dos estratos: (a) **fáciles** = paquetes reales establecidos (top-N PyPI); (b) **difíciles** = paquetes legítimos jóvenes / de baja descarga / metadata pobre (los que caen en banda gris y disparan L4). THE SYSTEM SHALL medir la garantía anti-FP **principalmente** sobre el estrato (b).
4. THE SYSTEM SHALL reportar `precision`/`recall`/`F1` **separados por nivel de veredicto**: (i) para `block` —donde L4 no participa: el delta de la ablación debe ser **0 por construcción**, validando el aislamiento—; (ii) para `warn-o-peor` —donde L4 contribuye—. SHALL NOT mezclar ambos en una métrica binaria global.
5. THE SYSTEM SHALL **pre-registrar** (en un ADR, **antes** de correr la ablación) un **piso numérico de precisión** y el conjunto sobre el que se mide: precisión de `block` = 100% (por construcción), y precisión de `warn` (sobre negativos difíciles) ≥ la línea base de H2 sin L4. La evaluación SHALL poder **FALLAR** si Capa 4 reduce la precisión por debajo del piso pre-registrado; el éxito es un **delta no-negativo medido**, no una afirmación.
6. THE SYSTEM SHALL ejecutar la **ablación** Capa 4 ON vs OFF (vía R3.5, no por flag en el scorer) y reportar el delta solo sobre la métrica `warn-o-peor`.
7. THE SYSTEM SHALL asegurar reproducibilidad: como Opus 4.8 no admite parámetros de muestreo, el determinismo se confina tras la caché y la salida estructurada; SHALL **versionar/publicar el hash de la caché de eval** (o un snapshot saneado de los veredictos LLM crudos) junto a la tabla de métricas, para que un tercero reproduzca sin re-llamar al LLM. SHALL reportar el **costo** a partir de los campos `usage` de las llamadas **reales** (no cacheadas) de la primera generación, separado del costo de re-ejecución cacheada (~0), y enlazado a la tasa de caché (R6.5).
8. WHERE el dataset usa depscope, THE SYSTEM SHALL respetar CC-BY-NC-SA: **solo consulta online + atribución**, **nunca** embeber/redistribuir; los positivos **versionados** deben tener procedencia propia e independiente (no obra derivada de depscope).

## Requisitos no-funcionales

### Seguridad
1. WHEN consulta el LLM, THE SYSTEM SHALL usar HTTPS+TLS (no desactivable), allowlist ampliado solo bajo `enable_layer4` (`{pypi.org, api.osv.dev, (depscope.dev?), api.anthropic.com}`), `llm_host` validado como FQDN https, sin redirecciones cross-host.
2. THE SYSTEM SHALL sanear **y truncar** todo texto del LLM antes de mostrarlo/serializarlo; tratarlo como entrada no confiable (incluido el consumo del JSON aguas abajo) e insertar el nombre no confiable en el prompt como **dato encajonado**, no instrucción.
3. THE SYSTEM SHALL NOT registrar/reflejar/persistir `ANTHROPIC_API_KEY`; leerla solo de entorno, transportarla solo vía el `extra_headers` allowlisteado.
4. THE SYSTEM SHALL NOT ejecutar/importar/evaluar código de paquetes. *(estático)*

### Privacidad
1. THE SYSTEM SHALL enviar al LLM **solo** nombre+ecosistema+contexto determinista, nunca el manifiesto/rutas/identificadores.
2. THE SYSTEM SHALL permitir desactivar toda Capa 4 (default OFF) para operar sin contactar a Anthropic.
3. THE SYSTEM SHALL documentar explícitamente qué se envía, a qué host y bajo qué condiciones.

### Determinismo
1. WHEN se le dan la misma entrada y el mismo veredicto LLM cacheado, THE SYSTEM SHALL producir idéntico resultado, con orden de capas fijo (0→1→2→3→4); el no-determinismo del LLM queda confinado tras la caché content-addressed (R6) y la salida estructurada validada (R2.2). El orden canónico de consumo del presupuesto de llamadas (R1.5) hace reproducible el subconjunto `LLM_UNAVAILABLE` bajo tope.

### Degradación segura y visibilidad
1. IF Capa 4 falla o se abstiene, THEN THE SYSTEM SHALL preservar el resultado determinista/threat-intel intacto, sin degradar `status` ni exit code, **pero** reportando la indisponibilidad de forma agregada y visible (R4.6) para no fingir "todo limpio".

### Costo acotado (cambio explícito vs H1/H2)
1. THE SYSTEM SHALL mantener **costo cero** en todo SlopGuard salvo Capa 4, que es **opt-in y metered**, acotada por gating (solo banda gris, sin señal dura), caché persistente, `llm_max_calls_por_corrida`, modelo configurable (Haiku 4.5 disponible) y posible evaluación por lotes; SHALL reportar costo/llamadas en verbose/eval.
2. THE SYSTEM SHALL mantener **cero dependencias de runtime** (solo stdlib): el transporte LLM usa el `SecureHttpClient` HTTPS crudo del Hito 1, sin SDK.

### Mantenibilidad
1. THE SYSTEM SHALL conservar tipado estricto (mypy --strict), funciones ≤50 líneas, docstrings en español, import-linter (frontera del LLM), y el scorer como función pura (la ablación vive fuera).

### Compatibilidad hacia atrás
1. THE SYSTEM SHALL mantener intactos H1/H2 (capas, threat-intel, exit codes, contrato JSON); los cambios son **aditivos** (`schema_version` 1.1 → 1.2) y Capa 4 es activable/desactivable sin afectar el comportamiento existente.

## Propiedades estructurales (verificación por análisis estático / test de propiedad)
- La abstracción del evaluador de alucinación desacopla Capa 4 del transporte concreto (R9) → import-linter (3 contratos enumerados en R9.3).
- Ausencia de `eval`/`exec`/deserialización insegura sobre respuestas del LLM (NFR-Seg.4) → AST/lint.
- Allowlist de red acotado, ampliado a `api.anthropic.com` **solo** bajo `enable_layer4`; `llm_host` validado → test estático + validación de config.
- **Invariante anti-block (crítico):** para toda combinación de señales sin una señal dura de block, `score_final < umbral_block` → test de propiedad sobre el scorer **y** validación de config (`SOFT_CAP + LLM_SOFT_CAP < umbral_block`). El *gating* garantiza `max_hard == 0` para deps con señal L4.
- `core.scoring` no lee ningún flag de ablación (R3.5) → import-linter/AST.
- La `ANTHROPIC_API_KEY` no aparece en excepciones/logs/JSON/blob de caché → test de no-fuga.

## Fuera de alcance (Hito 3)
- Frontends pre-commit y GitHub Action como producto → Hito 4.
- Adaptador npm / multi-ecosistema simultáneo → post-MVP.
- *Probing* generativo del LLM (medir cuántas veces el modelo *sugiere* el nombre) como detector online → no se hace; la "superficie" se estima por clasificación cacheada del nombre+contexto.
- Fine-tuning o modelos propios; modelos no-Claude.
- **Bloqueo (`block`) por señal LLM**: Capa 4 nunca bloquea (a lo sumo `warn`).
- Redistribuir/embeber el corpus depscope (CC-BY-NC-SA): solo consulta online + atribución.
- Que un `legitimo` del LLM **reduzca** señales deterministas previas (prohibido por R2.4/R4.5).
