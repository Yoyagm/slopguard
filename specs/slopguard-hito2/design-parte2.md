# Diseño SlopGuard (Hito 2) — Parte 2: ADRs, Trazabilidad, Alto riesgo

> Continuación de `design.md` (arquitectura §1, modelos §2, contratos §3, flujo del engine §4).
> Aquí: ADRs (§5), trazabilidad requisito→diseño (§6), non-goals (§7) y tareas de alto riesgo
> para `developer-complex` (§8). Numeración de ADRs continúa la del Hito 1 (ADR-01..05) → ADR-06..10.

---

## 5. ADRs

### ADR-06 — `MALICIOUS` como override de block: peso y precedencia

**Contexto.** OSV reporta paquetes confirmados maliciosos con advisories `MAL-*` (verificado en
vivo: `MAL-2025-47868` = "Malicious code in bioql (PyPI)"). Un paquete malicioso **existe** en
PyPI, puede tener metadatos completos y no ser typosquat de nada del top-N: las capas
deterministas lo dejarían pasar (`allow`). Es la señal de mayor severidad del producto: hay que
bloquear con certeza, independiente del score y de `umbral_block` (R1.2/R3.1). El Hito 1 ya tiene
un mecanismo de override fuera del scorer: la inexistencia (404 ⇒ `verdict=block`, `score=None`).

**Decisión.** `MALICIOUS` es un **override de block con precedencia máxima**, modelado igual que
`NONEXISTENT`: señal **dura** `is_soft=False`, `weight=0` (no entra al scorer), y
`build_dependency_result` la detecta **antes** que cualquier otra rama ⇒ `verdict=block`,
`score=None`, `status=ok` (la verificación SÍ se completó), poblando `advisories[]`. Orden de
precedencia explícito en el veredicto:

```
1. unverifiable (sin block dominante)   -> status=unverifiable
2. MALICIOUS                            -> block override, score=None, advisories[]   (NUEVO, máx.)
3. NONEXISTENT                          -> block override, score=None
4. score normal (typosquat/L3 hallu.)   -> umbral_block/umbral_warn
```

`MALICIOUS` precede a `NONEXISTENT` y a typosquat porque es la afirmación positiva más fuerte
("este artefacto es dañino"), mientras que 404/typosquat son inferencias de riesgo. Si coexisten
`MALICIOUS` + `NONEXISTENT` (raro: un nombre que estuvo en OSV y ya no existe), **ambas señales se
reportan**, el motivo primario es malicia y el resultado es `block` en cualquier caso (R3.4). Si
coexisten `MALICIOUS` + `TYPOSQUAT`, ambas se reportan, `block` por malicia.

**Alternativas.** (a) *Peso ≥ umbral_block dentro del scorer* (como haremos con
`KNOWN_HALLUCINATION`): funcionaría para producir block, pero rompe la semántica "certeza ≠
heurística" —el score sugiere gradiente de sospecha; la malicia es binaria y confirmada— y
expondría el bloqueo a que un `umbral_block` mal configurado lo degrade. El override es
inmune a la config. (b) *Excepción/short-circuit que aborta la dep*: perdería las demás señales
(typosquat, edad) que enriquecen la explicación (R3.4 exige reportarlas todas). El override
preserva la tupla de señales completa.

**Trade-offs.** ➕ Inmune a `umbral_block`; reusa el patrón probado de `NONEXISTENT`; explicación
completa; `score=None` comunica "no es cuestión de score". ➖ Una segunda ruta de override añade
una rama de precedencia en `build_dependency_result` (test exhaustivo de coexistencias). ➖
Depende de que OSV esté disponible; mitigado por degradación segura (ADR-10).

**Consecuencias.** `verdict.py` gana una rama `_has_malicious(signals)` evaluada **después** de
`ctx.is_unverifiable` (Capa 0) y **antes** de `_has_nonexistent` (orden exacto en §3.5). `advisories`
se extrae de las señales L3 portadoras vía `_advisories_from_signals` (importando `Advisory` de
`core.models`, módulo hoja — frontera import-linter §1.3). Por **simetría con `NONEXISTENT`**,
`MALICIOUS` (override `weight=0`) se **excluye explícitamente por code en `scorer._max_hard_weight`**
(no contribuye al score; defensa en profundidad ante un futuro cambio de peso — §2.1). El flag
`ctx.is_unverifiable` queda ligado **solo** a Capa 0: un threat-intel caído NO lo activa (entra por
la rama nueva del paso 4 de §3.5), de modo que `threat-intel caído + MALICIOUS ⇒ block` (no se
pierde el override). Riesgo: ver §8 RISK-H2-4 (override de veredicto — delegar a `developer-complex`).

---

### ADR-07 — `KNOWN_HALLUCINATION`: peso ≥ umbral_block (NO override), preservando la invariante anti-FP

**Contexto.** La watchlist depscope (opcional) lista **nombres exactos** de paquetes alucinados
conocidos por benchmarks de LLM. Un match exacto es alto riesgo, pero es **menos certero** que
`MALICIOUS`: el corpus es de terceros, opcional, y un nombre puede dejar de ser "alucinación
pura" si alguien lo registra legítimamente. R3.2 exige que produzca `block` **por sí sola**. La
pregunta del requirements: ¿override (como malicia) o peso ≥ umbral_block (dentro del scorer)?

**Decisión.** **Peso ≥ `umbral_block`, NO override.** `KNOWN_HALLUCINATION` es señal **dura**
`is_soft=False`, `weight=85` (> `umbral_block`=80 default), que fluye por el scorer normal y
produce `block` por **score** (no por override). Justificación frente a la invariante anti-FP:

- La invariante anti-FP del Hito 1 dice "**señales blandas** solas (≤25) nunca cruzan
  `umbral_warn`". `KNOWN_HALLUCINATION` es **dura**, no blanda: las señales duras (typosquat,
  name_untrusted) **sí** pueden elevar a warn/block por diseño. Tratarla como dura es
  consistente, no rompe la invariante (que solo acota las blandas).
- Mantenerla **dentro del scorer** (en vez de override) la hace **respetuosa de la config**: si un
  equipo sube `umbral_block` por encima de 85, degrada a `warn` (decisión informada del operador),
  a diferencia de la malicia que debe ser inmune. Esto es deseable: la watchlist es opcional y
  menos certera, el operador puede calibrar su severidad. La malicia (ADR-06) no.
- El peso 85 (no 100) deja margen para que, combinada con otra dura, no desborde el modelo, y para
  que el operador pueda situarla entre warn y block ajustando umbrales si su contexto lo exige.

`weight=85` se añade a `_max_hard_weight` del scorer **sin** tocar `SOFT_CAP` ni la fórmula: el
scorer ya toma el máximo de las duras; `KNOWN_HALLUCINATION` simplemente es una dura más con su
peso. La invariante "blandas ≤25 < umbral_warn" sigue intacta literalmente.

**Alternativas.** (a) *Override como MALICIOUS*: la haría inmune a config, sobre-estimando la
certeza de una fuente opcional de terceros; un FP en el corpus (nombre legítimo listado) sería
imposible de calibrar. Rechazada por el principio "el ruido es el enemigo" + opcionalidad. (b)
*Peso < umbral_block (p.ej. 60, solo warn)*: contradice R3.2 ("block por sí sola"). Rechazada.

**Trade-offs.** ➕ Respeta config (calibrable), consistente con el modelo de señales duras, no
toca la invariante anti-FP, no añade ruta de override. ➖ Si alguien configura `umbral_block>85`
deja de bloquear (es intencional, pero hay que documentarlo). ➖ Acoplada al default `umbral_block
=80`; si baja mucho, el margen se reduce (aceptable: típicamente solo sube).

**Consecuencias.** El scorer trata `KNOWN_HALLUCINATION` como dura de peso 85; ninguna constante
del Hito 1 cambia. Test de propiedad: `KNOWN_HALLUCINATION` sola ⇒ score 85 ⇒ block con defaults;
con `umbral_block=90` ⇒ warn (calibrable). Documentar la dependencia del default en el ADR y el
README.

---

### ADR-08 — Batch OSV intercalado entre Capa 0 y las capas por-dep (vs per-dep)

**Contexto.** OSV ofrece `POST /v1/querybatch` para resolver **muchos** paquetes en un request. El
Hito 1 evalúa todo **per-dep** (cada dep: fetch → capas → score, en paralelo). Capa 3 no encaja
en ese molde: consultar OSV per-dep (un request por dependencia) desperdiciaría el batch, multiplicaría
la latencia y el rate-limit. Pero el batch necesita saber **qué paquetes existen** (R1.5: no
consultar OSV de inexistentes), dato que solo se conoce **tras** la Capa 0.

**Decisión.** **Intercalar** un paso de resolución en lote **entre** la Capa 0 (concurrente,
per-dep) y el bucle de evaluación por-dep (§4): (1) `fetch_many` resuelve existencia per-dep como
en el Hito 1; (2) el engine recolecta los nombres `FOUND`; (3) `resolve_threatintel` los consulta
en **lotes ≤ `osv_batch_max`** (dedup, caché por-nombre, presupuesto de timeout por lote); (4) el
bucle por-dep evalúa 0→1→2→3 con el `ThreatIntelResult` ya disponible inyectado como entrada pura.

La caché es **por-nombre** (no por-lote): un lote consulta OSV solo para los nombres con miss, y
mezcla con los hits, de modo que dos corridas con dependencias solapadas reutilizan caché aunque
el lote sea distinto (NFR-Rend, R6.6 "no consultar más de una vez por nombre").

**Alternativas.** (a) *Per-dep dentro del ThreadPool del Hito 1* (cada worker consulta OSV para su
dep): rompe el batch (N requests vs ⌈N/1000⌉), multiplica latencia y rate-limit, y acoplaría la
Capa 3 al modelo concurrente per-dep. Rechazada por rendimiento (R6.7: 30 deps ≤12s) y por
limpieza arquitectónica. (b) *Resolver OSV ANTES de Capa 0* (para todos los nombres del
manifiesto): violaría R1.5 (consultaría inexistentes), gastaría cuota en paquetes 404 y mezclaría
el override de inexistencia con el de malicia de forma confusa. Rechazada. (c) *Segundo ThreadPool
de lotes en paralelo con la Capa 0*: complejidad de concurrencia anidada sin beneficio claro (la
Capa 0 debe terminar para saber los FOUND); el chunking de OSV ya es de pocos requests.

**Trade-offs.** ➕ Aprovecha el batch (1-pocos requests), respeta R1.5, mantiene la Capa 3 pura
(entrada inyectada), caché por-nombre maximiza hits. ➖ Introduce una **barrera** entre Capa 0 y el
resto (la Capa 0 debe completar antes del batch): pierde algo de solape, pero la Capa 0 ya es
concurrente y el batch es de baja latencia agregada. ➖ El engine gana un paso de orquestación (la
pieza más cambiada del Hito 1 — ver §8).

**Consecuencias.** `engine._scan` gana el paso 3-5 de §4.1. El orden de capas 0→1→2→3 se preserva
por-dep. Determinismo relativo a caché intacto (el batch no introduce reloj salvo el `now_epoch`
único ya existente). Riesgo: ver §8 RISK-H2-3 (intercalado batch+concurrencia).

---

### ADR-09 — Ampliación del allowlist sin perder el guardia estático anti-vacuo

**Contexto.** El Hito 1 fija `ALLOWED_HOSTS = frozenset({"pypi.org"})` como **constante global** y
lo verifica con un test estático anti-vacuo: el allowlist no debe poder crecer descontroladamente
ni vaciarse (un allowlist vacío o `{*}` anularía la defensa SSRF). Capa 3 necesita `api.osv.dev`
(siempre que `enable_layer3`) y `depscope.dev` (solo si `enable_watchlist`). Si simplemente
añadimos los tres a la constante global, el guardia pierde poder: `depscope.dev` quedaría
permitido aun con la watchlist desactivada (R2.1 lo prohíbe explícitamente), y la base ya no sería
"solo pypi.org".

**Decisión.** **Allowlist = base global (anclada) + extra por instancia (explícita y acotada).**
`ALLOWED_HOSTS = {"pypi.org"}` permanece como **constante base inmutable** (el guardia estático la
sigue anclando: `assert ALLOWED_HOSTS == frozenset({"pypi.org"})`). `SecureHttpClient` acepta
`extra_allowed_hosts` por instancia; la allowlist **efectiva** = `ALLOWED_HOSTS | extra`. Cada
fuente declara los hosts que necesita vía `ThreatIntelSource.extra_allowed_hosts`:
- `OsvSource.extra_allowed_hosts = {"api.osv.dev"}` (o `{config.osv_host}`).
- `WatchlistSource.extra_allowed_hosts = {"depscope.dev"}` **solo si** `enable_watchlist`; si no,
  la fuente no se instancia y el host nunca entra al allowlist (R2.1 por construcción).

El guardia estático se **generaliza sin perder poder**: dos invariantes verificadas por test:
1. `ALLOWED_HOSTS == frozenset({"pypi.org"})` (la base sigue siendo exactamente pypi.org; no se
   contaminó con hosts de Capa 3).
2. El conjunto de hosts que **cualquier** fuente puede aportar ⊆ `{"api.osv.dev", "depscope.dev"}`
   (un allowlist global cerrado de hosts conocidos), y `depscope.dev` solo aparece con
   `enable_watchlist=true`. Ningún host se construye dinámicamente desde entrada no confiable: los
   hosts vienen de `Config` validado (host https bien formado, R5.2) y de constantes de módulo.

**Alternativas.** (a) *Constante global con los 3 hosts*: simple pero permite `depscope.dev` con
watchlist off (viola R2.1) y diluye la base. Rechazada. (b) *Allowlist totalmente dinámica desde
config sin base anclada*: máximo poder de configuración pero pierde el guardia anti-vacuo (un
config malicioso podría meter cualquier host). Rechazada: la base anclada + el cierre `⊆ {hosts
conocidos}` es el balance. (c) *Un cliente HTTP por host*: duplicación; la allowlist por-instancia
ya aísla.

**Trade-offs.** ➕ La base sigue anclada y verificable; `depscope.dev` solo con watchlist activa
(R2.1 por construcción); cierre de hosts conocidos verificado estáticamente; sin contaminar el
Hito 1. ➖ La allowlist deja de ser una sola constante (hay base + efectiva); el test estático se
vuelve un poco más rico (dos invariantes en vez de una). ➖ `_validate_url` consulta
`self._allowed_hosts` en vez de la global (cambio quirúrgico en `http_client`).

**Consecuencias.** `http_client` gana `extra_allowed_hosts` en `__init__`; `_is_allowed` pasa a
recibir el conjunto efectivo `self._allowed_hosts`, y **el `_RejectRedirectHandler` recibe ese mismo
conjunto efectivo en construcción** (fix SSRF del finding rojo: la URL inicial Y las redirecciones se
validan contra la MISMA allowlist por-instancia, no contra la global `{pypi.org}` — §3.3). El test
estático del Hito 1 se amplía a las dos invariantes, más un test de redirect `api.osv.dev → host
arbitrario ⇒ NetworkUnverifiableError`. Riesgo: ver §8 RISK-H2-1 (transporte a hosts nuevos).

---

### ADR-10 — Degradación segura de threat-intel: `unverifiable` (default) vs `warn` (válvula)

**Contexto.** Si OSV/depscope no responden (timeout, 5xx, 429 agotado, 4xx inesperado, len
mismatch, corpus ilegible), SlopGuard **nunca** debe reportar un falso "todo bien" (NFR-Degr.1).
Pero tampoco debe convertir un fallo de red en un `block` espurio (FP). ¿Qué estado toma una dep
cuyo threat-intel no se pudo verificar, y cómo interactúa con los veredictos deterministas que
**sí** se calcularon?

**Decisión.** Señal blanda `THREATINTEL_UNVERIFIABLE` (`is_soft=True`, `weight=0`) que **nunca**
eleva por sí sola a warn/block (R3.3, preserva la invariante anti-FP), y que marca el `status` de
la dep a `unverifiable` **solo si no hay un veredicto dominante** de otra capa:

```
prioridad de status/verdict para la dep:
  MALICIOUS/NONEXISTENT/typosquat-block  -> block        (domina sobre el threat-intel caído)
  warn por score                          -> warn         (domina)
  THREATINTEL_UNVERIFIABLE (sin lo anterior) -> status=unverifiable, verdict=None  (R1.6/R4.2)
  todo limpio + threat-intel limpio       -> allow
```

Es decir: un block determinista (typosquat) **domina** sobre un OSV caído (R1.6 "salvo que
Capa 0/1/2 ya hayan determinado block"); un OSV caído sobre un paquete por lo demás limpio ⇒
`unverifiable` (exit 3), no `allow`. **Válvula de escape configurable** `threatintel_degraded_status`:
- `"unverifiable"` (default): comportamiento anterior; exit 3 distinguible de allow (R4.2). Apto
  para DevSecOps que no toleran un gate ciego.
- `"warn"` (documentado, opt-in): el threat-intel caído eleva a `warn` (exit 1) en vez de
  `unverifiable`. Para equipos que prefieren "avisar y seguir" sin romper el pipeline por un OSV
  flaky. Aun así **nunca** `allow` ni `block`, y nunca por sí sola si hay block dominante.

**Alternativas.** (a) *Fallo de threat-intel ⇒ `block`*: máxima seguridad pero FP masivos cuando
OSV tiene un mal día; contradice "el ruido es el enemigo". Rechazada. (b) *Fallo ⇒ silencioso
`allow`*: viola NFR-Degr.1 (falso "todo bien"). Rechazada de plano. (c) *Solo `unverifiable` sin
válvula*: más simple pero rígido; la válvula `warn` cubre un caso de uso real (CI tolerante) sin
comprometer la seguridad (sigue sin ser allow). El requirements ya la lista como alternativa
documentada (tabla R5).

**Trade-offs.** ➕ Nunca falso allow, nunca FP por red; respeta la invariante anti-FP; el block
determinista domina; válvula para CI tolerante. ➖ Dos modos de degradación que probar; el modo
`warn` debe documentarse con su implicación de seguridad (un OSV caído no bloquea, solo avisa). ➖
`status=unverifiable` por threat-intel reusa `network_unverifiable` como `error_category`
(sin categoría nueva, R-introducción), lo que mezcla "PyPI caído" y "OSV caído" en la misma
categoría operacional; se distingue por la señal `THREATINTEL_UNVERIFIABLE` en la explicación.

**Consecuencias.** `build_dependency_result` consulta `config.threatintel_degraded_status` para
decidir entre `unverifiable`/`warn` cuando la única señal relevante es `THREATINTEL_UNVERIFIABLE`.
La precedencia de exit codes del Hito 1 (block2 > unverif3 > warn1 > allow0) absorbe ambos modos
sin cambios. Riesgo: ver §8 RISK-H2-4.

**Interacción `degraded_status=warn` × `--strict` (finding amarillo/trazabilidad R4.3 — ambigüedad
resuelta).** Hay una tríada no documentada: con `threatintel_degraded_status="warn"`, un OSV caído
sobre una dep por lo demás limpia produce `verdict=WARN`; y `aggregate_exit_code` (Hito 1) devuelve
**exit 2** para cualquier `WARN` bajo `--strict`. Por tanto **OSV flaky + válvula `warn` + `--strict`
⇒ exit 2** (rompe el pipeline), lo que aparenta contradecir la promesa de la válvula `warn` ("avisar
y seguir sin romper"). **Decisión (opción a — coherencia con el Hito 1):** se **acepta** que
`--strict` eleve el `warn` de threat-intel a exit 2, y se **matiza la promesa** de la válvula:

- `degraded_status="warn"` significa "el threat-intel caído es un **warn**, no un unverifiable" — y
  `--strict` trata **todo** warn como fallo, por diseño del Hito 1 (R4.3/R7.6). Es **consistente**:
  `--strict` es precisamente el modo "cualquier aviso me rompe el build". No se introduce una
  excepción especial para `THREATINTEL_UNVERIFIABLE` bajo strict (sería una inconsistencia sutil y
  difícil de razonar: "este warn sí rompe, este otro no").
- **Guía documentada para el operador (README + ADR):** quien quiera "avisar y seguir aun en strict"
  debe usar `degraded_status="unverifiable"` (default) — exit 3, que es un fallo **operacional**
  distinguible y que `--strict` **no** convierte en exit 2 (strict solo toca warn). Es decir, el modo
  tolerante a OSV-flaky bajo strict es `unverifiable`+exit-3 (distinguible y filtrable en CI), no
  `warn`. La válvula `warn` es para CI **sin** `--strict`.
- Se rechaza la opción (b) ("THREATINTEL_UNVERIFIABLE nunca eleva a exit 2 bajo strict") por romper
  la semántica uniforme de `--strict` del Hito 1.

**Tabla de la tríada (test obligatorio, RISK-H2-4):**

| degraded_status | --strict | dep limpia + OSV caído ⇒ verdict | exit |
|---|---|---|---|
| unverifiable (default) | no | status=unverifiable | 3 |
| unverifiable (default) | sí | status=unverifiable (strict no toca unverifiable) | 3 |
| warn | no | warn | 1 |
| warn | sí | warn ⇒ strict lo eleva | 2 |

---

## 6. Trazabilidad (requisito → diseño)

| Req | Componente / Decisión |
|---|---|
| R1.1 | `engine._scan` recolecta FOUND → `resolver.resolve_threatintel` → `osv.OsvSource.query_batch` (`POST /v1/querybatch`, ecosystem PyPI, nombre PEP 503), chunked (§3.2, §4, ADR-08) |
| R1.2 | `osv.py` filtra `vulns[].id` prefijo `MAL-` ⇒ `MaliceState.MALICIOUS` + `Advisory`; `verdict.py` override block, `advisories[]` con enlace canónico (ADR-06) |
| R1.3 | `osv.py`: IDs sin prefijo `MAL-` (GHSA/CVE/PYSEC) se ignoran (sin señal, sin alterar veredicto) |
| R1.4 | `osv.py`: `results[i]` `{}`/`vulns=[]`/ausente ⇒ `MaliceState.CLEAN` (sin señal L3) |
| R1.5 | `engine`: solo `found` (state==FOUND) van a `resolve_threatintel`; NOT_FOUND/UNVERIFIABLE excluidos (ADR-08) |
| R1.6 | `osv._retry_batch` (backoff exp. base 0.5s, deadline=`osv_timeout_total_por_lote_s`, max_attempts=`osv_reintentos`+1, reusa semántica de `_sleep_within_budget`): 5xx/timeout/conexión caída tras reintentos ⇒ `UNVERIFIABLE`; `verdict.py` rama nueva degrada a `unverifiable` salvo block/warn dominante (§3.5, ADR-10) |
| R1.7 | `http_client`: `_HTTP_RATE_LIMIT=429` ⇒ `is_transient=True` (se reintenta); 4xx≠429 inesperado o 429 agotado ⇒ `UNVERIFIABLE`, nunca CLEAN (§3.2/§3.3) |
| R1.8 | `osv._build_body`: solo `{ecosystem, name}` normalizado + **validado por `_is_valid_osv_name` (charset `^[a-z0-9-]…$`)**; nombre inválido se excluye del POST y queda `UNVERIFIABLE` (§3.2); nunca manifiesto/rutas/versión (NFR-Priv.1, NFR-Seg.4) |
| R2.1 | `registry`: `WatchlistSource` no se instancia si `enable_watchlist=false`; `depscope.dev` no entra al allowlist (ADR-09 por construcción) |
| R2.2 | `watchlist.WatchlistSource`: GET corpus en runtime, caché TTL 24h; nunca embebido/redistribuido (CC-BY-NC-SA) (§2.5/§3.4) |
| R2.3 | `watchlist`: match exacto nombre normalizado ∈ corpus ⇒ `KNOWN_HALLUCINATION` + fuente+fecha |
| R2.4 | `verdict.py`: `KNOWN_HALLUCINATION` + `NONEXISTENT` ⇒ ambas reportadas, block (ADR-06/07, R3.4) |
| R2.5 | `watchlist`: corpus ilegible/sin respuesta ⇒ watchlist `UNVERIFIABLE`, no invalida OSV ni deterministas (composite §2.2, ADR-10) |
| R2.6 | `render_*` + `ThreatIntelResult.watchlist_source/date`: atribución+licencia en JSON y docs (R7.2) |
| R3.1 | `verdict._has_malicious` tras `ctx.is_unverifiable` (Capa 0) y antes de `_has_nonexistent`: `MALICIOUS` ⇒ block override, score=None, precedencia máx, advisories vía `_advisories_from_signals` (§3.5, ADR-06) |
| R3.2 | `scorer`: `KNOWN_HALLUCINATION` dura weight=85 ≥ umbral_block ⇒ block por score; participa en `_max_hard_weight` (no se filtra por code, a diferencia de NONEXISTENT/MALICIOUS) (§2.1, ADR-07) |
| R3.3 | `THREATINTEL_UNVERIFIABLE` blanda weight=0; `ctx.is_unverifiable` queda SOLO de Capa 0; la señal L3 blanda eleva a `status=unverifiable` por rama dedicada de `build_dependency_result` (no por ctx), nunca sola a warn/block; invariante anti-FP intacta (SOFT_CAP sin cambios, §3.5, ADR-07/10) |
| R3.4 | `verdict.py`/`scorer`: todas las señales contribuyentes en `signals[]`; block se mantiene (ADR-06) |
| R3.5 | orden de capas fijo 0→1→2→3; determinismo relativo a caché (engine §4, ADR-08) |
| R3.6 | Capa 3 corre tras Capa 0 (solo FOUND); `resolve_threatintel` entre L0 y bucle por-dep (ADR-08) |
| R4.1 | `aggregate_exit_code` sin cambios: any block ⇒ exit 2 (incluye MALICIOUS y KNOWN_HALLUCINATION) |
| R4.2 | `THREATINTEL_UNVERIFIABLE` sin block ⇒ status unverifiable ⇒ exit 3 (ADR-10); o `warn` (exit1) con válvula |
| R4.3 | `--strict`: `THREATINTEL_UNVERIFIABLE` (blanda) no eleva a warn por sí sola (R3.3, scorer). Tríada `degraded_status=warn × strict`: warn-de-threatintel SÍ sube a exit 2 bajo strict (coherente con Hito 1); modo tolerante = `unverifiable`+exit 3 (ADR-10, tabla de tríada) |
| R5.1 | `config.load_config`: 14 defaults L3, precedencia CLI > archivo > defaults (§3.6) |
| R5.2 | `config._validate_ranges` + validación host https / path / bool / `degraded_status` ∈ enum (§3.6) |
| R5.3 | `enable_layer3=false` ⇒ `source=None` ⇒ `ti={}`, sin hosts nuevos, comportamiento Hito 1 (engine §4, ADR-09) |
| R5.4 | `Config`: host/path/TTL/timeout de OSV y watchlist independientes (§3.6) |
| R6.1 | `osv`/`watchlist` cachean vía `DiskCache.get_blob`/`put_blob` (método genérico JSON-only que reusa `_atomic_write`/perms 0700-0600), clave `sha256(f"{namespace}:{key}")`, `cache_schema_version="ti-1"`, validador por fuente, TTL propios (§2.5) |
| R6.2 | caché hit vigente ⇒ sin red (osv per-nombre, watchlist corpus) (§2.5, ADR-08) |
| R6.3 | `--no-cache` ⇒ `DiskCache(enabled=False)` también para threat-intel (reuso Hito 1) |
| R6.4 | `resolver`: dedup GLOBAL antes del chunking ⇒ claves disjuntas entre chunks; chunk ≤ `osv_batch_max`; `len(results)==len(queries)` por chunk; reensamblado por nombre único con cobertura total (§3.2 contrato de reensamblado); presupuesto por lote vía `_retry_batch` (§3.5, ADR-08) |
| R6.5 | `resolver`: > `osv_batch_max` ⇒ múltiples lotes sin exceder el límite por request |
| R6.6 | dedup por nombre normalizado + caché por-nombre ⇒ ≤1 consulta por nombre por corrida (ADR-08) |
| R6.7 | batch (1-pocos requests) + caché ⇒ objetivo 30 deps ≤12s (ADR-08, criterio dominado por latencia) |
| R7.1 | `render_human`: IDs `MAL-*`, resumen saneado, enlace, acción "no instalar" (advisories[]) |
| R7.2 | `render_*`: fuente+licencia del corpus watchlist (`watchlist_source/date`) (R2.6) |
| R7.3 | `render_json` `schema_version=1.1`, `signals[]` L3 + `advisories[]`, claves estables, orden determinista (§2.4) |
| R7.4 | `normalize.sanitize_for_output` (reuso) sobre IDs/resúmenes externos de OSV/depscope; sin rutas abs |
| R7.5 | `engine._assemble_report`: orden `unverifiable→block→warn→allow`, luego nombre (sin cambios) |
| R8.1 | `ThreatIntelSource` (Protocol) desacopla Capa 3 de la red concreta; contrato import-linter (1) materializado en pyproject: `core.layers`+`core.scoring` ✗→ `core.threatintel` (entero) + `core.net` (§1.3) |
| R8.2 | nueva fuente = nuevo módulo que implementa el Protocol, sin tocar capas/scoring (§1.1/§3.1) |
| R8.3 | `core.layers.layer3_threatintel` consume `ThreatIntelResult`/`Advisory` como datos (de `core.models`), NO importa `core.threatintel.*`; contratos import-linter (1)+(3) materializados (§1.3) |
| NFR-Seg.1 | `http_client`: HTTPS + TLS verificado no desactivable + allowlist efectiva acotada; sin redirect cross-host (ADR-09) |
| NFR-Seg.2 | `safe_json_loads` (reuso) sobre respuestas OSV/depscope; sin eval/pickle/marshal (AST) |
| NFR-Seg.3 | Capa 3 solo inspecciona IDs/nombres de advisories; nunca ejecuta/importa paquetes (AST) |
| NFR-Seg.4 | `osv._build_body`: solo nombre+ecosistema validados/saneados, sin reflejar entrada cruda (R1.8) |
| NFR-Priv.1 | OSV/depscope reciben solo nombre+ecosistema, nunca manifiesto/rutas/usuario (R1.8/R3.4 §3.2/3.4) |
| NFR-Priv.2 | `enable_layer3=false` ⇒ modo solo-deterministas, sin terceros distintos de PyPI (ADR-09) |
| NFR-Priv.3 | §3.2/§3.4 documentan qué se envía, a qué hosts, bajo qué condiciones (transparencia) |
| NFR-Degr.1 | fuente caída ⇒ `UNVERIFIABLE` por dep, nunca falso allow; deterministas preservados (ADR-10) |
| NFR-Det.1 | `now_epoch` único; `ti` inyectado como entrada pura a Capa 3; orden 0→1→2→3; sin timestamps en JSON (engine §4) |
| NFR-Costo.1 | OSV gratis sin clave; depscope opcional gratis; sin servicios pagos (§3.2/§3.4) |
| NFR-Mant.1 | cero deps runtime (reusa stdlib `urllib`/`json`/`hashlib`), mypy strict, ≤50 líneas, docstrings ES |
| NFR-Compat.1 | cambios aditivos: `schema_version` 1.0→1.1, `DependencyResult.advisories` default (), Capa 3 activable/desactivable; Hito 1 intacto (§2.3/§2.4) |
| Propiedad estática 1 | import-linter contrato (1) MATERIALIZADO en pyproject: `core.layers`+`core.scoring` ✗→ `core.threatintel`+`core.net`. `Advisory` en `core.models` (hoja) ⇒ sin excepción de frontera (§1.3) |
| Propiedad estática 2 | import-linter contratos (2)+(3): `source` ✗→ `core.net`; `layer3_threatintel` ✗→ impls `osv/watchlist/composite/resolver`. CLI ✗→ core (contrato Hito 1) (§1.3) |
| Propiedad estática 3 | AST/lint (ruff select S, Hito 1): sin eval/exec/pickle/marshal sobre respuestas OSV/depscope (NFR-Seg.2) |
| Propiedad estática 4 | test estático: `ALLOWED_HOSTS=={pypi.org}` + hosts efectivos ⊆ `{api.osv.dev, depscope.dev}`, depscope solo si watchlist; redirect handler valida contra el conjunto EFECTIVO inyectado (§3.3, ADR-09) |

**Sin requisitos huérfanos:** R1.1–R8.3 y todos los NFR/propiedades estructurales están mapeados.
Los mecanismos antes implícitos (presupuesto de lote OSV, clasificación 429, flujo de
`THREATINTEL_UNVERIFIABLE` por `status`, contrato de caché L3, validación host/path, contratos
import-linter, charset del POST, redirect handler por-instancia) quedan **especificados** en §2.1,
§2.5, §3.2, §3.3, §3.5, §3.6, §1.3 y §4.1 — sin huérfanos de trazabilidad.

---

## 7. Non-goals (lo que este diseño NO hace)

- No mide ni reporta vulnerabilidades generales (CVE/GHSA/PYSEC) como criterio de veredicto: solo
  `MAL-*`. SlopGuard no es un escáner de CVEs.
- No redistribuye ni embebe el corpus depscope: solo consulta online + caché local + atribución
  (CC-BY-NC-SA).
- No pagina respuestas de OSV: un `next_page_token` ⇒ ese nombre `unverifiable` (conservador);
  paginar es post-MVP.
- No ejecuta/importa/`eval` código de paquetes; solo inspecciona IDs de advisories y nombres.
- No usa LLM/embeddings (eso es Capa 4 / Hito 3); no implementa frontends pre-commit/Action (Hito 4);
  no soporta npm (post-MVP).
- No introduce nuevas `ErrorCategory` operacionales totales: el fallo de threat-intel reusa
  `network_unverifiable` por-dependencia.
- No persiste fallos transitorios (`UNVERIFIABLE`) en caché; no incluye timestamps de reloj en el JSON.
- No hace fuzzy match en la watchlist (eso es Capa 1): solo igualdad exacta de nombre normalizado.

---

## 8. Tareas marcadas para `developer-complex` (alto riesgo)

Todas heredan el contrato de seguridad del Hito 1 (TLS no desactivable, anti-bomba, degradación
segura, R6.5). Requieren tests con servidor local malicioso y de propiedad.

1. **RISK-H2-1 — Transporte a hosts nuevos + `post_json` + allowlist por-instancia (ADR-09, ADR-08).**
   POST con cuerpo JSON sobre `SecureHttpClient`; allowlist efectiva = base anclada + extra por
   instancia; `_validate_url` Y el `_RejectRedirectHandler` validan contra el MISMO conjunto efectivo
   `self._allowed_hosts` inyectado (fix SSRF, §3.3); `_HTTP_RATE_LIMIT=429`/`5xx` clasificados
   transitorios. Predicado `_is_valid_https_host` rechaza IP/`localhost`/userinfo/puerto/path/no-FQDN
   y exige dominio cerrado (§3.6, anti-SSRF a host interno). Riesgo SSRF si el extra no se acota o el
   redirect handler consulta la global en vez del efectivo. Tests: redirect cross-host desde
   `api.osv.dev` ⇒ rechazado; redirect `api.osv.dev → pypi.org` ⇒ rechazado; host no permitido;
   `depscope.dev` bloqueado con watchlist off; `osv_host`=IP/localhost/`host:port` ⇒ exit 3;
   `429 ⇒ reintento ⇒ UNVERIFIABLE`; guardia estático de las dos invariantes de allowlist.

2. **RISK-H2-2 — Parseo defensivo de respuestas OSV/depscope + caché threat-intel.**
   `results[i]` posicional con validación `len(results)==len(queries)` **por chunk** y reensamblado
   por nombre único (§3.2); filtrado `MAL-*` con validación de `id` (`^MAL-[0-9A-Za-z-]+$`) antes de
   construir URL (que se **reconstruye**, no se refleja); nombre del POST validado por
   `_is_valid_osv_name` (§3.2, charset); corpus depscope con estructura tolerante + **cap
   `_WATCHLIST_MAX_NAMES` y charset por nombre validado AL LEER** (§2.5, anti-envenenamiento); reuso
   de `safe_json` + streaming + límites; caché `get_blob`/`put_blob` namespaced JSON-only
   atómica/validada (`cache_schema_version="ti-1"`, perms 0700/0600, UNVERIFIABLE no se cachea).
   Riesgo: inyección de terminal/log/JSON vía IDs/resúmenes externos (saneo R7.4), len-mismatch
   tratado como limpio (prohibido), corpus envenenado (falsos KNOWN_HALLUCINATION o retiro de
   alucinados). Tests: response truncada, `id`/nombre con ANSI/CRLF, `results` desalineado, corpus
   no-lista, corpus sobre el cap, blob de caché con `state=unverifiable` o schema desviado ⇒ miss,
   JSON bomb.

3. **RISK-H2-3 — Intercalado batch + concurrencia en el engine (ADR-08).**
   La pieza más cambiada: barrera entre Capa 0 (concurrente) y el batch; chunking ≤ `osv_batch_max`
   con dedup; presupuesto de timeout por lote; caché por-nombre mezclada con miss del lote; `ti`
   inyectado como entrada pura a Capa 3 preservando orden 0→1→2→3 y `now_epoch` único. Riesgo:
   condiciones de carrera al mezclar caché/red, determinismo relativo a caché, pérdida de un nombre
   entre Capa 0 y el batch. Tests: permutación del lote (R3.5), >1000 deps (múltiples lotes),
   solape de caché entre corridas, lote con FOUND+NOT_FOUND+UNVERIFIABLE mezclados.

4. **RISK-H2-4 — Override de veredicto `MALICIOUS` + precedencias + degradación (ADR-06, ADR-07, ADR-10).**
   Nueva rama de override con precedencia máxima (orden exacto §3.5: `ctx.is_unverifiable` →
   `_has_malicious` → `_has_nonexistent` → score → rama `THREATINTEL_UNVERIFIABLE` que respeta
   `threatintel_degraded_status`). `ctx.is_unverifiable` queda SOLO de Capa 0 (no lo toca threat-intel
   caído). Coexistencias: MALICIOUS+NONEXISTENT, MALICIOUS+typosquat, MALICIOUS+THREATINTEL_UNVERIFIABLE
   (block, no degrada), KNOWN_HALLUCINATION+NONEXISTENT, KNOWN_HALLUCINATION+THREATINTEL_UNVERIFIABLE.
   `KNOWN_HALLUCINATION` dura peso 85 entra al scorer (no se filtra); `MALICIOUS` se excluye de
   `_max_hard_weight` por simetría con NONEXISTENT. Tríada `degraded_status=warn × strict` ⇒ exit 2
   (documentada en ADR-10). Riesgo: romper la invariante anti-FP, el flujo de status por la señal L3
   blanda, o la precedencia de exit codes. Tests: **tabla exhaustiva de §3.5 + tabla de tríada de
   ADR-10** + propiedad anti-FP (blandas+THREATINTEL_UNVERIFIABLE nunca cruzan umbral_warn por sí
   solas).

**Criptografía:** solo `hashlib.sha256` (claves de caché namespaced), sin esquemas custom.
**Migraciones:** ninguna de datos; `schema_version` 1.0→1.1 es aditiva (lectores 1.0 ignoran
`advisories`); caché threat-intel usa su propio `cache_schema_version="ti-1"` separado del Hito 1.
