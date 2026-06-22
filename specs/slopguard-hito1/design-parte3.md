# Diseño SlopGuard (Hito 1) — Parte 3: ADRs y Trazabilidad

> Continuación de `design.md` y `design-parte2.md`. Secciones §5 (ADRs) y §6 (Trazabilidad).

---

## 5. ADRs

### ADR-01 — Función de scoring determinista (señales de capas 0/1/2 → 0-100)

**Contexto.** Hay que combinar señales heterogéneas en un score entero 0-100 determinista,
con override de inexistencia fuera del scoring (R5.2), regla de no-factor-único para señales
blandas (R5.6) y el objetivo dominante de **minimizar falsos positivos** ("el ruido es el
enemigo"). Defaults: `umbral_block=80`, `umbral_warn=50`, `c2_max_contrib=10`.

**Decisión.** Modelo **aditivo con saturación** y separación en dos clases de señal:

- **Señales DURAS** (basadas en el nombre; cruzan a warn/block). Mutuamente excluyentes
  TYPOSQUAT ⊕ NAME_UNTRUSTED (si el nombre supera `nombre_max_chars` no se corren distancias):

  | Señal | Condición (mejor candidato top-N) | Peso |
  |---|---|---|
  | TYPOSQUAT (dl=1) | mejor Damerau-Levenshtein `== 1` | 60 |
  | TYPOSQUAT (dl=2) | mejor DL `== 2` | 40 |
  | TYPOSQUAT (jw fuerte) | DL>dl_max y Jaro-Winkler `≥ 0.95` | 30 |
  | TYPOSQUAT (jw débil) | DL>dl_max y `0.92 ≤ JW < 0.95` | 25 |
  | NAME_UNTRUSTED | `len(nombre) > nombre_max_chars` | 30 |

- **Señales BLANDAS** (corroborantes, acotadas): NEW_PACKAGE `+15`; Capa 2 =
  `min(WEAK_METADATA(7) + LOW_VERIFIABILITY(5), c2_max_contrib=10)` ⇒ aporte L2 ∈ {0,5,7,10}.

  `score = min(100, dura + min(blandas, 25))`.

**Invariante anti-FP (núcleo del diseño).** Suma máxima de señales blandas = `15 + 10 = 25`,
estrictamente **< `umbral_warn` (50)**. Por tanto **ninguna combinación de señales blandas por
sí sola** puede producir warn ni block: un paquete que **existe** y **no** dispara typosquat
nunca supera 25 → siempre `allow`. Solo el typosquatting (señal dura) o la inexistencia
(override) elevan a warn/block. Esto satisface R5.6 *por construcción* y minimiza FP.

**Condición efectiva de `block` (≥80).** Como blandas ≤25, se requiere dura ≥55 ⇒ **solo
`dl=1`** califica, y aún necesita ≥20 de blandas (NEW_PACKAGE 15 + L2 ≥5). En palabras:
*bloqueo automático ⟺ nombre a 1 edición de un paquete popular **Y** recién publicado **Y**
con metadatos débiles/sin repo*. Esa conjunción es la firma de un typosquat real; un paquete
establecido (p. ej. `attr` vs `attrs`, dl=1) **no** es nuevo ni débil ⇒ score 60 ⇒ `warn`
(humano confirma), nunca block. `dl=2` satura en 65 ⇒ `warn` (mayor riesgo de FP con 10k
nombres; `--strict` lo eleva a fallo en CI).

**Override e independencia.** Inexistencia (404) ⇒ `verdict=block`, `score=None`, **fuera** de
esta función (R5.2), independiente de `umbral_block`. `unverifiable` ⇒ sin score (R5.8).
Pertenencia exacta al top-N ⇒ sin señal L1 (R3.2); no se usan pesos negativos (modelo de
riesgo no-negativo, evita underflow y mantiene 0-100).

**Alternativas.** (a) *Media ponderada normalizada*: difícil de razonar, los umbrales pierden
significado absoluto, riesgo de FP por inflado. (b) *Reglas if/else jerárquicas puras*: menos
explicable como score continuo y frágil ante nuevas señales. (c) *Pesos negativos
("bonus" por popularidad)*: introduce underflow y comportamiento no monótono.

**Trade-offs.** ➕ Determinista, explicable señal-a-señal, FP minimizados por invariante
estructural, extensible (añadir señales blandas no rompe el techo si se respeta el cap). ➖
`dl=2` nunca auto-bloquea (mitigado con `--strict`); los pesos son heurísticos iniciales a
calibrar con `depscope` en Hito 3.

**Consecuencias.** Pesos viven en una tabla/constantes versionadas; cambiarlos es una decisión
trazable. Tests de propiedad: (i) sin typosquat ni inexistencia ⇒ nunca > `umbral_warn`-1;
(ii) determinismo bajo permutación del lote (R5.7). **Riesgo (delegar a `developer-complex`):**
ninguno especial aquí, es aritmética pura; sí cubrir con tests de tabla exhaustivos.

---

### ADR-02 — Similaridad: Damerau-Levenshtein + Jaro-Winkler, combinación y cota de coste

**Contexto.** R3 exige DL + JW contra ~10k nombres, determinista, sin red, acotando el coste
cuadrático (R3.6, NFR-Seg.5) y con `nombre_max_chars=100`.

**Decisión.**
- **Combinación:** una entrada *dispara* señal si `1 ≤ DL ≤ dl_max` **o** `JW ≥ jw_min` (R3.3);
  `DL=0` (idéntico) ⇒ sin señal (R3.2). El **candidato primario** (objetivo sospechado, R3.4) se
  elige por: menor DL → mayor JW → nombre ascendente (desempate determinista). El **peso** se
  gradúa según (DL, JW) según la tabla de ADR-01.
- **Cota de coste (prefiltros sobre índices precomputados del dataset):**
  1. **DL acotada con banda + cutoff** (`damerau_levenshtein_bounded(a,b,max_distance)`):
     como `DL ≥ |len(a)−len(b)|`, solo se comparan candidatos con longitud en
     `[L−dl_max, L+dl_max]` (índice `by_length`); el algoritmo aborta la fila si el mínimo
     supera `dl_max` ⇒ O(`|a|·dl_max`) por candidato, no O(`|a|·|b|`).
  2. **JW solo sobre `by_first_char`**: Jaro-Winkler con boost de prefijo da `≥0.92`
     esencialmente cuando se comparte el primer carácter; los near-miss con primer carácter
     distinto los cubre DL (misma longitud ⇒ ya en `by_length`). Cobertura conjunta sólida sin
     escanear los 10k para JW.
  3. **Acotado previo de longitud** (R3.6): si `len > nombre_max_chars` ⇒ **no** se corre
     distancia; se emite NAME_UNTRUSTED. Nombres `≤3` ⇒ sin señal (R3.5).

**Alternativas.** (a) *Solo Damerau-Levenshtein*: pierde transposiciones/prefijos que JW
captura mejor (más FN). (b) *Comparar contra los 10k sin prefiltro*: O(N·|a|²) ≈ 10⁸/dep,
inaceptable y vector de DoS. (c) *BK-tree/trie*: menor coste asintótico pero más complejidad y
estado mutable; innecesario para N=10k con banda+buckets.

**Trade-offs.** ➕ Coste acotado y determinista, cero deps, prefiltros exactos para DL (sin FN)
y sólidos para JW. ➖ El prefiltro JW por primer carácter es heurístico (riesgo teórico de FN
si JW≥0.92 con primer char distinto y longitud fuera de banda; en la práctica improbable y
cubierto por DL). Documentar el supuesto y cubrir con tests.

**Consecuencias.** El dataset se carga como `TopNDataset` con `by_length`/`by_first_char`/
`members` precomputados una sola vez. **Riesgo (delegar a `developer-complex`):** la DL con
banda + cutoff es correctness-critical (off-by-one en transposiciones); aislar con tests
vectoriales (incl. casos `attrs/attr`, `requests/reqursts`, transposiciones `ab↔ba`).

---

### ADR-03 — Transporte HTTP: urllib (stdlib) + ThreadPool + endurecimiento

**Contexto.** Cero deps de runtime (solo stdlib), paralelismo I/O-bound, y NFR-Seguridad.3-4
(HTTPS estricto, allowlist, sin redirecciones cross-scheme/host, límites de respuesta,
anti-bomba). Objetivo R9.8: 30 deps caché fría ≤ `T_ref` (10s).

**Decisión.**
- **HTTP:** `urllib.request` con un `OpenerDirector` construido a medida que **omite el
  redirect handler por defecto** y usa uno propio que **rechaza** cualquier `Location` con
  scheme≠https o host∉allowlist (`{"pypi.org"}`) ⇒ `NetworkUnverifiableError`. `ssl` vía
  `ssl.create_default_context()` (verificación de certificado y hostname **activas**, sin
  opción de desactivar TLS).
- **Lectura segura:** rechazar `Content-Length` > `max_response_bytes`; leer en *chunks*
  acumulando y abortando si excede; **no** anunciar `Accept-Encoding: gzip` (evita bombas de
  descompresión); si llega `Content-Encoding`, descomprimir incrementalmente con cota de salida.
  Parseo con `safe_json_loads(max_json_depth=50)`.
- **Concurrencia:** `ThreadPoolExecutor(max_workers=concurrencia_max)`; **dedup** de nombres
  antes de despachar (no consultar el mismo paquete dos veces — NFR-Rend.2); `socket` con
  `connect_timeout_s`/`read_timeout_s`; reintentos `reintentos_red` con backoff exponencial
  base 0.5s acotado por `timeout_total_por_dep_s`; al agotar ⇒ `unverifiable` (R2.5), nunca
  `allow`. La caché se consulta **antes** de la red por dependencia.

**Alternativas.** (a) `requests`/`httpx`: ergonómicos pero violan "cero deps de runtime" y
amplían la superficie supply-chain de una herramienta de seguridad. (b) `asyncio`/`aiohttp`:
aiohttp es dep externa; asyncio puro con urllib no es natural. ThreadPool I/O-bound es simple
y suficiente para N≈30. (c) Procesos: overhead innecesario.

**Trade-offs.** ➕ Cero deps, control total del endurecimiento, suficiente rendimiento. ➖ Más
código de bajo nivel (redirect handler, streaming, descompresión); el GIL no estorba por ser
I/O-bound.

**Consecuencias.** Todo el acoplamiento a red vive en `core/net` + `adapters/pypi`; las capas
no lo importan (import-linter). **Riesgo alto (delegar a `developer-complex`):** concurrencia +
presupuesto de timeout por dependencia + transporte seguro (redirect handler, streaming caps,
descompresión incremental, `safe_json` de profundidad). Requiere tests con servidor local
malicioso (redirección cross-host, respuesta gigante, JSON profundo, gzip bomb).

---

### ADR-04 — Diseño del adapter para extensibilidad a npm

**Contexto.** R10: añadir npm sin tocar el motor de capas/scoring; core sin deps de CLI;
verificable por análisis estático.

**Decisión.** `EcosystemAdapter` (Protocol) con un primitivo de red único `fetch(name) →
FetchOutcome` que devuelve un **`PackageMetadata` normalizado** (agnóstico de ecosistema), más
`normalize_name`, `load_top_n` y el hook reservado `get_downloads` (None en Hito 1). El motor
de capas consume solo metadatos normalizados; el mapeo de la forma cruda (PyPI JSON, y mañana
el registry de npm) vive dentro de cada adapter. `registry.get_adapter(ecosystem_id)` como
factory (default `"pypi"`). Edad/override/scoring permanecen en el core, no en el adapter.

**Alternativas.** (a) Capas hablando con PyPI directamente: rápido pero rompe R10 y mezcla
responsabilidades. (b) Herencia de clase base abstracta (ABC) en vez de Protocol: válido, pero
Protocol da tipado estructural y evita acoplar por herencia. (c) Plugins por entry-points:
sobre-ingeniería para Hito 1 (un solo ecosistema real).

**Trade-offs.** ➕ Frontera limpia verificable con import-linter; npm = un módulo nuevo. ➖
El modelo normalizado debe ser superset razonable de varios ecosistemas; algún campo podría
no aplicar a npm (se mapea como ausente/booleano).

**Consecuencias.** `PackageMetadata` y `FetchOutcome` son el contrato estable entre adapters y
capas. Contratos import-linter (§1.3) hacen fallar el build si una capa importa `adapters.pypi`.

---

### ADR-05 — Caché en disco segura (JSON-only, atómica, validada)

**Contexto.** R9.1-9.7 + NFR-Seg.6: caché en `~/.cache/slopguard/`, TTL 24h, `--no-cache`,
JSON only (nunca pickle), escritura atómica, claves saneadas (anti path traversal), perms
0700/0600, validación al leer como entrada **no confiable**.

**Decisión.** Una entrada por paquete (§2.6). **Filename = `sha256(f"{ecosystem}:{name}")`**
⇒ elimina path traversal por construcción y normaliza longitud/caso. Serialización **JSON**
exclusivamente. **Escritura atómica:** archivo temporal en el mismo dir + `os.replace`
(rename atómico) tras `flush`; `os.makedirs(mode=0o700)`, `os.chmod(0o600)` en el archivo.
**TTL** por `fetched_at` vs `now`. **Lectura defensiva:** validar `cache_schema_version`,
tipos y rangos de cada campo; **cualquier** fallo (corrupto, esquema viejo, expirado) ⇒ tratar
como miss, refetch, **no** crashear (R9.5). `unverifiable` **no** se cachea (no persistir
fallos transitorios). `--no-cache` ⇒ ni lee ni escribe.

**Alternativas.** (a) `pickle`/`shelve`: prohibido (deserialización insegura, NFR-Seg.2). (b)
SQLite: robusto pero añade complejidad/locks; innecesario para una caché clave-valor pequeña.
(c) Nombre = nombre normalizado del paquete: legible pero arriesga colisiones/caso/traversal;
el hash es más seguro.

**Trade-offs.** ➕ Seguro por construcción, atómico bajo concurrencia, degradación a miss
nunca rompe. ➖ Filenames no legibles (se mitiga guardando `name` dentro); sin invalidación
selectiva más allá del TTL (aceptable en Hito 1).

**Consecuencias.** `DiskCache` encapsula perms, atomicidad y validación. **Riesgo (delegar a
`developer-complex`):** atomicidad/perms bajo concurrencia del ThreadPool y parsing defensivo
de entradas no confiables; tests de corrupción, TTL al límite, y carrera de escritura.

---

## 6. Trazabilidad (requisito → diseño)

| Req | Componente / Decisión |
|---|---|
| R1.1 | `manifests/requirements_txt.py` + `normalize.py` (PEP 503) |
| R1.2 | `manifests/pyproject_toml.py` (`[project].dependencies` + optional) vía `tomllib` |
| R1.3 | `manifests/pip_freeze.py`; `scan_stdin` para `-` |
| R1.4 | `requirements_txt.py`: ignora comentarios/blancos/`-e`/`--hash`/URL/VCS |
| R1.5 | `manifests/includes.py`: resuelve `-r`/`-c` confinado, ciclos, `max_include_depth` |
| R1.6 | `includes.py` → `ManifestParseError` (escape/inexistente) → exit 3 (§3.6) |
| R1.7 | `engine.scan`: manifiesto vacío ⇒ 0 deps, exit 0 |
| R1.8 | `ManifestParseError` con ruta+línea, sin stacktrace (§3.6, R6.5) |
| R1.9 | `Config.max_manifest_bytes`/`max_deps`; chequeo antes de cargar todo |
| R1.10 | `engine`/`base.py`: dedup por nombre normalizado |
| R1.11 | `Dependency.version_pin`; evaluación a nivel paquete (Capa 0) |
| R2.1 | `adapters/pypi.fetch` (PyPI JSON, nombre normalizado) |
| R2.2 | `layer0` + `scoring/verdict`: 404 ⇒ override `block` (ADR-01) |
| R2.3 | `layer0`: edad desde `first_release_epoch` |
| R2.4 | `layer0` NEW_PACKAGE (blanda +15, nunca bloquea sola — ADR-01) |
| R2.5 | `net/http_client` + adapter: reintentos+backoff, `unverifiable` (ADR-03) |
| R3.1 | `layer1` + `similarity/*` (DL+JW), rango 4..`nombre_max_chars` |
| R3.2 | `layer1`: match exacto ⇒ sin señal |
| R3.3 | `layer1`: `DL ≤ dl_max` o `JW ≥ jw_min` ⇒ señal + objetivo (ADR-02) |
| R3.4 | `layer1`: candidato primario por menor DL→mayor JW→nombre (ADR-02) |
| R3.5 | `layer1`: `len ≤ 3` ⇒ sin señal |
| R3.6 | `normalize.bound_name` + NAME_UNTRUSTED; no corre distancia (ADR-02) |
| R3.7 | `layer1` sin red, determinista (dataset local) |
| R3.8 | `engine`/`verdict`: Capa 0 (404) prevalece + nota de dataset desactualizado |
| R3.9 | `dataset/top_n` checksum ⇒ `DatasetIntegrityError` exit 3 (ADR-... NFR-Seg.7) |
| R4.1 | `adapters/pypi`: metadatos solo de PyPI JSON |
| R4.2 | `layer2` WEAK_METADATA (`releases_min`, `metadata_faltantes_min`) |
| R4.3 | `layer2` LOW_VERIFIABILITY (sin repo) |
| R4.4 | `PackageMetadata.in_top_n` (proxy); `get_downloads` hook=None; ausencia no es riesgo |
| R4.5 | `layer2`: aporte ≤ `c2_max_contrib` (cap, ADR-01) |
| R5.1 | `scoring/scorer` (función determinista documentada, ADR-01) |
| R5.2 | `scoring/verdict`: override inexistencia independiente de `umbral_block` |
| R5.3-5.5 | `scoring/verdict`: umbrales block/warn/allow |
| R5.6 | Invariante anti-FP: blandas ≤25 < `umbral_warn` (ADR-01) |
| R5.7 | `engine`/`scorer` deterministas bajo permutación del lote |
| R5.8 | `DependencyResult`: `unverifiable` sin score, nunca `allow` |
| R6.1-6.2 | `render_human` (nombre/score/verdict/explicación/objetivo/acción) |
| R6.3 | `render_json` + `schema_version` (§2.5) |
| R6.4 | `engine`: orden unverifiable→block→warn→allow, luego nombre |
| R6.5 | `normalize.sanitize_for_output` (ANSI/C0-C1/CRLF) en TTY/log/JSON; sin rutas abs |
| R7.1-7.5 | `scoring/verdict.aggregate_exit_code` (precedencia, §3.5) |
| R7.6 | `--strict`: warn→exit 2, etiqueta `warn` se mantiene |
| R8.1 | `config.load_config` (`[tool.slopguard]` / `.slopguard.toml`) |
| R8.2 | precedencia CLI > archivo > defaults |
| R8.3 | validación de rangos ⇒ `InvalidConfigError` exit 3 |
| R8.4 | `Config` defaults = tabla §R8 |
| R9.1-9.2 | `cache/disk_cache` TTL, hit sin red (ADR-05) |
| R9.3 | `--no-cache` ⇒ ni lee ni escribe |
| R9.4 | `ThreadPoolExecutor` + timeouts (ADR-03) |
| R9.5 | `DiskCache.get` ⇒ miss ante corrupto/expirado, no crashea |
| R9.6 | escritura atómica temp+`os.replace`, claves saneadas (hash) |
| R9.7 | JSON only, validación al leer, perms 0700/0600 (ADR-05) |
| R9.8 | ThreadPool + caché ⇒ objetivo `T_ref` (ADR-03) |
| R10.1 | `EcosystemAdapter` desacopla core de PyPI (import-linter) |
| R10.2 | nuevo adapter sin tocar capas/scoring (ADR-04) |
| R10.3 | core sin deps de CLI (import-linter) |
| NFR-Rend.1-2 | ADR-03 (paralelismo, dedup) |
| NFR-Seg.1-2 | regla AST/lint: sin `eval`/`exec`/`pickle`/`marshal`; nunca importa paquetes |
| NFR-Seg.3 | `http_client`: HTTPS+cert+allowlist, sin redirección cross-scheme/host (ADR-03) |
| NFR-Seg.4 | `http_client`+`safe_json`: `max_response_bytes`, streaming, `max_json_depth`, anti-bomba |
| NFR-Seg.5 | `normalize.bound_name` antes de distancia; manejo sin crashear (ADR-02) |
| NFR-Seg.6 | `disk_cache`: claves saneadas + validación al leer (ADR-05) |
| NFR-Seg.7 | `dataset/top_n`: versión+procedencia+checksum (R3.9) |
| NFR-Priv.1-2 | solo PyPI por nombre; sin LLM/terceros; no se envía el manifiesto |
| NFR-Degr.1 | `unverifiable`/exit 3; nunca falso "todo bien" (ADR-03) |
| NFR-Costo.1 | solo PyPI JSON + dataset embebido |
| NFR-Det.1 | `now_epoch` inyectado; resultados inmutables; orden de capas fijo; sin timestamps en JSON |
| NFR-Mant.1 | mypy strict, funciones ≤50 líneas, docstrings español (lint/mypy) |
| NFR-Mant.2 | core capas 0-2 solo stdlib (ADR-03, import-linter) |

**Sin requisitos huérfanos:** R1.1–R10.3 y todos los NFR están mapeados.

---

## 7. Non-goals (lo que este diseño NO hace)
- No ejecuta/importa/`eval` código de paquetes; solo inspecciona metadatos.
- No usa LLM, embeddings ni ML (Hito 1); no consulta descargas reales (hook reservado).
- No implementa Capa 3 (threat-intel) ni Capa 4 (LLM); ni frontends pre-commit/Action.
- No soporta multi-ecosistema simultáneo; npm es post-MVP vía adapter.
- No persiste fallos transitorios en caché; no invalida caché salvo por TTL.
- No incluye timestamps de reloj en la salida JSON (rompería el determinismo).

## 8. Tareas marcadas para `developer-complex` (alto riesgo)
1. **Concurrencia + presupuesto de timeout por dependencia** (ThreadPool, backoff, dedup).
2. **Transporte HTTP endurecido** (redirect handler, streaming caps, descompresión incremental,
   `safe_json` con `max_json_depth`).
3. **Damerau-Levenshtein con banda + cutoff** (correctness-critical: transposiciones, off-by-one).
4. **Caché atómica y validación defensiva** bajo concurrencia (perms, `os.replace`, parsing no
   confiable).
Criptografía: solo `hashlib.sha256` (checksum dataset + claves de caché), sin esquemas
custom. Migraciones: ninguna en Hito 1.
