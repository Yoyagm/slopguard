# Plan de Tareas: SlopGuard (Hito 3 — Capa 4 LLM)

Fuente: `requirements.md` (FASE 1) + `design.md` (FASE 2). Estado inicial: TODO. Orden por dependencias. Roles: `developer` (rutina) / `developer-complex` (alto riesgo: scoring, transporte, concurrencia/seguridad) / `tester` / `security-reviewer` / `critic` / `documenter`. Cada tarea pasa por `code-reviewer` tras implementarse; `security-reviewer` en las olas 2/4/5; `critic` valida contra criterios antes de cerrar.

## Ola 1 — Núcleo de scoring (alto riesgo: invariante anti-block)
| ID | Tarea | Rol | Depende de | Criterios de aceptación | Estado |
|---|---|---|---|---|---|
| H3-T01 | Extender `core/models.py` (hoja): `Layer.L4`; `SignalCode.{LLM_HALLUCINATION_SURFACE,LLM_UNAVAILABLE}`; `Clasificacion` StrEnum; `LlmAssessment`, `HallucinationContext` (frozen+slots); `LayerSignal.is_llm_channel:bool=False`; `DependencyResult.llm_assessment=None`; `ScanSummary.llm_unavailable:int=0` | developer | — | Aditivo y retro-compatible (defaults); frozen+slots; mypy --strict; no rompe constructores/serializadores existentes | DONE |
| H3-T02 | Extender `core/scoring/scorer.py`: `LLM_SOFT_CAP=50` (constante de módulo); `_max_hard_weight` excluye `is_llm_channel`; `_sum_heuristic_soft`/`_sum_llm_soft`; `compute_score` de 3 sumandos; corregir docstring desactualizado | developer-complex | H3-T01 | §2.3 diseño; scorer **puro** (no importa config); `score=min(100, max_hard + min(soft_heur,25) + min(soft_llm,50))` | DONE |
| H3-T03 | Tests de propiedad del scorer (§5.1 #1–#5) | tester | H3-T02 | Anti-block estructural (ninguna combinación sin dura ≥80); falla si señal `is_llm_channel` tiene `is_soft=False`; `_max_hard_weight` ignora canal LLM; partición `{llm}⊆{soft}`; regresión idéntica a H2 sin señal L4 | DONE |
| H3-T04 | `Layer4Config` en `core/config.py` con defaults R5 + validación (host https-FQDN, rangos, `llm_conf_min∈(0,1]`, `gray_edad_max_dias>0`) | developer | H3-T01 | R5.1/R5.2; config inválida ⇒ exit 3 `invalid_config` sin valores a medias | DONE |

## Ola 2 — Transporte LLM, caché y evaluador
| ID | Tarea | Rol | Depende de | Criterios de aceptación | Estado |
|---|---|---|---|---|---|
| H3-T05 | Extender `SecureHttpClient.post_json` con `extra_headers` kw-only allowlisteado (`x-api-key`,`anthropic-version`,`content-type`); merge normalizado a minúsculas, sin sobrescribir `Accept-Encoding: identity` | developer-complex | — | ADR-15; los 2 callers H2 (osv/watchlist) intactos; key nunca en `self`/excepción/log | DONE |
| H3-T06 | Extender `DiskCache.get_blob/put_blob` con `schema_version` por-llamada; sello `'llm-1'` para namespace `llm` | developer | — | §2.4; blobs L4 separados de `'ti-1'` por construcción | DONE |
| H3-T07 | Endurecer `safe_json` (`parse_constant=_reject` ante NaN/Infinity); helper de doble parseo (sobre → `content[0].text`) con `max_json_depth` | developer | — | §5.1 #7; ambos niveles reusan defensas anti-bomba/profundidad | DONE |
| H3-T08 | `core/llm/prompt.py`: `build_prompt` (nombre+contexto encajonados como dato), `RESPONSE_SCHEMA`, `PROMPT_VERSION='h3-v1'` | developer | H3-T01 | R2.1/ADR-19; `json_schema` con `additionalProperties:false`+`required` | DONE |
| H3-T09 | `core/llm/evaluator.py` (Protocol `LlmEvaluator`) + `core/llm/anthropic.py` (`AnthropicEvaluator`): arma request, llama `post_json(extra_headers=...)`, valida esquema + `confianza` con `math.isfinite`, mapea `stop_reason`/errores a abstención (`None`) | developer-complex | H3-T05,H3-T07,H3-T08 | R2/R4/R9.1; contrato de error (200+stop≠end_turn⇒abstención; 4xx perm.⇒sin reintento; 5xx/429/timeout⇒reintento); acceso defensivo a `content[0]`/`usage`; key de env, nunca en `self`/log/excepción; **no** deja escapar la excepción | DONE |
| H3-T11 | Revisión de seguridad ola 2 | security-reviewer | H3-T05,H3-T09 | Prompt-injection (encajonado), no-fuga de key (incl. `__cause__`), allowlist condicional, `safe_json` endurecido | DONE |

## Ola 3 — Capa 4, resolver y motor
| ID | Tarea | Rol | Depende de | Criterios de aceptación | Estado |
|---|---|---|---|---|---|
| H3-T12 | `core/llm/resolver.py` `resolve_layer4`: gating de banda gris (R1.2), orden canónico (nombre normalizado), presupuesto `llm_max_calls` (cache-hits NO cuentan), caché content-addressed | developer-complex | H3-T04,H3-T06,H3-T09 | R1.1–R1.5; subconjunto `LLM_UNAVAILABLE` por tope reproducible entre corridas | DONE |
| H3-T13 | `core/layers/layer4_hallucination.py` `evaluate_layer4` (puro): peso `f(clas,conf)=min(50,floor(W_base*conf))` si `clas∈{conf,typo,fabr}∧conf≥0.5`; emite `LayerSignal(is_soft=True,is_llm_channel=True)` o `LLM_UNAVAILABLE` o nada; `legitimo` NO reduce señales 0–3 | developer | H3-T02,H3-T04 | R2.3/R2.4/R3; importa **solo** `core.models`+`core.config` (NO `core.llm`) | DONE |
| H3-T14 | Wiring en `core/engine.py`: intercalar `resolve_layer4` tras Capa 3; inyectar assessment a `layer4`; `schema_version`→`1.2`; `summary.llm_unavailable`; advertencia agregada (R4.6) | developer | H3-T12,H3-T13 | Orden 0→1→2→3→4; `enable_layer4=false` ⇒ comportamiento idéntico a H2 | DONE |
| H3-T15 | Tests de gating/abstención/degradación (R1,R4) | tester | H3-T14 | Banda gris vs "claramente legítima" como negación exacta (sin solape); tope reproducible; `LLM_UNAVAILABLE` no degrada `status`/exit; advertencia agregada visible | DONE |

## Ola 4 — CLI y salida explicable
| ID | Tarea | Rol | Depende de | Criterios de aceptación | Estado |
|---|---|---|---|---|---|
| H3-T16 | `sanitize_and_truncate` en `core/normalize.py` (sanea PRIMERO, trunca DESPUÉS con marcador) | developer | — | ADR-19; `patron≤280`/`rationale≤1000`; `sanitize_for_output` intacta (test) | DONE |
| H3-T17 | Flags CLI `--enable-layer4`/`--no-layer4`/`--llm-model`; precedencia CLI>archivo>defaults | developer | H3-T04 | R5.1; sin `ANTHROPIC_API_KEY` ⇒ advertencia única, veredictos intactos (R4.1) | DONE |
| H3-T18 | `cli/render_json.py` (schema `1.2`): `signals[]` L4, bloque `llm_assessment` (re-saneado+truncado), `summary.llm_unavailable` | developer | H3-T14,H3-T16 | R7.2/R7.6; defensa en profundidad (no asume que el adaptador truncó); orden determinista | DONE |
| H3-T19 | `cli/render_human.py`: clasificación/confianza/`rationale` marcado "generado por LLM, no verificado", acción **advisory**; saneado+truncado | developer | H3-T14,H3-T16 | R7.1/R7.3/R7.4; transparencia de modelo+`prompt_version` | DONE |
| H3-T20 | Revisión de seguridad ola 4 | security-reviewer | H3-T18,H3-T19 | Saneo+truncado en render; marcado untrusted; sin rutas absolutas ni manifiesto en salida | DONE |

## Ola 5 — Frontera arquitectónica y tests de seguridad
| ID | Tarea | Rol | Depende de | Criterios de aceptación | Estado |
|---|---|---|---|---|---|
| H3-T21 | Añadir contratos import-linter (TOML real, 2 nuevos: `core.layers↛core.llm`, `core.scoring↛core.llm,core.net`) en `pyproject.toml` | developer | H3-T13,H3-T09 | R9.3; `lint-imports` pasa; sin contrato redundante de `core.net` | DONE |
| H3-T22 | Tests de seguridad: no-fuga de API key (incl. cadena `__cause__`), allowlist condicional `api.anthropic.com` solo bajo `enable_layer4`, separación de caché `'llm-1'` (§5.1 #6,#8,#9) | tester | H3-T05,H3-T06,H3-T09,H3-T21 | La key nunca en `str`/`repr` de excepciones, logs, JSON ni blob; host validado | DONE |

## Ola 6 — Evaluación precision/recall (entregable científico)
| ID | Tarea | Rol | Depende de | Criterios de aceptación | Estado |
|---|---|---|---|---|---|
| H3-T23 | Harness `eval/`: dataset versionado (positivos de procedencia independiente; negativos fáciles top-N + difíciles banda gris; splits train/dev/test); runner precision/recall/F1 **por nivel de veredicto**; ablación a nivel de emisión (no flag en scorer) | developer-complex | H3-T14 | R10.1–R10.7; ADR-18; reproducible vía hash de caché; depscope solo consulta+atribución | DONE |
| H3-T24 | ADR de **piso de precisión pre-registrado** (`eval/PREREGISTRO.md`), número fijado en `dev` ANTES de tocar `test`; congelar `prompt_version`+config | developer | H3-T23 | R10.5; `precision(block)=100%`, `precision(warn)`≥línea base H2 | DONE |
| H3-T25 | Test de evaluación que **FALLA** si `precision(warn)`<piso, `precision(block)≠100%` o delta de ablación en `block`≠0 (§5.1 #10) | tester | H3-T23,H3-T24 | La suite puede fallar (no tautológica) | DONE |

## Cierre
| ID | Tarea | Rol | Depende de | Criterios de aceptación | Estado |
|---|---|---|---|---|---|
| H3-T26 | Compuerta de calidad final | critic | H3-T01..H3-T25 | APROBAR/RECHAZAR contra todos los criterios de aceptación EARS y los 10 invariantes §5.1 | DONE |
| H3-T27 | Documentación + release: README/CHANGELOG/LaTeX, atribución depscope, transparencia de privacidad; bump `v0.3.0`; memoria | documenter | H3-T26 | Docs sincronizadas; `schema_version 1.2`; commits convencionales; CI verde | DONE |

## Notas de ejecución
- Cada ola se implementa con `developer`/`developer-complex` → `code-reviewer` (limpia 🔴/🟡) → `security-reviewer` (olas 2/4/5) → `tester` (verde) → `critic`.
- Skills a inyectar por el orquestador (los subagentes no tienen la herramienta Skill): **claude-api** (T05,T08,T09,T23), **senior-secops**/**security-pen-testing** (T11,T20,T22), **threat-detection** (T08,T23), **ci-cd-pipeline-builder**+**changelog-generator** (T27).
- El harness `eval/` NO debe requerir `ANTHROPIC_API_KEY` en CI (usa caché/snapshot publicado); la evaluación con LLM real es manual/opt-in.
