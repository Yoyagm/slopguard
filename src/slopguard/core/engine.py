"""Orquestador del escaneo (T33, R1.7/R5.7/R6.4/NFR-Det.1).

Cablea el flujo completo manifiesto -> parse+dedup+includes -> fetch concurrente
-> capas 0/1/2 -> scoring -> verdict -> `ScanReport` inmutable y ordenado, sin
hablar nunca con la red directamente (eso vive en el adapter, frontera R10.1).

Puntos de entrada (consumidos por la fachada `core.__init__`):
  - `scan_manifest`: manifiesto en disco (detecta tipo, includes confinados).
  - `scan_stdin`: texto en formato pip-freeze (entrada `-`).
  - `scan_dependencies`: lote ya parseado (entrada de bajo nivel).

Invariantes garantizados aqui:
  - `now_epoch` se captura UNA sola vez por corrida e se inyecta a Capa 0
    (NFR-Det.1): la edad es reproducible con datos/cache fijos.
  - Manifiesto vacio => `ScanReport` con 0 resultados y exit 0 (R1.7).
  - Errores OPERACIONALES TOTALES (`ManifestParseError`, `InvalidConfigError`,
    `DatasetIntegrityError`) NO crashean: producen un `ScanReport` con
    `error_category` poblado y summary vacio (exit 3), sin stacktrace crudo ni
    rutas absolutas (R6.5, §3.6). `NetworkUnverifiableError` no llega aqui: el
    adapter la colapsa a `FetchOutcome(UNVERIFIABLE)` por-dependencia.
  - Resultados ordenados `unverifiable -> block -> warn -> allow`, luego nombre
    ascendente (R6.4). El orden es total e independiente del orden de entrada,
    asi que el reporte es determinista bajo permutacion del lote (R5.7).

Frontera de arquitectura: el engine vive en `core` y coordina el adapter via
`get_adapter`/`fetch_many`; las capas y el scoring siguen sin importar red ni
adapter concreto. El engine NO importa la CLI (R10.3, import-linter).
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from slopguard import __version__ as _TOOL_VERSION
from slopguard.core.adapters.base import CandidateFilter, FetchOutcome, FetchState
from slopguard.core.adapters.concurrent import fetch_many
from slopguard.core.adapters.registry import get_adapter
from slopguard.core.config import Config
from slopguard.core.errors import SlopGuardError
from slopguard.core.layers import (
    layer0_existence,
    layer1_similarity,
    layer2_metadata,
    layer3_threatintel,
    layer4_hallucination,
)
from slopguard.core.llm.registry import build_llm_cache, get_llm_evaluator
from slopguard.core.llm.resolver import (
    build_context,
    is_gray_band,
    package_age_days,
    resolve_layer4,
)
from slopguard.core.manifests.detect import detect_and_parse, detect_and_parse_stdin
from slopguard.core.models import (
    Dependency,
    DependencyResult,
    ErrorCategory,
    LayerSignal,
    LlmAssessment,
    MaliceState,
    ScanReport,
    ScanSummary,
    SignalCode,
    Status,
    ThreatIntelResult,
    Verdict,
)
from slopguard.core.scoring.verdict import (
    DepContext,
    aggregate_exit_code,
    augment_with_dataset_note,
    build_dependency_result,
)
from slopguard.core.threatintel.registry import get_threatintel_source
from slopguard.core.threatintel.resolver import resolve_threatintel

if TYPE_CHECKING:
    from slopguard.core.adapters.npm import NpmAdapter
    from slopguard.core.adapters.pypi import PypiAdapter
    from slopguard.core.dataset.top_n import TopNDataset

# Version del esquema de salida (§2.4 Hito 2); sube 1.0 -> 1.1 de forma ADITIVA: se
# anade el campo `advisories` y las senales `layer:3`; ninguna clave 1.0 se quita ni
# renombra, asi un lector 1.0 ignora lo nuevo sin romperse (NFR-Compat.1). Con
# enable_layer3=false la salida es identica al Hito 1 salvo esta version.
# Hito 3 sube 1.1 -> 1.2 de forma ADITIVA: anade senales layer:4, el bloque
# llm_assessment y summary.llm_unavailable; con enable_layer4=false solo cambia esta
# version. Ningun campo previo se quita ni renombra (NFR-Compat.1).
_SCHEMA_VERSION = "1.2"

# Razon saneada cuando una dep FOUND no aparece en el dict de threat-intel (no deberia
# ocurrir por la cobertura total del resolver, pero se degrada a UNVERIFIABLE, jamas
# CLEAN; §4.1 fallback conservador, NFR-Degr.1).
_REASON_TI_AUSENTE = "threat-intel no resuelto para el nombre (cobertura incompleta)"

# Rangos de orden para R6.4: menor = mas arriba en el reporte.
_RANK_UNVERIFIABLE = 0
_RANK_BLOCK = 1
_RANK_WARN = 2
_RANK_ALLOW = 3

# Outcome canonico cuando un nombre no aparece en el dict de `fetch_many` (no
# deberia ocurrir tras la dedup, pero se degrada a UNVERIFIABLE por seguridad).
_UNVERIFIABLE_OUTCOME = FetchOutcome(
    state=FetchState.UNVERIFIABLE,
    error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
)


@dataclass(frozen=True, slots=True)
class _ScanContext:
    """Invariantes compartidos por TODA la corrida, fijados ANTES del bucle por-dep.

    Agrupa los datos que no cambian entre dependencias para que las funciones de
    evaluacion no superen la aridad (PLR0913) y para hacer explicito que son de
    corrida, no por-dep: `now_epoch` se lee UNA vez (NFR-Det.1), `top_n` se carga una
    vez, y `threat_intel` es el resultado del batch de Capa 3 intercalado (§4.1). Frozen
    e inmutable: el bucle por-dep no puede mutar el entorno compartido.

    `ecosystem_id` (H4-T33, ADR-6 pto 6): propagado desde `adapter.ecosystem_id` para
    que `_apply_layer4` lo reenvie a `resolve_layer4`/`evaluate` y selle la clave L4
    por ecosistema (aislamiento npm/PyPI, NFR-Seg.3).

    `candidate_filter` (H4-T23, ADR-4, R6.2): predicado agnostico provisto por
    `adapter.candidate_filter` que el engine pasa a `layer1_similarity.evaluate` por el
    mismo canal que el corpus; `None` (PyPI) = identidad. La Capa 1 lo invoca sin conocer
    su semantica (sin ramificacion por ecosistema en la capa pura, R6.3).
    """

    config: Config
    now_epoch: float
    top_n: TopNDataset
    threat_intel: dict[str, ThreatIntelResult]
    ecosystem_id: str = "pypi"
    candidate_filter: CandidateFilter | None = None


def scan_manifest(
    path: str | Path,
    config: Config,
    *,
    use_cache: bool = True,
    ecosystem_id: str = "pypi",
    manifest_type: str | None = None,
) -> ScanReport:
    """Escanea un manifiesto en disco y produce un `ScanReport` inmutable (§3.1).

    Detecta el tipo, parsea, deduplica, resuelve includes confinados, evalua las
    capas y ordena el resultado. Solo levanta errores del core; cualquier error
    operacional total se devuelve como `ScanReport` con `error_category` (§3.6),
    nunca como stacktrace crudo.

    `manifest_type` es el override opcional de `--manifest-type` (T34): fuerza el
    parser a `{requirements, pyproject, freeze}` y se reenvia tal cual a
    `detect_and_parse` (T11). Si es `None` (default) el tipo se autodetecta por
    nombre/extension, preservando el comportamiento congelado de §3.1. La fachada
    es el unico punto de entrada de la CLI (R10.3), asi que el override del tipo
    debe viajar por aqui: no hay otro camino legitimo desde la CLI a la deteccion.
    """
    try:
        adapter = get_adapter(ecosystem_id, config=config, use_cache=use_cache)
        deps = detect_and_parse(Path(path), config, manifest_type=manifest_type)
    except SlopGuardError as exc:
        return _error_report(exc, ecosystem_id)
    return _scan(deps, config, adapter, use_cache=use_cache)


def scan_stdin(
    text: str,
    config: Config,
    *,
    use_cache: bool = True,
    ecosystem_id: str = "pypi",
) -> ScanReport:
    """Escanea texto en formato pip-freeze leido de stdin (`-`) (§3.1, R1.3).

    Igual que `scan_manifest` pero la entrada llega como texto en memoria; aplica
    el mismo manejo de errores operacionales (`ScanReport` con `error_category`).
    """
    try:
        adapter = get_adapter(ecosystem_id, config=config, use_cache=use_cache)
        deps = detect_and_parse_stdin(text, config)
    except SlopGuardError as exc:
        return _error_report(exc, ecosystem_id)
    return _scan(deps, config, adapter, use_cache=use_cache)


def scan_dependencies(
    deps: Sequence[Dependency],
    config: Config,
    *,
    use_cache: bool = True,
    ecosystem_id: str = "pypi",
) -> ScanReport:
    """Evalua un lote ya parseado de dependencias (entrada de bajo nivel, §3.1).

    Determinista respecto al orden de entrada (R5.7): el reporte final se ordena
    con un criterio total, asi que permutar `deps` no altera el resultado.

    A diferencia de `scan_manifest`/`scan_stdin` (donde `detect_and_parse` ya
    normaliza y deduplica), este punto de bajo nivel no puede asumir que el caller
    paso nombres en forma canonica PEP 503. Por eso normaliza y deduplica aqui con
    la regla del adapter antes de evaluar: asi la clave del dict de `fetch_many`
    (indexado por nombre normalizado) coincide con el lookup del engine, y dos deps
    que colapsen al mismo nombre normalizado (p.ej. `Flask` y `flask`) producen un
    unico resultado, preservando la unicidad de nombres que exige el orden (R5.7).
    """
    try:
        adapter = get_adapter(ecosystem_id, config=config, use_cache=use_cache)
    except SlopGuardError as exc:
        return _error_report(exc, ecosystem_id)
    return _scan(
        _normalize_and_dedup(adapter, deps), config, adapter, use_cache=use_cache
    )


def _normalize_and_dedup(
    adapter: PypiAdapter | NpmAdapter,
    deps: Sequence[Dependency],
) -> tuple[Dependency, ...]:
    """Normaliza el nombre (PEP 503) y deduplica preservando el primer registro.

    Reemite cada `Dependency` con `name` ya normalizado por el adapter y descarta
    las apariciones posteriores del mismo nombre normalizado. Conserva el primer
    `version_pin`/`raw`/`origin` (misma politica de precedencia que el dedup de los
    parsers): el resultado es estable e independiente del orden de entrada (R5.7).
    """
    seen: set[str] = set()
    unique: list[Dependency] = []
    for dep in deps:
        normalized = adapter.normalize_name(dep.name)
        if normalized in seen:
            continue
        seen.add(normalized)
        if normalized == dep.name:
            unique.append(dep)
        else:
            unique.append(_rename(dep, normalized))
    return tuple(unique)


def _rename(dep: Dependency, name: str) -> Dependency:
    """Copia una `Dependency` cambiando solo su `name` (frozen ⇒ se reconstruye)."""
    return Dependency(
        name=name,
        version_pin=dep.version_pin,
        raw=dep.raw,
        origin=dep.origin,
    )


def _scan(
    deps: tuple[Dependency, ...],
    config: Config,
    adapter: PypiAdapter | NpmAdapter,
    *,
    use_cache: bool,
) -> ScanReport:
    """Nucleo del flujo: fetch concurrente, batch threat-intel, capas y ensamblado.

    Intercala (§4.1, ADR-08, RISK-H2-3) un viaje en lote de Capa 3 ENTRE la Capa 0
    (concurrente, per-dep) y el bucle de evaluacion por-dep: tras `fetch_many` recolecta
    los nombres FOUND (R1.5; NOT_FOUND/UNVERIFIABLE excluidos), los resuelve en lote con
    `resolve_threatintel` (fail-closed: chunk caido ⇒ UNVERIFIABLE, jamas CLEAN), y luego
    inyecta `ti[name]` como entrada PURA a la Capa 3 por-dep, preservando el orden 0→1→2→3.

    `now_epoch` se lee UNA sola vez DESPUES del batch (NFR-Det.1): el batch no usa reloj de
    pared para su veredicto, asi que la edad de Capa 0 sigue siendo reproducible. Con
    `enable_layer3=false` la fuente es None, `ti={}` y el flujo es identico al Hito 1 (R5.3).

    Captura los errores operacionales totales que `fetch_many` pueda re-lanzar desde un
    worker (`DatasetIntegrityError`, `InvalidConfigError`); los demas fallos por-dependencia
    ya vienen colapsados a `UNVERIFIABLE` por el adapter.
    """
    if not deps:
        return _empty_report(adapter.ecosystem_id)
    try:
        outcomes = fetch_many(adapter, (dep.name for dep in deps), config)
    except SlopGuardError as exc:
        return _error_report(exc, adapter.ecosystem_id)

    found = _found_names(outcomes)  # R1.5: solo existentes van al batch de Capa 3.
    source = get_threatintel_source(
        config, use_cache=use_cache, ecosystem_id=adapter.ecosystem_id
    )
    threat_intel = resolve_threatintel(source, found, config)

    now_epoch = time.time()  # NFR-Det.1: una sola lectura del reloj, tras el batch.
    ctx = _ScanContext(
        config=config,
        now_epoch=now_epoch,
        top_n=adapter.load_top_n(),
        threat_intel=threat_intel,
        ecosystem_id=adapter.ecosystem_id,  # H4-T33: sella la clave L4 por ecosistema
        candidate_filter=adapter.candidate_filter,  # H4-T23: filtro scoped a Capa 1 (ADR-4)
    )
    results = tuple(
        _evaluate_dependency(dep, outcomes.get(dep.name), ctx) for dep in deps
    )
    results = _apply_layer4(results, deps, outcomes, ctx, use_cache=use_cache)
    return _assemble_report(results, adapter.ecosystem_id)


def _found_names(outcomes: dict[str, FetchOutcome]) -> tuple[str, ...]:
    """Recolecta los nombres con `state==FOUND` desde las CLAVES de `outcomes` (R1.5).

    Derivar de las claves (no de `dep.name`) garantiza que `found` use la MISMA
    normalizacion que el lookup `ti.get(dep.name)` del bucle (ambos son nombres ya
    normalizados PEP 503): cierra el hueco de un falso CLEAN encubierto si una dep
    entrara a OSV con una normalizacion distinta (§4.1, finding bloqueante). Los
    NOT_FOUND/UNVERIFIABLE se excluyen: no se consulta OSV de inexistentes/no verificables.
    """
    return tuple(
        name for name, outcome in outcomes.items() if outcome.state is FetchState.FOUND
    )


def _apply_layer4(
    results: tuple[DependencyResult, ...],
    deps: tuple[Dependency, ...],
    outcomes: dict[str, FetchOutcome],
    ctx: _ScanContext,
    *,
    use_cache: bool,
) -> tuple[DependencyResult, ...]:
    """Segunda pasada de la Capa 4 (Hito 3, two-pass): gating + LLM + re-scoring.

    Con `enable_layer4=false` o sin evaluador (sin clave) devuelve `results` intacto
    (identico al Hito 2). Para las deps en banda gris (sin senal dura ⇒ `max_hard=0`,
    anti-block) y en ORDEN CANONICO (nombre asc), resuelve el LLM (cache + presupuesto),
    anade la senal L4 y re-evalua el veredicto, adjuntando el `llm_assessment`. La Capa 4
    solo puede subir a `warn`, NUNCA a `block` (garantia estructural del scorer).
    """
    if not ctx.config.enable_layer4:
        return results
    evaluator = get_llm_evaluator(ctx.config, use_cache=use_cache)
    if evaluator is None:
        return results  # Capa 4 desactivada o sin ANTHROPIC_API_KEY (R5.3/R4.1)
    cache = build_llm_cache(ctx.config, enabled=use_cache)
    paired = list(zip(deps, results, strict=True))
    gray = _gray_candidates(paired, outcomes, ctx)
    items = [
        (dep.name, build_context(dep.name, result, outcomes.get(dep.name), now_epoch=ctx.now_epoch))
        for dep, result in gray
    ]
    assessments = resolve_layer4(
        evaluator, cache, items, ctx.config, ctx.ecosystem_id, now=ctx.now_epoch
    )
    augmented = {
        dep.name: _augment_with_layer4(dep, result, assessments.get(dep.name), ctx.config)
        for dep, result in gray
    }
    return tuple(augmented.get(dep.name, result) for dep, result in paired)


def _gray_candidates(
    paired: list[tuple[Dependency, DependencyResult]],
    outcomes: dict[str, FetchOutcome],
    ctx: _ScanContext,
) -> list[tuple[Dependency, DependencyResult]]:
    """Filtra las deps en banda gris (ADR-12) y las ordena por nombre (orden canonico).

    La edad sale de `package_age_days` con el reloj unico `ctx.now_epoch` (NFR-Det.1),
    para la rama "joven" del gating.
    """
    gray = [
        (dep, result)
        for dep, result in paired
        if is_gray_band(
            result, package_age_days(outcomes.get(dep.name), ctx.now_epoch), ctx.config
        )
    ]
    return sorted(gray, key=lambda pair: pair[0].name)


def _augment_with_layer4(
    dep: Dependency,
    result: DependencyResult,
    assessment: LlmAssessment | None,
    config: Config,
) -> DependencyResult:
    """Re-evalua una dep gris anadiendo la senal L4 y adjunta el assessment (Hito 3).

    `evaluate_layer4` da `LLM_UNAVAILABLE` (weight 0) si `assessment is None`: el
    veredicto determinista queda intacto (degradacion segura, no degrada exit). Una
    clasificacion de alucinacion de confianza suficiente puede elevar a `warn`.
    """
    l4_signals = layer4_hallucination.evaluate_layer4(assessment, config)
    new_signals = result.signals + l4_signals
    dep_ctx = DepContext(
        name=dep.name,
        version_pin=dep.version_pin,
        is_unverifiable=False,
        error_category=None,
    )
    rebuilt = build_dependency_result(dep_ctx, new_signals, config)
    return replace(rebuilt, llm_assessment=assessment)


def _evaluate_dependency(
    dep: Dependency,
    outcome: FetchOutcome | None,
    ctx: _ScanContext,
) -> DependencyResult:
    """Evalua una dependencia: capas 0/1/2/3 -> senales -> veredicto (R5.2-5.8).

    Si el `FetchOutcome` es UNVERIFIABLE (o ausente por un fallo de despacho), no
    se corre scoring: la dep queda `unverifiable`, sin score y nunca `allow`
    (R5.8). En caso contrario se recolectan las senales de las cuatro capas (la
    Capa 3 solo para FOUND, R1.5) y se delega el veredicto/override a
    `build_dependency_result`.
    """
    resolved = outcome if outcome is not None else _UNVERIFIABLE_OUTCOME
    if resolved.state is FetchState.UNVERIFIABLE:
        return build_dependency_result(
            _unverifiable_context(dep, resolved), (), ctx.config
        )

    signals = _collect_signals(dep.name, resolved, ctx)
    if resolved.state is FetchState.NOT_FOUND and dep.name in ctx.top_n.members:
        # Prioridad Capa 0 sobre top-N (R3.8): el 404 prevalece y se anota el
        # posible desfase del dataset embebido.
        signals = augment_with_dataset_note(signals)
    dep_ctx = DepContext(
        name=dep.name,
        version_pin=dep.version_pin,
        is_unverifiable=False,
        error_category=None,
    )
    return build_dependency_result(dep_ctx, signals, ctx.config)


def _collect_signals(
    name: str,
    outcome: FetchOutcome,
    ctx: _ScanContext,
) -> tuple[LayerSignal, ...]:
    """Recolecta las senales de las capas 0, 1, 2 y 3 en orden fijo (NFR-Det.1).

    El orden de capas es estable (L0 -> L1 -> L2 -> L3) y cada capa consume solo la
    informacion de su entrada PURA inyectada; el scorer es invariante al orden, pero
    mantenerlo fijo facilita la explicacion y los tests (R5.7). La Capa 3 solo corre
    para FOUND (R1.5): un 404 no consulta OSV, asi que su nombre no esta en `threat_intel`.
    """
    config = ctx.config
    signals: list[LayerSignal] = []
    signals.extend(layer0_existence.evaluate(outcome, config, now_epoch=ctx.now_epoch))
    signals.extend(
        layer1_similarity.evaluate(
            name, ctx.top_n, config, candidate_filter=ctx.candidate_filter
        )
    )
    signals.extend(layer2_metadata.evaluate(outcome, config))
    layer3_result = _threat_intel_for(name, outcome, ctx.threat_intel)
    if layer3_result is not None:
        signals.extend(layer3_threatintel.evaluate(layer3_result))
    return tuple(signals)


def _threat_intel_for(
    name: str,
    outcome: FetchOutcome,
    threat_intel: dict[str, ThreatIntelResult],
) -> ThreatIntelResult | None:
    """Resuelve la entrada de Capa 3 para `name`, o None si no aplica (§4.1, R1.5).

    Tres casos, en orden:
    - `threat_intel` vacio (enable_layer3=false) o dep NO FOUND ⇒ None: la Capa 3 NO
      emite senal (comportamiento identico al Hito 1; un 404/UNVERIFIABLE no consulta OSV).
    - dep FOUND con entrada en el dict ⇒ su `ThreatIntelResult` real (CLEAN/MALICIOUS/
      KNOWN_HALLUCINATION/UNVERIFIABLE), inyectado como dato puro a la Capa 3.
    - dep FOUND SIN entrada pese a haber fuente activa (cobertura incompleta, no deberia
      ocurrir por la cobertura total del resolver) ⇒ UNVERIFIABLE conservador, jamas CLEAN
      (NFR-Degr.1): una dep FOUND nunca cae silenciosamente a "Capa 3 sin evaluar".
    """
    if not threat_intel or outcome.state is not FetchState.FOUND:
        return None
    result = threat_intel.get(name)
    if result is not None:
        return result
    return ThreatIntelResult(
        name=name,
        state=MaliceState.UNVERIFIABLE,
        unverifiable_reason=_REASON_TI_AUSENTE,
    )


def _unverifiable_context(dep: Dependency, outcome: FetchOutcome) -> DepContext:
    """Construye el contexto de una dependencia no verificable (R5.8)."""
    category = outcome.error_category or ErrorCategory.NETWORK_UNVERIFIABLE
    return DepContext(
        name=dep.name,
        version_pin=dep.version_pin,
        is_unverifiable=True,
        error_category=category,
    )


def _assemble_report(
    results: tuple[DependencyResult, ...],
    ecosystem_id: str,
) -> ScanReport:
    """Ordena los resultados (R6.4) y ensambla el `ScanReport` con summary y exit.

    El exit code del summary se computa en modo NO estricto (`strict=False`): es
    el codigo base del reporte. La CLI re-aplica `aggregate_exit_code(report,
    strict=...)` con su flag `--strict` (R7.6) sin recalcular el resto del flujo.
    """
    ordered = tuple(sorted(results, key=_result_sort_key))
    counts = _count_verdicts(ordered)
    summary = ScanSummary(
        total=len(ordered),
        allow=counts[_RANK_ALLOW],
        warn=counts[_RANK_WARN],
        block=counts[_RANK_BLOCK],
        unverifiable=counts[_RANK_UNVERIFIABLE],
        exit_code=0,
        llm_unavailable=_count_llm_unavailable(ordered),
    )
    report = ScanReport(
        schema_version=_SCHEMA_VERSION,
        tool_version=_TOOL_VERSION,
        ecosystem=ecosystem_id,
        summary=summary,
        results=ordered,
        error_category=None,
    )
    exit_code = aggregate_exit_code(report, strict=False)
    return _with_exit_code(report, exit_code)


def _result_sort_key(result: DependencyResult) -> tuple[int, str]:
    """Clave de orden total para R6.4: (rango de estado/verdict, nombre asc).

    Rango: unverifiable(0) -> block(1) -> warn(2) -> allow(3). El nombre como
    desempate hace el orden total (los nombres son unicos tras la dedup), de modo
    que el reporte es identico bajo cualquier permutacion de la entrada (R5.7).
    """
    return (_status_rank(result), result.name)


def _status_rank(result: DependencyResult) -> int:
    """Mapea el estado/veredicto de un resultado a su rango de orden (R6.4)."""
    if result.status is Status.UNVERIFIABLE:
        return _RANK_UNVERIFIABLE
    if result.verdict is Verdict.BLOCK:
        return _RANK_BLOCK
    if result.verdict is Verdict.WARN:
        return _RANK_WARN
    return _RANK_ALLOW


def _count_verdicts(results: tuple[DependencyResult, ...]) -> dict[int, int]:
    """Cuenta resultados por rango (allow/warn/block/unverifiable) para el summary."""
    counts = {
        _RANK_UNVERIFIABLE: 0,
        _RANK_BLOCK: 0,
        _RANK_WARN: 0,
        _RANK_ALLOW: 0,
    }
    for result in results:
        counts[_status_rank(result)] += 1
    return counts


def _count_llm_unavailable(results: tuple[DependencyResult, ...]) -> int:
    """Cuenta deps con senal LLM_UNAVAILABLE (Capa 4 activa pero no evaluable; R4.6/R7.6)."""
    return sum(
        1
        for result in results
        if any(signal.code is SignalCode.LLM_UNAVAILABLE for signal in result.signals)
    )


def _empty_report(ecosystem_id: str) -> ScanReport:
    """Reporte de un manifiesto vacio: 0 resultados, exit 0 (R1.7)."""
    summary = ScanSummary(
        total=0, allow=0, warn=0, block=0, unverifiable=0, exit_code=0
    )
    return ScanReport(
        schema_version=_SCHEMA_VERSION,
        tool_version=_TOOL_VERSION,
        ecosystem=ecosystem_id,
        summary=summary,
        results=(),
        error_category=None,
    )


def _error_report(exc: SlopGuardError, ecosystem_id: str) -> ScanReport:
    """Reporte de error operacional total: `error_category` poblado, exit 3 (§3.6).

    No incluye el mensaje crudo de la excepcion en el reporte estructurado: la
    categoria es suficiente para CI y la CLI sanea por separado el texto para
    stderr (R6.5). El summary queda vacio y `aggregate_exit_code` devuelve 3 por
    la sola presencia de `error_category`.
    """
    summary = ScanSummary(
        total=0, allow=0, warn=0, block=0, unverifiable=0, exit_code=0
    )
    report = ScanReport(
        schema_version=_SCHEMA_VERSION,
        tool_version=_TOOL_VERSION,
        ecosystem=ecosystem_id,
        summary=summary,
        results=(),
        error_category=exc.error_category,
    )
    exit_code = aggregate_exit_code(report, strict=False)
    return _with_exit_code(report, exit_code)


def _with_exit_code(report: ScanReport, exit_code: int) -> ScanReport:
    """Devuelve una copia del reporte con el `exit_code` fijado en su summary.

    `ScanReport`/`ScanSummary` son frozen; en vez de mutar se reconstruye el
    summary con el codigo ya calculado (inmutabilidad de verdad).
    """
    summary = ScanSummary(
        total=report.summary.total,
        allow=report.summary.allow,
        warn=report.summary.warn,
        block=report.summary.block,
        unverifiable=report.summary.unverifiable,
        exit_code=exit_code,
        llm_unavailable=report.summary.llm_unavailable,
    )
    return ScanReport(
        schema_version=report.schema_version,
        tool_version=report.tool_version,
        ecosystem=report.ecosystem,
        summary=summary,
        results=report.results,
        error_category=report.error_category,
    )
