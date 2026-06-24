"""Veredicto, overrides y agregacion de exit code (T31/H2-T11, R5.2-5.8, R7, R3, R4).

Funciones puras. Sin I/O, sin red, sin reloj.
Importa SOLO de: core.models (incl. `Advisory`, modelo hoja), core.config,
core.scoring.scorer. NUNCA importa core.threatintel.* (frontera import-linter §1.3).

Contratos:
  - `score_to_verdict(score, config)`: traduce score 0-100 a Verdict por umbrales
    (R5.3-5.5).
  - `build_dependency_result(dep, signals, config)`: ensambla DependencyResult con
    el ORDEN EXACTO de 5 ramas de §3.5 (ver abajo).
  - `aggregate_exit_code(report, strict)`: calcula exit code con precedencia
    block(2) > operacional/unverifiable(3) > warn(1) > allow(0) (R7.5).
    Con `--strict`, cualquier warn cuenta como exit 2 (R7.6).

Orden de precedencia de `build_dependency_result` (design §3.5, ADR-06/07/10):
  1. ctx.is_unverifiable (SOLO de Capa 0)  -> status=UNVERIFIABLE, verdict=None, score=None.
  2. _has_malicious(signals)               -> verdict=BLOCK, score=None, advisories[] (override
                                              de precedencia MAXIMA; ADR-06; fail-closed).
  3. _has_nonexistent(signals)             -> verdict=BLOCK, score=None (override 404; R5.2).
  4. score normal (typosquat / KNOWN_HALLUCINATION-85 / blandas) -> umbrales. Si block/warn,
     ese verdict DOMINA sobre un threat-intel caido.
  5. THREATINTEL_UNVERIFIABLE (solo si el paso 4 dio ALLOW): degrada segun
     config.threatintel_degraded_status (unverifiable=default | warn); nunca allow (ADR-10).

Invariante anti-FP (R3.3/R5.6): las señales BLANDAS (incl. THREATINTEL_UNVERIFIABLE,
weight=0) por si solas nunca cruzan a warn/block; SOFT_CAP sin cambios. El paso 5 cambia
el `status`, no eleva por score.

Fail-closed (NFR-Degr.1): MALICIOUS ⇒ block SIEMPRE (precedencia maxima, inmune a config
y a threat-intel parcialmente caido); THREATINTEL_UNVERIFIABLE ⇒ jamas allow.
"""

from __future__ import annotations

from dataclasses import dataclass

from slopguard.core.config import Config
from slopguard.core.models import (
    Advisory,
    DependencyResult,
    ErrorCategory,
    LayerSignal,
    ScanReport,
    SignalCode,
    Status,
    Verdict,
)
from slopguard.core.scoring.scorer import compute_score

# Estados de degradacion de threat-intel (R5.2, ADR-10). El default ("unverifiable")
# es fail-closed: ante OSV/depscope caido y sin block/warn dominante, la dep queda
# UNVERIFIABLE (exit 3), nunca allow. "warn" es la valvula opt-in (eleva a warn/exit 1).
_DEGRADED_WARN = "warn"

# Mensaje añadido cuando el paquete esta en el top-N pero no existe (R3.8).
_DATASET_OUTDATED_NOTE = (
    "El paquete figura en el dataset top-N pero no existe en PyPI: "
    "el dataset puede estar desactualizado."
)


@dataclass(frozen=True, slots=True)
class DepContext:
    """Contexto de una dependencia a evaluar. Agrupa los campos de identidad."""

    name: str
    version_pin: str | None
    is_unverifiable: bool
    error_category: ErrorCategory | None


def score_to_verdict(score: int, config: Config) -> Verdict:
    """Traduce un score 0-100 al veredicto por umbrales (R5.3-5.5).

    Precondicion: 0 <= score <= 100.
    """
    if score >= config.umbral_block:
        return Verdict.BLOCK
    if score >= config.umbral_warn:
        return Verdict.WARN
    return Verdict.ALLOW


def build_dependency_result(
    ctx: DepContext,
    signals: tuple[LayerSignal, ...],
    config: Config,
) -> DependencyResult:
    """Ensambla DependencyResult con el orden exacto de 5 ramas de §3.5.

    Precedencia (ADR-06/07/10, fail-closed): is_unverifiable(L0) -> MALICIOUS
    (override block, advisories) -> NONEXISTENT (override 404) -> score por umbrales;
    si el score dio ALLOW y hay THREATINTEL_UNVERIFIABLE, se degrada el status segun
    config.threatintel_degraded_status. El detalle de cada rama vive en el docstring
    del modulo. Todas las señales contribuyentes quedan en `signals` (R3.4).
    """
    if ctx.is_unverifiable:  # (1) Capa 0: existencia no verificable (R5.8). NUNCA por L3.
        return _result(ctx, signals, status=Status.UNVERIFIABLE, verdict=None, score=None)

    if _has_malicious(signals):  # (2) override de block, precedencia MAXIMA (ADR-06).
        return _result(
            ctx, signals, status=Status.OK, verdict=Verdict.BLOCK, score=None,
            advisories=_advisories_from_signals(signals),
        )

    if _has_nonexistent(signals):  # (3) override 404 (R5.2).
        return _result(ctx, signals, status=Status.OK, verdict=Verdict.BLOCK, score=None)

    # (4) score por umbrales (typosquat / KNOWN_HALLUCINATION-85 / blandas).
    score = compute_score(signals)
    verdict = score_to_verdict(score, config)
    if verdict is not Verdict.ALLOW:  # block/warn DOMINA sobre un threat-intel caido.
        return _result(ctx, signals, status=Status.OK, verdict=verdict, score=score)

    # (5) ALLOW + threat-intel caido: degrada segun config; nunca allow (ADR-10).
    if _has_threatintel_unverifiable(signals):
        return _degraded_result(ctx, signals, score, config)
    return _result(ctx, signals, status=Status.OK, verdict=Verdict.ALLOW, score=score)


def _result(  # noqa: PLR0913 (5 campos kw-only del DependencyResult + identidad de ctx)
    ctx: DepContext,
    signals: tuple[LayerSignal, ...],
    *,
    status: Status,
    verdict: Verdict | None,
    score: int | None,
    advisories: tuple[Advisory, ...] = (),
) -> DependencyResult:
    """Construye un DependencyResult con los campos comunes (identidad + señales).

    Centraliza el ensamblado para que las 5 ramas de `build_dependency_result`
    queden legibles y consistentes (mismo suspected_target/error_category/advisories).
    """
    return DependencyResult(
        name=ctx.name,
        version_pin=ctx.version_pin,
        status=status,
        verdict=verdict,
        score=score,
        signals=signals,
        suspected_target=_extract_suspected_target(signals),
        error_category=ctx.error_category,
        advisories=advisories,
    )


def _degraded_result(
    ctx: DepContext,
    signals: tuple[LayerSignal, ...],
    score: int,
    config: Config,
) -> DependencyResult:
    """Rama 5 (§3.5, ADR-10): threat-intel caido sobre una dep por lo demas limpia.

    Respeta `config.threatintel_degraded_status`:
      - "warn": status=OK, verdict=WARN, score=score (valvula opt-in; con --strict ⇒ exit 2).
      - "unverifiable" (default): status=UNVERIFIABLE, verdict=None, score=None (exit 3).
    En ambos casos NUNCA allow (fail-closed, NFR-Degr.1). La señal blanda no eleva por
    score (invariante anti-FP intacta); solo cambia el `status`/`verdict` aqui.
    """
    if config.threatintel_degraded_status == _DEGRADED_WARN:
        return _result(ctx, signals, status=Status.OK, verdict=Verdict.WARN, score=score)
    return _result(ctx, signals, status=Status.UNVERIFIABLE, verdict=None, score=None)


def aggregate_exit_code(report: ScanReport, *, strict: bool) -> int:
    """Calcula el exit code del reporte con precedencia R7.5.

    Precedencia: block(2) > operacional/unverifiable(3) > warn(1) > allow(0).
    Con strict=True, cualquier warn cuenta como exit 2 (R7.6).

    Algoritmo (design §3.5):
      if error_operacional_total:   return 3
      if any verdict==block:        return 2
      if any status==unverifiable:  return 3
      if any verdict==warn:         return 2 if strict else 1
      return 0
    """
    if report.error_category is not None:
        return 3
    if any(r.verdict is Verdict.BLOCK for r in report.results):
        return 2
    if any(r.status is Status.UNVERIFIABLE for r in report.results):
        return 3
    if any(r.verdict is Verdict.WARN for r in report.results):
        return 2 if strict else 1
    return 0


def _has_nonexistent(signals: tuple[LayerSignal, ...]) -> bool:
    """Verdad si alguna señal es NONEXISTENT (override de inexistencia, R5.2)."""
    return any(s.code is SignalCode.NONEXISTENT for s in signals)


def _has_malicious(signals: tuple[LayerSignal, ...]) -> bool:
    """Verdad si alguna señal es MALICIOUS (override de block, precedencia maxima, ADR-06).

    Analogo a `_has_nonexistent`. Una señal MALICIOUS proviene de un OSV que SI
    respondio para ese nombre; coexiste sin contradiccion con THREATINTEL_UNVERIFIABLE
    (otra fuente caida): la malicia confirmada domina y NO se degrada (fail-closed).
    """
    return any(s.code is SignalCode.MALICIOUS for s in signals)


def _has_threatintel_unverifiable(signals: tuple[LayerSignal, ...]) -> bool:
    """Verdad si alguna señal es THREATINTEL_UNVERIFIABLE (blanda L3, weight=0, ADR-10).

    Solo decide el status en la rama 5 de §3.5 (cuando el score dio ALLOW y no hay
    override). Nunca eleva por score: la invariante anti-FP queda intacta (R3.3).
    """
    return any(s.code is SignalCode.THREATINTEL_UNVERIFIABLE for s in signals)


def _advisories_from_signals(signals: tuple[LayerSignal, ...]) -> tuple[Advisory, ...]:
    """Extrae los advisories MAL-* de las señales MALICIOUS portadoras (ADR-06, §3.5).

    Los objetos `Advisory` (de `core.models`, ya saneados por la fuente) viajan en
    `LayerSignal.advisories` de la señal L3 MALICIOUS. Se concatenan en orden de aparicion
    (determinista: el engine recolecta las capas en orden fijo 0→1→2→3). No se reflejan
    datos crudos de red: el objeto Advisory ya viene construido y validado.
    """
    advisories: list[Advisory] = []
    for signal in signals:
        if signal.code is SignalCode.MALICIOUS:
            advisories.extend(signal.advisories)
    return tuple(advisories)


def _extract_suspected_target(signals: tuple[LayerSignal, ...]) -> str | None:
    """Devuelve el suspected_target de las señales de forma determinista (R5.7).

    Criterio: el minimo lexicografico de todos los targets no nulos. Esto garantiza
    que el resultado es identico independientemente del orden de la tupla (R5.7).

    Invariante actual: a lo sumo una señal porta suspected_target (solo TYPOSQUAT lo
    lleva; NAME_UNTRUSTED usa suspected_target=None). El min() es defensa en profundidad
    para blindar contra futuras señales portadoras de target sin romper el determinismo.
    """
    targets = [s.suspected_target for s in signals if s.suspected_target is not None]
    if not targets:
        return None
    return min(targets)


def augment_with_dataset_note(
    signals: tuple[LayerSignal, ...],
) -> tuple[LayerSignal, ...]:
    """Añade nota de dataset desactualizado a la señal NONEXISTENT (R3.8).

    Llamado por el orquestador cuando sabe que el nombre estaba exactamente en
    el top-N pero la Capa 0 reporta 404.
    """
    augmented = []
    for signal in signals:
        if signal.code is SignalCode.NONEXISTENT:
            augmented.append(
                LayerSignal(
                    layer=signal.layer,
                    code=signal.code,
                    weight=signal.weight,
                    is_soft=signal.is_soft,
                    detail=signal.detail + " " + _DATASET_OUTDATED_NOTE,
                    suspected_target=signal.suspected_target,
                )
            )
        else:
            augmented.append(signal)
    return tuple(augmented)
