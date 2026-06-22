"""Veredicto, override de inexistencia y agregacion de exit code (T31, R5.2-5.8, R7).

Funciones puras. Sin I/O, sin red, sin reloj.
Importa SOLO de: core.models, core.config, core.scoring.scorer.

Contratos:
  - `score_to_verdict(score, config)`: traduce score 0-100 a Verdict por umbrales
    (R5.3-5.5).
  - `build_dependency_result(dep, signals, config)`: ensambla DependencyResult con
    override de inexistencia (R5.2) y manejo de unverifiable (R5.8).
  - `aggregate_exit_code(report, strict)`: calcula exit code con precedencia
    block(2) > operacional/unverifiable(3) > warn(1) > allow(0) (R7.5).
    Con `--strict`, cualquier warn cuenta como exit 2 (R7.6).

Override de inexistencia (R5.2, ADR-01):
  La señal NONEXISTENT implica verdict=block y score=None, independientemente
  de umbral_block. Esta logica vive aqui, fuera del scorer (score no se calcula).

Prioridad Capa 0 sobre top-N (R3.8):
  Si el paquete esta en el top-N pero Capa 0 reporta 404, la Capa 0 prevalece
  (block) y se añade una nota de dataset posiblemente desactualizado.

Unverifiable (R5.8):
  status=UNVERIFIABLE => verdict=None, score=None, nunca allow.
"""

from __future__ import annotations

from dataclasses import dataclass

from slopguard.core.config import Config
from slopguard.core.models import (
    DependencyResult,
    ErrorCategory,
    LayerSignal,
    ScanReport,
    SignalCode,
    Status,
    Verdict,
)
from slopguard.core.scoring.scorer import compute_score

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
    """Ensambla DependencyResult aplicando overrides y umbrales (R5.2-5.8).

    Orden de precedencia:
      1. Unverifiable (R5.8): status=UNVERIFIABLE, verdict=None, score=None.
      2. Override NONEXISTENT (R5.2): verdict=BLOCK, score=None, status=OK.
      3. Score normal: compute_score -> score_to_verdict (R5.3-5.5).
    """
    if ctx.is_unverifiable:
        return DependencyResult(
            name=ctx.name,
            version_pin=ctx.version_pin,
            status=Status.UNVERIFIABLE,
            verdict=None,
            score=None,
            signals=signals,
            suspected_target=_extract_suspected_target(signals),
            error_category=ctx.error_category,
        )

    if _has_nonexistent(signals):
        return DependencyResult(
            name=ctx.name,
            version_pin=ctx.version_pin,
            status=Status.OK,
            verdict=Verdict.BLOCK,
            score=None,
            signals=signals,
            suspected_target=_extract_suspected_target(signals),
            error_category=ctx.error_category,
        )

    score = compute_score(signals)
    verdict = score_to_verdict(score, config)
    return DependencyResult(
        name=ctx.name,
        version_pin=ctx.version_pin,
        status=Status.OK,
        verdict=verdict,
        score=score,
        signals=signals,
        suspected_target=_extract_suspected_target(signals),
        error_category=ctx.error_category,
    )


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
