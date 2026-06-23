"""Capa 3 — threat-intel pura (R1, R2, R3, ADR-06, ADR-07, ADR-10).

Consume un `ThreatIntelResult` ya resuelto (inyectado por el engine) y emite
cero o mas senales `LayerSignal` L3. No importa nada de `core.threatintel.*`
(frontera import-linter §1.3 contratos 1 y 3): todos los modelos de dominio
(`ThreatIntelResult`, `MaliceState`, `Advisory`) vienen de `core.models` (hoja),
igual que L0/L1/L2 consumen modelos de `core.adapters.base`/`core.models`.

Mapeo de estados:
- `MALICIOUS`           -> senal dura, weight=0, is_soft=False (override ADR-06)
                           Porta los IDs MAL-* en el detail; el override block lo fija
                           `build_dependency_result` (H2-T11, simetria con NONEXISTENT).
- `KNOWN_HALLUCINATION` -> senal dura, weight=85, is_soft=False (ADR-07)
                           El detail incluye fuente y fecha del corpus (R7.2).
- `UNVERIFIABLE`        -> senal blanda, weight=0, is_soft=True (R3.3, ADR-10)
                           El detail incluye el motivo saneado.
- `CLEAN`               -> sin senal (R1.4).

Sin red. Determinista. Cero dependencias de runtime.
"""

from __future__ import annotations

from slopguard.core.models import (
    Advisory,
    Layer,
    LayerSignal,
    MaliceState,
    SignalCode,
    ThreatIntelResult,
)

# Peso de la senal KNOWN_HALLUCINATION (>= umbral_block=80, ADR-07).
_WEIGHT_KNOWN_HALLUCINATION = 85


def evaluate(result: ThreatIntelResult) -> tuple[LayerSignal, ...]:
    """Convierte un `ThreatIntelResult` en senales L3.

    Devuelve una tupla inmutable (0 o 1 elemento).
    No lanza excepciones: cualquier estado invalido produce tupla vacia.
    """
    if result.state is MaliceState.MALICIOUS:
        return (_malicious_signal(result.advisories),)
    if result.state is MaliceState.KNOWN_HALLUCINATION:
        return (_known_hallucination_signal(result.watchlist_source, result.watchlist_date),)
    if result.state is MaliceState.UNVERIFIABLE:
        return (_unverifiable_signal(result.unverifiable_reason),)
    # CLEAN o estado desconocido -> sin senal (R1.4).
    return ()


def _malicious_signal(advisories: tuple[Advisory, ...]) -> LayerSignal:
    """Senal de override: paquete confirmado malicioso por OSV (ADR-06, R1.2).

    Peso=0 porque el veredicto lo fija el override en `build_dependency_result`,
    no el scorer (simetria con NONEXISTENT). El detail porta los IDs MAL-* y la
    senal porta los objetos `Advisory` estructurados para que `verdict.py` pueble
    `DependencyResult.advisories` sin cruzar la frontera (los reflejan ya saneados).
    """
    ids = ", ".join(a.id for a in advisories) if advisories else "sin ID"
    detail = (
        f"Reportado como malicioso por OSV ({ids}). "
        "No instalar: paquete confirmado danino por inteligencia comunitaria."
    )
    return LayerSignal(
        layer=Layer.L3,
        code=SignalCode.MALICIOUS,
        weight=0,
        is_soft=False,
        detail=detail,
        suspected_target=None,
        advisories=advisories,
    )


def _known_hallucination_signal(
    watchlist_source: str | None,
    watchlist_date: str | None,
) -> LayerSignal:
    """Senal dura: nombre alucinado conocido en corpus watchlist (ADR-07, R2.3).

    Peso=85 (>= umbral_block=80): produce block por score, no por override.
    El detail incluye fuente y fecha para cumplir la atribucion R7.2.
    """
    fuente = watchlist_source or "depscope-hallucinations"
    fecha_str = f", {watchlist_date}" if watchlist_date else ""
    detail = (
        f"Nombre alucinado conocido segun el corpus {fuente}{fecha_str}. "
        "Alto riesgo de slopsquatting: el nombre figura en benchmarks de LLM."
    )
    return LayerSignal(
        layer=Layer.L3,
        code=SignalCode.KNOWN_HALLUCINATION,
        weight=_WEIGHT_KNOWN_HALLUCINATION,
        is_soft=False,
        detail=detail,
        suspected_target=None,
    )


def _unverifiable_signal(unverifiable_reason: str | None) -> LayerSignal:
    """Senal blanda informativa: threat-intel no verificable (ADR-10, R1.6, R3.3).

    Peso=0, is_soft=True: nunca eleva a warn/block por si sola (invariante anti-FP).
    El detail porta el motivo saneado por el caller antes de construir ThreatIntelResult.
    """
    motivo = unverifiable_reason or "fuente de threat-intel no disponible"
    detail = f"Threat-intel no verificable: {motivo}."
    return LayerSignal(
        layer=Layer.L3,
        code=SignalCode.THREATINTEL_UNVERIFIABLE,
        weight=0,
        is_soft=True,
        detail=detail,
        suspected_target=None,
    )
