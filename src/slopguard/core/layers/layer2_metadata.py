"""Capa 2 — senales de metadatos del paquete (R4, ADR-01).

Evalua los metadatos normalizados (PyPI JSON via adapter) y emite hasta dos
senales blandas cuyo aporte conjunto esta acotado a `c2_max_contrib` puntos:

- `WEAK_METADATA` (+7): releases <= releases_min Y faltan >=
  metadata_faltantes_min campos del conjunto cerrado
  {descripcion, autor, licencia, clasificadores} (R4.2).

- `LOW_VERIFIABILITY` (+5): paquete sin repositorio enlazado en PyPI (R4.3).

Aporte L2 posible: {0, 5, 7, 10}. La formula de cota es:
  aporte = min(weak + low, c2_max_contrib)

Cuando el paquete es popular (releases >= releases_populares Y repo enlazado Y
metadatos completos) el aporte se capa a `c2_max_contrib` por construccion
(ya que max(weak+low)=10 y c2_max_contrib=10, la cota actua si ambas senales
se emiten). Para paquetes claramente populares no se emite ninguna senal.

Sin red, sin adapters concretos, sin CLI. Determinista.
Importa SOLO de: core.adapters.base, core.models, core.config.
"""

from __future__ import annotations

from slopguard.core.adapters.base import FetchOutcome, FetchState, PackageMetadata
from slopguard.core.config import Config
from slopguard.core.models import Layer, LayerSignal, SignalCode

# Pesos brutos de cada senal (antes del cap global).
_WEIGHT_WEAK_METADATA = 7
_WEIGHT_LOW_VERIFIABILITY = 5


def evaluate(
    outcome: FetchOutcome,
    config: Config,
) -> list[LayerSignal]:
    """Evalua la Capa 2 a partir del resultado de fetch.

    Devuelve una lista con 0, 1 o 2 senales blandas, con pesos ajustados para
    que su suma no exceda `c2_max_contrib` (R4.5, ADR-01).
    Paquete no encontrado o no verificable -> lista vacia (L2 no aplica).
    """
    if outcome.state is not FetchState.FOUND or outcome.metadata is None:
        return []
    meta = outcome.metadata

    # Paquete popular con metadatos completos: sin senal L2 (R4.5).
    if _is_popular_complete(meta, config):
        return []

    raw_signals = _collect_raw_signals(meta, config)
    return _apply_cap(raw_signals, config.c2_max_contrib)


def _is_popular_complete(meta: PackageMetadata, config: Config) -> bool:
    """Verdad si el paquete cumple todos los criterios de popularidad (R4.5)."""
    return (
        meta.releases_count >= config.releases_populares
        and meta.has_repo_url
        and meta.has_description
        and meta.has_author
        and meta.has_license
        and meta.has_classifiers
    )


def _missing_metadata_count(meta: PackageMetadata) -> int:
    """Cuenta cuantos campos del conjunto cerrado {descripcion, autor, licencia,
    clasificadores} estan ausentes (R4.2)."""
    missing = 0
    if not meta.has_description:
        missing += 1
    if not meta.has_author:
        missing += 1
    if not meta.has_license:
        missing += 1
    if not meta.has_classifiers:
        missing += 1
    return missing


def _collect_raw_signals(
    meta: PackageMetadata,
    config: Config,
) -> list[LayerSignal]:
    """Genera las senales con sus pesos brutos (sin cap todavia)."""
    signals: list[LayerSignal] = []

    missing = _missing_metadata_count(meta)
    if meta.releases_count <= config.releases_min and missing >= config.metadata_faltantes_min:
        detail = (
            f"{meta.releases_count} release(s) publicada(s) y faltan {missing} "
            f"campo(s) de metadatos (descripcion, autor, licencia, clasificadores)."
        )
        signals.append(LayerSignal(
            layer=Layer.L2,
            code=SignalCode.WEAK_METADATA,
            weight=_WEIGHT_WEAK_METADATA,
            is_soft=True,
            detail=detail,
            suspected_target=None,
        ))

    if not meta.has_repo_url:
        signals.append(LayerSignal(
            layer=Layer.L2,
            code=SignalCode.LOW_VERIFIABILITY,
            weight=_WEIGHT_LOW_VERIFIABILITY,
            is_soft=True,
            detail="El paquete no tiene repositorio enlazado en PyPI.",
            suspected_target=None,
        ))

    return signals


def _apply_cap(
    signals: list[LayerSignal],
    c2_max_contrib: int,
) -> list[LayerSignal]:
    """Ajusta los pesos para que la suma no exceda `c2_max_contrib` (ADR-01).

    El aporte total de L2 pertenece al conjunto {0, 5, 7, 10}:
    - Ninguna senal -> 0
    - Solo LOW_VERIFIABILITY -> 5
    - Solo WEAK_METADATA -> 7
    - Ambas -> min(7+5, c2_max_contrib) = 10

    Cuando hay que recortar, se reduce el peso de WEAK_METADATA para mantener
    el peso nominal de LOW_VERIFIABILITY (criterio: las 2 senales aporten
    exactamente c2_max_contrib entre las dos).
    """
    if not signals:
        return []
    total = sum(s.weight for s in signals)
    if total <= c2_max_contrib:
        return signals

    # Necesitamos recortar `excess` puntos del total.
    excess = total - c2_max_contrib
    adjusted: list[LayerSignal] = []
    for signal in signals:
        if signal.code is SignalCode.WEAK_METADATA and excess > 0:
            new_weight = max(0, signal.weight - excess)
            excess -= signal.weight - new_weight
            adjusted.append(LayerSignal(
                layer=signal.layer,
                code=signal.code,
                weight=new_weight,
                is_soft=signal.is_soft,
                detail=signal.detail,
                suspected_target=signal.suspected_target,
            ))
        else:
            adjusted.append(signal)
    return adjusted
