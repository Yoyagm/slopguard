"""Capa 0 — existencia y edad del paquete (R2).

Consume un `FetchOutcome` ya resuelto y emite cero, una o dos senales:

- `NONEXISTENT` (dura, peso 0, override): paquete no encontrado en PyPI (404).
  Esta senal no entra al scorer; el orquestador aplica `verdict=block` directamente
  (R5.2, ADR-01). Peso=0 porque el veredicto lo fija el override, no el scoring.

- `NEW_PACKAGE` (blanda, peso 15): paquete encontrado pero con edad <
  `edad_minima_dias`. Nunca bloquea sola (invariante ADR-01: blandas <= 25 <
  umbral_warn=50). `now_epoch` se inyecta como parametro para que la funcion sea
  determinista y testeable sin acceso al reloj (NFR-Det.1).

Modulo hoja: importa solo de `core.adapters.base`, `core.models` y `core.config`.
Sin red, sin adapters concretos, sin CLI.
"""

from __future__ import annotations

from slopguard.core.adapters.base import FetchOutcome, FetchState
from slopguard.core.config import Config
from slopguard.core.models import Layer, LayerSignal, SignalCode

_SECONDS_PER_DAY = 86_400.0


def evaluate(
    outcome: FetchOutcome,
    config: Config,
    *,
    now_epoch: float,
) -> list[LayerSignal]:
    """Evalua la Capa 0 a partir del resultado de fetch.

    Devuelve una lista (0-2 elementos) de senales L0.
    No lanza excepciones: estado UNVERIFIABLE produce lista vacia (el orquestador
    ya marca la dependencia como unverifiable antes de llegar aqui).
    """
    if outcome.state is FetchState.NOT_FOUND:
        return [_nonexistent_signal()]
    if outcome.state is FetchState.UNVERIFIABLE or outcome.metadata is None:
        return []
    age_signal = _age_signal(outcome.metadata.first_release_epoch, config, now_epoch)
    if age_signal is not None:
        return [age_signal]
    return []


def _nonexistent_signal() -> LayerSignal:
    """Senal de override: paquete inexistente en PyPI (R2.2, R5.2)."""
    return LayerSignal(
        layer=Layer.L0,
        code=SignalCode.NONEXISTENT,
        weight=0,
        is_soft=False,
        detail="El paquete no existe en PyPI (posible alucinacion o slopsquatting).",
        suspected_target=None,
    )


def _age_signal(
    first_release_epoch: float | None,
    config: Config,
    now_epoch: float,
) -> LayerSignal | None:
    """Senal blanda de paquete nuevo si la edad es menor que el umbral (R2.3/R2.4).

    Devuelve None si no hay fecha de primera release o si el paquete ya supero el
    umbral de edad minima.
    """
    if first_release_epoch is None:
        return None
    age_days = (now_epoch - first_release_epoch) / _SECONDS_PER_DAY
    if age_days >= config.edad_minima_dias:
        return None
    age_days_int = max(0, int(age_days))
    detail = (
        f"Publicado hace {age_days_int} dias "
        f"(umbral minimo: {config.edad_minima_dias} dias)."
    )
    return LayerSignal(
        layer=Layer.L0,
        code=SignalCode.NEW_PACKAGE,
        weight=15,
        is_soft=True,
        detail=detail,
        suspected_target=None,
    )
