"""Capa 4: superficie de alucinacion con LLM (Hito 3). Funcion PURA.

Convierte el veredicto del LLM (`LlmAssessment | None`, ya validado+saneado por el
evaluador) en senales de capa. NO habla con la red ni el LLM: el resolver inyecta el
assessment ya resuelto como dato puro (frontera ADR-17: este modulo importa SOLO
`core.models` y `core.config`; no `core.llm`, `core.net` ni `core.scoring`).

La senal de riesgo va en el CANAL LLM separado (`is_llm_channel=True`, `is_soft=True`):
el scorer la acota a `LLM_SOFT_CAP` y, como el gating garantiza que estas deps no tienen
senal dura, NUNCA puede producir `block` (a lo sumo `warn`) (ADR-11). El peso crudo
`floor(w_base * confianza)` se emite sin capar aqui (el scorer aplica `min(.,LLM_SOFT_CAP)`).
"""

from __future__ import annotations

import math

from slopguard.core.config import Config
from slopguard.core.models import (
    Clasificacion,
    Layer,
    LayerSignal,
    LlmAssessment,
    SignalCode,
)
from slopguard.core.normalize import sanitize_for_output


def evaluate_layer4(
    assessment: LlmAssessment | None, config: Config
) -> tuple[LayerSignal, ...]:
    """Convierte el assessment del LLM en senales L4 (R2.3/R2.4, ADR-11).

    - `None` (abstencion/indisponible) ⇒ `LLM_UNAVAILABLE` (weight 0, informativa): no
      degrada nada, solo se reporta de forma visible (R4: degradacion segura, jamas
      finge "todo limpio").
    - `legitimo` ⇒ sin senal de riesgo (la capa quedo evaluada y limpia).
    - `conflacion`/`typo`/`fabricacion` con `confianza >= llm_conf_min` ⇒
      `LLM_HALLUCINATION_SURFACE` en el canal LLM, peso `floor(w_base * confianza)`.
    - `confianza < llm_conf_min` ⇒ sin senal (evidencia insuficiente; anti-FP).
    """
    if assessment is None:
        return (
            LayerSignal(
                layer=Layer.L4,
                code=SignalCode.LLM_UNAVAILABLE,
                weight=0,
                is_soft=True,
                detail="evaluacion de superficie de alucinacion (LLM) no disponible",
            ),
        )
    if assessment.clasificacion is Clasificacion.LEGITIMO:
        return ()
    w_base = _peso_base(assessment.clasificacion, config)
    if w_base is None or assessment.confianza < config.llm_conf_min:
        return ()
    weight = math.floor(w_base * assessment.confianza)
    return (
        LayerSignal(
            layer=Layer.L4,
            code=SignalCode.LLM_HALLUCINATION_SURFACE,
            weight=weight,
            is_soft=True,
            is_llm_channel=True,
            detail=_detalle(assessment),
        ),
    )


def _peso_base(clasificacion: Clasificacion, config: Config) -> int | None:
    """Peso base por clasificacion (config); `None` si no aporta riesgo (legitimo)."""
    return {
        Clasificacion.FABRICACION: config.w_base_fabricacion,
        Clasificacion.CONFLACION: config.w_base_conflacion,
        Clasificacion.TYPO: config.w_base_typo,
    }.get(clasificacion)


def _detalle(assessment: LlmAssessment) -> str:
    """Explicacion saneada y marcada como advisory (texto del LLM = no confiable).

    `patron` ya viene saneado+truncado del evaluador; se re-sanea (idempotente) como
    defensa en profundidad en la frontera de salida.
    """
    texto = (
        f"superficie de alucinacion (advisory, generado por LLM): "
        f"{assessment.clasificacion.value} (confianza {assessment.confianza:.2f}); "
        f"{assessment.patron}"
    )
    return sanitize_for_output(texto)
