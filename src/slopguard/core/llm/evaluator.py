"""Abstraccion del evaluador LLM de la Capa 4 (Hito 3, ADR-17).

Define SOLO el contrato (`LlmEvaluator` Protocol). NO contiene logica de red ni
de proveedor concreto: el resolver inyecta una implementacion (`AnthropicEvaluator`)
sin que las capas/scoring conozcan el adaptador (frontera import-linter, ADR-17).

`evaluate` devuelve `None` ante CUALQUIER abstencion (clave ausente, timeout,
refusal, respuesta invalida); el resolver mapea ese `None` a `LLM_UNAVAILABLE`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from slopguard.core.models import HallucinationContext, LlmAssessment


@runtime_checkable
class LlmEvaluator(Protocol):
    """Abstrae la clasificacion de un nombre de paquete en banda gris (R2, ADR-17).

    Una implementacion concreta (p.ej. `AnthropicEvaluator`) arma el request,
    valida el esquema de salida y mapea cualquier fallo a abstension. Anadir otro
    proveedor = implementar este Protocol sin tocar capas/scoring/engine.
    """

    def evaluate(
        self, name: str, context: HallucinationContext, ecosystem_id: str = "pypi"
    ) -> LlmAssessment | None:
        """Clasifica `name` usando el `context` deterministico de las capas 0-2.

        El `ecosystem_id` (``"pypi"``/``"npm"``) cruza la cadena hasta `build_prompt`
        para emitir el texto del ecosistema correcto y sellar la clave/veredicto L4
        por ecosistema (ADR-6, H4). El default ``"pypi"`` preserva el comportamiento
        existente mientras el wiring del resolver/engine se cablea (H4-T32/T33).

        Args:
            name: Nombre normalizado del paquete a evaluar.
            context: Contexto deterministico derivado de las capas 0-2.
            ecosystem_id: Identificador del ecosistema (``"pypi"`` o ``"npm"``).

        Returns:
            `LlmAssessment` validado+saneado si el LLM respondio de forma utilizable;
            `None` ante CUALQUIER abstencion (clave ausente, timeout, refusal,
            `stop_reason != end_turn`, esquema invalido). NUNCA lanza.
        """
        ...
