"""Resolucion de la Capa 4: gating de banda gris, orden canonico, presupuesto, cache.

Mirror conceptual de `threatintel.resolver`, con dos diferencias clave de la Capa 4:

1. **Two-pass (gating sobre el veredicto PRE-L4):** la banda gris (ADR-12) depende del
   `DependencyResult` ya computado por las capas 0-3, asi que el engine resuelve la
   Capa 4 en una SEGUNDA pasada. `is_gray_band` exige: verificable, no bloqueada,
   SIN ninguna senal dura (⇒ `max_hard=0`, base del anti-block) y con >=1 senal blanda.
2. **El resolver posee la cache:** los aciertos de cache NO cuentan contra
   `llm_max_calls_por_corrida` (que acota llamadas de RED). Orden canonico (nombre asc)
   ⇒ el subconjunto marcado como abstencion por tope es reproducible (NFR-Det.1).

Degradacion segura (senior-secops): un `None` (abstencion: sin clave, timeout, refusal,
tope) jamas se cachea y el engine lo mapea a `LLM_UNAVAILABLE` (weight 0), que NO degrada
el veredicto determinista (R4). Frontera: este modulo vive en `core.llm`; las capas y el
scoring no lo importan.
"""

from __future__ import annotations

import hashlib
import math
from typing import TYPE_CHECKING, Any, Final

from slopguard.core.models import (
    Clasificacion,
    HallucinationContext,
    LlmAssessment,
    Status,
    Verdict,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from slopguard.core.adapters.base import FetchOutcome
    from slopguard.core.cache.disk_cache import DiskCache
    from slopguard.core.config import Config
    from slopguard.core.llm.evaluator import LlmEvaluator
    from slopguard.core.models import DependencyResult

_NAMESPACE: Final = "llm"
_SCHEMA: Final = "llm-1"
_SECONDS_PER_HOUR: Final = 3600
_SECONDS_PER_DAY: Final = 86400


def is_gray_band(
    result: DependencyResult, edad_dias: int | None, config: Config
) -> bool:
    """True si la dep cae en la banda gris elegible para la Capa 4 (ADR-12, R1.2).

    Conjuncion: (i) `status == OK` (verificable); (ii) `verdict != BLOCK`; (iii) NINGUNA
    senal dura (`is_soft == False`) ⇒ `max_hard == 0`, base por construccion del anti-block;
    (iv) disparador de sospecha: JOVEN (`edad_dias < gray_edad_max_dias`, default 365) O
    >=1 senal blanda heuristica. La rama "joven" cubre paquetes de 90-365 dias con buena
    metadata (sin NEW_PACKAGE, que solo dispara <edad_minima_dias=90): justo el blanco del
    slopsquatting que las capas deterministas no marcan. Su negacion exacta es "claramente
    legitima" (viejo Y sin blanda): sin solape ni zona muerta.
    """
    if result.status is not Status.OK or result.verdict is Verdict.BLOCK:
        return False
    if any(not signal.is_soft for signal in result.signals):
        return False  # cualquier senal dura excluye (anti-block: garantiza max_hard=0)
    joven = edad_dias is not None and edad_dias < config.gray_edad_max_dias
    tiene_blanda = any(
        signal.is_soft and not signal.is_llm_channel for signal in result.signals
    )
    return joven or tiene_blanda


def build_context(
    name: str,
    result: DependencyResult,
    outcome: FetchOutcome | None,
    *,
    now_epoch: float,
) -> HallucinationContext:
    """Construye el contexto deterministico a enviar al LLM (R8.2): SOLO datos de capas 0-2.

    `typo_vecino`/`typo_distancia` quedan en `None` (la banda gris excluye typosquat por
    construccion). NUNCA incluye el manifiesto, rutas ni identificadores del usuario.
    """
    metadata = outcome.metadata if outcome is not None else None
    return HallucinationContext(
        existe=True,
        edad_dias=package_age_days(outcome, now_epoch),
        typo_vecino=None,
        typo_distancia=None,
        tiene_repo=bool(metadata is not None and metadata.has_repo_url),
        tiene_metadata=bool(metadata is not None and metadata.has_description),
        senales_blandas=tuple(
            signal.code.value
            for signal in result.signals
            if signal.is_soft and not signal.is_llm_channel
        ),
    )


def resolve_layer4(
    evaluator: LlmEvaluator,
    cache: DiskCache,
    items: Sequence[tuple[str, HallucinationContext]],
    config: Config,
    *,
    now: float | None = None,
) -> dict[str, LlmAssessment | None]:
    """Resuelve la Capa 4 para `items` (nombre, contexto) en ORDEN CANONICO ya fijado.

    Para cada item: intenta cache (HIT ⇒ no consume presupuesto); MISS con presupuesto
    ⇒ llama al evaluador (cuenta una llamada de RED) y cachea solo si hay assessment
    valido; MISS sin presupuesto ⇒ `None` (abstencion por tope). Nunca cachea `None`.
    """
    ttl_segundos = config.llm_ttl_cache_horas * _SECONDS_PER_HOUR
    resolved: dict[str, LlmAssessment | None] = {}
    network_calls = 0
    for name, context in items:
        key = _cache_key(name, context, config)
        cached = cache.get_blob(
            _NAMESPACE, key, _validate_blob,
            ttl_segundos=ttl_segundos, schema_version=_SCHEMA, now=now,
        )
        if cached is not None:
            resolved[name] = cached
            continue
        if network_calls >= config.llm_max_calls_por_corrida:
            resolved[name] = None  # tope de llamadas de red ⇒ abstencion (LLM_UNAVAILABLE)
            continue
        assessment = evaluator.evaluate(name, context)
        network_calls += 1
        if assessment is not None:
            cache.put_blob(_NAMESPACE, key, _to_blob(assessment), schema_version=_SCHEMA, now=now)
        resolved[name] = assessment
    return resolved


def package_age_days(outcome: FetchOutcome | None, now_epoch: float) -> int | None:
    """Edad del paquete en dias desde su primer release; `None` si no hay dato fiable.

    Fuente UNICA de la edad para el gating (`is_gray_band`) y `build_context`. Solo lee
    `outcome.metadata.first_release_epoch` (dato de capa 0), nunca el manifiesto.
    """
    metadata = outcome.metadata if outcome is not None else None
    if metadata is None or metadata.first_release_epoch is None:
        return None
    delta = now_epoch - metadata.first_release_epoch
    if delta < 0:
        return None
    return int(delta // _SECONDS_PER_DAY)


def _cache_key(name: str, context: HallucinationContext, config: Config) -> str:
    """Clave content-addressed: nombre + modelo + prompt_version + hash del contexto.

    El `DiskCache` hashea `namespace:key`, asi que aqui basta una cadena determinista.
    Incluir modelo y `prompt_version` invalida la entrada si cualquiera cambia (R6.4).
    """
    repr_ctx = "|".join((
        str(context.existe),
        str(context.edad_dias),
        str(context.typo_vecino),
        str(context.typo_distancia),
        str(context.tiene_repo),
        str(context.tiene_metadata),
        ",".join(context.senales_blandas),
    ))
    digest = hashlib.sha256(repr_ctx.encode("utf-8")).hexdigest()
    return f"{name}|{config.llm_model}|{config.prompt_version}|{digest}"


def _to_blob(assessment: LlmAssessment) -> dict[str, Any]:
    """Serializa el assessment al blob de cache (SOLO el veredicto, nunca el prompt/clave)."""
    return {
        "clasificacion": assessment.clasificacion.value,
        "confianza": assessment.confianza,
        "patron": assessment.patron,
        "rationale": assessment.rationale,
        "modelo": assessment.modelo,
        "prompt_version": assessment.prompt_version,
    }


def _validate_blob(payload: dict[str, Any]) -> LlmAssessment | None:
    """Reconstruye `LlmAssessment` desde el blob tratandolo como entrada NO confiable.

    Valida clasificacion (enum), confianza (numero finito en [0,1], no bool) y los
    strings. Cualquier desviacion ⇒ `None` (miss): la cache no inyecta datos invalidos.
    """
    clasificacion = _blob_clasificacion(payload.get("clasificacion"))
    confianza = _blob_confianza(payload.get("confianza"))
    if clasificacion is None or confianza is None:
        return None
    campos = {k: payload.get(k) for k in ("patron", "rationale", "modelo", "prompt_version")}
    if any(not isinstance(valor, str) for valor in campos.values()):
        return None
    return LlmAssessment(
        clasificacion=clasificacion,
        confianza=confianza,
        patron=str(campos["patron"]),
        rationale=str(campos["rationale"]),
        modelo=str(campos["modelo"]),
        prompt_version=str(campos["prompt_version"]),
    )


def _blob_clasificacion(value: Any) -> Clasificacion | None:
    """Convierte `value` a `Clasificacion` valido, o `None`."""
    if not isinstance(value, str):
        return None
    try:
        return Clasificacion(value)
    except ValueError:
        return None


def _blob_confianza(value: Any) -> float | None:
    """Valida confianza del blob: numero finito (no bool) en [0,1] (isfinite antes del rango)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    confianza = float(value)
    if not math.isfinite(confianza) or not (0.0 <= confianza <= 1.0):
        return None
    return confianza
