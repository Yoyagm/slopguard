"""Scoring determinista de señales de capas → score entero 0-100 (T30, R5.1, ADR-01).

Modelo aditivo con saturacion:

    score = min(100, dura + min(blandas_heuristicas, SOFT_CAP) + min(llm, LLM_SOFT_CAP))

Señales DURAS (mutuamente excluyentes: TYPOSQUAT ⊕ NAME_UNTRUSTED):
  - TYPOSQUAT  dl=1   → 60
  - TYPOSQUAT  dl=2   → 40
  - TYPOSQUAT  jw≥0.95 → 30
  - TYPOSQUAT  jw≥0.92 → 25  (jw debil; ya filtrado por capa 1)
  - NAME_UNTRUSTED     → 30
  Si llegan ambas, se toma la de mayor peso (la exclusividad la garantiza
  la capa 1; el scorer toma el maximo como defensa en profundidad).

Señales BLANDAS (acotadas a SOFT_CAP=25 en total):
  - NEW_PACKAGE                → +15
  - WEAK_METADATA              → +peso ajustado por capa 2 (≤7)
  - LOW_VERIFIABILITY          → +peso ajustado por capa 2 (≤5)
  Aporte L2 ya viene capado por la capa; el scorer solo suma y acota a 25.

Invariante anti-FP (R5.6, ADR-01): SOFT_CAP (25) < umbral_warn (50 por defecto).
Con la configuracion por defecto (umbral_warn=50), las señales blandas solas
nunca producen warn/block: max(blandas)=25 < 50 = umbral_warn.
La invariante depende de mantener umbral_warn > SOFT_CAP (25). Si umbral_warn
se configura a un valor <= 25, la garantia deja de cumplirse (R5.6 esta anclado
al default umbral_warn=50 segun ADR-01).

NONEXISTENT (peso=0, is_soft=False) se ignora aqui: el override lo aplica verdict.py.
UNVERIFIABLE: el orquestador nunca llama a esta funcion para deps unverificables.

Canal LLM separado (Hito 3, ADR-11): LLM_HALLUCINATION_SURFACE (is_soft=True,
is_llm_channel=True) suma en un tercer sumando acotado a LLM_SOFT_CAP (50), FUERA
del SOFT_CAP heuristico. El gating garantiza max_hard=0 para toda dep con senal L4,
asi que score <= 25 + 50 = 75 < umbral_block (80): la Capa 4 NUNCA bloquea (R3.1/R3.2).

Sin I/O, sin red, sin reloj. Funcion pura y determinista (R5.7).
Importa SOLO de: core.models. Los topes SOFT_CAP/LLM_SOFT_CAP viven en core.models
(hoja compartida) y se re-exportan aqui: asi `core.config` valida el invariante
anti-block sobre la MISMA fuente sin depender de `core.scoring` (frontera ADR-17).
"""

from __future__ import annotations

# SOFT_CAP/LLM_SOFT_CAP son constantes ESTRUCTURALES (no configurables): hacerlas
# moviles seria un footgun que romperia el anti-block. Definidas en core.models
# (hoja) y re-exportadas aqui para conservar `from ...scorer import SOFT_CAP`.
from slopguard.core.models import LLM_SOFT_CAP, SOFT_CAP, LayerSignal, SignalCode

# Cota maxima del score (R5.1).
SCORE_MAX = 100


def compute_score(signals: tuple[LayerSignal, ...]) -> int:
    """Combina señales de capas en un score entero 0-100 (R5.1, ADR-01).

    Recibe la tupla de señales emitidas por las capas 0, 1 y 2 para una
    dependencia verificable. Devuelve el score segun el modelo aditivo con
    saturacion descrito en ADR-01.

    La señal NONEXISTENT (peso=0) se omite porque es un override, no un score.
    El lote puede estar en cualquier orden; el resultado es identico (R5.7).
    """
    hard_weight = _max_hard_weight(signals)
    soft_heuristico = _sum_heuristic_soft(signals)
    soft_llm = _sum_llm_soft(signals)
    return min(
        SCORE_MAX,
        hard_weight + min(soft_heuristico, SOFT_CAP) + min(soft_llm, LLM_SOFT_CAP),
    )


# Señales duras de override (weight=0) que NO contribuyen al score numerico:
# el veredicto lo fija `build_dependency_result`, no el scorer. Se excluyen por
# code (defensa en profundidad ante un futuro cambio de peso — ADR-06, §2.1).
# KNOWN_HALLUCINATION (dura, weight=85) NO esta aqui: SI participa en el maximo.
_OVERRIDE_HARD_CODES = frozenset({SignalCode.NONEXISTENT, SignalCode.MALICIOUS})


def _max_hard_weight(signals: tuple[LayerSignal, ...]) -> int:
    """Devuelve el mayor peso de las señales duras que contribuyen al score.

    TYPOSQUAT y NAME_UNTRUSTED son mutuamente excluyentes en la capa 1, pero el
    scorer toma el maximo como defensa en profundidad (ADR-01). KNOWN_HALLUCINATION
    (dura, weight=85) participa con su peso y puede producir block por score (ADR-07).
    Las señales de override (NONEXISTENT y MALICIOUS, ambas weight=0) se excluyen por
    code: su veredicto lo fija el override en `verdict.py`, no el scoring (ADR-06).
    """
    best = 0
    for signal in signals:
        # El canal LLM (is_llm_channel) NUNCA entra al canal duro (defensa en
        # profundidad del anti-block: aunque una senal L4 saliera mal con
        # is_soft=False, su peso no se contaria dos veces — ADR-11, §5.1 #3).
        if signal.is_soft or signal.is_llm_channel:
            continue
        if signal.code in _OVERRIDE_HARD_CODES:
            # Override (NONEXISTENT/MALICIOUS): no contribuye al score numerico.
            continue
        best = max(best, signal.weight)
    return best


def _sum_heuristic_soft(signals: tuple[LayerSignal, ...]) -> int:
    """Suma los pesos de las señales blandas HEURISTICAS (NEW_PACKAGE,
    WEAK_METADATA, LOW_VERIFIABILITY). Excluye el canal LLM (is_llm_channel),
    que tiene su propio techo. El total se acotara a SOFT_CAP en `compute_score`.
    """
    total = 0
    for signal in signals:
        if signal.is_soft and not signal.is_llm_channel:
            total += signal.weight
    return total


def _sum_llm_soft(signals: tuple[LayerSignal, ...]) -> int:
    """Suma los pesos del canal LLM separado (Hito 3, is_llm_channel=True).

    El total se acotara a LLM_SOFT_CAP en `compute_score`. Por construccion la
    senal L4 lleva is_soft=True, de modo que `_max_hard_weight` la ignora; este
    filtro usa solo is_llm_channel para captar tambien una senal mal construida
    (defensa en profundidad: jamas duplica el peso en el canal duro).
    """
    total = 0
    for signal in signals:
        if signal.is_llm_channel:
            total += signal.weight
    return total
