"""Scoring determinista de señales de capas → score entero 0-100 (T30, R5.1, ADR-01).

Modelo aditivo con saturacion:

    score = min(100, dura + min(blandas, SOFT_CAP))

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

Sin I/O, sin red, sin reloj. Funcion pura y determinista (R5.7).
Importa SOLO de: core.models y core.config.
"""

from __future__ import annotations

from slopguard.core.models import LayerSignal, SignalCode

# Techo de las señales blandas (ADR-01).
# Invariante estructural: SOFT_CAP < umbral_warn (50 default) ⟹ blandas solas
# nunca producen warn/block (R5.6 por construccion).
SOFT_CAP = 25

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
    soft_total = _sum_soft_weights(signals)
    return min(SCORE_MAX, hard_weight + min(soft_total, SOFT_CAP))


def _max_hard_weight(signals: tuple[LayerSignal, ...]) -> int:
    """Devuelve el mayor peso de las señales duras (TYPOSQUAT y NAME_UNTRUSTED).

    TYPOSQUAT y NAME_UNTRUSTED son mutuamente excluyentes en la capa 1,
    pero el scorer toma el maximo como defensa en profundidad (ADR-01).
    NONEXISTENT tiene peso=0 y es_soft=False; al filtrarlo tambien se excluye.
    """
    best = 0
    for signal in signals:
        if signal.is_soft:
            continue
        if signal.code is SignalCode.NONEXISTENT:
            # Override: no contribuye al score numerico.
            continue
        best = max(best, signal.weight)
    return best


def _sum_soft_weights(signals: tuple[LayerSignal, ...]) -> int:
    """Suma los pesos de todas las señales blandas (NEW_PACKAGE, WEAK_METADATA,
    LOW_VERIFIABILITY). El total se acotara a SOFT_CAP en `compute_score`.
    """
    total = 0
    for signal in signals:
        if signal.is_soft:
            total += signal.weight
    return total
