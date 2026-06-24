"""Tests de propiedad del scorer extendido con el canal LLM (Hito 3, §5.1 #1-#5).

Blindan el invariante anti-block: la Capa 4 puede llevar a `warn` pero NUNCA a
`block`, ni sola ni combinada con blandas heuristicas, ni siquiera ante una senal
L4 mal construida (defensa en profundidad de `_max_hard_weight`).
"""

from __future__ import annotations

import itertools

from slopguard.core.config import Config
from slopguard.core.models import Layer, LayerSignal, SignalCode
from slopguard.core.scoring.scorer import (
    LLM_SOFT_CAP,
    SOFT_CAP,
    _max_hard_weight,
    _sum_llm_soft,
    compute_score,
)


def _sig(
    code: SignalCode,
    weight: int,
    *,
    is_soft: bool,
    is_llm_channel: bool = False,
    layer: Layer = Layer.L4,
) -> LayerSignal:
    return LayerSignal(
        layer=layer,
        code=code,
        weight=weight,
        is_soft=is_soft,
        detail="x",
        is_llm_channel=is_llm_channel,
    )


def _llm(weight: int) -> LayerSignal:
    """Senal L4 BIEN construida: is_soft=True + is_llm_channel=True."""
    return _sig(
        SignalCode.LLM_HALLUCINATION_SURFACE,
        weight,
        is_soft=True,
        is_llm_channel=True,
    )


_HEURISTICAS = (
    _sig(SignalCode.NEW_PACKAGE, 15, is_soft=True, layer=Layer.L0),
    _sig(SignalCode.WEAK_METADATA, 7, is_soft=True, layer=Layer.L2),
    _sig(SignalCode.LOW_VERIFIABILITY, 5, is_soft=True, layer=Layer.L2),
)


def test_caps_estructurales_bajo_umbral_block() -> None:
    """§5.1 #1 (cota): SOFT_CAP + LLM_SOFT_CAP < umbral_block por construccion."""
    assert SOFT_CAP + LLM_SOFT_CAP < Config().umbral_block


def test_anti_block_sin_senal_dura() -> None:
    """§5.1 #1: ninguna combinacion de blandas + canal LLM (sin dura) llega a block."""
    umbral_block = Config().umbral_block
    for r in range(len(_HEURISTICAS) + 1):
        for combo in itertools.combinations(_HEURISTICAS, r):
            for peso_llm in range(0, LLM_SOFT_CAP + 1):
                score = compute_score((*combo, _llm(peso_llm)))
                assert score < umbral_block, (combo, peso_llm, score)


def test_max_hard_excluye_canal_llm() -> None:
    """§5.1 #3: una senal mal construida (is_llm_channel=True, is_soft=False) NO
    se cuenta en el canal duro; su peso jamas se duplica."""
    mal = _sig(
        SignalCode.LLM_HALLUCINATION_SURFACE,
        50,
        is_soft=False,
        is_llm_channel=True,
    )
    assert _max_hard_weight((mal,)) == 0
    # score = 0 (dura) + 0 (heur) + 50 (llm) = 50, no 100.
    assert compute_score((mal,)) == 50


def test_canal_llm_separado_de_heuristicas() -> None:
    """§5.1 #4: una blanda heuristica NO entra al canal LLM y viceversa."""
    assert _sum_llm_soft((_HEURISTICAS[0],)) == 0
    assert _sum_llm_soft((_llm(30),)) == 30


def test_retrocompat_sin_canal_llm() -> None:
    """§5.1 #5: sin senal L4, el score es identico al modelo de 2 sumandos H1/H2."""
    dura = _sig(SignalCode.TYPOSQUAT, 60, is_soft=False, layer=Layer.L1)
    signals = (dura, *_HEURISTICAS)
    esperado = 60 + min(15 + 7 + 5, SOFT_CAP)  # 60 + 25 = 85
    assert compute_score(signals) == esperado


def test_llm_alta_confianza_puede_warn_no_block() -> None:
    """La senal L4 al tope alcanza `warn` (>=50) pero nunca `block` (>=80)."""
    cfg = Config()
    score = compute_score((_llm(LLM_SOFT_CAP),))
    assert score >= cfg.umbral_warn
    assert score < cfg.umbral_block
