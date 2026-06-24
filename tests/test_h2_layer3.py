"""Pruebas H2-T10: Capa 3 pura (layer3_threatintel) — senales L3 por MaliceState.

Cobertura de criterios EARS verificados:
- R1.2  : MALICIOUS => senal dura weight=0 + IDs MAL-* en detail.
- R1.4  : CLEAN => sin senal (tupla vacia).
- R2.3  : KNOWN_HALLUCINATION => senal dura weight=85 + fuente/fecha en detail (R7.2).
- R3.3  : THREATINTEL_UNVERIFIABLE => senal blanda weight=0; nunca eleva sola.
- R8.3  : layer3_threatintel NO importa core.threatintel.* (frontera import-linter §1.3).
- ADR-06: MALICIOUS es dura is_soft=False, peso=0 (override, simetria con NONEXISTENT).
- ADR-07: KNOWN_HALLUCINATION es dura is_soft=False, peso=85 (>= umbral_block=80).
- ADR-10: UNVERIFIABLE es blanda is_soft=True, peso=0 (invariante anti-FP).
- NFR-Det.1: funcion pura y determinista (misma entrada => misma salida).
"""

from __future__ import annotations

import importlib
import sys

import pytest

from slopguard.core import models as core_models
from slopguard.core.layers import layer3_threatintel
from slopguard.core.models import (
    Advisory,
    Layer,
    LayerSignal,
    MaliceState,
    SignalCode,
    ThreatIntelResult,
)
from slopguard.core.scoring.scorer import compute_score

# ---------------------------------------------------------------------------
# Helpers de construccion
# ---------------------------------------------------------------------------

_ADV_1 = Advisory(
    id="MAL-2025-47868",
    kind="malicious",
    url="https://osv.dev/vulnerability/MAL-2025-47868",
    source="osv",
)
_ADV_2 = Advisory(
    id="MAL-2025-99999",
    kind="malicious",
    url="https://osv.dev/vulnerability/MAL-2025-99999",
    source="osv",
)


def _malicious(advisories: tuple[Advisory, ...] = (_ADV_1,)) -> ThreatIntelResult:
    """ThreatIntelResult MALICIOUS con un advisory por defecto."""
    return ThreatIntelResult(
        name="bioql",
        state=MaliceState.MALICIOUS,
        advisories=advisories,
    )


def _hallucination(
    source: str | None = "depscope-hallucinations",
    date: str | None = "2026-06-20",
) -> ThreatIntelResult:
    """ThreatIntelResult KNOWN_HALLUCINATION con fuente y fecha por defecto."""
    return ThreatIntelResult(
        name="reqe",
        state=MaliceState.KNOWN_HALLUCINATION,
        watchlist_source=source,
        watchlist_date=date,
    )


def _unverifiable(reason: str | None = "timeout en OSV") -> ThreatIntelResult:
    """ThreatIntelResult UNVERIFIABLE con motivo saneado."""
    return ThreatIntelResult(
        name="flaky",
        state=MaliceState.UNVERIFIABLE,
        unverifiable_reason=reason,
    )


def _clean() -> ThreatIntelResult:
    """ThreatIntelResult CLEAN (sin advisories, sin senales)."""
    return ThreatIntelResult(name="requests", state=MaliceState.CLEAN)


# ===========================================================================
# Frontera de import (R8.3, contrato import-linter 1+3)
# ===========================================================================


class TestFronteraDeImport:
    """layer3_threatintel NO importa core.threatintel.* (design §1.4, R8.3)."""

    def test_layer3_no_importa_threatintel_source(self) -> None:
        """La Capa 3 no debe referenciar ningun modulo de core.threatintel.*."""
        layer3_mod = importlib.import_module(
            "slopguard.core.layers.layer3_threatintel"
        )
        modulos_prohibidos = {
            "slopguard.core.threatintel.source",
            "slopguard.core.threatintel.osv",
            "slopguard.core.threatintel.watchlist",
            "slopguard.core.threatintel.composite",
            "slopguard.core.threatintel.resolver",
        }
        for mod_name in modulos_prohibidos:
            mod = sys.modules.get(mod_name)
            if mod is None:
                continue
            assert mod not in vars(layer3_mod).values(), (
                f"layer3_threatintel importa '{mod_name}' directamente (viola R8.3)"
            )

    def test_malicestate_viene_de_core_models(self) -> None:
        """MaliceState importado en el modulo es el mismo objeto que core.models.MaliceState."""
        assert MaliceState is core_models.MaliceState

    def test_threatintelresult_viene_de_core_models(self) -> None:
        """ThreatIntelResult importado en el modulo es el mismo objeto que en core.models."""
        assert ThreatIntelResult is core_models.ThreatIntelResult

    def test_advisory_viene_de_core_models(self) -> None:
        """Advisory importado en el modulo es el mismo objeto que en core.models."""
        assert Advisory is core_models.Advisory


# ===========================================================================
# Estado CLEAN: sin senal (R1.4)
# ===========================================================================


class TestClean:
    """R1.4: CLEAN => tupla vacia, nunca genera senales."""

    def test_clean_produce_tupla_vacia(self) -> None:
        signals = layer3_threatintel.evaluate(_clean())
        assert signals == ()

    def test_clean_es_tuple_no_list(self) -> None:
        signals = layer3_threatintel.evaluate(_clean())
        assert isinstance(signals, tuple)


# ===========================================================================
# Estado MALICIOUS: senal dura weight=0 + advisories en detail (ADR-06, R1.2)
# ===========================================================================


class TestMalicious:
    """ADR-06 / R1.2: MALICIOUS => senal dura, weight=0, is_soft=False."""

    def test_malicious_produce_exactamente_una_senal(self) -> None:
        signals = layer3_threatintel.evaluate(_malicious())
        assert len(signals) == 1

    def test_malicious_capa_es_l3(self) -> None:
        signal = layer3_threatintel.evaluate(_malicious())[0]
        assert signal.layer is Layer.L3

    def test_malicious_code_es_malicious(self) -> None:
        signal = layer3_threatintel.evaluate(_malicious())[0]
        assert signal.code is SignalCode.MALICIOUS

    def test_malicious_weight_es_cero(self) -> None:
        """Peso=0: el override lo aplica build_dependency_result, no el scorer (ADR-06)."""
        signal = layer3_threatintel.evaluate(_malicious())[0]
        assert signal.weight == 0

    def test_malicious_es_dura(self) -> None:
        """is_soft=False: senal dura, simetria con NONEXISTENT (ADR-06)."""
        signal = layer3_threatintel.evaluate(_malicious())[0]
        assert signal.is_soft is False

    def test_malicious_detail_porta_id_advisory(self) -> None:
        """El ID MAL-* aparece en el detail (R7.1)."""
        signal = layer3_threatintel.evaluate(_malicious((_ADV_1,)))[0]
        assert "MAL-2025-47868" in signal.detail

    def test_malicious_detail_porta_multiples_ids(self) -> None:
        """Con varios advisories, todos los IDs aparecen en el detail."""
        signal = layer3_threatintel.evaluate(_malicious((_ADV_1, _ADV_2)))[0]
        assert "MAL-2025-47868" in signal.detail
        assert "MAL-2025-99999" in signal.detail

    def test_malicious_sin_advisories_no_falla(self) -> None:
        """Sin advisories (caso raro), la senal se emite con 'sin ID' en el detail."""
        result = ThreatIntelResult(name="bioql", state=MaliceState.MALICIOUS)
        signals = layer3_threatintel.evaluate(result)
        assert len(signals) == 1
        assert "sin ID" in signals[0].detail

    def test_malicious_suspected_target_es_none(self) -> None:
        """MALICIOUS no es typosquat: suspected_target=None."""
        signal = layer3_threatintel.evaluate(_malicious())[0]
        assert signal.suspected_target is None


# ===========================================================================
# Estado KNOWN_HALLUCINATION: senal dura weight=85 (ADR-07, R2.3)
# ===========================================================================


class TestKnownHallucination:
    """ADR-07 / R2.3: KNOWN_HALLUCINATION => senal dura, weight=85, is_soft=False."""

    def test_hallucination_produce_exactamente_una_senal(self) -> None:
        signals = layer3_threatintel.evaluate(_hallucination())
        assert len(signals) == 1

    def test_hallucination_capa_es_l3(self) -> None:
        signal = layer3_threatintel.evaluate(_hallucination())[0]
        assert signal.layer is Layer.L3

    def test_hallucination_code_es_known_hallucination(self) -> None:
        signal = layer3_threatintel.evaluate(_hallucination())[0]
        assert signal.code is SignalCode.KNOWN_HALLUCINATION

    def test_hallucination_weight_es_85(self) -> None:
        """Peso=85 >= umbral_block=80: bloquea por score, no por override (ADR-07)."""
        signal = layer3_threatintel.evaluate(_hallucination())[0]
        assert signal.weight == 85

    def test_hallucination_es_dura(self) -> None:
        """is_soft=False: senal dura que puede cruzar umbral_block (ADR-07)."""
        signal = layer3_threatintel.evaluate(_hallucination())[0]
        assert signal.is_soft is False

    def test_hallucination_detail_incluye_fuente(self) -> None:
        """La fuente del corpus aparece en el detail (R7.2)."""
        signal = layer3_threatintel.evaluate(
            _hallucination(source="depscope-hallucinations")
        )[0]
        assert "depscope-hallucinations" in signal.detail

    def test_hallucination_detail_incluye_fecha(self) -> None:
        """La fecha del corpus aparece en el detail (R7.2)."""
        signal = layer3_threatintel.evaluate(_hallucination(date="2026-06-20"))[0]
        assert "2026-06-20" in signal.detail

    def test_hallucination_sin_fuente_usa_fallback(self) -> None:
        """Si watchlist_source=None, el detail usa un fallback legible no vacio."""
        signal = layer3_threatintel.evaluate(_hallucination(source=None, date=None))[0]
        assert len(signal.detail) > 0

    def test_hallucination_suspected_target_es_none(self) -> None:
        signal = layer3_threatintel.evaluate(_hallucination())[0]
        assert signal.suspected_target is None


# ===========================================================================
# Estado UNVERIFIABLE: senal blanda weight=0 (ADR-10, R3.3)
# ===========================================================================


class TestUnverifiable:
    """ADR-10 / R3.3: UNVERIFIABLE => senal blanda, weight=0, is_soft=True."""

    def test_unverifiable_produce_exactamente_una_senal(self) -> None:
        signals = layer3_threatintel.evaluate(_unverifiable())
        assert len(signals) == 1

    def test_unverifiable_capa_es_l3(self) -> None:
        signal = layer3_threatintel.evaluate(_unverifiable())[0]
        assert signal.layer is Layer.L3

    def test_unverifiable_code_es_threatintel_unverifiable(self) -> None:
        signal = layer3_threatintel.evaluate(_unverifiable())[0]
        assert signal.code is SignalCode.THREATINTEL_UNVERIFIABLE

    def test_unverifiable_weight_es_cero(self) -> None:
        """Peso=0: nunca contribuye al score numerico (invariante anti-FP, R3.3)."""
        signal = layer3_threatintel.evaluate(_unverifiable())[0]
        assert signal.weight == 0

    def test_unverifiable_es_blanda(self) -> None:
        """is_soft=True: nunca eleva sola a warn/block (invariante anti-FP, R3.3)."""
        signal = layer3_threatintel.evaluate(_unverifiable())[0]
        assert signal.is_soft is True

    def test_unverifiable_detail_incluye_motivo(self) -> None:
        """El motivo saneado del fallo aparece en el detail."""
        signal = layer3_threatintel.evaluate(_unverifiable("timeout en OSV"))[0]
        assert "timeout en OSV" in signal.detail

    def test_unverifiable_sin_motivo_usa_fallback(self) -> None:
        """Si unverifiable_reason=None, el detail usa un fallback no vacio."""
        signal = layer3_threatintel.evaluate(_unverifiable(None))[0]
        assert len(signal.detail) > 0

    def test_unverifiable_suspected_target_es_none(self) -> None:
        signal = layer3_threatintel.evaluate(_unverifiable())[0]
        assert signal.suspected_target is None


# ===========================================================================
# Tabla exhaustiva: cada estado => exactamente la senal esperada
# ===========================================================================


@pytest.mark.parametrize(
    "result, expected_code, expected_weight, expected_is_soft, expected_count",
    [
        (_malicious(), SignalCode.MALICIOUS, 0, False, 1),
        (_hallucination(), SignalCode.KNOWN_HALLUCINATION, 85, False, 1),
        (_unverifiable(), SignalCode.THREATINTEL_UNVERIFIABLE, 0, True, 1),
        (_clean(), None, None, None, 0),
    ],
    ids=["MALICIOUS", "KNOWN_HALLUCINATION", "UNVERIFIABLE", "CLEAN"],
)
def test_tabla_estado_senal(
    result: ThreatIntelResult,
    expected_code: SignalCode | None,
    expected_weight: int | None,
    expected_is_soft: bool | None,
    expected_count: int,
) -> None:
    """Tabla exhaustiva: cada MaliceState produce exactamente la senal esperada."""
    signals = layer3_threatintel.evaluate(result)
    assert len(signals) == expected_count
    if expected_count == 1:
        sig = signals[0]
        assert sig.code is expected_code
        assert sig.weight == expected_weight
        assert sig.is_soft is expected_is_soft
        assert sig.layer is Layer.L3


# ===========================================================================
# Determinismo: misma entrada => misma salida (NFR-Det.1)
# ===========================================================================


class TestDeterminismo:
    """NFR-Det.1: la Capa 3 es pura y determinista."""

    def test_malicious_es_determinista(self) -> None:
        r = _malicious((_ADV_1, _ADV_2))
        assert layer3_threatintel.evaluate(r) == layer3_threatintel.evaluate(r)

    def test_hallucination_es_determinista(self) -> None:
        r = _hallucination()
        assert layer3_threatintel.evaluate(r) == layer3_threatintel.evaluate(r)

    def test_unverifiable_es_determinista(self) -> None:
        r = _unverifiable("error de red")
        assert layer3_threatintel.evaluate(r) == layer3_threatintel.evaluate(r)

    def test_clean_es_determinista(self) -> None:
        r = _clean()
        assert layer3_threatintel.evaluate(r) == layer3_threatintel.evaluate(r)

    def test_mismos_advisories_mismo_detail(self) -> None:
        """El detail de MALICIOUS es determinista respecto al orden de advisories."""
        r1 = _malicious((_ADV_1, _ADV_2))
        r2 = _malicious((_ADV_1, _ADV_2))
        s1 = layer3_threatintel.evaluate(r1)[0]
        s2 = layer3_threatintel.evaluate(r2)[0]
        assert s1.detail == s2.detail


# ===========================================================================
# Invariante anti-FP: UNVERIFIABLE no contribuye al scorer (R3.3)
# ===========================================================================


class TestInvarianteAntiFP:
    """R3.3: THREATINTEL_UNVERIFIABLE (blanda, peso=0) no alimenta el score."""

    def test_unverifiable_peso_cero_no_afecta_scorer(self) -> None:
        """La senal blanda con peso=0 no debe sumar al scorer."""
        signals = layer3_threatintel.evaluate(_unverifiable())
        score = compute_score(signals)
        assert score == 0

    def test_unverifiable_mas_blandas_queda_bajo_umbral_warn(self) -> None:
        """THREATINTEL_UNVERIFIABLE + NEW_PACKAGE (peso 15) < umbral_warn=50 (anti-FP)."""
        soft_signal = LayerSignal(
            layer=Layer.L3,
            code=SignalCode.NEW_PACKAGE,
            weight=15,
            is_soft=True,
            detail="Paquete nuevo",
        )
        unverif_signal = layer3_threatintel.evaluate(_unverifiable())[0]
        score = compute_score((soft_signal, unverif_signal))
        # 15 blandas + 0 THREATINTEL_UNVERIFIABLE = 15 < 50 umbral_warn
        assert score < 50

    def test_malicious_no_contribuye_al_scorer(self) -> None:
        """MALICIOUS (dura, peso=0) no altera el maximo de duras en el scorer."""
        signals = layer3_threatintel.evaluate(_malicious())
        score = compute_score(signals)
        assert score == 0
