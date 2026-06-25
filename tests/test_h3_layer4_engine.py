"""Tests de la Capa 4: layer4_hallucination, gating y wiring two-pass del engine (Hito 3).

El two-pass se prueba sobre `engine._apply_layer4` directamente (sin red ni PyPI),
con un evaluador FALSO inyectado via monkeypatch y la cache deshabilitada (use_cache=False).
"""

from __future__ import annotations

import pytest

from slopguard.core import engine
from slopguard.core.adapters.base import FetchOutcome, FetchState, PackageMetadata
from slopguard.core.config import Config
from slopguard.core.dataset.top_n import build_top_n
from slopguard.core.layers.layer4_hallucination import evaluate_layer4
from slopguard.core.llm.resolver import is_gray_band
from slopguard.core.models import (
    Clasificacion,
    Dependency,
    DependencyResult,
    Layer,
    LayerSignal,
    LlmAssessment,
    SignalCode,
    Status,
    Verdict,
)
from slopguard.core.scoring.verdict import DepContext, build_dependency_result


def _assess(clasificacion: Clasificacion, confianza: float) -> LlmAssessment:
    return LlmAssessment(
        clasificacion=clasificacion,
        confianza=confianza,
        patron="p",
        rationale="r",
        modelo="claude-opus-4-8",
        prompt_version="h3-v1",
    )


def _new_package_signal() -> LayerSignal:
    return LayerSignal(
        layer=Layer.L0, code=SignalCode.NEW_PACKAGE, weight=15, is_soft=True, detail="joven"
    )


def _gray_result(config: Config, name: str = "reqursts") -> DependencyResult:
    """DependencyResult pre-L4 en banda gris: OK, ALLOW, con una blanda (NEW_PACKAGE)."""
    return build_dependency_result(
        DepContext(name=name, version_pin=None, is_unverifiable=False, error_category=None),
        (_new_package_signal(),),
        config,
    )


def _outcome(name: str = "reqursts", *, edad_dias: int = 10) -> FetchOutcome:
    epoch = 1_700_000_000.0 - edad_dias * 86400
    return FetchOutcome(
        state=FetchState.FOUND,
        metadata=PackageMetadata(
            name=name,
            first_release_epoch=epoch,
            releases_count=1,
            has_repo_url=False,
            has_description=False,
            has_author=False,
            has_license=False,
            has_classifiers=False,
            in_top_n=False,
        ),
    )


def _ctx(config: Config) -> engine._ScanContext:
    return engine._ScanContext(
        config=config,
        now_epoch=1_700_000_000.0,
        top_n=build_top_n([], version="test", generated_at="test"),
        threat_intel={},
    )


class _FakeEvaluator:
    def __init__(self, assessment: LlmAssessment | None) -> None:
        self.assessment = assessment
        self.calls = 0

    def evaluate(
        self, name: str, context: object, ecosystem_id: str = "pypi"
    ) -> LlmAssessment | None:
        self.calls += 1
        return self.assessment


# --- layer4_hallucination.evaluate_layer4 (R2.3/R2.4) ---

def test_evaluate_layer4_abstencion() -> None:
    sig = evaluate_layer4(None, Config())
    assert len(sig) == 1
    assert sig[0].code is SignalCode.LLM_UNAVAILABLE
    assert sig[0].weight == 0


def test_evaluate_layer4_legitimo_sin_senal() -> None:
    assert evaluate_layer4(_assess(Clasificacion.LEGITIMO, 0.99), Config()) == ()


def test_evaluate_layer4_fabricacion_peso() -> None:
    sig = evaluate_layer4(_assess(Clasificacion.FABRICACION, 0.9), Config())
    assert len(sig) == 1
    assert sig[0].code is SignalCode.LLM_HALLUCINATION_SURFACE
    assert sig[0].is_soft is True
    assert sig[0].is_llm_channel is True
    assert sig[0].weight == 49  # floor(55 * 0.9)


def test_evaluate_layer4_confianza_baja_sin_senal() -> None:
    # confianza 0.3 < llm_conf_min (0.5) -> sin senal de riesgo.
    assert evaluate_layer4(_assess(Clasificacion.FABRICACION, 0.3), Config()) == ()


# --- gating is_gray_band (ADR-12) ---

def test_is_gray_band_positivo() -> None:
    config = Config()
    assert is_gray_band(_gray_result(config), None, config) is True


def test_is_gray_band_excluye_senal_dura() -> None:
    config = Config()
    dura = build_dependency_result(
        DepContext(name="flask-x", version_pin=None, is_unverifiable=False, error_category=None),
        (LayerSignal(layer=Layer.L1, code=SignalCode.TYPOSQUAT, weight=60,
                     is_soft=False, detail="t", suspected_target="flask"),),
        config,
    )
    assert dura.verdict is Verdict.WARN  # 60 -> warn, no block; pero tiene senal dura
    assert is_gray_band(dura, None, config) is False


def test_is_gray_band_excluye_viejo_sin_blanda() -> None:
    config = Config()
    limpio = build_dependency_result(
        DepContext(name="requests", version_pin=None, is_unverifiable=False, error_category=None),
        (),
        config,
    )
    # Sin blanda y viejo (>= gray_edad_max_dias): "claramente legitima" -> excluida.
    assert is_gray_band(limpio, config.gray_edad_max_dias, config) is False
    assert is_gray_band(limpio, 10_000, config) is False


def test_is_gray_band_joven_sin_blanda() -> None:
    config = Config()
    limpio = build_dependency_result(
        DepContext(name="reqs-nuevo", version_pin=None, is_unverifiable=False, error_category=None),
        (),
        config,
    )
    # ADR-12 rama "joven": un paquete de 90-365 dias con buena metadata (sin senal
    # blanda, NEW_PACKAGE solo dispara <90) entra a la Capa 4 por edad. (Bug del review.)
    assert is_gray_band(limpio, config.gray_edad_max_dias - 1, config) is True
    assert is_gray_band(limpio, 100, config) is True


# --- engine two-pass (_apply_layer4) ---

def test_two_pass_eleva_a_warn_nunca_block(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config(enable_layer4=True)
    fab = _assess(Clasificacion.FABRICACION, 1.0)
    fake = _FakeEvaluator(fab)
    monkeypatch.setattr(engine, "get_llm_evaluator", lambda _c, *, use_cache: fake)
    dep = Dependency(name="reqursts", version_pin=None, raw="reqursts", origin="r.txt")
    result = _gray_result(config)
    assert result.verdict is Verdict.ALLOW  # pre-L4
    out = engine._apply_layer4(
        (result,), (dep,), {"reqursts": _outcome()}, _ctx(config), use_cache=False
    )
    assert fake.calls == 1
    assert out[0].verdict is Verdict.WARN  # 15 (NEW_PACKAGE) + min(55,50)=50 -> 65 -> warn
    assert out[0].verdict is not Verdict.BLOCK  # type: ignore[comparison-overlap]
    assert out[0].llm_assessment is fab


def test_two_pass_abstencion_preserva_veredicto(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config(enable_layer4=True)
    fake = _FakeEvaluator(None)
    monkeypatch.setattr(engine, "get_llm_evaluator", lambda _c, *, use_cache: fake)
    dep = Dependency(name="reqursts", version_pin=None, raw="reqursts", origin="r.txt")
    result = _gray_result(config)
    out = engine._apply_layer4(
        (result,), (dep,), {"reqursts": _outcome()}, _ctx(config), use_cache=False
    )
    assert out[0].verdict is Verdict.ALLOW  # intacto: LLM_UNAVAILABLE no degrada
    assert out[0].llm_assessment is None
    assert any(s.code is SignalCode.LLM_UNAVAILABLE for s in out[0].signals)
    assert out[0].status is Status.OK  # no degrada a unverifiable


def test_two_pass_off_es_identico(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config(enable_layer4=False)
    # Si por error llamara al factory, fallaria; verifica que NO lo llama.
    def _boom(_c: object, *, use_cache: bool) -> object:
        raise AssertionError("get_llm_evaluator no debe llamarse con enable_layer4=False")
    monkeypatch.setattr(engine, "get_llm_evaluator", _boom)
    dep = Dependency(name="reqursts", version_pin=None, raw="reqursts", origin="r.txt")
    result = _gray_result(config)
    out = engine._apply_layer4(
        (result,), (dep,), {"reqursts": _outcome()}, _ctx(config), use_cache=False
    )
    assert out == (result,)


def test_schema_version_1_2() -> None:
    assert engine._SCHEMA_VERSION == "1.2"


def test_count_llm_unavailable() -> None:
    config = Config()
    sig = LayerSignal(
        layer=Layer.L4, code=SignalCode.LLM_UNAVAILABLE, weight=0, is_soft=True, detail="x"
    )
    con = build_dependency_result(
        DepContext(name="a", version_pin=None, is_unverifiable=False, error_category=None),
        (sig,), config,
    )
    sin = build_dependency_result(
        DepContext(name="b", version_pin=None, is_unverifiable=False, error_category=None),
        (), config,
    )
    assert engine._count_llm_unavailable((con, sin)) == 1
