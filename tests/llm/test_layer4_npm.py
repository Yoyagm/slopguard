"""Tests de la Capa 4 (LLM) para el ecosistema npm (H4-T34, ADR-6, §7.1, §7.2).

Cierra R9.1/R9.2/R9.3/R9.4 desde la perspectiva del COMPORTAMIENTO observable de la
Capa 4 cuando la corrida es npm, no de los detalles internos del resolver (esos los
cubre `test_h4_resolver_ecosystem.py`). Aqui se verifican las propiedades de frontera:

- **R9.1** un `LlmEvaluator` falso recibe `ecosystem_id == "npm"` por toda la cadena, y
  `build_prompt` emite el texto "npm" (no "PyPI") para una dep npm.
- **R9.2** la clave de cache L4 incluye `ecosystem_id` como primer componente (npm y PyPI
  del MISMO nombre/contexto NO colisionan) y el blob persiste/valida `ecosystem` (2a capa:
  un blob `pypi` se RECHAZA al leer como `npm` para el mismo `react`, y viceversa). El sello
  del assessment usa `Config.prompt_version == "h4-v1"`.
- **R9.3** propiedad estructural anti-block: la Capa 4 npm, por agresivo que sea el veredicto
  del LLM (fabricacion, confianza 1.0), NUNCA produce `block` (a lo sumo `warn`).
- **R9.4** `LLM_UNAVAILABLE` (abstencion) no degrada `status`/veredicto ni el exit code.

El two-pass se ejercita sobre `engine._apply_layer4` con un evaluador FALSO inyectado por
monkeypatch y la cache deshabilitada (sin red ni clave de API), espejando
`test_h3_layer4_engine.py` pero con `ecosystem_id == "npm"`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from slopguard.core import engine
from slopguard.core.adapters.base import FetchOutcome, FetchState, PackageMetadata
from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config
from slopguard.core.dataset.top_n import build_top_n
from slopguard.core.llm.prompt import build_prompt
from slopguard.core.llm.resolver import _cache_key, _to_blob, _validate_blob, resolve_layer4
from slopguard.core.models import (
    LLM_SOFT_CAP,
    SOFT_CAP,
    Clasificacion,
    Dependency,
    DependencyResult,
    HallucinationContext,
    Layer,
    LayerSignal,
    LlmAssessment,
    SignalCode,
    Status,
    Verdict,
)
from slopguard.core.scoring.verdict import (
    DepContext,
    aggregate_exit_code,
    build_dependency_result,
)

if TYPE_CHECKING:
    from pathlib import Path

_NOW_EPOCH = 1_700_000_000.0


# --------------------------------------------------------------------------- #
# Dobles de prueba y constructores deterministas.
# --------------------------------------------------------------------------- #


class _RecordingEvaluator:
    """`LlmEvaluator` FALSO conforme al Protocol: registra el `ecosystem_id` recibido.

    Contrato de `evaluate` (design §3.7): NUNCA lanza; devuelve `LlmAssessment` o `None`.
    """

    def __init__(self, assessment: LlmAssessment | None) -> None:
        self._assessment = assessment
        self.calls: list[tuple[str, str]] = []

    def evaluate(
        self, name: str, context: HallucinationContext, ecosystem_id: str = "pypi"
    ) -> LlmAssessment | None:
        self.calls.append((name, ecosystem_id))
        return self._assessment


def _assessment(
    clasificacion: Clasificacion = Clasificacion.FABRICACION,
    confianza: float = 1.0,
    *,
    prompt_version: str = "h4-v1",
) -> LlmAssessment:
    return LlmAssessment(
        clasificacion=clasificacion,
        confianza=confianza,
        patron="p",
        rationale="r",
        modelo="claude-opus-4-8",
        prompt_version=prompt_version,
    )


def _context() -> HallucinationContext:
    return HallucinationContext(
        existe=True,
        edad_dias=10,
        typo_vecino=None,
        typo_distancia=None,
        tiene_repo=False,
        tiene_metadata=False,
        senales_blandas=(),
    )


def _new_package_signal() -> LayerSignal:
    return LayerSignal(
        layer=Layer.L0, code=SignalCode.NEW_PACKAGE, weight=15, is_soft=True, detail="joven"
    )


def _gray_result(config: Config, name: str) -> DependencyResult:
    """`DependencyResult` pre-L4 en banda gris: OK, ALLOW, una sola senal blanda."""
    return build_dependency_result(
        DepContext(name=name, version_pin=None, is_unverifiable=False, error_category=None),
        (_new_package_signal(),),
        config,
    )


def _outcome(name: str, *, edad_dias: int = 10) -> FetchOutcome:
    epoch = _NOW_EPOCH - edad_dias * 86400
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


def _npm_ctx(config: Config) -> engine._ScanContext:
    return engine._ScanContext(
        config=config,
        now_epoch=_NOW_EPOCH,
        top_n=build_top_n([], version="test", generated_at="test"),
        threat_intel={},
        ecosystem_id="npm",
    )


# --------------------------------------------------------------------------- #
# R9.1 — el ecosistema "npm" cruza toda la cadena y llega al texto del prompt.
# --------------------------------------------------------------------------- #


def test_two_pass_npm_propaga_ecosystem_id_al_evaluador(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Arrange: corrida npm, dep en banda gris, evaluador falso que registra el ecosistema.
    config = Config(enable_layer4=True)
    fake = _RecordingEvaluator(_assessment(Clasificacion.LEGITIMO, 0.9))
    monkeypatch.setattr(engine, "get_llm_evaluator", lambda _c, *, use_cache: fake)
    dep = Dependency(name="lodahs", version_pin=None, raw="lodahs", origin="package.json")
    result = _gray_result(config, "lodahs")

    # Act
    engine._apply_layer4(
        (result,), (dep,), {"lodahs": _outcome("lodahs")}, _npm_ctx(config), use_cache=False
    )

    # Assert: el evaluador fue invocado con ecosystem_id == "npm" (no el default "pypi").
    assert fake.calls == [("lodahs", "npm")]


def test_build_prompt_npm_dice_npm_no_pypi() -> None:
    # R9.1: el texto del prompt para una dep npm contiene "npm" y NO "PyPI".
    prompt = build_prompt("lodahs", _context(), "npm")
    assert "npm" in prompt
    assert "PyPI" not in prompt


def test_build_prompt_pypi_conserva_pypi() -> None:
    # Cero regresion del texto PyPI (R9.5): la rama pypi sigue diciendo "PyPI".
    prompt = build_prompt("reqursts", _context(), "pypi")
    assert "PyPI" in prompt


# --------------------------------------------------------------------------- #
# R9.2 — aislamiento por CLAVE: npm y PyPI del mismo nombre/contexto no colisionan.
# --------------------------------------------------------------------------- #


def test_cache_key_npm_no_colisiona_con_pypi_mismo_nombre() -> None:
    config = Config()
    context = _context()
    key_npm = _cache_key("react", context, config, "npm")
    key_pypi = _cache_key("react", context, config, "pypi")
    assert key_npm != key_pypi
    # El ecosistema es el PRIMER componente de la clave content-addressed (Nota A).
    assert key_npm.split("|")[0] == "npm"
    assert key_pypi.split("|")[0] == "pypi"


# --------------------------------------------------------------------------- #
# R9.2 — aislamiento por VALIDADOR (2a capa): blob de ecosistema ajeno => miss.
# --------------------------------------------------------------------------- #


def test_validate_blob_rechaza_blob_pypi_leido_como_npm_para_react() -> None:
    # Un blob L4 sellado con ecosystem=="pypi" se RECHAZA al leer como npm (mismo `react`).
    blob_pypi = _to_blob(_assessment(), "pypi")
    assert _validate_blob(blob_pypi, "npm") is None


def test_validate_blob_rechaza_blob_npm_leido_como_pypi_para_react() -> None:
    # Y la simetria inversa: un blob npm no es legible como pypi (aislamiento bidireccional).
    blob_npm = _to_blob(_assessment(), "npm")
    assert _validate_blob(blob_npm, "pypi") is None


def test_validate_blob_acepta_mismo_ecosistema_npm() -> None:
    # Sanidad: el blob npm SI se reconstruye cuando se lee como npm.
    reconstruido = _validate_blob(_to_blob(_assessment(), "npm"), "npm")
    assert reconstruido is not None
    assert reconstruido.clasificacion is Clasificacion.FABRICACION


def test_resolve_layer4_blob_pypi_manipulado_a_clave_npm_no_se_sirve(
    tmp_path: Path,
) -> None:
    # Defensa por VALIDADOR end-to-end: aunque un blob con ecosystem=="pypi" se persistiera
    # bajo la clave de npm (clave malformada), `_validate_blob` lo rechaza al leer como npm
    # => miss => refetch. El aislamiento no depende solo de la clave (NFR-Seg.3, §7.2 pto 4).
    config = Config()
    cache = DiskCache(tmp_path, config.llm_ttl_cache_horas, enabled=True)
    context = _context()
    npm_key = _cache_key("react", context, config, "npm")
    cache.put_blob(
        "llm", npm_key, _to_blob(_assessment(), "pypi"),
        schema_version="llm-1", now=_NOW_EPOCH,
    )

    evaluator = _RecordingEvaluator(_assessment())
    resolved = resolve_layer4(
        evaluator, cache, [("react", context)], config, "npm", now=_NOW_EPOCH
    )

    assert resolved["react"] is not None
    # El blob de ecosistema ajeno fue rechazado: el evaluador npm tuvo que ejecutarse.
    assert evaluator.calls == [("react", "npm")]


# --------------------------------------------------------------------------- #
# R9.2 — el sello del assessment usa Config.prompt_version == "h4-v1".
# --------------------------------------------------------------------------- #


def test_config_prompt_version_default_h4_v1() -> None:
    # El bump del Hito 4 (ADR-6 pto 1): el campo que gobierna la clave/sello es h4-v1.
    assert Config().prompt_version == "h4-v1"


def test_cache_key_npm_incluye_prompt_version_h4_v1() -> None:
    # El sello viaja como cuarto componente de la clave content-addressed (forma Nota A).
    config = Config()
    key = _cache_key("react", _context(), config, "npm")
    assert key.split("|")[3] == "h4-v1"


# --------------------------------------------------------------------------- #
# R9.3 — anti-block estructural: la Capa 4 npm NUNCA produce block.
# --------------------------------------------------------------------------- #


def test_two_pass_npm_eleva_a_warn_nunca_block(monkeypatch: pytest.MonkeyPatch) -> None:
    # Propiedad estructural (ADR-11): con el veredicto LLM mas agresivo posible
    # (fabricacion, confianza 1.0) la Capa 4 npm sube a `warn`, jamas a `block`.
    config = Config(enable_layer4=True)
    fab = _assessment(Clasificacion.FABRICACION, 1.0)
    fake = _RecordingEvaluator(fab)
    monkeypatch.setattr(engine, "get_llm_evaluator", lambda _c, *, use_cache: fake)
    dep = Dependency(name="lodahs", version_pin=None, raw="lodahs", origin="package.json")
    result = _gray_result(config, "lodahs")
    assert result.verdict is Verdict.ALLOW  # pre-L4

    out = engine._apply_layer4(
        (result,), (dep,), {"lodahs": _outcome("lodahs")}, _npm_ctx(config), use_cache=False
    )

    assert out[0].verdict is Verdict.WARN
    assert out[0].verdict is not Verdict.BLOCK  # type: ignore[comparison-overlap]
    assert out[0].llm_assessment is fab


def test_anti_block_invariante_de_topes_para_npm() -> None:
    # Refuerzo de la propiedad por construccion (R9.3): incluso sumando el techo heuristico
    # (SOFT_CAP) y el canal LLM al maximo (LLM_SOFT_CAP), no se alcanza umbral_block.
    config = Config()
    assert SOFT_CAP + LLM_SOFT_CAP < config.umbral_block


# --------------------------------------------------------------------------- #
# R9.4 — LLM_UNAVAILABLE (abstencion) no degrada status/veredicto ni exit code.
# --------------------------------------------------------------------------- #


def test_two_pass_npm_abstencion_preserva_veredicto_y_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Una abstencion del evaluador (=> None) emite LLM_UNAVAILABLE (weight 0): el veredicto
    # determinista y el `status` quedan intactos (R9.4, degradacion segura).
    config = Config(enable_layer4=True)
    fake = _RecordingEvaluator(None)
    monkeypatch.setattr(engine, "get_llm_evaluator", lambda _c, *, use_cache: fake)
    dep = Dependency(name="lodahs", version_pin=None, raw="lodahs", origin="package.json")
    result = _gray_result(config, "lodahs")

    out = engine._apply_layer4(
        (result,), (dep,), {"lodahs": _outcome("lodahs")}, _npm_ctx(config), use_cache=False
    )

    assert out[0].verdict is Verdict.ALLOW  # intacto: la abstencion no eleva el veredicto
    assert out[0].status is Status.OK  # no degrada a unverifiable
    assert out[0].llm_assessment is None
    assert any(s.code is SignalCode.LLM_UNAVAILABLE for s in out[0].signals)


def test_npm_abstencion_no_altera_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    # El exit code de una corrida npm con una abstencion L4 (LLM_UNAVAILABLE) es el mismo
    # que el del veredicto pre-L4 (allow => 0): R9.4 a nivel de salida observable.
    config = Config(enable_layer4=True)
    fake = _RecordingEvaluator(None)
    monkeypatch.setattr(engine, "get_llm_evaluator", lambda _c, *, use_cache: fake)
    dep = Dependency(name="lodahs", version_pin=None, raw="lodahs", origin="package.json")
    result = _gray_result(config, "lodahs")

    out = engine._apply_layer4(
        (result,), (dep,), {"lodahs": _outcome("lodahs")}, _npm_ctx(config), use_cache=False
    )
    report = engine._assemble_report(out, "npm")

    assert report.summary.exit_code == 0
    assert aggregate_exit_code(report, strict=False) == 0
