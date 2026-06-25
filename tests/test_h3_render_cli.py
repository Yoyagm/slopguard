"""Suite Hito 3 (H3-T18/T19/T17): render JSON/humano del LlmAssessment y flags de Capa 4.

Cubre los cuatro criterios de aceptacion del Hito 3 para el borde CLI/render:

  1. render_json de un ScanReport con un DependencyResult que lleva llm_assessment
     (construido a mano) incluye el bloque "llm_assessment" con sus 6 campos saneados
     y la clave "llm_unavailable" en summary (H3-T18, schema 1.2).
  2. Un result SIN llm_assessment serializa "llm_assessment": null y el JSON sigue
     siendo parseable (clave estable, NFR-Compat.1).
  3. render_human de un result con llm_assessment escribe clasificacion/confianza/
     rationale, la marca de "no verificado" (advisory LLM) y la transparencia de
     modelo/prompt_version (H3-T19, R6.5/R7.4).
  4. Las flags --enable-layer4 / --no-layer4 / --llm-model se parsean y mapean a
     cli_overrides, y load_config las aplica con la precedencia correcta (H3-T17, R5.1).

Todos los modelos se construyen a mano (sin red, sin engine, sin disco): los tests
de render son funciones puras sobre dataclasses frozen y el JSON/texto producido.
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from slopguard.cli import main as cli_main
from slopguard.cli.render_human import render_human
from slopguard.cli.render_json import render_json
from slopguard.core import (
    Config,
    DependencyResult,
    LayerSignal,
    ScanReport,
    ScanSummary,
    Status,
    Verdict,
    load_config,
)
from slopguard.core.llm.resolver import _validate_blob
from slopguard.core.models import Clasificacion, LlmAssessment

# Secuencias de control para verificar el saneo (R6.5/R7.4).
_ANSI = "\x1b[31m"
_OSC = "\x1b]0;titulo\x07"
_CRLF = "\r\n"

# Marcador de truncado (R7.3/ADR-19): debe espejar `normalize._TRUNCADO_MARKER`.
_MARKER = "...[truncado]"


# --------------------------------------------------------------------------- #
# Builders en memoria (sin red): modelos frozen construidos a mano.
# --------------------------------------------------------------------------- #


def _assessment(
    *,
    clasificacion: Clasificacion = Clasificacion.FABRICACION,
    confianza: float = 0.87,
    patron: str = "nombre confabulado sin paquete real cercano",
    rationale: str = "El nombre no corresponde a ningun paquete conocido.",
    modelo: str = "claude-opus-4-8",
    prompt_version: str = "h3-v1",
) -> LlmAssessment:
    """Construye un LlmAssessment a mano (ya saneado/truncado por el evaluador)."""
    return LlmAssessment(
        clasificacion=clasificacion,
        confianza=confianza,
        patron=patron,
        rationale=rationale,
        modelo=modelo,
        prompt_version=prompt_version,
    )


def _result(
    *,
    name: str = "requets",
    verdict: Verdict | None = Verdict.WARN,
    score: int | None = 55,
    signals: tuple[LayerSignal, ...] = (),
    assessment: LlmAssessment | None = None,
) -> DependencyResult:
    """Construye un DependencyResult a mano con o sin evaluacion LLM."""
    return DependencyResult(
        name=name,
        version_pin=None,
        status=Status.OK,
        verdict=verdict,
        score=score,
        signals=signals,
        suspected_target=None,
        error_category=None,
        advisories=(),
        llm_assessment=assessment,
    )


def _summary(
    *,
    total: int = 1,
    allow: int = 0,
    warn: int = 1,
    block: int = 0,
    unverifiable: int = 0,
    exit_code: int = 1,
    llm_unavailable: int = 0,
) -> ScanSummary:
    """Construye un ScanSummary a mano con conteos arbitrarios."""
    return ScanSummary(
        total=total,
        allow=allow,
        warn=warn,
        block=block,
        unverifiable=unverifiable,
        exit_code=exit_code,
        llm_unavailable=llm_unavailable,
    )


def _report(
    results: tuple[DependencyResult, ...],
    *,
    summary: ScanSummary | None = None,
) -> ScanReport:
    """Construye un ScanReport a mano (schema 1.2, sin engine ni red)."""
    return ScanReport(
        schema_version="1.2",
        tool_version="0.3.0",
        ecosystem="pypi",
        summary=summary if summary is not None else _summary(total=len(results)),
        results=results,
        error_category=None,
    )


# ===========================================================================
# Criterio 1: render_json con llm_assessment => bloque con 6 campos + summary
# ===========================================================================


def _json_with_assessment(**assessment_kwargs: object) -> dict[str, Any]:
    """Render JSON de un report de una dep con LlmAssessment; devuelve el JSON parseado."""
    assessment = _assessment(**assessment_kwargs)  # type: ignore[arg-type]
    report = _report(
        (_result(assessment=assessment),),
        summary=_summary(llm_unavailable=3),
    )
    result: dict[str, Any] = json.loads(render_json(report))
    return result


def test_json_llm_assessment_presente_con_clasificacion() -> None:
    """H3-T18: el JSON expone llm_assessment.clasificacion como el .value del StrEnum."""
    parsed = _json_with_assessment(clasificacion=Clasificacion.CONFLACION)
    block = parsed["results"][0]["llm_assessment"]
    assert block is not None
    assert block["clasificacion"] == "conflacion"


def test_json_llm_assessment_tiene_los_seis_campos() -> None:
    """H3-T18: el bloque llm_assessment lleva exactamente los 6 campos del schema 1.2."""
    parsed = _json_with_assessment()
    block = parsed["results"][0]["llm_assessment"]
    assert set(block.keys()) == {
        "clasificacion",
        "confianza",
        "patron",
        "rationale",
        "modelo",
        "prompt_version",
    }


def test_json_llm_assessment_porta_valores() -> None:
    """H3-T18: los campos textuales y la confianza se serializan tal cual (ya saneados)."""
    parsed = _json_with_assessment(
        confianza=0.42,
        patron="typo de requests",
        rationale="distancia 1 a requests",
        modelo="claude-opus-4-8",
        prompt_version="h3-v1",
    )
    block = parsed["results"][0]["llm_assessment"]
    assert block["confianza"] == 0.42
    assert block["patron"] == "typo de requests"
    assert block["rationale"] == "distancia 1 a requests"
    assert block["modelo"] == "claude-opus-4-8"
    assert block["prompt_version"] == "h3-v1"


def test_json_summary_incluye_llm_unavailable() -> None:
    """H3-T18: el summary del JSON expone la clave llm_unavailable con su conteo."""
    parsed = _json_with_assessment()
    assert parsed["summary"]["llm_unavailable"] == 3


def test_json_llm_assessment_sanea_ansi_en_rationale() -> None:
    """R6.5/R7.4: una secuencia ANSI inyectada en el rationale se elimina del JSON."""
    parsed = _json_with_assessment(rationale=f"texto malicioso{_ANSI}")
    payload = json.dumps(parsed, ensure_ascii=False)
    assert "\x1b" not in payload
    block = parsed["results"][0]["llm_assessment"]
    assert block["rationale"] == "texto malicioso"


def test_json_llm_assessment_sanea_crlf_en_patron() -> None:
    """R6.5/R7.4: CR/LF inyectado en el patron se neutraliza en el JSON."""
    parsed = _json_with_assessment(patron=f"conflacion{_CRLF}inyectada")
    block = parsed["results"][0]["llm_assessment"]
    assert "\r" not in block["patron"]
    assert "\n" not in block["patron"]
    assert block["patron"] == "conflacioninyectada"


def test_json_llm_assessment_sanea_osc_en_modelo() -> None:
    """R6.5/R7.4: una secuencia OSC inyectada en el modelo se elimina del JSON."""
    parsed = _json_with_assessment(modelo=f"claude{_OSC}-opus")
    payload = json.dumps(parsed, ensure_ascii=False)
    assert "\x1b" not in payload
    block = parsed["results"][0]["llm_assessment"]
    assert block["modelo"] == "claude-opus"


# ===========================================================================
# Criterio 2: result SIN llm_assessment => "llm_assessment": null, JSON valido
# ===========================================================================


def test_json_sin_assessment_serializa_null() -> None:
    """NFR-Compat.1: una dep sin evaluacion LLM produce llm_assessment == None (null)."""
    report = _report((_result(assessment=None),))
    parsed = json.loads(render_json(report))
    assert "llm_assessment" in parsed["results"][0]
    assert parsed["results"][0]["llm_assessment"] is None


def test_json_sin_assessment_sigue_siendo_parseable() -> None:
    """NFR-Compat.1: el JSON sigue siendo parseable y trae las claves obligatorias."""
    report = _report((_result(assessment=None),))
    payload = render_json(report)
    # El literal JSON usa null (no None de Python) para el campo ausente.
    assert '"llm_assessment": null' in payload
    parsed = json.loads(payload)
    for key in ("schema_version", "tool_version", "ecosystem", "summary", "results"):
        assert key in parsed


def test_json_sin_assessment_summary_llm_unavailable_cero_por_defecto() -> None:
    """H3-T18: sin deps en banda gris, llm_unavailable es 0 (clave estable presente)."""
    report = _report((_result(assessment=None),), summary=_summary(llm_unavailable=0))
    parsed = json.loads(render_json(report))
    assert parsed["summary"]["llm_unavailable"] == 0


def test_json_mezcla_con_y_sin_assessment() -> None:
    """H3-T18: en un report mixto, cada result lleva su llm_assessment (dict o null)."""
    con = _result(name="fabricado", assessment=_assessment())
    sin = _result(name="requests", verdict=Verdict.ALLOW, score=10, assessment=None)
    report = _report((con, sin), summary=_summary(total=2, allow=1, warn=1))
    parsed = json.loads(render_json(report))
    by_name = {r["name"]: r for r in parsed["results"]}
    assert by_name["fabricado"]["llm_assessment"] is not None
    assert by_name["requests"]["llm_assessment"] is None


# ===========================================================================
# Criterio 3: render_human con llm_assessment => clasif/conf/rationale + no verificado
# ===========================================================================


def _human_with_assessment(**assessment_kwargs: object) -> str:
    """Render humano de un report de una dep con LlmAssessment; devuelve el texto."""
    assessment = _assessment(**assessment_kwargs)  # type: ignore[arg-type]
    report = _report((_result(name="requets", assessment=assessment),))
    buf = io.StringIO()
    render_human(report, out=buf)
    return buf.getvalue()


def test_human_muestra_clasificacion() -> None:
    """H3-T19: el render humano muestra la clasificacion del LLM."""
    text = _human_with_assessment(clasificacion=Clasificacion.TYPO)
    assert "clasificacion=typo" in text


def test_human_muestra_confianza() -> None:
    """H3-T19: el render humano muestra la confianza formateada a 2 decimales."""
    text = _human_with_assessment(confianza=0.87)
    assert "confianza=0.87" in text


def test_human_muestra_rationale() -> None:
    """H3-T19: el render humano muestra el rationale del LLM."""
    text = _human_with_assessment(rationale="No corresponde a ningun paquete real.")
    assert "No corresponde a ningun paquete real." in text


def test_human_marca_no_verificado() -> None:
    """H3-T19/R6.5: el bloque LLM se marca explicitamente como advisory NO verificado."""
    text = _human_with_assessment()
    upper = text.upper()
    assert "NO VERIFICADO" in upper
    assert "LLM" in upper


def test_human_muestra_modelo_y_prompt_version() -> None:
    """H3-T19: el bloque de transparencia muestra modelo y prompt_version."""
    text = _human_with_assessment(modelo="claude-opus-4-8", prompt_version="h3-v1")
    assert "modelo=claude-opus-4-8" in text
    assert "prompt_version=h3-v1" in text


def test_human_sanea_ansi_en_rationale() -> None:
    """R7.4: ANSI inyectado en el rationale no aparece en el render humano."""
    text = _human_with_assessment(rationale=f"texto{_ANSI} con escape")
    assert "\x1b" not in text
    assert "texto con escape" in text


def test_human_sanea_crlf_en_modelo() -> None:
    """R7.4: CR/LF inyectado en el modelo no rompe la linea de transparencia."""
    text = _human_with_assessment(modelo=f"claude{_CRLF}injected")
    assert "modelo=claudeinjected" in text


def test_human_sin_assessment_no_muestra_bloque_llm() -> None:
    """H3-T19: una dep sin evaluacion LLM no imprime el bloque de advisory LLM."""
    report = _report((_result(assessment=None),))
    buf = io.StringIO()
    render_human(report, out=buf)
    text = buf.getvalue()
    assert "ADVISORY LLM" not in text.upper()
    assert "prompt_version" not in text


# ===========================================================================
# Criterio 4: flags --enable-layer4 / --no-layer4 / --llm-model => cli_overrides
# ===========================================================================


def test_cli_enable_layer4_parseable() -> None:
    """H3-T17: --enable-layer4 se parsea y produce enable_layer4=True en el namespace."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--enable-layer4"])
    assert args.enable_layer4 is True
    assert args.no_layer4 is False


def test_cli_no_layer4_parseable() -> None:
    """H3-T17: --no-layer4 se parsea y produce no_layer4=True en el namespace."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--no-layer4"])
    assert args.no_layer4 is True
    assert args.enable_layer4 is False


def test_cli_llm_model_parseable() -> None:
    """H3-T17: --llm-model captura el valor del modelo como string."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--llm-model", "claude-sonnet-4-5"])
    assert args.llm_model == "claude-sonnet-4-5"


def test_cli_defaults_layer4_flags() -> None:
    """H3-T17: sin flags, enable_layer4/no_layer4 son False y llm_model es None."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt"])
    assert args.enable_layer4 is False
    assert args.no_layer4 is False
    assert args.llm_model is None


def test_cli_enable_layer4_y_no_layer4_mutuamente_excluyentes() -> None:
    """H3-T17: --enable-layer4 y --no-layer4 son mutuamente excluyentes (argparse aborta)."""
    parser = cli_main._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "req.txt", "--enable-layer4", "--no-layer4"])


def test_cli_overrides_enable_layer4_produce_true() -> None:
    """H3-T17: _cli_overrides con --enable-layer4 inyecta enable_layer4=True."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--enable-layer4"])
    overrides = cli_main._cli_overrides(args)
    assert overrides.get("enable_layer4") is True


def test_cli_overrides_no_layer4_produce_false() -> None:
    """H3-T17: _cli_overrides con --no-layer4 inyecta enable_layer4=False."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--no-layer4"])
    overrides = cli_main._cli_overrides(args)
    assert overrides.get("enable_layer4") is False


def test_cli_overrides_llm_model_produce_valor() -> None:
    """H3-T17: _cli_overrides con --llm-model inyecta el modelo como override string."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--llm-model", "claude-opus-4-8"])
    overrides = cli_main._cli_overrides(args)
    assert overrides["llm_model"] == "claude-opus-4-8"


def test_cli_overrides_sin_flags_layer4_keys_son_none_o_ausentes() -> None:
    """H3-T17: sin flags, llm_model es None y enable_layer4 NO aparece (no-op en load_config)."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt"])
    overrides = cli_main._cli_overrides(args)
    assert overrides["llm_model"] is None
    assert "enable_layer4" not in overrides


# --------------------------------------------------------------------------- #
# Criterio 4 (cont.): load_config aplica los overrides de Capa 4 con precedencia
# --------------------------------------------------------------------------- #


def test_load_config_enable_layer4_override_true() -> None:
    """R5.1: el override enable_layer4=True sobreescribe el default False de Config."""
    config = load_config(None, {"enable_layer4": True})
    assert config.enable_layer4 is True


def test_load_config_enable_layer4_override_false() -> None:
    """R5.1: el override enable_layer4=False mantiene la Capa 4 apagada (default)."""
    config = load_config(None, {"enable_layer4": False})
    assert config.enable_layer4 is False


def test_load_config_llm_model_override() -> None:
    """R5.1: el override llm_model sobreescribe el default del modelo LLM."""
    config = load_config(None, {"llm_model": "claude-sonnet-4-5"})
    assert config.llm_model == "claude-sonnet-4-5"


def test_load_config_llm_model_none_es_noop() -> None:
    """R5.1: un override llm_model=None se ignora; prevalece el default de Config."""
    config = load_config(None, {"llm_model": None})
    assert config.llm_model == Config().llm_model


def test_load_config_layer4_defaults_sin_overrides() -> None:
    """R5.1: sin overrides, Capa 4 queda OFF y con el modelo por defecto."""
    config = load_config(None, {})
    assert config.enable_layer4 is False
    assert config.llm_model == "claude-opus-4-8"


def test_cli_overrides_a_load_config_flujo_completo() -> None:
    """H3-T17/R5.1: el flujo parser -> _cli_overrides -> load_config aplica Capa 4 end-to-end.

    Verifica la integracion real del cableado CLI: parsear --enable-layer4 y --llm-model,
    extraer los overrides y construir la Config sin tocar disco ni red.
    """
    parser = cli_main._build_parser()
    args = parser.parse_args(
        ["scan", "req.txt", "--enable-layer4", "--llm-model", "claude-opus-4-8"]
    )
    overrides = cli_main._cli_overrides(args)
    config = load_config(None, overrides)
    assert config.enable_layer4 is True
    assert config.llm_model == "claude-opus-4-8"


# ===========================================================================
# R7.3/ADR-19: re-saneo+truncado del texto del LLM en la FRONTERA de salida.
#
# Bug que corrige el critic: el render usaba `sanitize_for_output` (solo sanea,
# NO trunca) para `patron`/`rationale`. Un texto gigante (p.ej. un blob de cache
# rehidratado sin truncar) saldria sin acotar. La salida es la ultima linea de
# defensa: no asume que una capa previa ya trunco (defensa en profundidad).
# ===========================================================================


def test_json_rationale_se_trunca_en_la_salida() -> None:
    """R7.3: un rationale > 1000 chars se trunca con marcador en el JSON (limite por defecto)."""
    parsed = _json_with_assessment(rationale="r" * 2000)
    block = parsed["results"][0]["llm_assessment"]
    assert block["rationale"].endswith(_MARKER)
    assert len(block["rationale"]) <= 1000


def test_json_patron_se_trunca_en_la_salida() -> None:
    """R7.3: un patron > 280 chars se trunca con marcador en el JSON (limite por defecto)."""
    parsed = _json_with_assessment(patron="p" * 600)
    block = parsed["results"][0]["llm_assessment"]
    assert block["patron"].endswith(_MARKER)
    assert len(block["patron"]) <= 280


def test_json_rationale_corto_no_se_trunca() -> None:
    """R7.3: un rationale dentro del limite no recibe marcador (truncado solo si excede)."""
    parsed = _json_with_assessment(rationale="ok")
    block = parsed["results"][0]["llm_assessment"]
    assert block["rationale"] == "ok"


def test_json_respeta_limite_personalizado() -> None:
    """R7.3: render_json acepta limites custom (los que _render toma de Config)."""
    report = _report((_result(assessment=_assessment(rationale="r" * 500)),))
    parsed = json.loads(render_json(report, max_rationale=100))
    block = parsed["results"][0]["llm_assessment"]
    assert block["rationale"].endswith(_MARKER)
    assert len(block["rationale"]) <= 100


def test_human_rationale_se_trunca_en_la_salida() -> None:
    """R7.3: un rationale gigante se trunca con marcador en el render humano."""
    text = _human_with_assessment(rationale="r" * 2000)
    assert _MARKER in text
    assert "r" * 2000 not in text


def test_cache_blob_gigante_se_trunca_en_render_json() -> None:
    """R7.3: un blob de cache rehidratado SIN truncar se trunca igual en la frontera JSON.

    `_validate_blob` (resolver) reconstruye el LlmAssessment con `str(...)` sin
    truncar; el render es la ultima linea de defensa. Cubre la ruta de cache que
    el critic senalo como camino por el que un texto gigante podia salir sin acotar.
    """
    payload: dict[str, object] = {
        "ecosystem": "pypi",
        "clasificacion": "fabricacion",
        "confianza": 0.9,
        "patron": "p" * 600,
        "rationale": "r" * 3000,
        "modelo": "claude-opus-4-8",
        "prompt_version": "h4-v1",
    }
    assessment = _validate_blob(payload, "pypi")
    assert assessment is not None
    # El blob NO se trunca al rehidratar: la defensa esta en la salida, no en la cache.
    assert len(assessment.rationale) == 3000
    assert len(assessment.patron) == 600

    parsed = json.loads(render_json(_report((_result(assessment=assessment),))))
    block = parsed["results"][0]["llm_assessment"]
    assert block["rationale"].endswith(_MARKER)
    assert len(block["rationale"]) <= 1000
    assert block["patron"].endswith(_MARKER)
    assert len(block["patron"]) <= 280


def test_render_propaga_limites_de_config_json(capsys: pytest.CaptureFixture[str]) -> None:
    """R7.3: cli._render toma los limites de la Config activa y los pasa al render JSON."""
    config = Config(llm_max_text_rationale=50)
    report = _report((_result(assessment=_assessment(rationale="r" * 500)),))
    cli_main._render(report, config, fmt="json")
    parsed = json.loads(capsys.readouterr().out)
    block = parsed["results"][0]["llm_assessment"]
    assert block["rationale"].endswith(_MARKER)
    assert len(block["rationale"]) <= 50


def test_render_propaga_limites_de_config_human(capsys: pytest.CaptureFixture[str]) -> None:
    """R7.3: cli._render toma los limites de la Config activa y los pasa al render humano."""
    config = Config(llm_max_text_rationale=40)
    report = _report((_result(assessment=_assessment(rationale="r" * 500)),))
    cli_main._render(report, config, fmt="human")
    out = capsys.readouterr().out
    assert _MARKER in out
    assert "r" * 500 not in out
