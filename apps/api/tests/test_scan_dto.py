"""Tests del mapeo ScanReport → ScanDTO (H5-T16, design §4.3).

Verifica que el DTO sea fiel al ScanReport del motor: ningún campo se pierde, los
valores de los enums se exportan como primitivos, y el JSON crudo (report_raw) es
parseable y equivalente al dict que render_json produce.

Se usan objetos del motor directamente (sin mocks): el motor es zero-deps y sus
dataclasses frozen son seguros de construir en tests.
"""

from __future__ import annotations

import datetime
import json
import uuid

import pytest
from slopguard.core import (
    Advisory,
    DependencyResult,
    ErrorCategory,
    Layer,
    LayerSignal,
    ScanReport,
    ScanSummary,
    SignalCode,
    Status,
    Verdict,
)
from slopguard.core.models import Clasificacion, LlmAssessment

from app.schemas.scan import (
    AdvisoryDTO,
    DependencyResultDTO,
    LlmAssessmentDTO,
    ScanDTO,
    ScanSummaryDTO,
    SignalDTO,
)
from app.services.scan_mapper import scan_report_to_dto

# ---------------------------------------------------------------------------
# Helpers de construcción de objetos del motor
# ---------------------------------------------------------------------------

_SCAN_ID = uuid.UUID("12345678-1234-5678-1234-567812345678")
_NOW = datetime.datetime(2026, 6, 25, 12, 0, 0, tzinfo=datetime.UTC)


def _summary(
    *,
    total: int = 1,
    allow: int = 1,
    warn: int = 0,
    block: int = 0,
    unverifiable: int = 0,
    llm_unavailable: int = 0,
    exit_code: int = 0,
) -> ScanSummary:
    return ScanSummary(
        total=total,
        allow=allow,
        warn=warn,
        block=block,
        unverifiable=unverifiable,
        llm_unavailable=llm_unavailable,
        exit_code=exit_code,
    )


def _allow_signal() -> LayerSignal:
    return LayerSignal(
        layer=Layer.L0,
        code=SignalCode.NEW_PACKAGE,
        weight=5,
        is_soft=True,
        is_llm_channel=False,
        detail="paquete reciente",
        suspected_target=None,
    )


def _typosquat_signal() -> LayerSignal:
    return LayerSignal(
        layer=Layer.L1,
        code=SignalCode.TYPOSQUAT,
        weight=50,
        is_soft=False,
        is_llm_channel=False,
        detail="similar a requests",
        suspected_target="requests",
    )


def _advisory() -> Advisory:
    return Advisory(
        id="MAL-2025-47868",
        kind="malicious",
        url="https://osv.dev/vulnerability/MAL-2025-47868",
        source="osv",
    )


def _allow_result(name: str = "requests") -> DependencyResult:
    return DependencyResult(
        name=name,
        version_pin="2.28.0",
        status=Status.OK,
        verdict=Verdict.ALLOW,
        score=10,
        signals=(_allow_signal(),),
        suspected_target=None,
        error_category=None,
        advisories=(),
        llm_assessment=None,
    )


def _unverifiable_result(name: str = "unknown-pkg") -> DependencyResult:
    return DependencyResult(
        name=name,
        version_pin=None,
        status=Status.UNVERIFIABLE,
        verdict=None,
        score=None,
        signals=(),
        suspected_target=None,
        error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
        advisories=(),
        llm_assessment=None,
    )


def _block_result_with_advisory(name: str = "evil-pkg") -> DependencyResult:
    return DependencyResult(
        name=name,
        version_pin=None,
        status=Status.OK,
        verdict=Verdict.BLOCK,
        score=None,  # block-override: score es None
        signals=(),
        suspected_target=None,
        error_category=None,
        advisories=(_advisory(),),
        llm_assessment=None,
    )


def _result_with_llm(name: str = "suspicious-pkg") -> DependencyResult:
    assessment = LlmAssessment(
        clasificacion=Clasificacion.TYPO,
        confianza=0.85,
        patron="variante tipográfica de requests",
        rationale="alta similitud fonética",
        modelo="claude-3-5-sonnet",
        prompt_version="v1",
    )
    return DependencyResult(
        name=name,
        version_pin=None,
        status=Status.OK,
        verdict=Verdict.WARN,
        score=60,
        signals=(_typosquat_signal(),),
        suspected_target="requests",
        error_category=None,
        advisories=(),
        llm_assessment=assessment,
    )


def _minimal_report() -> ScanReport:
    return ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(),
        results=(_allow_result(),),
        error_category=None,
    )


def _make_dto(report: ScanReport) -> ScanDTO:
    return scan_report_to_dto(
        report, scan_id=_SCAN_ID, origin="on_demand", created_at=_NOW
    )


# ---------------------------------------------------------------------------
# Tests de metadatos de persistencia
# ---------------------------------------------------------------------------


def test_dto_carries_persistence_metadata() -> None:
    dto = _make_dto(_minimal_report())

    assert dto.scan_id == _SCAN_ID
    assert dto.origin == "on_demand"
    assert dto.created_at == _NOW


# ---------------------------------------------------------------------------
# Tests de campos 1:1 del ScanReport
# ---------------------------------------------------------------------------


def test_schema_version_is_preserved() -> None:
    dto = _make_dto(_minimal_report())
    assert dto.schema_version == "1.2"


def test_tool_version_is_preserved() -> None:
    dto = _make_dto(_minimal_report())
    assert dto.tool_version == "0.8.0"


def test_ecosystem_is_preserved() -> None:
    dto = _make_dto(_minimal_report())
    assert dto.ecosystem == "pypi"


def test_error_category_none_when_clean() -> None:
    dto = _make_dto(_minimal_report())
    assert dto.error_category is None


def test_error_category_mapped_when_present() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="npm",
        summary=_summary(total=1, allow=0, unverifiable=1, exit_code=3),
        results=(_unverifiable_result(),),
        error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
    )
    dto = _make_dto(report)

    assert dto.error_category == "network_unverifiable"


# ---------------------------------------------------------------------------
# Tests de summary (exit_code desde ScanSummary, R4.3 nota)
# ---------------------------------------------------------------------------


def test_summary_exit_code_mapped_correctly() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(
            total=3, allow=1, warn=1, block=1,
            unverifiable=0, llm_unavailable=0, exit_code=2
        ),
        results=(_allow_result(), _allow_result("flask"), _allow_result("django")),
        error_category=None,
    )
    dto = _make_dto(report)

    assert dto.summary.exit_code == 2
    assert dto.summary.total == 3
    assert dto.summary.allow == 1
    assert dto.summary.warn == 1
    assert dto.summary.block == 1
    assert dto.summary.unverifiable == 0
    assert dto.summary.llm_unavailable == 0


def test_summary_llm_unavailable_field_mapped() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(total=2, allow=1, llm_unavailable=1, exit_code=0),
        results=(_allow_result(),),
        error_category=None,
    )
    dto = _make_dto(report)

    assert dto.summary.llm_unavailable == 1


# ---------------------------------------------------------------------------
# Tests de resultados por dependencia
# ---------------------------------------------------------------------------


def test_allow_result_fields_mapped() -> None:
    dto = _make_dto(_minimal_report())

    assert len(dto.results) == 1
    result = dto.results[0]

    assert result.name == "requests"
    assert result.version_pin == "2.28.0"
    assert result.status == "ok"
    assert result.verdict == "allow"
    assert result.score == 10
    assert result.suspected_target is None
    assert result.error_category is None


def test_unverifiable_result_has_null_verdict_and_score() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(total=1, allow=0, unverifiable=1, exit_code=3),
        results=(_unverifiable_result(),),
        error_category=None,
    )
    dto = _make_dto(report)
    result = dto.results[0]

    assert result.status == "unverifiable"
    assert result.verdict is None
    assert result.score is None
    assert result.version_pin is None
    assert result.error_category == "network_unverifiable"


def test_block_override_has_null_score() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(total=1, allow=0, block=1, exit_code=2),
        results=(_block_result_with_advisory(),),
        error_category=None,
    )
    dto = _make_dto(report)
    result = dto.results[0]

    assert result.verdict == "block"
    assert result.score is None  # block-override: sin score numérico


# ---------------------------------------------------------------------------
# Tests de señales por capa
# ---------------------------------------------------------------------------


def test_signal_fields_mapped() -> None:
    dto = _make_dto(_minimal_report())
    signal = dto.results[0].signals[0]

    assert signal.layer == 0  # Layer.L0.value
    assert signal.code == "new_package"
    assert signal.weight == 5
    assert signal.is_soft is True
    assert signal.is_llm_channel is False
    assert signal.detail == "paquete reciente"
    assert signal.suspected_target is None


def test_signal_with_suspected_target_mapped() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(total=1, allow=0, warn=1, exit_code=1),
        results=(_result_with_llm(),),
        error_category=None,
    )
    dto = _make_dto(report)
    signal = dto.results[0].signals[0]

    assert signal.layer == 1  # Layer.L1.value
    assert signal.code == "typosquat"
    assert signal.suspected_target == "requests"


# ---------------------------------------------------------------------------
# Tests de advisories (MAL-*)
# ---------------------------------------------------------------------------


def test_advisories_empty_when_no_malice() -> None:
    dto = _make_dto(_minimal_report())
    assert dto.results[0].advisories == []


def test_advisory_fields_mapped() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(total=1, allow=0, block=1, exit_code=2),
        results=(_block_result_with_advisory(),),
        error_category=None,
    )
    dto = _make_dto(report)
    advisory = dto.results[0].advisories[0]

    assert advisory.id == "MAL-2025-47868"
    assert advisory.kind == "malicious"
    assert advisory.url == "https://osv.dev/vulnerability/MAL-2025-47868"
    assert advisory.source == "osv"


# ---------------------------------------------------------------------------
# Tests de llm_assessment
# ---------------------------------------------------------------------------


def test_llm_assessment_none_when_absent() -> None:
    dto = _make_dto(_minimal_report())
    assert dto.results[0].llm_assessment is None


def test_llm_assessment_mapped_when_present() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(total=1, allow=0, warn=1, exit_code=1),
        results=(_result_with_llm(),),
        error_category=None,
    )
    dto = _make_dto(report)
    assessment = dto.results[0].llm_assessment

    assert assessment is not None
    assert assessment.clasificacion == "typo"  # Clasificacion.TYPO.value
    assert assessment.confianza == pytest.approx(0.85)
    assert assessment.patron == "variante tipográfica de requests"
    assert assessment.rationale == "alta similitud fonética"
    assert assessment.modelo == "claude-3-5-sonnet"
    assert assessment.prompt_version == "v1"


# ---------------------------------------------------------------------------
# Tests del JSON crudo (R4.3)
# ---------------------------------------------------------------------------


def test_report_raw_is_valid_json() -> None:
    dto = _make_dto(_minimal_report())
    data = json.loads(dto.report_raw)
    assert isinstance(data, dict)


def test_report_raw_has_schema_version_1_2() -> None:
    dto = _make_dto(_minimal_report())
    data = json.loads(dto.report_raw)
    assert data["schema_version"] == "1.2"


def test_report_raw_has_exit_code_in_summary() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(exit_code=2),
        results=(_allow_result(),),
        error_category=None,
    )
    dto = _make_dto(report)
    data = json.loads(dto.report_raw)

    assert data["summary"]["exit_code"] == 2


def test_report_raw_has_ecosystem_field() -> None:
    dto = _make_dto(_minimal_report())
    data = json.loads(dto.report_raw)
    assert data["ecosystem"] == "pypi"


def test_report_raw_results_count_matches_dto() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(total=2, allow=2),
        results=(_allow_result("requests"), _allow_result("flask")),
        error_category=None,
    )
    dto = _make_dto(report)
    data = json.loads(dto.report_raw)

    assert len(data["results"]) == len(dto.results) == 2


def test_report_raw_has_all_required_top_level_keys() -> None:
    dto = _make_dto(_minimal_report())
    data = json.loads(dto.report_raw)

    required_keys = {
        "schema_version", "tool_version", "ecosystem",
        "summary", "results", "error_category",
    }
    assert required_keys.issubset(data.keys())


def test_report_raw_result_has_signals_advisories_llm_assessment() -> None:
    """El JSON crudo tiene las 3 claves estables de schema 1.2 por resultado."""
    dto = _make_dto(_minimal_report())
    data = json.loads(dto.report_raw)
    result = data["results"][0]

    assert "signals" in result
    assert "advisories" in result
    assert "llm_assessment" in result


# ---------------------------------------------------------------------------
# Test de múltiples resultados / ecosistema npm
# ---------------------------------------------------------------------------


def test_npm_ecosystem_mapped() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="npm",
        summary=_summary(total=1, allow=1),
        results=(_allow_result("lodash"),),
        error_category=None,
    )
    dto = _make_dto(report)

    assert dto.ecosystem == "npm"
    data = json.loads(dto.report_raw)
    assert data["ecosystem"] == "npm"


def test_multiple_results_all_mapped() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(total=3, allow=1, warn=1, unverifiable=1, exit_code=3),
        results=(
            _allow_result("requests"),
            _result_with_llm("reqests"),
            _unverifiable_result("unknown-pkg"),
        ),
        error_category=None,
    )
    dto = _make_dto(report)

    assert len(dto.results) == 3
    assert dto.results[0].verdict == "allow"
    assert dto.results[1].verdict == "warn"
    assert dto.results[2].verdict is None


# ---------------------------------------------------------------------------
# Tests de tipos de los DTO (inmutabilidad y tipado Pydantic)
# ---------------------------------------------------------------------------


def test_dto_types_are_correct() -> None:
    dto = _make_dto(_minimal_report())

    assert isinstance(dto, ScanDTO)
    assert isinstance(dto.summary, ScanSummaryDTO)
    assert isinstance(dto.results[0], DependencyResultDTO)
    assert isinstance(dto.results[0].signals[0], SignalDTO)
    assert isinstance(dto.results[0].advisories, list)


def test_advisory_dto_type() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(total=1, block=1, exit_code=2),
        results=(_block_result_with_advisory(),),
        error_category=None,
    )
    dto = _make_dto(report)
    assert isinstance(dto.results[0].advisories[0], AdvisoryDTO)


def test_llm_assessment_dto_type() -> None:
    report = ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=_summary(total=1, warn=1, exit_code=1),
        results=(_result_with_llm(),),
        error_category=None,
    )
    dto = _make_dto(report)
    assert isinstance(dto.results[0].llm_assessment, LlmAssessmentDTO)
