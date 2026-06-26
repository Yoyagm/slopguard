"""Mapeo `ScanReport` → `ScanDTO` (design §4.3, H5-T16, ADR-3).

Este módulo es la única frontera entre el modelo de dominio inmutable del motor
(`slopguard.core.models`) y el contrato HTTP del SaaS (`app.schemas.scan`).

Reglas de mapeo:
- Mapeo 1:1: ningún campo del `ScanReport` se pierde ni se inventa.
- Enums del motor (StrEnum/IntEnum) → sus `.value` primitivos (str/int),
  para que la capa de serialización Pydantic no dependa de los tipos del motor.
- `render_json` produce el JSON canónico (schema 1.2) que se porta como `report_raw`
  (R4.3); se reutiliza la fachada pública de la CLI sin reimplementar la serialización.
- Los metadatos de persistencia (`scan_id`, `origin`, `created_at`) los aporta el
  llamador (el router o el worker), no el motor.
"""

from __future__ import annotations

import datetime
import uuid

from slopguard.cli.render_json import render_json
from slopguard.core import Advisory, DependencyResult, LayerSignal, ScanReport
from slopguard.core.models import LlmAssessment

from app.schemas.scan import (
    AdvisoryDTO,
    DependencyResultDTO,
    LlmAssessmentDTO,
    ScanDTO,
    ScanSummaryDTO,
    SignalDTO,
)


def _map_advisory(advisory: Advisory) -> AdvisoryDTO:
    return AdvisoryDTO(
        id=advisory.id,
        kind=advisory.kind,
        url=advisory.url,
        source=advisory.source,
    )


def _map_llm_assessment(assessment: LlmAssessment) -> LlmAssessmentDTO:
    return LlmAssessmentDTO(
        clasificacion=assessment.clasificacion.value,
        confianza=assessment.confianza,
        patron=assessment.patron,
        rationale=assessment.rationale,
        modelo=assessment.modelo,
        prompt_version=assessment.prompt_version,
    )


def _map_signal(signal: LayerSignal) -> SignalDTO:
    return SignalDTO(
        layer=signal.layer.value,
        code=signal.code.value,
        weight=signal.weight,
        is_soft=signal.is_soft,
        is_llm_channel=signal.is_llm_channel,
        detail=signal.detail,
        suspected_target=signal.suspected_target,
    )


def _map_dependency_result(result: DependencyResult) -> DependencyResultDTO:
    return DependencyResultDTO(
        name=result.name,
        version_pin=result.version_pin,
        status=result.status.value,
        verdict=result.verdict.value if result.verdict is not None else None,
        score=result.score,
        suspected_target=result.suspected_target,
        error_category=(
            result.error_category.value if result.error_category is not None else None
        ),
        signals=[_map_signal(s) for s in result.signals],
        advisories=[_map_advisory(a) for a in result.advisories],
        llm_assessment=(
            _map_llm_assessment(result.llm_assessment)
            if result.llm_assessment is not None
            else None
        ),
    )


def scan_report_to_dto(
    report: ScanReport,
    *,
    scan_id: uuid.UUID,
    origin: str,
    created_at: datetime.datetime,
) -> ScanDTO:
    """Convierte un `ScanReport` inmutable del motor en el `ScanDTO` HTTP del SaaS.

    `scan_id`, `origin` y `created_at` son metadatos de persistencia que aporta el
    llamador: el motor no los conoce. `render_json` produce el JSON canónico que viaja
    en `report_raw` para el endpoint `/scans/{id}/raw` (R4.3).
    """
    summary = report.summary
    return ScanDTO(
        scan_id=scan_id,
        origin=origin,
        created_at=created_at,
        schema_version=report.schema_version,
        tool_version=report.tool_version,
        ecosystem=report.ecosystem,
        error_category=(
            report.error_category.value if report.error_category is not None else None
        ),
        summary=ScanSummaryDTO(
            total=summary.total,
            allow=summary.allow,
            warn=summary.warn,
            block=summary.block,
            unverifiable=summary.unverifiable,
            llm_unavailable=summary.llm_unavailable,
            exit_code=summary.exit_code,
        ),
        results=[_map_dependency_result(r) for r in report.results],
        report_raw=render_json(report),
    )
