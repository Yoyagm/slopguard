"""DTOs Pydantic del reporte de escaneo (design §4.3, H5-T16).

Mapeo 1:1 del `ScanReport` del motor (schema 1.2) más metadatos de persistencia del
SaaS (`scan_id`, `origin`, `created_at`). Los campos reflejan exactamente la estructura
que produce `slopguard.cli.render_json.render_json` — sin inventar campos ni eliminar
ninguno de la semántica del motor.

Reglas de modelado:
- Strings opcionales del motor (suspected_target, version_pin, etc.) → `str | None`.
- Veredicto → `str | None` (permite allow/warn/block o None si unverifiable).
- Score → `int | None` (None si unverifiable o block-override, R4.3 nota).
- `llm_assessment` → `LlmAssessmentDTO | None` (null mientras Capa 4 esté off, R7.2).
- `advisories` siempre presente (lista vacía si sin malicia, schema 1.1+).
"""

from __future__ import annotations

import datetime
import json
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict


class AdvisoryDTO(BaseModel):
    """Advisory de malicia normalizado (MAL-*) de la Capa 3 (Hito 2, schema 1.1+)."""

    model_config = ConfigDict(frozen=True)

    id: str
    kind: str
    url: str
    source: str


class SignalDTO(BaseModel):
    """Señal emitida por una capa de detección con su explicación saneada."""

    model_config = ConfigDict(frozen=True)

    layer: int
    code: str
    weight: int
    is_soft: bool
    is_llm_channel: bool
    detail: str
    suspected_target: str | None


class LlmAssessmentDTO(BaseModel):
    """Veredicto del LLM (Capa 4, Hito 3, schema 1.2). null cuando Capa 4 está off."""

    model_config = ConfigDict(frozen=True)

    clasificacion: str
    confianza: float
    patron: str
    rationale: str
    modelo: str
    prompt_version: str


class DependencyResultDTO(BaseModel):
    """Resultado de una dependencia: estado, veredicto, score y señales por capa."""

    model_config = ConfigDict(frozen=True)

    name: str
    version_pin: str | None
    status: str  # "ok" | "unverifiable"
    verdict: str | None  # "allow" | "warn" | "block" | None
    score: int | None  # None si unverifiable o block-override
    suspected_target: str | None
    error_category: str | None
    signals: list[SignalDTO]
    advisories: list[AdvisoryDTO]  # lista vacía si sin malicia
    llm_assessment: LlmAssessmentDTO | None  # null si Capa 4 off


class ScanSummaryDTO(BaseModel):
    """Conteos del escaneo y exit code final (de `ScanSummary.exit_code`)."""

    model_config = ConfigDict(frozen=True)

    total: int
    allow: int
    warn: int
    block: int
    unverifiable: int
    llm_unavailable: int
    exit_code: int


class ScanDTO(BaseModel):
    """DTO completo del reporte de escaneo (design §4.3).

    Fusiona el `ScanReport` 1:1 (schema_version 1.2, ecosystem, summary, results,
    error_category) con los metadatos de persistencia del SaaS (scan_id, origin,
    created_at). `report_dict` porta el JSON canónico del motor (R4.3) como dict.
    """

    model_config = ConfigDict(frozen=True)

    scan_id: uuid.UUID
    origin: str  # "on_demand" | "pull_request"
    created_at: datetime.datetime

    # Campos 1:1 del ScanReport (schema 1.2)
    schema_version: str  # siempre "1.2"
    tool_version: str
    ecosystem: str  # "pypi" | "npm"
    error_category: str | None
    summary: ScanSummaryDTO
    results: list[DependencyResultDTO]

    # Reporte canónico del motor (schema 1.2) como dict — exactamente lo que produce
    # render_json() ya parseado (R4.3). Es la fuente de verdad para /scans/{id}/raw:
    # se devuelve directamente sin re-parsear (sin dumps→loads en el router). El
    # SqlScanRepository lo toma del JSONB sin serializar de vuelta. Se omite de la
    # respuesta principal de /scans y /scans/{id} (el raw va solo en /scans/{id}/raw).
    report_dict: dict[str, Any]

    @property
    def report_raw(self) -> str:
        """JSON canónico serializado (compat): derivado de `report_dict`."""
        return json.dumps(self.report_dict)


class ScanListItemDTO(BaseModel):
    """Resumen de un escaneo para la lista paginada del histórico (GET /scans, R5.2).

    No incluye `results` detallados ni `report_raw` — solo los campos suficientes
    para renderizar la fila del histórico y navegar al detalle.
    """

    model_config = ConfigDict(frozen=True)

    scan_id: uuid.UUID
    origin: str  # "on_demand" | "pull_request"
    created_at: datetime.datetime
    ecosystem: str
    schema_version: str
    tool_version: str
    error_category: str | None
    summary: ScanSummaryDTO


class ScanPageDTO(BaseModel):
    """Respuesta paginada del histórico (GET /scans, R5.2)."""

    model_config = ConfigDict(frozen=True)

    items: list[ScanListItemDTO]
    total: int
    page: int
    page_size: int
