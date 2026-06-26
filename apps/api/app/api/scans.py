"""Scan Router: endpoints de escaneo y histórico (H5-T19/T20).

POST /api/v1/scans           — escaneo on-demand (T19).
GET  /api/v1/scans           — lista paginada del histórico (T20, R5.2).
GET  /api/v1/scans/{id}      — detalle del escaneo (T20, R5.3).
GET  /api/v1/scans/{id}/raw  — report_json crudo schema 1.2 (T20, R4.3).

Mapeo de errores saneados (R9.2, design §4):
- `ScanServiceError(INVALID_INPUT)` → 422
- `ScanServiceError(TIMEOUT)`       → 504
- `ScanServiceError(ENGINE_FAILURE)` → 502
- Escaneo no encontrado o de otro usuario → 404 (no 403, R5.3)
Forma estable: `{ "error": { "code", "message", "request_id" } }` — sin stacktrace ni secretos.

source=repo: camino preparado con error saneado documentado (lectura real en T24).
"""

from __future__ import annotations

import datetime
import logging
import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from ..auth.guard import require_user
from ..db.models import User
from ..scans.scan_repo import FakeScanRepository, ScanRepository, SqlScanRepository
from ..schemas.scan import ScanDTO, ScanPageDTO
from ..schemas.scan_request import ScanRequest
from ..services.scan import ScanErrorCategory, ScanService, ScanServiceError, build_scan_service
from ..services.scan_mapper import scan_report_to_dto
from ..settings import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

# Tipo anotado del usuario autenticado (reutiliza el guard de sesión).
CurrentUser = Annotated[User, Depends(require_user)]


# ---------------------------------------------------------------------------
# Forma de error estable (R9.2, design §4)
# ---------------------------------------------------------------------------


class _ErrorDetail(BaseModel):
    """Detalle del error saneado."""

    model_config = ConfigDict(frozen=True)

    code: str
    message: str
    request_id: str


class _ErrorBody(BaseModel):
    """Cuerpo de error estable: `{ error: { code, message, request_id } }` (R9.2)."""

    model_config = ConfigDict(frozen=True)

    error: _ErrorDetail


def _error_response(
    http_status: int,
    code: str,
    message: str,
    request_id: str,
) -> JSONResponse:
    """Construye la respuesta de error saneada con la forma estable del diseño (R9.2)."""
    body = _ErrorBody(
        error=_ErrorDetail(code=code, message=message, request_id=request_id)
    )
    return JSONResponse(
        status_code=http_status,
        content=body.model_dump(),
    )


# ---------------------------------------------------------------------------
# Dependencias inyectables del router
# ---------------------------------------------------------------------------


def get_scan_service() -> ScanService:
    """Provider del Scan Service desde Settings (Capa 4 off salvo clave presente)."""
    settings = get_settings()
    anthropic_key = (
        settings.anthropic_api_key.get_secret_value()
        if settings.anthropic_api_key is not None
        else None
    )
    return build_scan_service(
        wrapper_timeout_s=settings.scan_wrapper_timeout_s,
        anthropic_api_key=anthropic_key,
        max_manifest_bytes=settings.scan_max_manifest_bytes,
        max_deps=settings.scan_max_deps,
    )


def get_scan_repository() -> ScanRepository:
    """Provider del repositorio de scans (SQLAlchemy en entornos con DB)."""
    settings = get_settings()
    if not settings.database_url:
        # Sin DB configurada usamos el fake (desarrollo / tests de integración manual).
        return FakeScanRepository()
    from ..db.base import get_sessionmaker

    return SqlScanRepository(get_sessionmaker())


ScanServiceDep = Annotated[ScanService, Depends(get_scan_service)]
ScanRepoDep = Annotated[ScanRepository, Depends(get_scan_repository)]


# ---------------------------------------------------------------------------
# Endpoint POST /scans
# ---------------------------------------------------------------------------

# Id placeholder para el DTO previo a persistir: persist() lo ignora y devuelve el
# id autoritativo. Usamos el UUID nil para que nunca se confunda con un id real.
_PLACEHOLDER_SCAN_ID = uuid.UUID(int=0)


@router.post("", status_code=status.HTTP_200_OK)
async def create_scan(
    body: ScanRequest,
    current_user: CurrentUser,
    scan_service: ScanServiceDep,
    scan_repo: ScanRepoDep,
) -> Any:
    """Lanza un escaneo on-demand y persiste el resultado (R3.1, R5.1, design §2.2).

    Flujo:
    1. Valida la forma del request (source + campos requeridos).
    2. Para source=inline: invoca `scan_service.scan_text`.
       Para source=repo: error saneado documentado (lectura real en T24).
    3. Mapea `ScanReport` → `ScanDTO` con metadatos de persistencia.
    4. Persiste en `scans` + `scan_results` vía `ScanRepository`.
    5. Devuelve `ScanDTO` sin `report_raw` (R4.3: el raw va en `/scans/{id}/raw`).

    Errores saneados R9.2:
    - source inválido / campo requerido ausente → 422
    - motor: INVALID_INPUT → 422, TIMEOUT → 504, ENGINE_FAILURE → 502
    """
    request_id = str(uuid.uuid4())

    # Validación de source y campos requeridos
    validation_error = _validate_request(body)
    if validation_error:
        return _error_response(
            422,
            code="INVALID_REQUEST",
            message=validation_error,
            request_id=request_id,
        )

    # source=repo: camino preparado; lectura real en T24.
    if body.source == "repo":
        return _error_response(
            422,
            code="REPO_SOURCE_NOT_IMPLEMENTED",
            message=(
                "El escaneo desde repo conectado no está disponible en esta versión. "
                "Use source=inline con el contenido del manifiesto."
            ),
            request_id=request_id,
        )

    # source=inline: invocar el motor
    # `content` garantizado no-None por _validate_request (rechaza inline sin content).
    content = body.content or ""
    try:
        report = await scan_service.scan_text(content, ecosystem=body.ecosystem)
    except ScanServiceError as exc:
        return _scan_error_response(exc, request_id)

    created_at = datetime.datetime.now(tz=datetime.UTC)
    # Mapeamos UNA sola vez. El scan_id va como placeholder: persist() lo IGNORA y
    # genera el id autoritativo de la capa de persistencia (ver ScanRepository.persist).
    dto = scan_report_to_dto(
        report,
        scan_id=_PLACEHOLDER_SCAN_ID,
        origin="on_demand",
        created_at=created_at,
    )

    # Persistir (el await es al threadpool, no a I/O de red pesado). Devuelve el id real.
    persisted_id = await scan_repo.persist(
        dto,
        user_id=current_user.id,
        repo_id=None,
        origin="on_demand",
    )

    # Re-sellamos el DTO con el id autoritativo (sin re-mapear ni re-serializar el motor)
    # y respondemos excluyendo el reporte crudo del body principal (R4.3).
    final_dto = dto.model_copy(update={"scan_id": persisted_id})
    return _dto_response(final_dto)


# Tipos anotados para los query params del histórico (patrón Annotated evita B008 de ruff).
# El `default=` va en la firma de la función (no dentro de Query); solo metadatos aquí.
RepoIdQuery = Annotated[uuid.UUID | None, Query(description="Filtrar por repo (UUID).")]
# Allowlist del ecosistema: un valor fuera de dominio → 422 (antes de tocar DB/motor).
EcosystemQuery = Annotated[
    Literal["pypi", "npm"] | None, Query(description="Filtrar por ecosistema (pypi|npm).")
]
PageQuery = Annotated[int, Query(ge=1, description="Número de página (base 1).")]
PageSizeQuery = Annotated[int, Query(ge=1, le=100, description="Elementos por página.")]


# ---------------------------------------------------------------------------
# GET /scans — histórico paginado con filtros (R5.2, H5-T20)
# ---------------------------------------------------------------------------


@router.get("", status_code=status.HTTP_200_OK)
async def list_scans(
    current_user: CurrentUser,
    scan_repo: ScanRepoDep,
    repo_id: RepoIdQuery = None,
    ecosystem: EcosystemQuery = None,
    page: PageQuery = 1,
    page_size: PageSizeQuery = 20,
) -> ScanPageDTO:
    """Lista paginada del histórico de escaneos del usuario autenticado (R5.2).

    Orden: created_at DESC (más reciente primero).
    Filtros opcionales: repo_id, ecosystem.
    Nunca devuelve escaneos de otros usuarios (R5.3).
    """
    return await scan_repo.list_by_user(
        current_user.id,
        repo_id=repo_id,
        ecosystem=ecosystem,
        page=page,
        page_size=page_size,
    )


# ---------------------------------------------------------------------------
# GET /scans/{id} — detalle completo (R5.3, H5-T20)
# ---------------------------------------------------------------------------


@router.get("/{scan_id}", status_code=status.HTTP_200_OK)
async def get_scan(
    scan_id: uuid.UUID,
    current_user: CurrentUser,
    scan_repo: ScanRepoDep,
) -> Any:
    """Devuelve el ScanDTO completo del escaneo indicado (sin report_raw en body, R4.3).

    Aislamiento R5.3: escaneo de otro usuario → 404, no 403.
    No se filtra si el escaneo existe o no: la respuesta es idéntica en ambos casos.
    """
    request_id = str(uuid.uuid4())
    dto = await scan_repo.get_by_id_for_user(scan_id, current_user.id)
    if dto is None:
        return _error_response(
            status.HTTP_404_NOT_FOUND,
            code="SCAN_NOT_FOUND",
            message="Escaneo no encontrado.",
            request_id=request_id,
        )
    return _dto_response(dto)


# ---------------------------------------------------------------------------
# GET /scans/{id}/raw — JSON crudo schema 1.2 (R4.3, H5-T20)
# ---------------------------------------------------------------------------


@router.get("/{scan_id}/raw", status_code=status.HTTP_200_OK)
async def get_scan_raw(
    scan_id: uuid.UUID,
    current_user: CurrentUser,
    scan_repo: ScanRepoDep,
) -> Any:
    """Devuelve el report_json crudo (schema 1.2) del escaneo indicado (R4.3).

    Aislamiento R5.3: escaneo de otro usuario → 404, no 403.
    El JSON crudo corresponde exactamente a la salida de render_json() persistida en DB.
    """
    request_id = str(uuid.uuid4())
    dto = await scan_repo.get_by_id_for_user(scan_id, current_user.id)
    if dto is None:
        return _error_response(
            status.HTTP_404_NOT_FOUND,
            code="SCAN_NOT_FOUND",
            message="Escaneo no encontrado.",
            request_id=request_id,
        )
    # El reporte ya viaja como dict en el DTO: lo devolvemos sin re-parsear (R4.3).
    return JSONResponse(content=dto.report_dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_request(body: ScanRequest) -> str | None:
    """Valida la coherencia del ScanRequest. Devuelve un mensaje de error o None si OK."""
    if body.source not in ("inline", "repo"):
        return "El campo 'source' debe ser 'inline' o 'repo'."
    if body.source == "inline" and not body.content:
        return "El campo 'content' es requerido cuando source=inline."
    if body.source == "repo" and not body.repo_id:
        return "El campo 'repo_id' es requerido cuando source=repo."
    if body.source == "repo" and not body.path:
        return "El campo 'path' es requerido cuando source=repo."
    return None


def _scan_error_response(exc: ScanServiceError, request_id: str) -> JSONResponse:
    """Mapea un `ScanServiceError` a la respuesta HTTP saneada correspondiente (R9.2)."""
    if exc.category is ScanErrorCategory.INVALID_INPUT:
        http_status = 422
        code = "SCAN_INVALID_INPUT"
    elif exc.category is ScanErrorCategory.TIMEOUT:
        http_status = status.HTTP_504_GATEWAY_TIMEOUT
        code = "SCAN_TIMEOUT"
    else:
        # ENGINE_FAILURE
        http_status = status.HTTP_502_BAD_GATEWAY
        code = "SCAN_ENGINE_FAILURE"

    # El mensaje de `ScanServiceError` ya está saneado (sin contenido del manifiesto ni secretos).
    logger.warning("Scan falló [%s]: %s (request_id=%s)", code, exc, request_id)
    return _error_response(http_status, code=code, message=str(exc), request_id=request_id)


def _dto_response(dto: ScanDTO) -> dict[str, object]:
    """Serializa el ScanDTO excluyendo el reporte crudo del body principal (R4.3)."""
    return dto.model_dump(exclude={"report_dict"})
