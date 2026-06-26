"""Scan Router: endpoints de escaneo y histórico (H5-T19/T20/T24).

POST /api/v1/scans           — escaneo on-demand (T19, T24).
GET  /api/v1/scans           — lista paginada del histórico (T20, R5.2).
GET  /api/v1/scans/{id}      — detalle del escaneo (T20, R5.3).
GET  /api/v1/scans/{id}/raw  — report_json crudo schema 1.2 (T20, R4.3).

Mapeo de errores saneados (R9.2, design §4):
- `ScanServiceError(INVALID_INPUT)` → 422
- `ScanServiceError(TIMEOUT)`       → 504
- `ScanServiceError(ENGINE_FAILURE)` → 502
- Escaneo no encontrado o de otro usuario → 404 (no 403, R5.3)
- source=repo: repo no encontrado/sin acceso/token fallido → 422 REPO_UNAVAILABLE
Forma estable: `{ "error": { "code", "message", "request_id" } }` — sin stacktrace ni secretos.
"""

from __future__ import annotations

import datetime
import logging
import uuid
from collections.abc import Callable
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from ..auth.guard import require_user
from ..db.models import User
from ..github_app.contents_client import (
    GitHubContentsClient,
    HttpxGitHubContentsClient,
    RepoUnavailableError,
    confine_path,
)

# `get_installation_repository` se importa (y re-exporta) desde el provider ÚNICO en
# `github_app.deps`: un solo proveedor fail-closed compartido por scans/installations/webhooks.
# Re-exportar el MISMO símbolo mantiene válidos los `dependency_overrides` de los tests que
# apuntan a `app.api.scans.get_installation_repository`.
from ..github_app.deps import (
    AppConfigError,
    get_github_app_token_client,
    get_installation_repository,
)
from ..github_app.installation_repo import InstallationRepository
from ..github_app.token_client import GitHubAppTokenClient, InstallationTokenError
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


def get_contents_client() -> GitHubContentsClient:
    """Provider del cliente de la GitHub Contents API (T24, inyectable en tests)."""
    return HttpxGitHubContentsClient()


class _UnconfiguredTokenClient:
    """Centinela: GitHub App no configurada. Lanza AppConfigError al intentar usarlo.

    Permite que `get_scan_token_client` nunca levante en boot; solo falla al llamarlo
    (cuando source=repo en tiempo de request). Los escaneos inline no lo invocan.
    """

    async def get_installation_token(self, installation_id: int) -> str:
        raise AppConfigError(
            "La GitHub App no está configurada: "
            "los escaneos desde repo no están disponibles (fail-closed)."
        )


def get_scan_token_client() -> GitHubAppTokenClient:
    """Provider del token client para el scan router. Degradación graceful si no configurado.

    En vez de levantar `AppConfigError` en boot (lo que rompería escaneos inline), devuelve
    un centinela que falla solo cuando se intenta obtener un token (source=repo). Esto permite
    que los escaneos inline sigan funcionando sin la GitHub App configurada (T24, R2.5).
    """
    try:
        return get_github_app_token_client()
    except AppConfigError:
        return _UnconfiguredTokenClient()


# Fábrica perezosa del installation repo: difiere la construcción del provider ÚNICO fail-closed
# (`github_app.deps.get_installation_repository`) hasta que el camino `source=repo` lo necesita
# de verdad. Así un escaneo `source=inline` NO toca el repositorio de instalaciones (ni exige DB):
# coherente con `_UnconfiguredTokenClient` para el token. El callable subyacente sigue siendo el
# mismo provider unificado.
InstallationRepoProvider = Callable[[], InstallationRepository]


def get_installation_repo_provider(request: Request) -> InstallationRepoProvider:
    """Devuelve una fábrica del installation repo SIN construirlo aún (lazy, source=repo).

    Resuelve el provider efectivo respetando `app.dependency_overrides`: si un test sustituyó
    `get_installation_repository`, la fábrica usa ese override; en otro caso usa el provider ÚNICO
    fail-closed de producción. Esto evita que un escaneo `source=inline` dispare el fail-closed por
    falta de DB (no necesita el repo) y mantiene un único provider de instalaciones en el sistema.
    """
    overrides = request.app.dependency_overrides
    provider = overrides.get(get_installation_repository, get_installation_repository)

    def _factory() -> InstallationRepository:
        # `dependency_overrides` está tipado como Callable[..., Any]; el provider efectivo
        # siempre construye un InstallationRepository (prod fail-closed o el doble de tests).
        return cast(InstallationRepository, provider())

    return _factory


ScanServiceDep = Annotated[ScanService, Depends(get_scan_service)]
ScanRepoDep = Annotated[ScanRepository, Depends(get_scan_repository)]
InstallationRepoProviderDep = Annotated[
    InstallationRepoProvider, Depends(get_installation_repo_provider)
]
ContentsClientDep = Annotated[GitHubContentsClient, Depends(get_contents_client)]
TokenClientDep = Annotated[GitHubAppTokenClient, Depends(get_scan_token_client)]


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
    installation_repo_provider: InstallationRepoProviderDep,
    contents_client: ContentsClientDep,
    token_client: TokenClientDep,
) -> Any:
    """Lanza un escaneo on-demand y persiste el resultado (R3.1, R5.1, T24, design §2.2).

    Flujo:
    1. Valida la forma del request (source + campos requeridos).
    2. Para source=inline: invoca `scan_service.scan_text`.
       Para source=repo: resuelve repo → installation token → lee manifiesto → scan_text.
    3. Mapea `ScanReport` → `ScanDTO` con metadatos de persistencia.
    4. Persiste en `scans` + `scan_results` vía `ScanRepository`.
    5. Devuelve `ScanDTO` sin `report_raw` (R4.3: el raw va en `/scans/{id}/raw`).

    Errores saneados R9.2:
    - source inválido / campo requerido ausente → 422
    - motor: INVALID_INPUT → 422, TIMEOUT → 504, ENGINE_FAILURE → 502
    - repo no disponible (no existe, sin acceso, token fallido, archivo ausente)
      → 422 REPO_UNAVAILABLE
    """
    request_id = str(uuid.uuid4())

    # Validación de source y campos requeridos.
    validation_error = _validate_request(body)
    if validation_error:
        return _error_response(
            422,
            code="INVALID_REQUEST",
            message=validation_error,
            request_id=request_id,
        )

    # Determinar el contenido a escanear según la fuente.
    if body.source == "repo":
        # Solo aquí construimos el installation repo (provider ÚNICO fail-closed): un escaneo
        # inline nunca lo necesita y por tanto no exige DB. Si la App no está configurada, el
        # provider lanza AppConfigError → el handler global responde 503 (fail-closed).
        installation_repo = installation_repo_provider()
        repo_result = await _resolve_repo_content(
            body=body,
            current_user=current_user,
            installation_repo=installation_repo,
            contents_client=contents_client,
            token_client=token_client,
            request_id=request_id,
        )
        if isinstance(repo_result, JSONResponse):
            # Propagamos el error saneado sin exponerlo más.
            return repo_result
        content, repo_internal_id = repo_result
    else:
        # source=inline: `content` garantizado no-None por _validate_request.
        content = body.content or ""
        repo_internal_id = None

    # Invocar el motor con el contenido (inline o leído del repo).
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
        repo_id=repo_internal_id,
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


async def _resolve_repo_content(
    *,
    body: ScanRequest,
    current_user: User,
    installation_repo: InstallationRepository,
    contents_client: GitHubContentsClient,
    token_client: GitHubAppTokenClient,
    request_id: str,
) -> tuple[str, uuid.UUID] | JSONResponse:
    """Resuelve el manifiesto de un repo conectado para el scan (T24, R2.5).

    Pasos:
    1. Parsear `repo_id` como UUID (garantizado no-None por `_validate_request`).
    2. Buscar el repo + installation_id de GitHub en la DB, verificando que el repo
       pertenece al usuario y la instalación está activa (aislamiento R5.3 + R2.4).
    3. Obtener un installation token fresco (puede venir de caché Redis AEAD).
    4. Leer el manifiesto via GitHub Contents API (path confinado anti-traversal).
    5. Devolver `(content_str, repo_internal_uuid)` para que el caller persista el scan
       con el `repo_id` correcto.

    En cualquier fallo (repo desconocido, instalación revocada, token fallido, archivo
    ausente, error de red) → devuelve una `JSONResponse` 422 REPO_UNAVAILABLE saneada
    (sin token ni detalles internos, R9.2/NFR-Seg-3).
    """
    # Parsear UUID del repo (la validación previa solo confirma que no es None/vacío).
    raw_repo_id = body.repo_id or ""
    try:
        repo_uuid = uuid.UUID(raw_repo_id)
    except ValueError:
        return _error_response(
            422,
            code="REPO_UNAVAILABLE",
            message="El 'repo_id' no tiene un formato UUID válido.",
            request_id=request_id,
        )

    # Buscar repo + installation_id en la DB: falla si no existe o instalación inactiva.
    repo_with_inst = await installation_repo.get_repo_with_installation_id(
        repo_uuid, current_user.id
    )
    if repo_with_inst is None:
        return _error_response(
            422,
            code="REPO_UNAVAILABLE",
            message=(
                "El repo no está disponible. Puede que la instalación de la GitHub App "
                "haya sido revocada o el repo no sea accesible con tu cuenta."
            ),
            request_id=request_id,
        )

    # Obtener installation token (renovar si expirado; cacheable en Redis AEAD).
    try:
        token = await token_client.get_installation_token(
            repo_with_inst.github_installation_id
        )
    except (InstallationTokenError, AppConfigError) as exc:
        # Logueamos solo el tipo de error, sin el token ni la clave privada.
        logger.warning(
            "No se pudo obtener el installation token para installation_id=%d "
            "(request_id=%s): %s",
            repo_with_inst.github_installation_id,
            request_id,
            type(exc).__name__,
        )
        return _error_response(
            422,
            code="REPO_UNAVAILABLE",
            message=(
                "No se pudo obtener acceso al repo. "
                "El token de instalación no está disponible; intenta de nuevo en unos segundos."
            ),
            request_id=request_id,
        )

    # Confinamiento de ruta antes de llegar a la red (anti path traversal).
    # La validación ocurre aquí (en el borde del servicio) además de en el cliente HTTP,
    # de modo que el fake en tests también la dispara sin llamar a GitHub.
    raw_path = body.path or ""
    try:
        safe_path = confine_path(raw_path)
    except RepoUnavailableError as path_exc:
        return _error_response(
            422,
            code="REPO_UNAVAILABLE",
            message=str(path_exc),
            request_id=request_id,
        )

    # Leer el manifiesto vía GitHub Contents API.
    ref = body.ref  # None = rama por defecto del repo
    try:
        content = await contents_client.fetch_manifest(
            token=token,
            full_name=repo_with_inst.full_name,
            path=safe_path,
            ref=ref,
        )
    except RepoUnavailableError as exc:
        # El mensaje ya está saneado (no incluye el token). Lo propagamos como 422.
        logger.warning(
            "Manifiesto no disponible en repo '%s' path='%s' (request_id=%s): %s",
            repo_with_inst.full_name,
            safe_path,
            request_id,
            exc,
        )
        return _error_response(
            422,
            code="REPO_UNAVAILABLE",
            message=str(exc),
            request_id=request_id,
        )

    return content, repo_with_inst.repo.id


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
