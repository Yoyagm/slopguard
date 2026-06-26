"""Webhook Router de la GitHub App (R2.2/R2.4, R6.1, NFR-Seg-2, design §2.3/§4.1).

`POST /api/v1/webhooks/github` es la ÚNICA ruta pública sin sesión: el control de acceso es la
firma HMAC del webhook. Orden de operaciones (estricto, ver ADR-4):

  1. Leer el **cuerpo crudo** (`await request.body()`) — bytes exactos que GitHub firmó.
  2. Resolver el secreto del webhook (fail-closed: sin secreto ⇒ 503, nunca aceptar a ciegas).
  3. **Verificar HMAC en tiempo constante ANTES de parsear** — firma inválida ⇒ 204 descartado
     sin efecto (R6.1). Parsear antes expondría el parser JSON a entrada no autenticada.
  4. Solo con firma válida: parsear el JSON y despachar por tipo de evento.

Eventos manejados en la Ola 4 (T22):
  - `installation` (created/...): upsert de `github_installations` + `repos` (R2.2).
  - `installation` (deleted/suspend/unsuspend): cambia `status` SIN borrar histórico (R2.4).
  - `installation_repositories` (added/removed): sincroniza la lista de repos.
  - `ping`: ack benigno (GitHub lo envía al registrar el webhook).

`pull_request` queda PREPARADO pero NO implementado aquí: el dispatch al worker async es de la
Ola 5 (T26+). Hoy se reconoce y se hace ack 202 sin encolar (ver `_handle_pull_request`).
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request, status
from fastapi.responses import Response

from ..github_app.deps import (
    WebhookConfigError,
    get_installation_repository,
    require_webhook_secret,
)
from ..github_app.events import (
    INSTALL_ACTION_DELETED,
    INSTALL_ACTION_SUSPEND,
    MalformedEventError,
    parse_installation_event,
    parse_installation_repositories_event,
)
from ..github_app.installation_repo import (
    STATUS_REVOKED,
    STATUS_SUSPENDED,
    InstallationData,
    InstallationRepository,
)
from ..security.webhook_signature import verify_signature
from ..settings import Settings, get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Cabeceras de GitHub (declaradas con el patrón Annotated para no disparar B008 de ruff).
SignatureHeader = Annotated[str | None, Header(alias="X-Hub-Signature-256")]
EventHeader = Annotated[str | None, Header(alias="X-GitHub-Event")]

# Mapa action→status para los eventos de `installation` que desactivan la App (R2.4). Cualquier
# otra action (created, new_permissions_accepted, ...) se trata como instalación activa.
_DEACTIVATION_STATUS: dict[str, str] = {
    INSTALL_ACTION_DELETED: STATUS_REVOKED,
    INSTALL_ACTION_SUSPEND: STATUS_SUSPENDED,
}


def _settings_dep() -> Settings:
    return get_settings()


SettingsDep = Annotated[Settings, Depends(_settings_dep)]
InstallationRepoDep = Annotated[
    InstallationRepository, Depends(get_installation_repository)
]


class _BodyTooLargeError(Exception):
    """El cuerpo del webhook supera el límite configurado (DoS). Se traduce a 413."""


async def _read_body_capped(request: Request, max_bytes: int) -> bytes:
    """Lee el cuerpo crudo con un TOPE de tamaño, ANTES de cualquier verificación (anti-DoS).

    Estrategia de doble barrera (el webhook es el único endpoint público no autenticado):
      1. Si la cabecera `Content-Length` declara más de `max_bytes` ⇒ rechazamos sin leer nada.
      2. Como `Content-Length` puede faltar o mentir (Transfer-Encoding: chunked, atacante),
         leemos por chunks y abortamos en cuanto el acumulado supera `max_bytes`, sin materializar
         el cuerpo completo en memoria.

    Lanza `_BodyTooLargeError` (→ 413) si se excede; devuelve los bytes exactos en caso contrario
    (los mismos que GitHub firmó, imprescindible para la verificación HMAC posterior).
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > max_bytes:
                raise _BodyTooLargeError
        except ValueError:
            # Content-Length no numérico: cabecera malformada ⇒ tratamos como hostil (413).
            raise _BodyTooLargeError from None

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            raise _BodyTooLargeError
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/github")
async def github_webhook(
    request: Request,
    settings: SettingsDep,
    installations: InstallationRepoDep,
    signature: SignatureHeader = None,
    event: EventHeader = None,
) -> Response:
    """Recibe un webhook de GitHub. Acota el tamaño, verifica HMAC y solo luego parsea (R6.1)."""
    # 0) Límite de tamaño ANTES de leer todo / verificar HMAC: el webhook es público y no
    #    autenticado, así que un cuerpo enorme sería un DoS barato. Tope -> 413 (anti-DoS).
    try:
        raw_body = await _read_body_capped(request, settings.webhook_max_body_bytes)
    except _BodyTooLargeError:
        logger.warning(
            "Webhook rechazado: cuerpo supera el límite de %d bytes (posible DoS).",
            settings.webhook_max_body_bytes,
        )
        return Response(status_code=status.HTTP_413_CONTENT_TOO_LARGE)

    # 2) Secreto del webhook (fail-closed): sin él no podemos verificar nada ⇒ 503.
    try:
        secret = require_webhook_secret(settings)
    except WebhookConfigError:
        logger.error("Webhook recibido pero github_webhook_secret no está configurado.")
        return Response(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

    # 3) HMAC en tiempo constante, ANTES de parsear. Firma inválida ⇒ 204 descartado sin efecto.
    if not verify_signature(secret=secret, raw_body=raw_body, signature_header=signature):
        logger.warning("Webhook descartado: firma HMAC inválida o ausente (posible spoofing).")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # 4) Solo aquí el cuerpo es de confianza: parseamos y despachamos.
    payload = _parse_json_body(raw_body)
    if payload is None:
        # Cuerpo de un actor autenticado pero no-JSON/forma inesperada: ack 202 y no-op (no
        # reintentamos contra GitHub por una entrada malformada). No filtramos el cuerpo crudo.
        logger.warning("Webhook con firma válida pero cuerpo no-JSON; ignorado.")
        return _accepted()

    return await _dispatch(event=event, payload=payload, installations=installations)


async def _dispatch(
    *,
    event: str | None,
    payload: dict[str, object],
    installations: InstallationRepository,
) -> Response:
    """Despacha por tipo de evento. Eventos desconocidos ⇒ ack 202 sin efecto (no ruido)."""
    if event == "installation":
        return await _handle_installation(payload, installations)
    if event == "installation_repositories":
        return await _handle_installation_repositories(payload, installations)
    if event == "pull_request":
        return _handle_pull_request()
    if event == "ping":
        # GitHub envía `ping` al crear el webhook: ack benigno.
        logger.info("Webhook ping recibido (verificación de endpoint).")
        return _accepted()

    logger.info("Webhook de evento no manejado en esta ola: %s.", event)
    return _accepted()


async def _handle_installation(
    payload: dict[str, object], installations: InstallationRepository
) -> Response:
    """`installation`: alta/actualización de repos o desactivación sin borrar histórico (R2.4)."""
    try:
        action, data = parse_installation_event(payload)
    except MalformedEventError as exc:
        logger.warning("Evento installation malformado: %s.", exc)
        return _accepted()

    deactivation_status = _DEACTIVATION_STATUS.get(action)
    if deactivation_status is not None:
        # deleted/suspend: solo cambia status; los scans permanecen intactos (R2.4).
        changed = await installations.set_status(
            installation_id=data.installation_id, status=deactivation_status
        )
        if not changed:
            logger.info(
                "installation/%s para instalación desconocida; ignorado.", action
            )
        else:
            logger.info(
                "Instalación %s marcada %s (histórico conservado).",
                data.installation_id,
                deactivation_status,
            )
        return _accepted()

    # created / unsuspend / new_permissions_accepted / ... ⇒ instalación activa: upsert completo.
    # `unsuspend` reactiva reusando el mismo upsert (vuelve a `status=active`).
    return await _activate_installation(payload, data, installations)


async def _activate_installation(
    payload: dict[str, object],
    data: InstallationData,
    installations: InstallationRepository,
) -> Response:
    """Resuelve el dueño (sender) y hace upsert de la instalación + repos (R2.2)."""
    owner_id = await _resolve_owner(payload, installations)
    if owner_id is None:
        # Instalador no es un usuario conocido (nunca hizo login): no podemos asociar la
        # instalación a un dueño. Ack 202 (no reintentar) pero no persistimos (fail-closed).
        logger.warning(
            "Instalación %s de un usuario no registrado; no se asocia.", data.installation_id
        )
        return _accepted()

    # El internal_id devuelto no se expone al cliente; el upsert es el efecto buscado.
    await installations.upsert_installation(data, user_id=owner_id)
    logger.info(
        "Instalación %s persistida (%d repos accesibles).",
        data.installation_id,
        len(data.repos),
    )
    return _accepted()


async def _handle_installation_repositories(
    payload: dict[str, object], installations: InstallationRepository
) -> Response:
    """`installation_repositories`: sincroniza el delta de repos (added/removed)."""
    try:
        change = parse_installation_repositories_event(payload)
    except MalformedEventError as exc:
        logger.warning("Evento installation_repositories malformado: %s.", exc)
        return _accepted()

    synced = await installations.sync_repos(
        installation_id=change.installation_id,
        added=change.added,
        removed_repo_ids=change.removed_repo_ids,
    )
    if not synced:
        logger.info(
            "installation_repositories para instalación desconocida %s; ignorado.",
            change.installation_id,
        )
    else:
        logger.info(
            "Repos sincronizados para instalación %s (+%d/-%d).",
            change.installation_id,
            len(change.added),
            len(change.removed_repo_ids),
        )
    return _accepted()


def _handle_pull_request() -> Response:
    """`pull_request`: PREPARADO para la Ola 5. Hoy solo ack, NO encola el escaneo.

    El dispatch al worker async (Arq+Redis) con `{repo, pr, head_sha, installation_id}` es de la
    Ola 5 (T26+). Reconocemos el evento aquí para no devolver un 404 que haría a GitHub reintentar,
    pero deliberadamente NO escaneamos ni encolamos nada en esta tarea.
    """
    logger.info("Webhook pull_request reconocido; dispatch al worker pendiente (Ola 5).")
    # TODO(Ola 5 / T26): verificar action (opened/synchronize/reopened), extraer
    # {repo_full_name, pr_number, head_sha, installation_id} y encolar el job de escaneo.
    return _accepted()


async def _resolve_owner(
    payload: dict[str, object], installations: InstallationRepository
) -> uuid.UUID | None:
    """Resuelve el `users.id` del instalador a partir de `sender.id` del payload.

    En el demo single-tenant, la instalación pertenece al usuario que la realizó (`sender`). Si el
    `sender` no es un usuario conocido (nunca hizo login OAuth), devolvemos None y el caller
    descarta sin persistir (fail-closed: no inventamos un dueño).
    """
    sender = payload.get("sender")
    if not isinstance(sender, dict):
        return None
    sender_id = sender.get("id")
    if isinstance(sender_id, bool) or not isinstance(sender_id, int):
        return None
    return await installations.resolve_owner(sender_id)


def _parse_json_body(raw_body: bytes) -> dict[str, object] | None:
    """Decodifica el cuerpo JSON a un dict. None si no es JSON o no es un objeto (no lanza)."""
    try:
        decoded = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


def _accepted() -> Response:
    """Ack rápido 202 (R9.3): aceptamos el evento sin procesar inline pesado."""
    return Response(status_code=status.HTTP_202_ACCEPTED)
