"""Inyección de dependencias de la GitHub App (H5-T22/T23).

Construye la implementación SQL real del repositorio de instalaciones tras su abstracción
(`InstallationRepository`), resuelve el secreto del webhook con fail-closed, y provee el
`GitHubAppTokenClient` (firma JWT + canje de installation token, H5-T23).

El router depende solo de las interfaces, así que los tests las sustituyen con
`app.dependency_overrides` sin tocar Postgres ni secretos reales.
"""

from __future__ import annotations

from ..auth.deps import get_redis_client
from ..db.base import get_sessionmaker
from ..settings import Settings, get_settings
from .installation_repo import InstallationRepository, SqlInstallationRepository
from .token_client import (
    GitHubAppTokenClient,
    HttpxGitHubAppTokenClient,
    InstallationTokenError,
    _pem_bytes_from_setting,
)


class WebhookConfigError(RuntimeError):
    """El secreto del webhook no está configurado (fail-closed). NUNCA incluye el secreto."""


class AppConfigError(RuntimeError):
    """La configuración de la GitHub App está incompleta (fail-closed). Sin secretos."""


def get_installation_repository() -> InstallationRepository:
    """Provider ÚNICO del repositorio de instalaciones (SQLAlchemy, fail-closed).

    Es el único provider de `InstallationRepository` del servicio: lo consumen los routers de
    webhooks, installations y scans (este último lo re-exporta) para garantizar una semántica
    homogénea y fail-closed en todos los endpoints.

    Fail-closed (NFR-Seg / ADR-4): sin `database_url` configurada NO degradamos a un doble de
    tests ni instanciamos un engine inválido — lanzamos `AppConfigError` (el caller la traduce a
    503). El `FakeInstallationRepository` queda EXCLUSIVAMENTE para tests, inyectado vía
    `app.dependency_overrides`; nunca se construye en el camino de producción.
    """
    settings = get_settings()
    if not settings.database_url:
        raise AppConfigError(
            "database_url no configurada: el repositorio de instalaciones no está disponible "
            "(fail-closed)."
        )
    return SqlInstallationRepository(get_sessionmaker())


def require_webhook_secret(settings: Settings) -> str:
    """Devuelve el secreto del webhook desempaquetado, o falla cerrado si no está.

    Sin secreto no podemos verificar el HMAC: rechazamos el webhook (503) en lugar de aceptar
    eventos sin autenticar. El valor JAMÁS se loguea (solo lo consume `verify_signature`).
    """
    secret = settings.github_webhook_secret
    if secret is None:
        raise WebhookConfigError("github_webhook_secret no configurado: webhooks deshabilitados.")
    value = secret.get_secret_value()
    if not value:
        raise WebhookConfigError("github_webhook_secret vacío: webhooks deshabilitados.")
    return value


def get_github_app_token_client() -> GitHubAppTokenClient:
    """Provider del cliente de installation tokens (H5-T23, R2.5, ADR-4).

    Fail-closed: si `github_app_id` o `github_app_private_key` no están configurados
    lanza `AppConfigError` (sin exponer los valores). Inyecta Redis si está disponible
    para caché cifrada del token; si Redis falla, opera sin caché.

    La clave privada se desempaqueta SOLO aquí y se pasa como bytes al cliente; el cliente
    la usa solo en el momento de firmar el JWT.
    """
    settings = get_settings()
    app_id = settings.github_app_id
    private_key_secret = settings.github_app_private_key

    if not app_id:
        raise AppConfigError(
            "github_app_id no configurado: installation tokens deshabilitados (fail-closed)."
        )
    if private_key_secret is None:
        raise AppConfigError(
            "github_app_private_key no configurada: "
            "installation tokens deshabilitados (fail-closed)."
        )
    raw_key = private_key_secret.get_secret_value()
    if not raw_key:
        raise AppConfigError(
            "github_app_private_key vacía: installation tokens deshabilitados (fail-closed)."
        )

    pem_bytes = _pem_bytes_from_setting(raw_key)

    # Redis es opcional: si no está configurado o falla al construir el cliente,
    # el token client opera sin caché (degradación graceful, no fallo).
    redis_client = None
    if settings.redis_url:
        try:
            redis_client = get_redis_client()
        except Exception as exc:
            # Redis no disponible: continúa sin caché (degradación graceful, no fallo).
            import logging as _log

            _log.getLogger(__name__).warning(
                "Redis no disponible al construir el token client: %s", exc
            )

    return HttpxGitHubAppTokenClient(
        app_id=app_id,
        private_key_pem=pem_bytes,
        redis_client=redis_client,
    )


__all__ = [
    "AppConfigError",
    "InstallationTokenError",
    "WebhookConfigError",
    "get_github_app_token_client",
    "get_installation_repository",
    "require_webhook_secret",
]
