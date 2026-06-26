"""Inyección de dependencias del flujo OAuth (H5-T11).

Construye las implementaciones reales (Redis state/session, httpx GitHub, SQL user repo) detrás
de las abstracciones (`StateStore`, `SessionStore`, `GitHubOAuthClient`, `UserRepository`). El
router depende solo de las interfaces, así que los tests las sustituyen con
`app.dependency_overrides` sin tocar Redis/GitHub/Postgres.

Fail-closed: si falta una configuración crítica (Redis URL, credenciales de GitHub), la
dependencia lanza un error explícito en lugar de degradar silenciosamente el login.
"""

from __future__ import annotations

from functools import lru_cache
from urllib.parse import urlparse

import redis.asyncio as aioredis

from ..db.base import get_sessionmaker
from ..services.github import GitHubOAuthClient, HttpxGitHubOAuthClient
from ..settings import Settings, get_settings
from .session import RedisSessionStore, SessionStore
from .state_store import RedisStateStore, StateStore
from .user_repo import SqlUserRepository, UserRepository


class AuthConfigError(RuntimeError):
    """Configuración de auth incompleta en runtime (fail-closed). No incluye secretos."""


@lru_cache(maxsize=1)
def get_redis_client() -> aioredis.Redis[str]:
    """Cliente Redis async compartido (cacheado). Fail-closed si `REDIS_URL` no está."""
    settings = get_settings()
    if not settings.redis_url:
        raise AuthConfigError("REDIS_URL no configurada: el login OAuth no puede operar.")
    # `decode_responses=True`: GETDEL/GET devuelven str, no bytes — encaja con state/session.
    client: aioredis.Redis[str] = aioredis.Redis.from_url(
        settings.redis_url, decode_responses=True
    )
    return client


def _require_github_credentials(settings: Settings) -> tuple[str, str]:
    """Devuelve (client_id, client_secret) o falla. Nunca incluye el secret en el error."""
    client_id = settings.github_client_id
    client_secret = settings.github_client_secret
    if not client_id or client_secret is None:
        raise AuthConfigError(
            "github_client_id / github_client_secret no configurados: login OAuth deshabilitado."
        )
    secret_value = client_secret.get_secret_value()
    if not secret_value:
        raise AuthConfigError(
            "github_client_id / github_client_secret no configurados: login OAuth deshabilitado."
        )
    return client_id, secret_value


def callback_redirect_uri(settings: Settings) -> str:
    """URI de callback registrada en la GitHub OAuth App (absoluta, primer origen CORS).

    DEBE coincidir bit a bit con la `redirect_uri` que el router pone en el authorize_url y con la
    registrada en GitHub; por eso vive en un único sitio (aquí) y el router la reutiliza.

    Fail-closed (SEC): si `cors_origins` está vacío o su primer origen no es una URL absoluta
    (sin esquema/host), construir el redirect_uri produciría una URI RELATIVA que GitHub
    rechazaría — un fallo silencioso de login. Se lanza `AuthConfigError` (sin secretos) en su
    lugar. El esquema https en producción ya lo garantiza el validador de `Settings` en boot.
    """
    # En el demo single-tenant el front y el API comparten origen lógico; el callback cuelga del
    # prefijo de versión del API. El origen base sale del primer `cors_origins` (front confiable).
    if not settings.cors_origins:
        raise AuthConfigError(
            "cors_origins vacío: no hay origen base para construir el redirect_uri de OAuth "
            "(fail-closed)."
        )

    base = settings.cors_origins[0].rstrip("/")
    parsed = urlparse(base)
    if not parsed.scheme or not parsed.netloc:
        # Sin esquema o sin host, el redirect_uri sería relativo: GitHub lo rechaza. Fail-closed.
        raise AuthConfigError(
            "cors_origins[0] no es una URL absoluta (falta esquema o host): el redirect_uri "
            "de OAuth quedaría relativo (fail-closed)."
        )

    return f"{base}{settings.api_v1_prefix}/auth/callback"


def get_state_store() -> StateStore:
    """Provider del store de state OAuth (Redis)."""
    return RedisStateStore(get_redis_client())


def get_session_store() -> SessionStore:
    """Provider del store de sesión de servidor (Redis), firmado con `session_secret`."""
    settings = get_settings()
    return RedisSessionStore(
        get_redis_client(), session_secret=settings.session_secret.get_secret_value()
    )


def get_github_client() -> GitHubOAuthClient:
    """Provider del cliente OAuth de GitHub (httpx). Fail-closed sin credenciales."""
    settings = get_settings()
    client_id, client_secret = _require_github_credentials(settings)
    return HttpxGitHubOAuthClient(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=callback_redirect_uri(settings),
    )


def get_user_repository() -> UserRepository:
    """Provider del repositorio de usuarios (SQLAlchemy)."""
    return SqlUserRepository(get_sessionmaker())
