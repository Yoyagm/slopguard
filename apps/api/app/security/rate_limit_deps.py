"""Inyección de dependencias del rate limiting (H5-T42).

Expone la dependencia `RateLimit(category, ...)` que se cuelga de los endpoints públicos. La
construcción del limiter es FAIL-OPEN: sin `redis_url` devuelve `None` y la dependencia es no-op
(no limita), de modo que el SaaS no se cae por un Redis ausente y los tests corren sin Redis.

El render del 429 (envelope estable `{ "error": { code, message, request_id } }` + cabeceras
`X-RateLimit-*` y `Retry-After`) lo hace `RateLimitExceeded` + su handler en `app.main`.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Depends, Request, Response

from ..request_context import get_request_id
from ..settings import Settings, get_settings
from .rate_limit import RateLimiter, RateLimitResult, RedisRateLimiter

logger = logging.getLogger(__name__)

_WINDOW_SECONDS = 60


class RateLimitExceeded(Exception):
    """Se superó el límite de la categoría. La traduce a 429 el handler de `app.main`."""

    def __init__(self, result: RateLimitResult) -> None:
        super().__init__("rate limit exceeded")
        self.result = result


def get_rate_limiter() -> RateLimiter | None:
    """Provider del limiter. Devuelve `None` (fail-open) si Redis no está configurado.

    Reutiliza el cliente Redis compartido del flujo de auth para no abrir un segundo pool. Si
    `redis_url` no está, NO se limita (fail-open): rate limiting es protección, no autenticación.
    """
    settings = get_settings()
    if not settings.redis_url:
        return None
    # Import diferido: evita acoplar este módulo al arranque de auth en el import-time.
    from ..auth.deps import get_redis_client

    return RedisRateLimiter(get_redis_client())


def _settings_dep() -> Settings:
    return get_settings()


SettingsDep = Annotated[Settings, Depends(_settings_dep)]
RateLimiterDep = Annotated[RateLimiter | None, Depends(get_rate_limiter)]


def client_ip(request: Request, settings: Settings) -> str:
    """IP del cliente para la clave de límite.

    Por defecto `request.client.host`. Solo si `rate_limit_trust_forwarded_for` está activo
    (hay un proxy de confianza por delante) se toma el PRIMER valor de `X-Forwarded-For` (el
    cliente original); confiar en toda la cadena dejaría spoofear el límite con cabeceras falsas.
    """
    if settings.rate_limit_trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            first = forwarded.split(",", 1)[0].strip()
            if first:
                return first
    client = request.client
    return client.host if client is not None else "unknown"


def set_rate_limit_headers(response: Response, result: RateLimitResult) -> None:
    """Estampa las cabeceras `X-RateLimit-*` en la respuesta (informativas para el cliente)."""
    response.headers["X-RateLimit-Limit"] = str(result.limit)
    response.headers["X-RateLimit-Remaining"] = str(result.remaining)
    response.headers["X-RateLimit-Reset"] = str(result.reset_seconds)


class RateLimit:
    """Dependencia de rate limit por endpoint. `Depends(RateLimit("auth"))`.

    Una instancia por categoría/límite; FastAPI resuelve sus sub-dependencias (settings, limiter)
    al ejecutar `__call__`. No añade parámetros al endpoint (se usa en `dependencies=[...]`).
    """

    def __init__(self, category: str, *, settings_attr: str = "rate_limit_per_minute") -> None:
        self._category = category
        # Nombre del campo de `Settings` que define el límite/min de esta categoría: permite que
        # webhooks use un límite más holgado (`rate_limit_webhook_per_minute`) sin hardcodearlo.
        self._settings_attr = settings_attr

    async def __call__(
        self,
        request: Request,
        response: Response,
        settings: SettingsDep,
        limiter: RateLimiterDep,
    ) -> None:
        if not settings.rate_limit_enabled or limiter is None:
            return  # fail-open: deshabilitado o sin Redis ⇒ no se limita
        limit = int(getattr(settings, self._settings_attr))
        key = f"{self._category}:{client_ip(request, settings)}"
        try:
            result = await limiter.hit(key, limit=limit, window_seconds=_WINDOW_SECONDS)
        except Exception:
            # FAIL-OPEN ante Redis caído: logueamos y dejamos pasar (no romper disponibilidad por
            # una protección anti-abuso). No filtramos el detalle del fallo de infra.
            logger.warning(
                "Rate limiter no disponible para la categoría %s; fail-open (request permitido).",
                self._category,
            )
            return
        set_rate_limit_headers(response, result)
        if not result.allowed:
            logger.warning(
                "Rate limit excedido en %s (limit=%d, reset=%ds).",
                self._category,
                result.limit,
                result.reset_seconds,
            )
            raise RateLimitExceeded(result)


def rate_limit_error_body() -> dict[str, dict[str, str]]:
    """Cuerpo del 429 con el envelope de error estable del repo (saneado, sin infra)."""
    return {
        "error": {
            "code": "RATE_LIMITED",
            "message": "Demasiadas peticiones. Inténtalo de nuevo más tarde.",
            "request_id": get_request_id(),
        }
    }
