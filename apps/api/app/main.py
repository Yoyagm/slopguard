"""App factory de FastAPI (design §1.4).

`create_app()` ensambla la aplicación: logging, CORS y los routers. Mantener este módulo
delgado; la lógica vive en `app/db`, `app/services` y `app/api/*`.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.auth import router as auth_router
from .api.health import router as health_router
from .api.installations import router as installations_router
from .api.me import router as me_router
from .api.scans import router as scans_router
from .api.webhooks import router as webhooks_router
from .github_app.deps import AppConfigError
from .logging_config import configure_logging
from .middleware import RequestIdMiddleware
from .security.rate_limit_deps import (
    RateLimitExceeded,
    rate_limit_error_body,
    set_rate_limit_headers,
)
from .settings import get_settings

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Construye y configura la instancia de FastAPI."""
    settings = get_settings()
    configure_logging()

    app = FastAPI(
        title="SlopGuard SaaS API",
        version="0.1.0",
        description="Backend que envuelve el motor SlopGuard (zero-deps) como librería in-process.",
    )

    # Correlación request-id: se añade DESPUÉS de CORS para quedar como el middleware más
    # externo (add_middleware apila el último como outermost), de modo que toda línea de log
    # de la petición —incluido el preflight CORS— lleve el mismo `request_id`.
    app.add_middleware(RequestIdMiddleware)

    # CORS endurecido (NFR-Seg): orígenes explícitos + credenciales. `allow_headers` se
    # restringe a lo que el front necesita; `allow_headers=["*"]` con `allow_credentials=True`
    # amplía la superficie innecesariamente. La validación de que los orígenes sean https y
    # sin comodín en producción vive en `Settings` (fail-closed en boot).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.include_router(health_router, prefix=settings.api_v1_prefix)
    app.include_router(auth_router, prefix=settings.api_v1_prefix)
    app.include_router(me_router, prefix=settings.api_v1_prefix)
    app.include_router(installations_router, prefix=settings.api_v1_prefix)
    app.include_router(scans_router, prefix=settings.api_v1_prefix)
    app.include_router(webhooks_router, prefix=settings.api_v1_prefix)

    @app.exception_handler(AppConfigError)
    async def _app_config_error_handler(
        _request: Request, _exc: AppConfigError
    ) -> JSONResponse:
        """La GitHub App no está configurada (fail-closed) ⇒ 503 saneado, sin filtrar el motivo.

        `AppConfigError` solo se lanza cuando falta configuración de la App (p.ej. `database_url`
        del repositorio de instalaciones). Respondemos 503 (servicio no disponible) en vez del 500
        por defecto: es un fallo de configuración esperado, no un bug. El cuerpo NO incluye el
        mensaje de la excepción (podría aludir a nombres de campos sensibles); solo lo registramos.
        """
        logger.error("AppConfigError: GitHub App no configurada (fail-closed); respondiendo 503.")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": {
                    "code": "GITHUB_APP_UNCONFIGURED",
                    "message": "La integración con la GitHub App no está disponible.",
                }
            },
        )

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limit_handler(
        _request: Request, exc: RateLimitExceeded
    ) -> JSONResponse:
        """Límite por IP superado ⇒ 429 con el envelope estable + `Retry-After` y `X-RateLimit-*`.

        El cuerpo NO filtra la IP, la clave ni el contador; solo un mensaje saneado y el
        `request_id` para soporte. `Retry-After` (segundos) guía al cliente bien comportado.
        """
        response = JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=rate_limit_error_body(),
        )
        set_rate_limit_headers(response, exc.result)
        response.headers["Retry-After"] = str(exc.result.reset_seconds)
        return response

    return app


app = create_app()
