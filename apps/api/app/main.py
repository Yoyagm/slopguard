"""App factory de FastAPI (design §1.4).

`create_app()` ensambla la aplicación: logging, CORS y los routers. Mantener este módulo
delgado; la lógica vive en `app/db`, `app/services` y `app/api/*`.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.health import router as health_router
from .logging_config import configure_logging
from .settings import get_settings


def create_app() -> FastAPI:
    """Construye y configura la instancia de FastAPI."""
    settings = get_settings()
    configure_logging()

    app = FastAPI(
        title="SlopGuard SaaS API",
        version="0.1.0",
        description="Backend que envuelve el motor SlopGuard (zero-deps) como librería in-process.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    app.include_router(health_router, prefix=settings.api_v1_prefix)
    return app


app = create_app()
