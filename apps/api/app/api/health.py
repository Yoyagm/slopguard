"""Health endpoint (design §4.1): `GET /health` → `{ status, db, redis }`.

En la Ola 0 el chequeo refleja la CONFIGURACIÓN de las dependencias (no abre conexiones
reales); el ping real a Postgres/Redis se añade con la observabilidad (H5-T42). Si una
dependencia configurada está caída, responde 503.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Response, status
from pydantic import BaseModel

from ..settings import get_settings

router = APIRouter(tags=["health"])

DepStatus = Literal["ok", "down", "not_configured"]


class HealthDTO(BaseModel):
    status: Literal["ok", "degraded"]
    db: DepStatus
    redis: DepStatus


@router.get("/health", response_model=HealthDTO)
def health(response: Response) -> HealthDTO:
    """Estado del servicio y de sus dependencias."""
    settings = get_settings()
    db = _dep_status(settings.database_url)
    redis = _dep_status(settings.redis_url)

    if "down" in (db, redis):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthDTO(status="degraded", db=db, redis=redis)

    return HealthDTO(status="ok", db=db, redis=redis)


def _dep_status(url: str | None) -> DepStatus:
    """Refleja si la dependencia está configurada (Ola 0). El ping real llega en H5-T42."""
    if not url:
        return "not_configured"
    return "ok"
