"""Health endpoint (design §4.1): `GET /health` → `{ status, db, redis }` (H5-T42).

Ahora hace un ping REAL a las dependencias configuradas:
  - Postgres: `SELECT 1` con timeout corto (en threadpool: el engine es síncrono).
  - Redis:    `PING` con timeout corto.

Estados por dependencia: `ok` | `down` | `not_configured`. Si alguna CONFIGURADA está `down`
⇒ 503 `degraded`. El chequeo es rápido y NUNCA lanza: cualquier error se traduce a `down` sin
filtrar detalles de la infra (host, credenciales, traza). Los probes son inyectables (Protocol)
para poder doblarlos en tests sin Postgres/Redis reales.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated, Literal, Protocol

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from ..db.base import get_engine
from ..settings import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

DepStatus = Literal["ok", "down", "not_configured"]

# Timeout corto por dependencia: el health debe responder rápido aunque la dep esté colgada.
_PING_TIMEOUT_S = 2.0


class HealthDTO(BaseModel):
    status: Literal["ok", "degraded"]
    db: DepStatus
    redis: DepStatus


class DependencyProbe(Protocol):
    """Contrato de un chequeo de dependencia. `check()` NUNCA lanza: devuelve el estado."""

    async def check(self) -> DepStatus:
        ...


class NotConfiguredProbe:
    """La dependencia no está configurada (sin URL): se reporta `not_configured`, no se pinguea."""

    async def check(self) -> DepStatus:
        return "not_configured"


class PostgresProbe:
    """Ping real a Postgres (`SELECT 1`) con timeout. Cualquier fallo ⇒ `down` (no lanza)."""

    async def check(self) -> DepStatus:
        try:
            async with asyncio.timeout(_PING_TIMEOUT_S):
                await run_in_threadpool(self._ping)
        except Exception:
            # No filtramos el detalle (host/credenciales): solo registramos que la dep está caída.
            logger.warning("Health: ping a Postgres falló; se reporta db=down.")
            return "down"
        return "ok"

    @staticmethod
    def _ping() -> None:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))


class RedisProbe:
    """Ping real a Redis (`PING`) con timeout. Cualquier fallo ⇒ `down` (no lanza)."""

    def __init__(self, redis_url: str) -> None:
        self._url = redis_url

    async def check(self) -> DepStatus:
        client: aioredis.Redis[bytes] = aioredis.from_url(
            self._url,
            socket_connect_timeout=_PING_TIMEOUT_S,
            socket_timeout=_PING_TIMEOUT_S,
        )
        try:
            async with asyncio.timeout(_PING_TIMEOUT_S):
                await client.ping()
            return "ok"
        except Exception:
            logger.warning("Health: ping a Redis falló; se reporta redis=down.")
            return "down"
        finally:
            # `aclose()` es la API vigente (redis 5.3); `close()` está deprecada. types-redis
            # 4.6 (pinneado) aún no la tipa, de ahí el ignore acotado.
            await client.aclose()  # type: ignore[attr-defined]


def get_db_probe() -> DependencyProbe:
    """Provider del probe de Postgres (o `not_configured` si falta `DATABASE_URL`)."""
    if not get_settings().database_url:
        return NotConfiguredProbe()
    return PostgresProbe()


def get_redis_probe() -> DependencyProbe:
    """Provider del probe de Redis (o `not_configured` si falta `REDIS_URL`)."""
    url = get_settings().redis_url
    if not url:
        return NotConfiguredProbe()
    return RedisProbe(url)


DbProbeDep = Annotated[DependencyProbe, Depends(get_db_probe)]
RedisProbeDep = Annotated[DependencyProbe, Depends(get_redis_probe)]


@router.get("/health", response_model=HealthDTO)
async def health(
    response: Response, db_probe: DbProbeDep, redis_probe: RedisProbeDep
) -> HealthDTO:
    """Estado del servicio y de sus dependencias (ping real, rápido y sin filtrar detalles)."""
    db = await db_probe.check()
    redis = await redis_probe.check()

    if "down" in (db, redis):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthDTO(status="degraded", db=db, redis=redis)

    return HealthDTO(status="ok", db=db, redis=redis)
