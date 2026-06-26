"""Providers del worker: cola de jobs (Arq) inyectable en el webhook.

`get_job_queue` se inyecta en el router del webhook; en tests se sustituye por `InMemoryJobQueue`
vía `app.dependency_overrides`, así el ack 202 nunca depende de un Redis vivo en las pruebas.
La construcción NO falla sin Redis (lazy): solo el encolado real exige `redis_url`, y el webhook
captura ese fallo para no perder el ack (R9.3).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..settings import get_settings
from .jobs import PR_SCAN_TASK, JobQueue, PrScanJob

if TYPE_CHECKING:
    from arq import ArqRedis


class WorkerConfigError(RuntimeError):
    """No hay `redis_url` configurado para encolar (fail-closed en el momento del encolado)."""


class ArqJobQueue:
    """Cola real sobre Arq/Redis. El pool se crea perezosamente en el primer encolado."""

    def __init__(self, redis_url: str | None) -> None:
        self._redis_url = redis_url
        self._pool: ArqRedis | None = None

    async def enqueue_pr_scan(self, job: PrScanJob) -> None:
        if not self._redis_url:
            raise WorkerConfigError("redis_url no está configurado; no se puede encolar.")
        if self._pool is None:
            from arq import create_pool
            from arq.connections import RedisSettings

            self._pool = await create_pool(RedisSettings.from_dsn(self._redis_url))
        await self._pool.enqueue_job(PR_SCAN_TASK, job.model_dump())


def get_job_queue() -> JobQueue:
    """Provider de la cola para el webhook. No conecta a Redis hasta el primer encolado."""
    return ArqJobQueue(get_settings().redis_url)
