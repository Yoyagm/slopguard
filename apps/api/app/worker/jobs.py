"""Modelo del job de escaneo de PR y la abstracción de cola (R6.1/R9.3, ADR-2).

`JobQueue` es un `Protocol` inyectable: en producción se usa `ArqJobQueue` (Redis), en tests
`InMemoryJobQueue` (sin red). El webhook solo conoce el `Protocol`, así que el ack 202 nunca
depende de un Redis vivo en las pruebas.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict

# Nombre de la tarea Arq que el worker registra (ver `worker.main`). Compartido por la cola real.
PR_SCAN_TASK = "run_pr_scan"


class PrScanJob(BaseModel):
    """Datos mínimos para que el worker resuelva todo el escaneo de un PR.

    Inmutable: una vez encolado, el job no cambia. El worker re-resuelve el installation token,
    el diff y los manifiestos a partir de estos identificadores (no se confía en payloads gordos).
    """

    model_config = ConfigDict(frozen=True)

    installation_id: int  # ID de GitHub App (entero) para obtener el installation token.
    repo_full_name: str  # "owner/repo" — usado en la PR files / contents API.
    github_repo_id: int  # ID numérico del repo en GitHub (para resolver el repo interno).
    pr_number: int
    head_sha: str  # SHA del head del PR: clave de idempotencia (repo, pr, head_sha).


class JobQueue(Protocol):
    """Contrato de encolado. La impl real encola en Arq/Redis; el fake guarda en memoria."""

    async def enqueue_pr_scan(self, job: PrScanJob) -> None:
        """Encola un escaneo de PR para procesamiento asíncrono. No bloquea el ack del webhook."""
        ...


class InMemoryJobQueue:
    """Cola de pruebas: acumula los jobs encolados sin tocar Redis (determinista)."""

    def __init__(self) -> None:
        self._jobs: list[PrScanJob] = []

    async def enqueue_pr_scan(self, job: PrScanJob) -> None:
        self._jobs.append(job)

    @property
    def jobs(self) -> list[PrScanJob]:
        """Jobs encolados, en orden (para aserciones en tests)."""
        return list(self._jobs)
