"""Cableado del worker Arq (ADR-2). SOLO conecta `process_pr_scan` con las impls reales.

Toda la lógica vive en `pr_scan.process_pr_scan` (pura, testeada con fakes). Aquí no hay reglas de
negocio: este módulo solo existe para que `arq worker app.worker.main.WorkerSettings` arranque el
consumidor. No se ejecuta en el gate (necesita Redis/Arq vivos).
"""

from __future__ import annotations

from typing import Any, ClassVar

from ..api.scans import get_scan_repository, get_scan_service
from ..github_app.contents_client import HttpxGitHubContentsClient
from ..github_app.deps import get_github_app_token_client, get_installation_repository
from ..settings import get_settings
from .github_pr import HttpxGitHubPrClient
from .jobs import PrScanJob
from .pr_scan import process_pr_scan


async def run_pr_scan(ctx: dict[str, Any], job_data: dict[str, Any]) -> None:
    """Tarea Arq: reconstruye el job y delega en la lógica pura con las impls reales."""
    job = PrScanJob.model_validate(job_data)
    await process_pr_scan(
        job,
        token_client=get_github_app_token_client(),
        installation_repo=get_installation_repository(),
        pr_client=HttpxGitHubPrClient(),
        contents_client=HttpxGitHubContentsClient(),
        scan_service=get_scan_service(),
        scan_repo=get_scan_repository(),
    )


def _redis_settings() -> Any:
    """RedisSettings de Arq desde `redis_url` (o el default localhost si no está configurado)."""
    from arq.connections import RedisSettings

    redis_url = get_settings().redis_url
    return RedisSettings.from_dsn(redis_url) if redis_url else RedisSettings()


class WorkerSettings:
    """Configuración que `arq` descubre. `functions` registra la tarea por su `__name__`."""

    functions: ClassVar = [run_pr_scan]
    redis_settings: ClassVar = _redis_settings()
