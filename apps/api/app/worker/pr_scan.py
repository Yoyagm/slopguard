"""Lógica del escaneo de PR (R6.2-R6.6, ADR-2). Función PURA inyectable, testeable sin Redis/Arq.

`process_pr_scan` recibe todas sus colaboraciones como dependencias (clientes/repos inyectables),
así el worker Arq (`worker.main`) solo la CABLEA con las impls reales y los tests la ejercitan con
fakes. Invariantes de seguridad: fail-closed (un manifiesto que no se puede bajar/escanear cuenta
como UNVERIFIABLE, JAMÁS limpio) y no bloqueante (el Check Run nunca es `required`).
"""

from __future__ import annotations

import datetime
import logging
import uuid
from dataclasses import dataclass

from ..github_app.contents_client import GitHubContentsClient, RepoUnavailableError
from ..github_app.installation_repo import InstallationRepository
from ..github_app.token_client import GitHubAppTokenClient, InstallationTokenError
from ..scans.scan_repo import ScanRepository
from ..schemas.scan import ScanDTO
from ..services.scan import ScanService, ScanServiceError
from ..services.scan_mapper import scan_report_to_dto
from .github_pr import (
    CONCLUSION_FAILURE,
    CONCLUSION_NEUTRAL,
    CONCLUSION_SUCCESS,
    GitHubPrClient,
    PrApiError,
)
from .jobs import PrScanJob
from .manifests import supported_manifests

logger = logging.getLogger(__name__)

_PLACEHOLDER_SCAN_ID = uuid.UUID(int=0)
_ORIGIN_PR = "pull_request"

# Tope anti-DoS: un PR con un número desorbitado de manifiestos no debe amplificar el trabajo del
# worker ni la cuota de la GitHub API sin límite. Los manifiestos que excedan cuentan como
# UNVERIFIABLE (fail-closed: el resultado nunca queda "limpio" por haberlos ignorado).
_MAX_MANIFESTS_PER_PR = 20

# Rango de severidad para agregar el peor veredicto entre manifiestos.
_RANK_ALLOW = 0
_RANK_UNVERIFIABLE = 1
_RANK_WARN = 2
_RANK_BLOCK = 3

# Exit code que el motor (`aggregate_exit_code`) asigna a un error-report degradado
# (manifiesto no parseable, fallo de dataset/adaptador…): veredicto NO concluyente.
_ENGINE_ERROR_EXIT_CODE = 3


@dataclass(frozen=True, slots=True)
class ManifestOutcome:
    """Resultado de un manifiesto del PR: su DTO (si se escaneó) o el motivo de no-verificable."""

    path: str
    dto: ScanDTO | None  # None ⇒ no se pudo bajar/escanear ⇒ UNVERIFIABLE.


def _dto_rank(dto: ScanDTO) -> int:
    """Severidad de un DTO a partir de su summary. UNVERIFIABLE nunca colapsa a allow (R6 §118)."""
    summary = dto.summary
    if summary.block > 0:
        return _RANK_BLOCK
    if summary.warn > 0:
        return _RANK_WARN
    # Fail-closed: un error-report del motor (manifiesto no parseable, fallo de dataset/adaptador…)
    # llega con `error_category` poblado y summary en ceros — un resultado NO concluyente que JAMÁS
    # debe pintarse "limpio" (allow → check verde). Se espeja `aggregate_exit_code` del motor
    # (error_category ⇒ exit 3): degrada a UNVERIFIABLE como mínimo, igual que un manifiesto que
    # no se pudo bajar. Sin esto, un `requirements.txt` con `>=` o un `package.json` malformado
    # pintaban el PR en verde sin escanearse (fail-open).
    if (
        summary.unverifiable > 0
        or dto.error_category is not None
        or summary.exit_code == _ENGINE_ERROR_EXIT_CODE
    ):
        return _RANK_UNVERIFIABLE
    return _RANK_ALLOW


def _outcome_rank(outcome: ManifestOutcome) -> int:
    # Un manifiesto que no se pudo escanear es UNVERIFIABLE (nunca limpio).
    return _RANK_UNVERIFIABLE if outcome.dto is None else _dto_rank(outcome.dto)


def _rank_to_conclusion(rank: int) -> str:
    """allow→success, warn/unverifiable→neutral, block→failure (R6.2; nunca bloqueante, R6.3)."""
    if rank >= _RANK_BLOCK:
        return CONCLUSION_FAILURE
    if rank == _RANK_ALLOW:
        return CONCLUSION_SUCCESS
    return CONCLUSION_NEUTRAL


def _summarize_outcome(outcome: ManifestOutcome) -> str:
    """Una línea del comentario: solo nombre del manifiesto + veredicto (sin exponer contenido)."""
    if outcome.dto is None:
        return f"- `{outcome.path}` — no verificable (UNVERIFIABLE)"
    if outcome.dto.error_category is not None:
        # El motor no pudo escanear el manifiesto (p.ej. no parseable): no verificable, no "limpio".
        # `error_category` es un código fijo del motor, no contenido del manifiesto (sin fuga).
        return f"- `{outcome.path}` — no verificable (error: {outcome.dto.error_category})"
    s = outcome.dto.summary
    return (
        f"- `{outcome.path}` — {s.total} deps · "
        f"allow {s.allow} / warn {s.warn} / block {s.block} / unverifiable {s.unverifiable}"
    )


def _build_comment(outcomes: list[ManifestOutcome], conclusion: str) -> str:
    """Comentario resumen (Markdown). Solo nombres de manifiestos y conteos, nunca el manifiesto."""
    lines = [
        "**SlopGuard** escaneó los manifiestos cambiados en este PR (check informativo):",
        "",
        *[_summarize_outcome(o) for o in outcomes],
        "",
        f"Resultado global: **{conclusion}**.",
    ]
    return "\n".join(lines)


async def process_pr_scan(
    job: PrScanJob,
    *,
    token_client: GitHubAppTokenClient,
    installation_repo: InstallationRepository,
    pr_client: GitHubPrClient,
    contents_client: GitHubContentsClient,
    scan_service: ScanService,
    scan_repo: ScanRepository,
) -> None:
    """Procesa un PR: baja los manifiestos del diff, escanea, publica check + comentario y persiste.

    Idempotente por (repo, pr_number, head_sha): la persistencia hace UPSERT por el índice único
    parcial y el check/comentario también se upsertan, así reprocesar el mismo head_sha no duplica.
    """
    target = await installation_repo.resolve_pr_target(
        installation_id=job.installation_id, github_repo_id=job.github_repo_id
    )
    if target is None:
        # Instalación revocada/desconocida o repo sin acceso: no escaneamos (fail-closed, R2.4).
        logger.warning(
            "PR scan ignorado: sin instalación activa para repo %s.", job.github_repo_id
        )
        return

    try:
        token = await token_client.get_installation_token(job.installation_id)
    except InstallationTokenError:
        logger.warning("PR scan abortado: no se pudo obtener el installation token.")
        return

    try:
        changed = await pr_client.list_pr_files(
            token=token, full_name=target.full_name, pr_number=job.pr_number
        )
    except (PrApiError, RepoUnavailableError):
        logger.warning("PR scan abortado: no se pudo leer el diff del PR.")
        return

    manifests = supported_manifests(changed)
    if not manifests:
        # Sin manifiestos soportados ⇒ check neutral sin ruido (R6.4); no se persiste ni comenta.
        await pr_client.upsert_check_run(
            token=token,
            full_name=target.full_name,
            head_sha=job.head_sha,
            conclusion=CONCLUSION_NEUTRAL,
            title="Sin manifiestos que revisar",
            summary="El PR no cambia manifiestos de dependencias soportados.",
        )
        return

    outcomes = await _scan_manifests(
        manifests, job=job, token=token, target_full_name=target.full_name,
        contents_client=contents_client, scan_service=scan_service,
    )
    conclusion = _rank_to_conclusion(max(_outcome_rank(o) for o in outcomes))
    comment = _build_comment(outcomes, conclusion)

    await _persist_worst(
        outcomes,
        job=job,
        target_user_id=target.user_id,
        target_repo_id=target.repo_id,
        scan_repo=scan_repo,
    )
    await pr_client.upsert_check_run(
        token=token,
        full_name=target.full_name,
        head_sha=job.head_sha,
        conclusion=conclusion,
        title=f"SlopGuard: {conclusion}",
        summary=comment,
    )
    await pr_client.upsert_comment(
        token=token,
        full_name=target.full_name,
        pr_number=job.pr_number,
        body=comment,
    )


async def _scan_manifests(
    manifests: list[tuple[str, str]],
    *,
    job: PrScanJob,
    token: str,
    target_full_name: str,
    contents_client: GitHubContentsClient,
    scan_service: ScanService,
) -> list[ManifestOutcome]:
    """Escanea cada manifiesto @ head_sha. Un fallo de bajada/escaneo ⇒ outcome UNVERIFIABLE.

    Aplica un tope (`_MAX_MANIFESTS_PER_PR`): los manifiestos que excedan no se bajan ni escanean
    (no amplificamos trabajo ni cuota de API), pero se reportan como UNVERIFIABLE para no dar un
    veredicto limpio ignorándolos (fail-closed).
    """
    outcomes: list[ManifestOutcome] = []
    created_at = datetime.datetime.now(tz=datetime.UTC)
    to_scan = manifests[:_MAX_MANIFESTS_PER_PR]
    overflow = manifests[_MAX_MANIFESTS_PER_PR:]
    for path, ecosystem in to_scan:
        try:
            content = await contents_client.fetch_manifest(
                token=token, full_name=target_full_name, path=path, ref=job.head_sha
            )
            report = await scan_service.scan_text(content, ecosystem=ecosystem)
        except (RepoUnavailableError, ScanServiceError):
            logger.info("Manifiesto %s no verificable en el PR (fail-closed).", path)
            outcomes.append(ManifestOutcome(path=path, dto=None))
            continue
        dto = scan_report_to_dto(
            report, scan_id=_PLACEHOLDER_SCAN_ID, origin=_ORIGIN_PR, created_at=created_at
        )
        outcomes.append(ManifestOutcome(path=path, dto=dto))
    if overflow:
        logger.warning(
            "PR con %d manifiestos; se escanean %d y el resto queda UNVERIFIABLE (tope anti-DoS).",
            len(manifests),
            _MAX_MANIFESTS_PER_PR,
        )
        outcomes.extend(ManifestOutcome(path=path, dto=None) for path, _ in overflow)
    return outcomes


async def _persist_worst(
    outcomes: list[ManifestOutcome],
    *,
    job: PrScanJob,
    target_user_id: uuid.UUID,
    target_repo_id: uuid.UUID,
    scan_repo: ScanRepository,
) -> None:
    """Persiste el escaneo del manifiesto con peor veredicto (idempotente por head_sha).

    El esquema persiste UN scan por (repo, pr, head_sha) (índice único parcial), así que se guarda
    el manifiesto más severo como representativo del PR. Si ninguno se pudo escanear, no persiste.
    """
    scannable = [o for o in outcomes if o.dto is not None]
    if not scannable:
        return
    worst = max(scannable, key=_outcome_rank)
    assert worst.dto is not None  # noqa: S101 — garantizado por el filtro anterior (ayuda a mypy).
    await scan_repo.persist(
        worst.dto,
        user_id=target_user_id,
        repo_id=target_repo_id,
        origin=_ORIGIN_PR,
        pr_number=job.pr_number,
        head_sha=job.head_sha,
    )
