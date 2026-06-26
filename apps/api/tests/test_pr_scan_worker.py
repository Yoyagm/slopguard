"""Aceptación del worker de escaneo de PR (`process_pr_scan`, Ola 5, R6.2-R6.6, ADR-2).

Ejercita la función PURA inyectable con dobles en memoria (sin Redis, sin Postgres, sin red).
Verifica el COMPORTAMIENTO observable: qué Check Run se publica, qué se persiste y la idempotencia
por `head_sha`. Mapea a los criterios EARS:

- R6.2: PR con manifiesto soportado ⇒ escanea, persiste con origin='pull_request' y publica check.
- R6.3 (no bloqueante): el `conclusion` SIEMPRE es success/neutral/failure (nunca `required`).
- R6.4: sin manifiestos soportados ⇒ check neutral "sin manifiestos", NO persiste.
- R6.5 (fail-closed): un manifiesto que no se puede bajar ⇒ UNVERIFIABLE, el check JAMÁS es success.
- R6.6 (idempotencia): reprocesar el MISMO head_sha upsertea check + comentario, no duplica.
- R2.4 (fail-closed): instalación no resoluble ⇒ no escanea ni publica nada.

Los dobles del token client y del scan service son LOCALES y triviales: el contrato real ya se
prueba en sus propios tests. `ScanService` es una dataclass concreta (no Protocol), así que el doble
se pasa con `cast` (estándar para inyectar un fake estructural donde se espera el tipo nominal).
"""

from __future__ import annotations

import uuid
from typing import cast

import pytest
from slopguard.core import ScanReport, ScanSummary

from app.github_app.contents_client import FakeGitHubContentsClient
from app.github_app.installation_repo import (
    FakeInstallationRepository,
    InstallationData,
    RepoData,
)
from app.scans.scan_repo import FakeScanRepository
from app.services.scan import ScanService
from app.worker.github_pr import (
    CONCLUSION_FAILURE,
    CONCLUSION_NEUTRAL,
    CONCLUSION_SUCCESS,
    FakeGitHubPrClient,
)
from app.worker.jobs import PrScanJob
from app.worker.pr_scan import process_pr_scan

# Identificadores fijos del PR bajo prueba. El Fake de instalaciones se siembra con estos.
_INSTALLATION_ID = 5050
_GITHUB_REPO_ID = 9100
_REPO_FULL_NAME = "octo-owner/api"
_PR_NUMBER = 11
_HEAD_SHA = "feedface00112233445566778899aabbccddeeff"
_ACCOUNT_LOGIN = "octo-owner"

# Conclusiones válidas de un Check Run informativo (R6.3: nunca `required`/bloqueante).
_NON_BLOCKING_CONCLUSIONS = frozenset(
    {CONCLUSION_SUCCESS, CONCLUSION_NEUTRAL, CONCLUSION_FAILURE}
)


# ---------------------------------------------------------------------------
# Dobles locales triviales (token + scan service)
# ---------------------------------------------------------------------------


class _FakeTokenClient:
    """Emite siempre un token de prueba (el contrato real vive en test_installation_token.py)."""

    async def get_installation_token(self, installation_id: int) -> str:
        return "tok"  # token sintético de prueba, no un secreto real


class _FakeScanService:
    """Devuelve un `ScanReport` fijo configurado por construcción (verdict controlado)."""

    def __init__(self, report: ScanReport) -> None:
        self._report = report

    async def scan_text(
        self, content: str, *, ecosystem: str | None = None
    ) -> ScanReport:
        return self._report


def _as_scan_service(fake: _FakeScanService) -> ScanService:
    """Adapta el doble estructural al tipo nominal esperado por `process_pr_scan` (mypy strict)."""
    return cast(ScanService, fake)


# ---------------------------------------------------------------------------
# Builders de ScanReport por veredicto (reusan el patrón de test_scan_dto.py)
# ---------------------------------------------------------------------------


def _summary(
    *,
    total: int = 1,
    allow: int = 0,
    warn: int = 0,
    block: int = 0,
    unverifiable: int = 0,
) -> ScanSummary:
    return ScanSummary(
        total=total,
        allow=allow,
        warn=warn,
        block=block,
        unverifiable=unverifiable,
        llm_unavailable=0,
        exit_code=0,
    )


def _report(summary: ScanSummary) -> ScanReport:
    """ScanReport mínimo schema 1.2 con el summary dado. results vacío: el veredicto vive ahí.

    El worker deriva el veredicto del PR del `summary` del DTO (block>0 ⇒ failure, warn o
    unverifiable ⇒ neutral, si no allow ⇒ success); el summary basta para fijar el resultado.
    """
    return ScanReport(
        schema_version="1.2",
        tool_version="0.8.0",
        ecosystem="pypi",
        summary=summary,
        results=(),
        error_category=None,
    )


def _allow_report() -> ScanReport:
    return _report(_summary(total=1, allow=1))


def _warn_report() -> ScanReport:
    return _report(_summary(total=1, warn=1))


def _block_report() -> ScanReport:
    return _report(_summary(total=1, block=1))


def _unverifiable_report() -> ScanReport:
    return _report(_summary(total=1, unverifiable=1))


# ---------------------------------------------------------------------------
# Fixtures de entorno: instalación sembrada + job + contents client
# ---------------------------------------------------------------------------


@pytest.fixture
async def installation_repo() -> FakeInstallationRepository:
    """Repo de instalaciones con la instalación del PR ya persistida (activa)."""
    repo = FakeInstallationRepository()
    await repo.upsert_installation(
        InstallationData(
            installation_id=_INSTALLATION_ID,
            account_login=_ACCOUNT_LOGIN,
            repos=(
                RepoData(
                    github_repo_id=_GITHUB_REPO_ID,
                    full_name=_REPO_FULL_NAME,
                    private=True,
                ),
            ),
        ),
        user_id=uuid.uuid4(),
    )
    return repo


@pytest.fixture
def job() -> PrScanJob:
    return PrScanJob(
        installation_id=_INSTALLATION_ID,
        repo_full_name=_REPO_FULL_NAME,
        github_repo_id=_GITHUB_REPO_ID,
        pr_number=_PR_NUMBER,
        head_sha=_HEAD_SHA,
    )


# ---------------------------------------------------------------------------
# (1) R6.2/R6.3 — manifiesto soportado: escanea, persiste y publica el check según el veredicto
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("report_factory", "expected_conclusion"),
    [
        (_allow_report, CONCLUSION_SUCCESS),
        (_warn_report, CONCLUSION_NEUTRAL),
        (_unverifiable_report, CONCLUSION_NEUTRAL),
        (_block_report, CONCLUSION_FAILURE),
    ],
)
async def test_manifiesto_soportado_escanea_persiste_y_publica_check(
    installation_repo: FakeInstallationRepository,
    job: PrScanJob,
    report_factory: object,
    expected_conclusion: str,
) -> None:
    """PR con requirements.txt ⇒ escanea, persiste origin='pull_request' y check por veredicto."""
    pr_client = FakeGitHubPrClient(files=["requirements.txt"])
    contents = FakeGitHubContentsClient(content="requests==2.28.0\n")
    scan_repo = FakeScanRepository()
    service = _FakeScanService(report_factory())  # type: ignore[operator]

    await process_pr_scan(
        job,
        token_client=_FakeTokenClient(),
        installation_repo=installation_repo,
        pr_client=pr_client,
        contents_client=contents,
        scan_service=_as_scan_service(service),
        scan_repo=scan_repo,
    )

    # Check Run publicado con la conclusión derivada del veredicto del report.
    check = pr_client.check_runs[(_REPO_FULL_NAME, _HEAD_SHA)]
    assert check["conclusion"] == expected_conclusion

    # Persistió EXACTAMENTE un scan con el origen y repo correctos.
    assert scan_repo.persisted_count == 1
    last = scan_repo.last_call()
    assert last["origin"] == "pull_request"
    assert last["pr_number"] == _PR_NUMBER
    assert last["head_sha"] == _HEAD_SHA
    # El repo_id persistido es el UUID interno que el Fake asignó al repo del PR.
    target = await installation_repo.resolve_pr_target(
        installation_id=_INSTALLATION_ID, github_repo_id=_GITHUB_REPO_ID
    )
    assert target is not None
    assert last["repo_id"] == target.repo_id


# ---------------------------------------------------------------------------
# (2) R6.4 — sin manifiestos soportados ⇒ check neutral "sin manifiestos", NO persiste
# ---------------------------------------------------------------------------


async def test_sin_manifiestos_soportados_check_neutral_y_no_persiste(
    installation_repo: FakeInstallationRepository, job: PrScanJob
) -> None:
    """Un PR que no cambia manifiestos ⇒ check neutral informativo y nada que persistir (R6.4)."""
    pr_client = FakeGitHubPrClient(files=["README.md"])
    contents = FakeGitHubContentsClient()
    scan_repo = FakeScanRepository()
    service = _FakeScanService(_allow_report())

    await process_pr_scan(
        job,
        token_client=_FakeTokenClient(),
        installation_repo=installation_repo,
        pr_client=pr_client,
        contents_client=contents,
        scan_service=_as_scan_service(service),
        scan_repo=scan_repo,
    )

    check = pr_client.check_runs[(_REPO_FULL_NAME, _HEAD_SHA)]
    assert check["conclusion"] == CONCLUSION_NEUTRAL
    assert "manifiesto" in check["summary"].lower()
    # No se persiste nada (no hubo escaneo) ni se comenta el PR.
    assert scan_repo.persisted_count == 0
    assert pr_client.comments == {}
    # Tampoco se contactó la contents API (no había qué bajar).
    assert contents.fetch_calls == []


# ---------------------------------------------------------------------------
# (3) TEST ESTRELLA — R6.6: idempotencia por head_sha (upsert, no duplica)
# ---------------------------------------------------------------------------


async def test_reprocesar_mismo_head_sha_es_idempotente(
    installation_repo: FakeInstallationRepository, job: PrScanJob
) -> None:
    """Reprocesar el MISMO head_sha upsertea: 1 sola entrada de check y 1 de comentario (R6.6).

    El `FakeGitHubPrClient` indexa check_runs/comments por (full_name, head_sha)/(full_name, pr),
    modelando el UPSERT real de GitHub. Dos pasadas con el mismo head_sha NO deben crear dos checks
    ni dos comentarios: deben SOBREESCRIBIR la misma clave.
    """
    pr_client = FakeGitHubPrClient(files=["requirements.txt"])
    contents = FakeGitHubContentsClient(content="requests==2.28.0\n")
    scan_repo = FakeScanRepository()
    service = _FakeScanService(_warn_report())

    async def _run() -> None:
        await process_pr_scan(
            job,
            token_client=_FakeTokenClient(),
            installation_repo=installation_repo,
            pr_client=pr_client,
            contents_client=contents,
            scan_service=_as_scan_service(service),
            scan_repo=scan_repo,
        )

    await _run()
    await _run()  # segunda entrega del MISMO head_sha

    # Idempotencia observable: una sola clave de check y una de comentario (upsert, no duplica).
    assert len(pr_client.check_runs) == 1
    assert (_REPO_FULL_NAME, _HEAD_SHA) in pr_client.check_runs
    assert len(pr_client.comments) == 1
    assert (_REPO_FULL_NAME, _PR_NUMBER) in pr_client.comments
    # Se invocó dos veces el upsert (reprocesamiento real), pero el estado final no se duplicó.
    assert pr_client.check_run_writes == 2
    assert pr_client.comment_writes == 2
    # La PERSISTENCIA también es idempotente: el índice único parcial (repo, pr, head_sha) hace
    # UPSERT, así que tras dos pasadas hay UNA sola fila de scan, no dos (regresión del MAJOR).
    assert scan_repo.persisted_count == 1


# ---------------------------------------------------------------------------
# (4) R6.5 — fail-closed: contents client falla ⇒ UNVERIFIABLE, el check JAMÁS es success
# ---------------------------------------------------------------------------


async def test_manifiesto_no_descargable_es_unverifiable_nunca_success(
    installation_repo: FakeInstallationRepository, job: PrScanJob
) -> None:
    """Si la contents API lanza RepoUnavailableError, el manifiesto es UNVERIFIABLE (fail-closed).

    Aunque el scan service devolvería 'allow' si se le invocara, el manifiesto nunca se baja, así
    que el outcome es UNVERIFIABLE y el check resultante NUNCA es success (R6.5: degradado != ok).
    """
    pr_client = FakeGitHubPrClient(files=["requirements.txt"])
    contents = FakeGitHubContentsClient(fail=True)  # toda bajada lanza RepoUnavailableError
    scan_repo = FakeScanRepository()
    # El service devolvería allow, pero nunca se le llama porque la bajada falla antes.
    service = _FakeScanService(_allow_report())

    await process_pr_scan(
        job,
        token_client=_FakeTokenClient(),
        installation_repo=installation_repo,
        pr_client=pr_client,
        contents_client=contents,
        scan_service=_as_scan_service(service),
        scan_repo=scan_repo,
    )

    check = pr_client.check_runs[(_REPO_FULL_NAME, _HEAD_SHA)]
    assert check["conclusion"] != CONCLUSION_SUCCESS  # jamás limpio si no se pudo verificar
    assert check["conclusion"] == CONCLUSION_NEUTRAL  # UNVERIFIABLE ⇒ neutral
    # Ningún manifiesto escaneable ⇒ no se persiste (no hay veredicto representativo).
    assert scan_repo.persisted_count == 0


# ---------------------------------------------------------------------------
# (5) R2.4 — instalación no resoluble ⇒ no escanea ni publica nada (fail-closed)
# ---------------------------------------------------------------------------


async def test_instalacion_no_resoluble_no_escanea_ni_publica(job: PrScanJob) -> None:
    """Sin instalación activa para el repo (resolve_pr_target None) ⇒ no toca nada (R2.4)."""
    empty_repo = FakeInstallationRepository()  # sin sembrar: resolve_pr_target devolverá None
    pr_client = FakeGitHubPrClient(files=["requirements.txt"])
    contents = FakeGitHubContentsClient(content="requests==2.28.0\n")
    scan_repo = FakeScanRepository()
    service = _FakeScanService(_allow_report())

    await process_pr_scan(
        job,
        token_client=_FakeTokenClient(),
        installation_repo=empty_repo,
        pr_client=pr_client,
        contents_client=contents,
        scan_service=_as_scan_service(service),
        scan_repo=scan_repo,
    )

    # Nada publicado, nada persistido, nada descargado: salida temprana fail-closed.
    assert pr_client.check_runs == {}
    assert pr_client.comments == {}
    assert pr_client.check_run_writes == 0
    assert scan_repo.persisted_count == 0
    assert contents.fetch_calls == []


# ---------------------------------------------------------------------------
# (6) R6.3 — no bloqueante: el conclusion publicado SIEMPRE es success/neutral/failure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "report_factory",
    [_allow_report, _warn_report, _unverifiable_report, _block_report],
)
async def test_conclusion_siempre_es_no_bloqueante(
    installation_repo: FakeInstallationRepository,
    job: PrScanJob,
    report_factory: object,
) -> None:
    """Sea cual sea el veredicto, el Check Run es informativo: jamás bloqueante (R6.3)."""
    pr_client = FakeGitHubPrClient(files=["requirements.txt"])
    contents = FakeGitHubContentsClient(content="requests==2.28.0\n")
    scan_repo = FakeScanRepository()
    service = _FakeScanService(report_factory())  # type: ignore[operator]

    await process_pr_scan(
        job,
        token_client=_FakeTokenClient(),
        installation_repo=installation_repo,
        pr_client=pr_client,
        contents_client=contents,
        scan_service=_as_scan_service(service),
        scan_repo=scan_repo,
    )

    conclusion = pr_client.check_runs[(_REPO_FULL_NAME, _HEAD_SHA)]["conclusion"]
    assert conclusion in _NON_BLOCKING_CONCLUSIONS
