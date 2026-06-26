"""Tests de POST /api/v1/scans con source=repo (H5-T24, R2.5, R9.2).

Ejercita:
- Happy path: repo → installation token → contents → motor → 200 DTO.
- repo_id UUID inválido → 422 REPO_UNAVAILABLE (antes de tocar la red).
- repo_id no encontrado (no pertenece al usuario / instalación inactiva) → 422 REPO_UNAVAILABLE.
- Token de instalación no disponible (GitHub App no configurada) → 422 REPO_UNAVAILABLE.
- Archivo no existe en GitHub (FakeGitHubContentsClient con fail=True) → 422 REPO_UNAVAILABLE.
- Path traversal rechazado → 422 REPO_UNAVAILABLE (sin exponer la ruta original).
- El installation token NUNCA aparece en la respuesta ni en los logs.
- Persistencia: scan_repo.persist() llamado con repo_id correcto.
- origin=on_demand en el DTO persistido.

Los dobles sustituyen: motor (FakeScanServiceOK), repositorio de scans (FakeScanRepository),
instalaciones (FakeInstallationRepository), contents client (FakeGitHubContentsClient),
token client (FakeTokenClient), sesión/usuario (FakeUser + guards override).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi.testclient import TestClient
from slopguard.core import ScanReport, ScanSummary

from app.api.scans import (
    get_contents_client,
    get_installation_repository,
    get_scan_repository,
    get_scan_service,
    get_scan_token_client,
)
from app.auth.deps import get_session_store, get_user_repository
from app.auth.guard import require_user
from app.db.models import User
from app.github_app.contents_client import FakeGitHubContentsClient
from app.github_app.installation_repo import (
    FakeInstallationRepository,
    InstallationData,
    RepoData,
)
from app.github_app.token_client import InstallationTokenError
from app.main import create_app
from app.scans.scan_repo import FakeScanRepository
from tests.conftest import FakeSessionStore, FakeUser, FakeUserRepository

# ---------------------------------------------------------------------------
# Constantes de test
# ---------------------------------------------------------------------------

_USER_ID = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000002")
_ECOSYSTEM = "pypi"
_MANIFEST = "requests==2.28.0\n"

# installation_id de GitHub (entero) para el doble en memoria.
_GITHUB_INSTALLATION_ID = 999


# ---------------------------------------------------------------------------
# Dobles del Scan Service y token client
# ---------------------------------------------------------------------------


def _clean_report() -> ScanReport:
    return ScanReport(
        schema_version="1.2",
        tool_version="0.0.0-test",
        ecosystem=_ECOSYSTEM,
        summary=ScanSummary(
            total=1, allow=1, warn=0, block=0, unverifiable=0, exit_code=0
        ),
        results=(),
        error_category=None,
    )


class _FakeScanServiceOK:
    async def scan_text(self, content: str, *, ecosystem: str | None = None) -> ScanReport:
        return _clean_report()

    async def scan_path(self, path: Any, *, ecosystem: str | None = None) -> ScanReport:
        return _clean_report()

    def check_deps_count(self, count: int) -> None:
        pass

    wrapper_timeout_s: float = 5.0
    max_manifest_bytes: int = 5_000_000
    max_deps: int = 5000
    enable_layer4: bool = False


class _FakeTokenClientOK:
    """Token client que devuelve un token fijo sin llamar a GitHub."""

    FAKE_TOKEN = "ghs_FAKE_INSTALLATION_TOKEN_DO_NOT_LEAK"

    async def get_installation_token(self, installation_id: int) -> str:
        return self.FAKE_TOKEN


class _FakeTokenClientFail:
    """Token client que simula un fallo al obtener el token."""

    async def get_installation_token(self, installation_id: int) -> str:
        raise InstallationTokenError("token no disponible (doble de prueba).")


# ---------------------------------------------------------------------------
# Fixture de instalación
# ---------------------------------------------------------------------------


def _make_installation_repo_with_repo(
    user_id: uuid.UUID,
) -> tuple[FakeInstallationRepository, uuid.UUID]:
    """Crea un repositorio fake con una instalación activa y un repo.

    Devuelve (installation_repo, repo_internal_uuid).
    """
    inst_repo = FakeInstallationRepository()
    repo_data = RepoData(
        github_repo_id=12345,
        full_name="octocat/hello-world",
        private=False,
    )
    installation_data = InstallationData(
        installation_id=_GITHUB_INSTALLATION_ID,
        account_login="octocat",
        repos=(repo_data,),
    )

    import asyncio

    asyncio.run(inst_repo.upsert_installation(installation_data, user_id=user_id))

    # Obtener el UUID interno del repo recién insertado.
    repos = asyncio.run(inst_repo.list_repos_for_user(user_id))
    assert repos, "el repo debería estar en la instalación"
    return inst_repo, repos[0].id


# ---------------------------------------------------------------------------
# Helper: construye el TestClient con dependencias dobladas
# ---------------------------------------------------------------------------


def _make_client(
    *,
    installation_repo: FakeInstallationRepository | None = None,
    contents_client: FakeGitHubContentsClient | None = None,
    token_client: Any = None,
    scan_repo: FakeScanRepository | None = None,
    authenticated: bool = True,
) -> tuple[TestClient, FakeScanRepository, FakeInstallationRepository]:
    app = create_app()

    fake_scan_service = _FakeScanServiceOK()
    fake_scan_repo = scan_repo or FakeScanRepository()
    fake_inst_repo = installation_repo or FakeInstallationRepository()
    fake_contents = contents_client or FakeGitHubContentsClient(content=_MANIFEST)
    fake_token_client = token_client or _FakeTokenClientOK()
    fake_user_repo = FakeUserRepository()
    fake_session = FakeSessionStore()

    if authenticated:
        fake_user = FakeUser(_USER_ID)
        fake_user_repo.add_user(fake_user)
        async def _fake_require_user() -> User:
            return fake_user  # type: ignore[return-value]
        app.dependency_overrides[require_user] = _fake_require_user

    app.dependency_overrides[get_scan_service] = lambda: fake_scan_service
    app.dependency_overrides[get_scan_repository] = lambda: fake_scan_repo
    app.dependency_overrides[get_installation_repository] = lambda: fake_inst_repo
    app.dependency_overrides[get_contents_client] = lambda: fake_contents
    app.dependency_overrides[get_scan_token_client] = lambda: fake_token_client
    app.dependency_overrides[get_user_repository] = lambda: fake_user_repo
    app.dependency_overrides[get_session_store] = lambda: fake_session

    return TestClient(app, raise_server_exceptions=False), fake_scan_repo, fake_inst_repo


# ---------------------------------------------------------------------------
# Helpers de assertions
# ---------------------------------------------------------------------------


def _assert_error_shape(data: dict[str, Any]) -> None:
    assert "error" in data
    err = data["error"]
    assert "code" in err
    assert "message" in err
    assert "request_id" in err


def _assert_repo_unavailable(resp: Any) -> None:
    assert resp.status_code == 422
    data = resp.json()
    _assert_error_shape(data)
    assert data["error"]["code"] == "REPO_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Happy path: source=repo → 200 con ScanDTO
# ---------------------------------------------------------------------------


def test_source_repo_happy_path_returns_200() -> None:
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    client, _, _ = _make_client(installation_repo=inst_repo)
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    assert resp.status_code == 200


def test_source_repo_happy_path_has_scan_id() -> None:
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    client, _, _ = _make_client(installation_repo=inst_repo)
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    data = resp.json()
    uuid.UUID(data["scan_id"])  # válido → no lanza


def test_source_repo_happy_path_has_origin_on_demand() -> None:
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    client, _, _ = _make_client(installation_repo=inst_repo)
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    assert resp.json()["origin"] == "on_demand"


def test_source_repo_happy_path_no_report_raw() -> None:
    """El report crudo nunca viaja en el body de /scans (R4.3)."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    client, _, _ = _make_client(installation_repo=inst_repo)
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    data = resp.json()
    assert "report_raw" not in data
    assert "report_dict" not in data


def test_source_repo_persists_with_repo_id() -> None:
    """El scan se persiste con el repo_id interno correcto."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    scan_repo = FakeScanRepository()
    client, _, _ = _make_client(installation_repo=inst_repo, scan_repo=scan_repo)
    client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    assert scan_repo.persisted_count == 1
    assert scan_repo.last_call()["repo_id"] == repo_uuid


def test_source_repo_persists_user_id() -> None:
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    scan_repo = FakeScanRepository()
    client, _, _ = _make_client(installation_repo=inst_repo, scan_repo=scan_repo)
    client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    assert scan_repo.last_call()["user_id"] == _USER_ID


def test_source_repo_contents_called_with_correct_path() -> None:
    """El contents client recibe la ruta correcta (sin path traversal)."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    fake_contents = FakeGitHubContentsClient(content=_MANIFEST)
    client, _, _ = _make_client(installation_repo=inst_repo, contents_client=fake_contents)
    client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    assert len(fake_contents.fetch_calls) == 1
    assert fake_contents.fetch_calls[0]["path"] == "requirements.txt"
    assert fake_contents.fetch_calls[0]["full_name"] == "octocat/hello-world"


def test_source_repo_with_ref_passed_to_contents() -> None:
    """El `ref` se propaga al contents client."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    fake_contents = FakeGitHubContentsClient(content=_MANIFEST)
    client, _, _ = _make_client(installation_repo=inst_repo, contents_client=fake_contents)
    client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
            "ref": "develop",
        },
    )
    assert fake_contents.fetch_calls[0]["ref"] == "develop"


def test_source_repo_token_never_in_response() -> None:
    """El installation token no debe aparecer en ninguna respuesta (NFR-Seg-3)."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    client, _, _ = _make_client(installation_repo=inst_repo)
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    body_str = resp.text
    assert _FakeTokenClientOK.FAKE_TOKEN not in body_str


# ---------------------------------------------------------------------------
# Errores de validación → 422 REPO_UNAVAILABLE
# ---------------------------------------------------------------------------


def test_source_repo_invalid_uuid_returns_422() -> None:
    """repo_id que no es UUID válido → 422 REPO_UNAVAILABLE."""
    client, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": "not-a-uuid",
            "path": "requirements.txt",
        },
    )
    _assert_repo_unavailable(resp)


def test_source_repo_not_found_returns_422() -> None:
    """repo_id que no pertenece al usuario (inst. repo vacío) → 422 REPO_UNAVAILABLE."""
    client, _, _ = _make_client()  # inst_repo vacío: no hay repos
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(uuid.uuid4()),
            "path": "requirements.txt",
        },
    )
    _assert_repo_unavailable(resp)


def test_source_repo_revoked_installation_returns_422() -> None:
    """Instalación revocada → 422 REPO_UNAVAILABLE (aislamiento R5.3 + R2.4)."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)

    import asyncio
    asyncio.run(inst_repo.set_status(installation_id=_GITHUB_INSTALLATION_ID, status="revoked"))

    client, _, _ = _make_client(installation_repo=inst_repo)
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    _assert_repo_unavailable(resp)


def test_source_repo_token_failure_returns_422() -> None:
    """Fallo al obtener el installation token → 422 REPO_UNAVAILABLE."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    client, _, _ = _make_client(
        installation_repo=inst_repo,
        token_client=_FakeTokenClientFail(),
    )
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    _assert_repo_unavailable(resp)


def test_source_repo_file_not_found_returns_422() -> None:
    """Archivo ausente en GitHub → 422 REPO_UNAVAILABLE."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    failing_contents = FakeGitHubContentsClient(fail=True, fail_message="archivo no encontrado")
    client, _, _ = _make_client(
        installation_repo=inst_repo,
        contents_client=failing_contents,
    )
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    _assert_repo_unavailable(resp)


def test_source_repo_no_persist_on_token_failure() -> None:
    """Si falla el token, no se llama a persist (fail-closed en persistencia)."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    scan_repo = FakeScanRepository()
    client, _, _ = _make_client(
        installation_repo=inst_repo,
        token_client=_FakeTokenClientFail(),
        scan_repo=scan_repo,
    )
    client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    assert scan_repo.persisted_count == 0


def test_source_repo_no_persist_on_contents_failure() -> None:
    """Si falla la contents API, no se llama a persist."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    scan_repo = FakeScanRepository()
    failing_contents = FakeGitHubContentsClient(fail=True)
    client, _, _ = _make_client(
        installation_repo=inst_repo,
        contents_client=failing_contents,
        scan_repo=scan_repo,
    )
    client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    assert scan_repo.persisted_count == 0


def test_source_repo_error_has_stable_shape() -> None:
    """Errores de repo tienen la forma estable { error: { code, message, request_id } }."""
    client, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(uuid.uuid4()),
            "path": "requirements.txt",
        },
    )
    _assert_error_shape(resp.json())
    assert resp.json()["error"]["code"] == "REPO_UNAVAILABLE"


def test_source_repo_error_has_no_traceback() -> None:
    """Errores de repo no deben exponer traceback ni secretos (R9.2)."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    failing_contents = FakeGitHubContentsClient(fail=True)
    client, _, _ = _make_client(
        installation_repo=inst_repo,
        contents_client=failing_contents,
    )
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "requirements.txt",
        },
    )
    body_str = resp.text
    assert "Traceback" not in body_str
    assert "File \"" not in body_str


# ---------------------------------------------------------------------------
# Path confinement (anti path traversal)
# ---------------------------------------------------------------------------


def test_path_traversal_rejected() -> None:
    """Ruta con '..' rechazada antes de llegar a GitHub → 422 REPO_UNAVAILABLE."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    fake_contents = FakeGitHubContentsClient(content=_MANIFEST)
    client, _, _ = _make_client(installation_repo=inst_repo, contents_client=fake_contents)
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "../../etc/passwd",
        },
    )
    # El contents client no debe haber sido llamado (rechazo antes de la red).
    assert len(fake_contents.fetch_calls) == 0
    _assert_repo_unavailable(resp)


def test_path_traversal_nested_rejected() -> None:
    """Ruta con '..' anidado también se rechaza."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    fake_contents = FakeGitHubContentsClient(content=_MANIFEST)
    client, _, _ = _make_client(installation_repo=inst_repo, contents_client=fake_contents)
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "subdir/../../secret.txt",
        },
    )
    assert len(fake_contents.fetch_calls) == 0
    _assert_repo_unavailable(resp)


def test_valid_nested_path_accepted() -> None:
    """Una ruta válida anidada (sin '..') se acepta y llega al contents client."""
    inst_repo, repo_uuid = _make_installation_repo_with_repo(_USER_ID)
    fake_contents = FakeGitHubContentsClient(content=_MANIFEST)
    client, _, _ = _make_client(installation_repo=inst_repo, contents_client=fake_contents)
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(repo_uuid),
            "path": "backend/requirements.txt",
        },
    )
    assert resp.status_code == 200
    assert len(fake_contents.fetch_calls) == 1
    assert fake_contents.fetch_calls[0]["path"] == "backend/requirements.txt"
