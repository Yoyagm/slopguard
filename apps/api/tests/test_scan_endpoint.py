"""Tests de `POST /api/v1/scans` (H5-T19, R3.1, R5.1, R9.2).

Ejercita:
- Happy path: inline → escaneo → DTO persistido → 200 sin report_raw.
- Validación de campos: source inválido, content ausente → 422 con forma estable.
- source=repo → 422 con código REPO_SOURCE_NOT_IMPLEMENTED (documentado, T24).
- Errores del motor: INVALID_INPUT → 422, TIMEOUT → 504, ENGINE_FAILURE → 502.
- Forma de error estable: { error: { code, message, request_id } }.
- `report_raw` NUNCA viaja en el body principal (R4.3).
- Persistencia: ScanRepository.persist() llamado con user_id correcto.
- Sin sesión → 401 del guard.

Los dobles sustituyen: motor (FakeScanService), repositorio (FakeScanRepository),
sesión/usuario (FakeUser + FakeSessionStore + FakeUserRepository).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi.testclient import TestClient
from slopguard.core import ScanReport, ScanSummary

from app.api.scans import get_scan_repository, get_scan_service
from app.auth.deps import get_session_store, get_user_repository
from app.auth.guard import require_user
from app.db.models import User
from app.main import create_app
from app.scans.scan_repo import FakeScanRepository
from app.services.scan import ScanErrorCategory, ScanServiceError
from tests.conftest import FakeSessionStore, FakeUser, FakeUserRepository

# ---------------------------------------------------------------------------
# Dobles del Scan Service
# ---------------------------------------------------------------------------

_FAKE_USER_ID = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
_ECOSYSTEM = "pypi"


def _clean_report() -> ScanReport:
    """Reporte minimal allow para happy-path."""
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


class FakeScanServiceOK:
    """Doble que devuelve un reporte limpio sin llamar al motor."""

    async def scan_text(self, content: str, *, ecosystem: str | None = None) -> ScanReport:
        return _clean_report()

    async def scan_path(self, path: Any, *, ecosystem: str | None = None) -> ScanReport:
        return _clean_report()

    def check_deps_count(self, count: int) -> None:
        pass

    # Atributos que satisfacen el dataclass (no se usan en tests pero mypy los puede ver)
    wrapper_timeout_s: float = 5.0
    max_manifest_bytes: int = 5_000_000
    max_deps: int = 5000
    enable_layer4: bool = False


class FakeScanServiceError:
    """Doble que lanza un ScanServiceError con la categoría dada."""

    def __init__(self, category: ScanErrorCategory) -> None:
        self._category = category

    async def scan_text(self, content: str, *, ecosystem: str | None = None) -> ScanReport:
        raise ScanServiceError("error saneado de prueba", self._category)

    async def scan_path(self, path: Any, *, ecosystem: str | None = None) -> ScanReport:
        raise ScanServiceError("error saneado de prueba", self._category)

    def check_deps_count(self, count: int) -> None:
        pass

    wrapper_timeout_s: float = 5.0
    max_manifest_bytes: int = 5_000_000
    max_deps: int = 5000
    enable_layer4: bool = False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_client(
    *,
    scan_service: Any = None,
    scan_repo: FakeScanRepository | None = None,
    authenticated: bool = True,
) -> tuple[TestClient, FakeScanRepository, FakeUserRepository, FakeUser | None]:
    """Construye un TestClient con dependencias dobladas.

    Devuelve (client, repo, user_repo, fake_user) para que los tests puedan
    inspeccionar lo que se persistió y el usuario que se resolvió.
    """
    app = create_app()

    fake_scan_service = scan_service or FakeScanServiceOK()
    fake_repo = scan_repo or FakeScanRepository()
    fake_user_repo = FakeUserRepository()
    fake_session = FakeSessionStore()
    fake_user: FakeUser | None = None

    if authenticated:
        fake_user = FakeUser(_FAKE_USER_ID)
        fake_user_repo.add_user(fake_user)

    app.dependency_overrides[get_scan_service] = lambda: fake_scan_service
    app.dependency_overrides[get_scan_repository] = lambda: fake_repo
    app.dependency_overrides[get_user_repository] = lambda: fake_user_repo
    app.dependency_overrides[get_session_store] = lambda: fake_session

    if authenticated and fake_user is not None:
        # Inyectamos el user directamente en require_user para no pasar por la cookie.
        async def _fake_require_user() -> User:
            return fake_user  # type: ignore[return-value]

        app.dependency_overrides[require_user] = _fake_require_user

    return TestClient(app, raise_server_exceptions=False), fake_repo, fake_user_repo, fake_user


# ---------------------------------------------------------------------------
# Happy path: inline → 200 con ScanDTO sin report_raw
# ---------------------------------------------------------------------------


def test_post_scan_inline_returns_200() -> None:
    client, _repo, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )
    assert resp.status_code == 200


def test_post_scan_inline_response_has_scan_id() -> None:
    client, _, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )
    data = resp.json()
    assert "scan_id" in data
    # Es un UUID válido
    uuid.UUID(data["scan_id"])


def test_post_scan_inline_response_has_no_report_raw() -> None:
    """Ni report_raw ni report_dict (el reporte crudo) viajan en el body de /scans (R4.3)."""
    client, _, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )
    data = resp.json()
    assert "report_raw" not in data
    assert "report_dict" not in data


def test_post_scan_inline_response_has_summary_and_results() -> None:
    client, _, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )
    data = resp.json()
    assert "summary" in data
    assert "results" in data
    assert "exit_code" in data["summary"]


def test_post_scan_inline_response_has_origin_on_demand() -> None:
    client, _, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )
    assert resp.json()["origin"] == "on_demand"


def test_post_scan_inline_response_has_ecosystem() -> None:
    client, _, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )
    assert resp.json()["ecosystem"] == _ECOSYSTEM


# ---------------------------------------------------------------------------
# Persistencia: ScanRepository.persist llamado con user_id correcto (R5.1)
# ---------------------------------------------------------------------------


def test_post_scan_persists_with_correct_user_id() -> None:
    client, repo, _, _ = _make_client()
    client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )
    assert repo.persisted_count == 1
    assert repo.last_call()["user_id"] == _FAKE_USER_ID


def test_post_scan_persists_origin_on_demand() -> None:
    client, repo, _, _ = _make_client()
    client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )
    assert repo.last_call()["origin"] == "on_demand"


def test_post_scan_persists_repo_id_none_for_inline() -> None:
    client, repo, _, _ = _make_client()
    client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )
    assert repo.last_call()["repo_id"] is None


# ---------------------------------------------------------------------------
# Validación de entrada → 422 con forma estable (R9.2)
# ---------------------------------------------------------------------------


def _assert_error_shape(data: dict[str, Any]) -> None:
    """Verifica la forma estable de error { error: { code, message, request_id } }."""
    assert "error" in data
    err = data["error"]
    assert "code" in err
    assert "message" in err
    assert "request_id" in err


def test_invalid_source_returns_422() -> None:
    client, _, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={"source": "clipboard"},
    )
    assert resp.status_code == 422
    _assert_error_shape(resp.json())


def test_inline_without_content_returns_422() -> None:
    client, _, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline"},
    )
    assert resp.status_code == 422
    _assert_error_shape(resp.json())


def test_inline_with_empty_content_returns_422() -> None:
    client, _, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": ""},
    )
    assert resp.status_code == 422
    _assert_error_shape(resp.json())


def test_repo_without_repo_id_returns_422() -> None:
    client, _, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={"source": "repo", "path": "requirements.txt"},
    )
    assert resp.status_code == 422
    _assert_error_shape(resp.json())


def test_repo_without_path_returns_422() -> None:
    client, _, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={"source": "repo", "repo_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 422
    _assert_error_shape(resp.json())


def test_invalid_ecosystem_returns_422_without_invoking_engine() -> None:
    """ecosystem fuera de la allowlist (pypi|npm) → 422 por validación del schema.

    El rechazo ocurre ANTES de tocar el motor: el doble del servicio lanzaría si lo
    invocaran, así que un 422 limpio confirma que ni siquiera se llamó.
    """
    client, repo, _, _ = _make_client(
        scan_service=FakeScanServiceError(ScanErrorCategory.ENGINE_FAILURE)
    )
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n", "ecosystem": "cargo"},
    )
    assert resp.status_code == 422
    assert repo.persisted_count == 0


# ---------------------------------------------------------------------------
# source=repo → 422 documentado (T24)
# ---------------------------------------------------------------------------


def test_source_repo_returns_422_not_implemented() -> None:
    client, _, _, _ = _make_client()
    resp = client.post(
        "/api/v1/scans",
        json={
            "source": "repo",
            "repo_id": str(uuid.uuid4()),
            "path": "requirements.txt",
        },
    )
    assert resp.status_code == 422
    data = resp.json()
    _assert_error_shape(data)
    assert data["error"]["code"] == "REPO_SOURCE_NOT_IMPLEMENTED"


# ---------------------------------------------------------------------------
# Errores del motor → códigos HTTP saneados (R9.2)
# ---------------------------------------------------------------------------


def test_engine_invalid_input_returns_422() -> None:
    client, _, _, _ = _make_client(
        scan_service=FakeScanServiceError(ScanErrorCategory.INVALID_INPUT)
    )
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "x==1\n"},
    )
    assert resp.status_code == 422
    data = resp.json()
    _assert_error_shape(data)
    assert data["error"]["code"] == "SCAN_INVALID_INPUT"


def test_engine_timeout_returns_504() -> None:
    client, _, _, _ = _make_client(
        scan_service=FakeScanServiceError(ScanErrorCategory.TIMEOUT)
    )
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "x==1\n"},
    )
    assert resp.status_code == 504
    data = resp.json()
    _assert_error_shape(data)
    assert data["error"]["code"] == "SCAN_TIMEOUT"


def test_engine_failure_returns_502() -> None:
    client, _, _, _ = _make_client(
        scan_service=FakeScanServiceError(ScanErrorCategory.ENGINE_FAILURE)
    )
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "x==1\n"},
    )
    assert resp.status_code == 502
    data = resp.json()
    _assert_error_shape(data)
    assert data["error"]["code"] == "SCAN_ENGINE_FAILURE"


# ---------------------------------------------------------------------------
# Error no persiste cuando el motor falla (fail-closed en persistencia)
# ---------------------------------------------------------------------------


def test_engine_error_does_not_persist(
) -> None:
    """Si el motor falla, no debe haber llamada a persist (no hay veredicto que guardar)."""
    client, repo, _, _ = _make_client(
        scan_service=FakeScanServiceError(ScanErrorCategory.ENGINE_FAILURE)
    )
    client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "x==1\n"},
    )
    assert repo.persisted_count == 0


# ---------------------------------------------------------------------------
# Sin sesión → 401 del guard (ADR-4)
# ---------------------------------------------------------------------------


def test_post_scan_without_session_returns_401() -> None:
    client, _, _, _ = _make_client(authenticated=False)
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# La forma de error nunca expone stacktrace ni secretos (R9.2)
# ---------------------------------------------------------------------------


def test_error_response_has_no_traceback_in_message() -> None:
    client, _, _, _ = _make_client(
        scan_service=FakeScanServiceError(ScanErrorCategory.ENGINE_FAILURE)
    )
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "x==1\n"},
    )
    body_str = resp.text
    # No debe haber traceback ni palabras de stacktrace crudo
    assert "Traceback" not in body_str
    assert "File \"" not in body_str
