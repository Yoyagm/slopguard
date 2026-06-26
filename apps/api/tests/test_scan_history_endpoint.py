"""Tests de GET /api/v1/scans, GET /api/v1/scans/{id} y GET /api/v1/scans/{id}/raw (H5-T20).

Ejercita:
- GET /scans lista vacía → 200 con items=[] total=0.
- GET /scans con escaneos → devuelve items ordenados desc y paginados.
- GET /scans filtro ecosystem → solo los que coinciden.
- GET /scans/{id} → 200 con ScanDTO sin report_raw.
- GET /scans/{id} escaneo de otro usuario → 404 (no 403, R5.3).
- GET /scans/{id} inexistente → 404.
- GET /scans/{id}/raw → 200 con report_json crudo.
- GET /scans/{id}/raw otro usuario → 404 (R5.3).
- Sin sesión → 401 en todos los endpoints.

Los dobles son FakeScanRepository (en memoria) + FakeUser ya existentes en conftest.
"""

from __future__ import annotations

import asyncio
import datetime
import uuid
from typing import Any

from fastapi.testclient import TestClient

from app.api.scans import get_scan_repository, get_scan_service
from app.auth.deps import get_session_store, get_user_repository
from app.auth.guard import require_user
from app.db.models import User
from app.main import create_app
from app.scans.scan_repo import FakeScanRepository
from app.schemas.scan import ScanDTO, ScanSummaryDTO
from tests.conftest import FakeSessionStore, FakeUser, FakeUserRepository

# ---------------------------------------------------------------------------
# Constantes de prueba
# ---------------------------------------------------------------------------

_USER_A = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
_USER_B = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000002")
_ECOSYSTEM = "pypi"


def _minimal_summary() -> ScanSummaryDTO:
    return ScanSummaryDTO(
        total=1, allow=1, warn=0, block=0, unverifiable=0, llm_unavailable=0, exit_code=0
    )


def _make_dto(
    *,
    scan_id: uuid.UUID | None = None,
    ecosystem: str = _ECOSYSTEM,
    created_at: datetime.datetime | None = None,
) -> ScanDTO:
    """Construye un ScanDTO minimal para poblar el FakeScanRepository."""
    sid = scan_id or uuid.uuid4()
    ts = created_at or datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.UTC)
    report_dict = {
        "schema_version": "1.2",
        "tool_version": "0.0.0-test",
        "ecosystem": ecosystem,
        "error_category": None,
        "summary": {
            "total": 1,
            "allow": 1,
            "warn": 0,
            "block": 0,
            "unverifiable": 0,
            "llm_unavailable": 0,
            "exit_code": 0,
        },
        "results": [],
    }
    return ScanDTO(
        scan_id=sid,
        origin="on_demand",
        created_at=ts,
        schema_version="1.2",
        tool_version="0.0.0-test",
        ecosystem=ecosystem,
        error_category=None,
        summary=_minimal_summary(),
        results=[],
        report_dict=report_dict,
    )


def _seed(repo: FakeScanRepository, dto: ScanDTO, *, user_id: uuid.UUID) -> uuid.UUID:
    """Persiste un DTO en el FakeScanRepository (wrapper síncrono para tests sin loop)."""
    return asyncio.run(repo.persist(dto, user_id=user_id))


# ---------------------------------------------------------------------------
# Helpers de construcción de cliente
# ---------------------------------------------------------------------------


def _make_client(
    *,
    repo: FakeScanRepository | None = None,
    user_id: uuid.UUID = _USER_A,
    authenticated: bool = True,
) -> tuple[TestClient, FakeScanRepository]:
    """Construye un TestClient con dependencias dobladas para el histórico."""
    app = create_app()
    fake_repo = repo or FakeScanRepository()
    fake_user_repo = FakeUserRepository()
    fake_session = FakeSessionStore()

    # Doble del scan service (no se usa en GETs, pero el router lo requiere).
    class _NoopScanService:
        async def scan_text(self, content: str, *, ecosystem: str | None = None) -> Any:
            raise NotImplementedError  # pragma: no cover

        async def scan_path(self, path: Any, *, ecosystem: str | None = None) -> Any:
            raise NotImplementedError  # pragma: no cover

        def check_deps_count(self, count: int) -> None:
            pass  # pragma: no cover

        wrapper_timeout_s: float = 5.0
        max_manifest_bytes: int = 5_000_000
        max_deps: int = 5000
        enable_layer4: bool = False

    app.dependency_overrides[get_scan_service] = lambda: _NoopScanService()
    app.dependency_overrides[get_scan_repository] = lambda: fake_repo
    app.dependency_overrides[get_user_repository] = lambda: fake_user_repo
    app.dependency_overrides[get_session_store] = lambda: fake_session

    if authenticated:
        fake_user = FakeUser(user_id)
        fake_user_repo.add_user(fake_user)

        async def _fake_require_user() -> User:
            return fake_user  # type: ignore[return-value]

        app.dependency_overrides[require_user] = _fake_require_user

    return TestClient(app, raise_server_exceptions=False), fake_repo


# ---------------------------------------------------------------------------
# GET /scans — lista vacía
# ---------------------------------------------------------------------------


def test_list_scans_empty_returns_200() -> None:
    client, _ = _make_client()
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 200


def test_list_scans_empty_has_zero_items() -> None:
    client, _ = _make_client()
    data = client.get("/api/v1/scans").json()
    assert data["items"] == []
    assert data["total"] == 0


def test_list_scans_response_has_pagination_fields() -> None:
    client, _ = _make_client()
    data = client.get("/api/v1/scans").json()
    assert "page" in data
    assert "page_size" in data
    assert "total" in data
    assert "items" in data


# ---------------------------------------------------------------------------
# GET /scans — con escaneos persistidos
# ---------------------------------------------------------------------------


def test_list_scans_returns_persisted_items() -> None:
    repo = FakeScanRepository()
    _seed(repo, _make_dto(), user_id=_USER_A)

    client, _ = _make_client(repo=repo)
    data = client.get("/api/v1/scans").json()
    assert data["total"] == 1
    assert len(data["items"]) == 1


def test_list_scans_item_has_expected_fields() -> None:
    repo = FakeScanRepository()
    _seed(repo, _make_dto(), user_id=_USER_A)

    client, _ = _make_client(repo=repo)
    item = client.get("/api/v1/scans").json()["items"][0]
    assert "scan_id" in item
    assert "origin" in item
    assert "created_at" in item
    assert "ecosystem" in item
    assert "summary" in item
    # report_raw y results NO deben estar en el listado (payload liviano).
    assert "report_raw" not in item
    assert "results" not in item


def test_list_scans_item_has_no_report_raw() -> None:
    """El listado es payload liviano: no incluye report_raw (solo detalle en /scans/{id})."""
    repo = FakeScanRepository()
    _seed(repo, _make_dto(), user_id=_USER_A)

    client, _ = _make_client(repo=repo)
    item = client.get("/api/v1/scans").json()["items"][0]
    assert "report_raw" not in item


# ---------------------------------------------------------------------------
# GET /scans — filtro ecosystem
# ---------------------------------------------------------------------------


def test_list_scans_filter_ecosystem_returns_only_matching() -> None:
    repo = FakeScanRepository()
    _seed(repo, _make_dto(ecosystem="pypi"), user_id=_USER_A)
    _seed(repo, _make_dto(ecosystem="npm"), user_id=_USER_A)

    client, _ = _make_client(repo=repo)
    data = client.get("/api/v1/scans?ecosystem=pypi").json()
    assert data["total"] == 1
    assert data["items"][0]["ecosystem"] == "pypi"


# ---------------------------------------------------------------------------
# GET /scans — aislamiento por usuario (R5.3)
# ---------------------------------------------------------------------------


def test_list_scans_does_not_return_other_user_scans() -> None:
    """Un usuario solo ve sus propios escaneos (R5.3)."""
    repo = FakeScanRepository()
    # Persiste un escaneo para USER_B, consulta como USER_A.
    _seed(repo, _make_dto(), user_id=_USER_B)

    client, _ = _make_client(repo=repo, user_id=_USER_A)
    data = client.get("/api/v1/scans").json()
    assert data["total"] == 0
    assert data["items"] == []


# ---------------------------------------------------------------------------
# GET /scans/{id} — happy path
# ---------------------------------------------------------------------------


def test_get_scan_returns_200_for_own_scan() -> None:
    repo = FakeScanRepository()
    scan_id = _seed(repo, _make_dto(), user_id=_USER_A)

    client, _ = _make_client(repo=repo)
    resp = client.get(f"/api/v1/scans/{scan_id}")
    assert resp.status_code == 200


def test_get_scan_response_has_scan_id() -> None:
    repo = FakeScanRepository()
    scan_id = _seed(repo, _make_dto(), user_id=_USER_A)

    client, _ = _make_client(repo=repo)
    data = client.get(f"/api/v1/scans/{scan_id}").json()
    assert "scan_id" in data


def test_get_scan_response_has_no_report_raw() -> None:
    """Ni report_raw ni report_dict aparecen en el body de /scans/{id} (R4.3)."""
    repo = FakeScanRepository()
    scan_id = _seed(repo, _make_dto(), user_id=_USER_A)

    client, _ = _make_client(repo=repo)
    data = client.get(f"/api/v1/scans/{scan_id}").json()
    assert "report_raw" not in data
    assert "report_dict" not in data


def test_get_scan_response_has_results_and_summary() -> None:
    repo = FakeScanRepository()
    scan_id = _seed(repo, _make_dto(), user_id=_USER_A)

    client, _ = _make_client(repo=repo)
    data = client.get(f"/api/v1/scans/{scan_id}").json()
    assert "results" in data
    assert "summary" in data


# ---------------------------------------------------------------------------
# GET /scans/{id} — aislamiento R5.3: otro usuario → 404 (no 403)
# ---------------------------------------------------------------------------


def test_get_scan_other_user_returns_404_not_403() -> None:
    """Escaneo de USER_B visto como USER_A → 404, no 403 (R5.3: no filtramos existencia)."""
    repo = FakeScanRepository()
    scan_id = _seed(repo, _make_dto(), user_id=_USER_B)

    # Consulta como USER_A.
    client, _ = _make_client(repo=repo, user_id=_USER_A)
    resp = client.get(f"/api/v1/scans/{scan_id}")
    assert resp.status_code == 404
    # Forma de error estable.
    data = resp.json()
    assert "error" in data
    assert data["error"]["code"] == "SCAN_NOT_FOUND"


def test_get_scan_nonexistent_returns_404() -> None:
    client, _ = _make_client()
    resp = client.get(f"/api/v1/scans/{uuid.uuid4()}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /scans/{id}/raw — happy path
# ---------------------------------------------------------------------------


def test_get_scan_raw_returns_200() -> None:
    repo = FakeScanRepository()
    scan_id = _seed(repo, _make_dto(), user_id=_USER_A)

    client, _ = _make_client(repo=repo)
    resp = client.get(f"/api/v1/scans/{scan_id}/raw")
    assert resp.status_code == 200


def test_get_scan_raw_response_is_valid_json() -> None:
    repo = FakeScanRepository()
    scan_id = _seed(repo, _make_dto(), user_id=_USER_A)

    client, _ = _make_client(repo=repo)
    resp = client.get(f"/api/v1/scans/{scan_id}/raw")
    # El contenido debe ser parseable como JSON.
    data = resp.json()
    assert isinstance(data, dict)


def test_get_scan_raw_has_schema_version() -> None:
    repo = FakeScanRepository()
    scan_id = _seed(repo, _make_dto(), user_id=_USER_A)

    client, _ = _make_client(repo=repo)
    data = client.get(f"/api/v1/scans/{scan_id}/raw").json()
    assert data.get("schema_version") == "1.2"


# ---------------------------------------------------------------------------
# GET /scans/{id}/raw — aislamiento R5.3: otro usuario → 404
# ---------------------------------------------------------------------------


def test_get_scan_raw_other_user_returns_404() -> None:
    """report_json crudo de USER_B visto como USER_A → 404 (R5.3)."""
    repo = FakeScanRepository()
    scan_id = _seed(repo, _make_dto(), user_id=_USER_B)

    client, _ = _make_client(repo=repo, user_id=_USER_A)
    resp = client.get(f"/api/v1/scans/{scan_id}/raw")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_get_scan_raw_nonexistent_returns_404() -> None:
    client, _ = _make_client()
    resp = client.get(f"/api/v1/scans/{uuid.uuid4()}/raw")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Sin sesión → 401 en todos los endpoints (ADR-4)
# ---------------------------------------------------------------------------


def test_list_scans_without_session_returns_401() -> None:
    client, _ = _make_client(authenticated=False)
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 401


def test_get_scan_without_session_returns_401() -> None:
    client, _ = _make_client(authenticated=False)
    resp = client.get(f"/api/v1/scans/{uuid.uuid4()}")
    assert resp.status_code == 401


def test_get_scan_raw_without_session_returns_401() -> None:
    client, _ = _make_client(authenticated=False)
    resp = client.get(f"/api/v1/scans/{uuid.uuid4()}/raw")
    assert resp.status_code == 401
