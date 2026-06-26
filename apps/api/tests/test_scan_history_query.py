"""Tests de orden, paginación y filtros del histórico GET /scans (H5-T21, R5.2).

Refuerza las dimensiones de la consulta del histórico que el test de aceptación base no
cubre en profundidad:
- Orden created_at DESC (más reciente primero), criterio explícito de R5.2.
- Paginación: page/page_size, página parcial final, página fuera de rango.
- Filtro repo_id (además del de ecosystem ya cubierto en test_scan_history_endpoint).

Hermético: dobles en memoria, sin Postgres/Redis/red. El filtro `repo_id` usa directamente
el `FakeScanRepository` de producción, que ahora honra el filtro por repo (paridad de
contrato con el `SqlScanRepository`); ya no se necesita un doble local a tests/.
"""

from __future__ import annotations

import asyncio
import datetime
import uuid

from fastapi.testclient import TestClient

from app.api.scans import get_scan_repository, get_scan_service
from app.auth.deps import get_session_store, get_user_repository
from app.auth.guard import require_user
from app.db.models import User
from app.main import create_app
from app.scans.scan_repo import FakeScanRepository
from app.schemas.scan import ScanDTO, ScanSummaryDTO
from tests.conftest import FakeSessionStore, FakeUser, FakeUserRepository

_USER = uuid.UUID("cccccccc-0000-0000-0000-00000000000c")


# ---------------------------------------------------------------------------
# Factoría de DTOs
# ---------------------------------------------------------------------------


def _summary() -> ScanSummaryDTO:
    return ScanSummaryDTO(
        total=0, allow=0, warn=0, block=0, unverifiable=0, llm_unavailable=0, exit_code=0
    )


def _make_dto(
    *,
    scan_id: uuid.UUID | None = None,
    ecosystem: str = "pypi",
    created_at: datetime.datetime | None = None,
) -> ScanDTO:
    sid = scan_id or uuid.uuid4()
    ts = created_at or datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.UTC)
    report_dict = {
        "schema_version": "1.2",
        "tool_version": "0.0.0-test",
        "ecosystem": ecosystem,
        "error_category": None,
        "summary": {
            "total": 0,
            "allow": 0,
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
        summary=_summary(),
        results=[],
        report_dict=report_dict,
    )


def _ts(day: int) -> datetime.datetime:
    """Timestamp determinista (sin reloj real → sin flakiness por tiempo)."""
    return datetime.datetime(2026, 1, day, 0, 0, 0, tzinfo=datetime.UTC)


# ---------------------------------------------------------------------------
# Cliente con repositorio inyectable
# ---------------------------------------------------------------------------


def _make_client(repo: object) -> TestClient:
    """TestClient autenticado con el repositorio dado y un scan service que no se usa."""
    app = create_app()
    fake_user = FakeUser(_USER)
    fake_user_repo = FakeUserRepository()
    fake_user_repo.add_user(fake_user)

    async def _require_user() -> User:
        return fake_user  # type: ignore[return-value]

    class _UnusedScanService:
        async def scan_text(self, content: str, *, ecosystem: str | None = None) -> object:
            raise AssertionError("scan_text no debe invocarse en tests de listado")

    app.dependency_overrides[get_scan_repository] = lambda: repo
    app.dependency_overrides[get_scan_service] = lambda: _UnusedScanService()
    app.dependency_overrides[get_user_repository] = lambda: fake_user_repo
    app.dependency_overrides[get_session_store] = lambda: FakeSessionStore()
    app.dependency_overrides[require_user] = _require_user
    return TestClient(app, raise_server_exceptions=False)


def _seed(repo: FakeScanRepository, dto: ScanDTO) -> uuid.UUID:
    return asyncio.run(repo.persist(dto, user_id=_USER))


# ---------------------------------------------------------------------------
# Orden created_at DESC (R5.2: más reciente primero)
# ---------------------------------------------------------------------------


def test_list_orders_by_created_at_descending() -> None:
    """Tres escaneos en orden de inserción arbitrario → listado por fecha DESC (R5.2)."""
    # Arrange: insertamos en orden NO cronológico para forzar el ordenamiento real.
    repo = FakeScanRepository()
    _seed(repo, _make_dto(created_at=_ts(2)))  # medio
    _seed(repo, _make_dto(created_at=_ts(3)))  # más reciente
    _seed(repo, _make_dto(created_at=_ts(1)))  # más antiguo

    # Act.
    client = _make_client(repo)
    items = client.get("/api/v1/scans").json()["items"]

    # Assert: created_at estrictamente descendente.
    timestamps = [item["created_at"] for item in items]
    assert timestamps == sorted(timestamps, reverse=True)
    # El primero es el del día 3 (el más reciente).
    assert timestamps[0].startswith("2026-01-03")
    assert timestamps[-1].startswith("2026-01-01")


# ---------------------------------------------------------------------------
# Paginación
# ---------------------------------------------------------------------------


def test_pagination_first_page_limits_items_and_reports_total() -> None:
    """page=1&page_size=2 sobre 5 escaneos → 2 items pero total=5 (R5.2)."""
    # Arrange.
    repo = FakeScanRepository()
    for day in range(1, 6):
        _seed(repo, _make_dto(created_at=_ts(day)))

    # Act.
    client = _make_client(repo)
    data = client.get("/api/v1/scans?page=1&page_size=2").json()

    # Assert: la página trae 2, pero el total refleja los 5 existentes.
    assert len(data["items"]) == 2
    assert data["total"] == 5
    assert data["page"] == 1
    assert data["page_size"] == 2


def test_pagination_second_page_continues_without_overlap() -> None:
    """page=2 continúa donde acabó page=1, sin repetir elementos (R5.2)."""
    # Arrange: 5 escaneos con fechas distintas.
    repo = FakeScanRepository()
    for day in range(1, 6):
        _seed(repo, _make_dto(created_at=_ts(day)))

    # Act.
    client = _make_client(repo)
    page1 = client.get("/api/v1/scans?page=1&page_size=2").json()["items"]
    page2 = client.get("/api/v1/scans?page=2&page_size=2").json()["items"]

    # Assert: sin solape entre páginas (ids disjuntos).
    ids_page1 = {item["scan_id"] for item in page1}
    ids_page2 = {item["scan_id"] for item in page2}
    assert ids_page1.isdisjoint(ids_page2)
    assert len(page2) == 2


def test_pagination_last_partial_page_returns_remainder() -> None:
    """Última página parcial: 5 elementos, page_size=2, page=3 → 1 elemento (R5.2)."""
    # Arrange.
    repo = FakeScanRepository()
    for day in range(1, 6):
        _seed(repo, _make_dto(created_at=_ts(day)))

    # Act.
    client = _make_client(repo)
    data = client.get("/api/v1/scans?page=3&page_size=2").json()

    # Assert: solo queda 1 elemento en la tercera página.
    assert len(data["items"]) == 1
    assert data["total"] == 5


def test_pagination_out_of_range_page_is_empty_but_total_preserved() -> None:
    """Página fuera de rango → items vacíos, pero total sigue informando el conteo real."""
    # Arrange.
    repo = FakeScanRepository()
    for day in range(1, 4):
        _seed(repo, _make_dto(created_at=_ts(day)))

    # Act: pedimos una página muy más allá del final.
    client = _make_client(repo)
    data = client.get("/api/v1/scans?page=99&page_size=10").json()

    # Assert: sin items, pero el total no miente.
    assert data["items"] == []
    assert data["total"] == 3


def test_pagination_rejects_page_below_one() -> None:
    """page<1 viola la cota de validación de FastAPI (ge=1) → 422."""
    # Arrange.
    repo = FakeScanRepository()
    _seed(repo, _make_dto())

    # Act.
    client = _make_client(repo)
    resp = client.get("/api/v1/scans?page=0")

    # Assert: FastAPI valida la query y rechaza.
    assert resp.status_code == 422


def test_pagination_rejects_page_size_above_max() -> None:
    """page_size>100 viola la cota le=100 → 422."""
    # Arrange.
    repo = FakeScanRepository()
    _seed(repo, _make_dto())

    # Act.
    client = _make_client(repo)
    resp = client.get("/api/v1/scans?page_size=101")

    # Assert.
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Filtro repo_id — FakeScanRepository de producción (ahora honra repo_id, paridad SQL)
# ---------------------------------------------------------------------------


def _seed_with_repo(
    repo: FakeScanRepository, dto: ScanDTO, *, repo_id: uuid.UUID | None
) -> uuid.UUID:
    """Persiste un DTO con su repo_id y devuelve el scan_id autoritativo de persist()."""
    return asyncio.run(repo.persist(dto, user_id=_USER, repo_id=repo_id))


def test_filter_repo_id_returns_only_scans_of_that_repo() -> None:
    """repo_id filtra el listado a los escaneos de ese repo (R5.2)."""
    # Arrange: dos repos del mismo usuario.
    repo_one = uuid.uuid4()
    repo_two = uuid.uuid4()
    store = FakeScanRepository()
    id_in_repo_one = _seed_with_repo(store, _make_dto(), repo_id=repo_one)
    _seed_with_repo(store, _make_dto(), repo_id=repo_two)
    _seed_with_repo(store, _make_dto(), repo_id=None)  # on-demand sin repo

    # Act.
    client = _make_client(store)
    data = client.get(f"/api/v1/scans?repo_id={repo_one}").json()

    # Assert: solo el escaneo de repo_one (con el id autoritativo persistido).
    assert data["total"] == 1
    assert data["items"][0]["scan_id"] == str(id_in_repo_one)


def test_filter_repo_id_and_ecosystem_combine() -> None:
    """repo_id + ecosystem se combinan (AND) en el filtro (R5.2)."""
    # Arrange.
    repo_target = uuid.uuid4()
    store = FakeScanRepository()
    expected_id = _seed_with_repo(
        store, _make_dto(ecosystem="pypi"), repo_id=repo_target
    )
    _seed_with_repo(store, _make_dto(ecosystem="npm"), repo_id=repo_target)
    _seed_with_repo(store, _make_dto(ecosystem="pypi"), repo_id=uuid.uuid4())

    # Act.
    client = _make_client(store)
    data = client.get(f"/api/v1/scans?repo_id={repo_target}&ecosystem=pypi").json()

    # Assert: solo el pypi del repo objetivo.
    assert data["total"] == 1
    assert data["items"][0]["scan_id"] == str(expected_id)


def test_filter_repo_id_with_invalid_uuid_returns_422() -> None:
    """repo_id no-UUID viola la validación de tipo del query param → 422."""
    # Arrange.
    store = FakeScanRepository()
    _seed_with_repo(store, _make_dto(), repo_id=uuid.uuid4())

    # Act.
    client = _make_client(store)
    resp = client.get("/api/v1/scans?repo_id=not-a-uuid")

    # Assert: FastAPI rechaza el parseo del UUID.
    assert resp.status_code == 422


def test_filter_invalid_ecosystem_returns_422_not_empty_page() -> None:
    """ecosystem fuera de la allowlist (pypi|npm) → 422, no una página vacía (R5.2)."""
    # Arrange.
    store = FakeScanRepository()
    _seed_with_repo(store, _make_dto(ecosystem="pypi"), repo_id=None)

    # Act.
    client = _make_client(store)
    resp = client.get("/api/v1/scans?ecosystem=cargo")

    # Assert: la allowlist del query param rechaza el valor fuera de dominio.
    assert resp.status_code == 422
