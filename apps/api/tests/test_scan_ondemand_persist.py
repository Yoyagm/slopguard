"""Tests de POST /scans: persistencia on-demand + saneo de errores (H5-T21, R5.1/R9.2).

Refuerza el camino on-demand del test de aceptación base con foco en:
- Persistencia: el ScanDTO persistido lleva los resultados por dependencia (origen de las
  filas `scan_results`) y los metadatos correctos (origin, ecosystem, user_id) — R5.1.
- Round-trip: lo persistido es recuperable por su id para el mismo usuario (R5.1 + R5.3).
- Saneo de errores: TIMEOUT→504 y ENGINE_FAILURE→502 con mensaje saneado; el contenido del
  manifiesto (que puede traer secretos) JAMÁS aparece en la respuesta de error (R9.2,
  NFR-Seg-3), ni hay stacktrace.

Hermético: dobles en memoria del motor y del repositorio; sin Postgres/Redis/red.
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
from app.schemas.scan import ScanDTO
from app.services.scan import ScanErrorCategory, ScanServiceError
from tests.conftest import FakeSessionStore, FakeUser, FakeUserRepository

_USER = uuid.UUID("dddddddd-0000-0000-0000-00000000000d")
_ECOSYSTEM = "pypi"

# Aguja: un "secreto" embebido en el manifiesto que NUNCA debe salir en un error (R9.2).
_SECRET_IN_MANIFEST = "ghp_SECRET_TOKEN_INSIDE_MANIFEST_DO_NOT_LEAK_0xDEAD"


# ---------------------------------------------------------------------------
# Dobles del Scan Service
# ---------------------------------------------------------------------------


def _report_with_results() -> ScanReport:
    """Reporte con UNA dependencia: origen de una fila scan_results desnormalizada (R5.1)."""
    from slopguard.core import DependencyResult
    from slopguard.core.models import Status, Verdict

    dep = DependencyResult(
        name="requests",
        version_pin="2.28.0",
        status=Status.OK,
        verdict=Verdict.ALLOW,
        score=0,
        suspected_target=None,
        error_category=None,
        signals=(),
        advisories=(),
        llm_assessment=None,
    )
    return ScanReport(
        schema_version="1.2",
        tool_version="0.0.0-test",
        ecosystem=_ECOSYSTEM,
        summary=ScanSummary(
            total=1, allow=1, warn=0, block=0, unverifiable=0, exit_code=0
        ),
        results=(dep,),
        error_category=None,
    )


class _ScanServiceWithResults:
    """Doble del motor que devuelve un reporte con una dependencia."""

    async def scan_text(self, content: str, *, ecosystem: str | None = None) -> ScanReport:
        return _report_with_results()

    async def scan_path(self, path: Any, *, ecosystem: str | None = None) -> ScanReport:
        return _report_with_results()  # pragma: no cover

    def check_deps_count(self, count: int) -> None:
        pass

    wrapper_timeout_s: float = 5.0
    max_manifest_bytes: int = 5_000_000
    max_deps: int = 5000
    enable_layer4: bool = False


class _ScanServiceSanitizedError:
    """Doble que recibe el contenido (posiblemente con secretos) y lanza un error SANEADO.

    Modela el contrato real de `ScanService`: el mensaje del `ScanServiceError` JAMÁS
    incluye el contenido del manifiesto. Verifica que el router no re-introduce el secreto.
    """

    def __init__(self, category: ScanErrorCategory) -> None:
        self._category = category
        self.received_content: str | None = None

    async def scan_text(self, content: str, *, ecosystem: str | None = None) -> ScanReport:
        self.received_content = content  # capturamos lo recibido para afirmar que llegó
        raise ScanServiceError("el escaneo falló (mensaje saneado)", self._category)

    async def scan_path(self, path: Any, *, ecosystem: str | None = None) -> ScanReport:
        # pragma: no cover — el camino repo no se ejercita aquí (source=inline).
        raise ScanServiceError("el escaneo falló (mensaje saneado)", self._category)

    def check_deps_count(self, count: int) -> None:
        pass

    wrapper_timeout_s: float = 5.0
    max_manifest_bytes: int = 5_000_000
    max_deps: int = 5000
    enable_layer4: bool = False


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _make_client(
    *, scan_service: Any, repo: FakeScanRepository | None = None
) -> tuple[TestClient, FakeScanRepository]:
    app = create_app()
    fake_repo = repo or FakeScanRepository()
    fake_user = FakeUser(_USER)
    fake_user_repo = FakeUserRepository()
    fake_user_repo.add_user(fake_user)

    async def _require_user() -> User:
        return fake_user  # type: ignore[return-value]

    app.dependency_overrides[get_scan_service] = lambda: scan_service
    app.dependency_overrides[get_scan_repository] = lambda: fake_repo
    app.dependency_overrides[get_user_repository] = lambda: fake_user_repo
    app.dependency_overrides[get_session_store] = lambda: FakeSessionStore()
    app.dependency_overrides[require_user] = _require_user
    return TestClient(app, raise_server_exceptions=False), fake_repo


# ---------------------------------------------------------------------------
# Persistencia: el DTO persistido lleva resultados + metadatos (R5.1)
# ---------------------------------------------------------------------------


def test_persisted_dto_carries_dependency_results() -> None:
    """El DTO persistido incluye los resultados por dependencia (origen de scan_results, R5.1)."""
    # Arrange.
    client, repo = _make_client(scan_service=_ScanServiceWithResults())

    # Act.
    client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )

    # Assert: se persistió exactamente un escaneo con una dependencia.
    assert repo.persisted_count == 1
    persisted_dto = repo.last_call()["dto"]
    assert isinstance(persisted_dto, ScanDTO)
    assert len(persisted_dto.results) == 1
    assert persisted_dto.results[0].name == "requests"


def test_persisted_dto_has_on_demand_origin_and_ecosystem() -> None:
    """El escaneo persistido lleva origin=on_demand y el ecosistema correcto (R5.1)."""
    # Arrange.
    client, repo = _make_client(scan_service=_ScanServiceWithResults())

    # Act.
    client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )

    # Assert.
    persisted_dto = repo.last_call()["dto"]
    assert isinstance(persisted_dto, ScanDTO)
    assert persisted_dto.origin == "on_demand"
    assert persisted_dto.ecosystem == _ECOSYSTEM
    assert repo.last_call()["user_id"] == _USER


def test_scan_is_retrievable_after_post_for_owner() -> None:
    """Round-trip: tras POST, el dueño recupera el escaneo por el id devuelto (R5.1 + R5.3).

    Contrato endurecido: la persistencia genera el scan_id autoritativo y re-sella el DTO,
    así que el `scan_id` del body del detalle es IDÉNTICO al id de la URL — tanto en el
    SqlScanRepository (reconstruye desde la fila ORM) como en el FakeScanRepository
    (paridad de contrato). Ya no existe la "deuda del fake".
    """
    # Arrange.
    client, _repo = _make_client(scan_service=_ScanServiceWithResults())

    # Act: creamos y luego leemos su detalle por el id devuelto en la respuesta.
    created = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    ).json()
    scan_id = created["scan_id"]
    detail = client.get(f"/api/v1/scans/{scan_id}")

    # Assert: el detalle existe para el dueño y trae la dependencia escaneada.
    assert detail.status_code == 200
    body = detail.json()
    assert body["results"][0]["name"] == "requests"
    assert "report_raw" not in body  # el raw nunca viaja en el detalle (R4.3)
    assert "report_dict" not in body  # tampoco el reporte crudo como dict (R4.3)
    # Igualdad estricta del scan_id: el id del body coincide con el de la URL (= el devuelto).
    assert body["scan_id"] == scan_id


def test_post_returns_authoritative_persisted_scan_id() -> None:
    """El scan_id de la respuesta del POST es el id autoritativo de la persistencia.

    El placeholder que el router pasa a persist() se ignora: el id que persist() genera y
    devuelve es el que aparece en el body y bajo el cual el escaneo queda almacenado.
    """
    # Arrange.
    client, repo = _make_client(scan_service=_ScanServiceWithResults())

    # Act.
    created = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    ).json()

    # Assert: el id del body es exactamente el devuelto por persist() (el de last_call).
    persisted_id = repo.last_call()["scan_id"]
    assert created["scan_id"] == str(persisted_id)
    # Y el DTO almacenado quedó re-sellado con ese mismo id (sin divergencia interna).
    stored_dto = repo.last_call()["dto"]
    assert isinstance(stored_dto, ScanDTO)
    assert str(stored_dto.scan_id) == created["scan_id"]


def test_created_scan_appears_in_owner_history() -> None:
    """Tras POST, el escaneo aparece en el histórico del dueño (R5.1 + R5.2)."""
    # Arrange.
    client, _repo = _make_client(scan_service=_ScanServiceWithResults())

    # Act.
    client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "requests==2.28.0\n"},
    )
    history = client.get("/api/v1/scans").json()

    # Assert.
    assert history["total"] == 1
    assert len(history["items"]) == 1


# ---------------------------------------------------------------------------
# Saneo de errores: TIMEOUT→504 / ENGINE_FAILURE→502 sin fuga de secretos (R9.2)
# ---------------------------------------------------------------------------


def test_timeout_maps_to_504() -> None:
    """ScanServiceError TIMEOUT → 504 con código estable (R9.2)."""
    # Arrange.
    service = _ScanServiceSanitizedError(ScanErrorCategory.TIMEOUT)
    client, _ = _make_client(scan_service=service)

    # Act.
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "x==1\n"},
    )

    # Assert.
    assert resp.status_code == 504
    assert resp.json()["error"]["code"] == "SCAN_TIMEOUT"


def test_engine_failure_maps_to_502() -> None:
    """ScanServiceError ENGINE_FAILURE → 502 con código estable (R9.2)."""
    # Arrange.
    service = _ScanServiceSanitizedError(ScanErrorCategory.ENGINE_FAILURE)
    client, _ = _make_client(scan_service=service)

    # Act.
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "x==1\n"},
    )

    # Assert.
    assert resp.status_code == 502
    assert resp.json()["error"]["code"] == "SCAN_ENGINE_FAILURE"


def test_error_response_does_not_leak_manifest_secret() -> None:
    """El secreto embebido en el manifiesto NO aparece en la respuesta de error (R9.2)."""
    # Arrange: el manifiesto contiene un token sensible.
    service = _ScanServiceSanitizedError(ScanErrorCategory.ENGINE_FAILURE)
    client, _ = _make_client(scan_service=service)
    manifest = f"requests==2.28.0  # {_SECRET_IN_MANIFEST}\n"

    # Act.
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": manifest},
    )

    # Assert: el contenido llegó al servicio, pero el secreto no se filtró a la respuesta.
    assert service.received_content == manifest
    assert _SECRET_IN_MANIFEST not in resp.text


def test_error_response_has_no_stacktrace() -> None:
    """La respuesta de error no expone stacktrace ni rutas de archivo (R9.2)."""
    # Arrange.
    service = _ScanServiceSanitizedError(ScanErrorCategory.ENGINE_FAILURE)
    client, _ = _make_client(scan_service=service)

    # Act.
    resp = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "x==1\n"},
    )

    # Assert.
    body = resp.text
    assert "Traceback" not in body
    assert 'File "' not in body


def test_error_response_keeps_stable_shape() -> None:
    """El cuerpo de error mantiene la forma { error: { code, message, request_id } } (R9.2)."""
    # Arrange.
    service = _ScanServiceSanitizedError(ScanErrorCategory.TIMEOUT)
    client, _ = _make_client(scan_service=service)

    # Act.
    err = client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "x==1\n"},
    ).json()["error"]

    # Assert.
    assert set(err.keys()) == {"code", "message", "request_id"}


def test_error_does_not_persist_anything() -> None:
    """Si el motor falla, no se persiste ningún escaneo (fail-closed en persistencia, R5.1)."""
    # Arrange.
    service = _ScanServiceSanitizedError(ScanErrorCategory.TIMEOUT)
    client, repo = _make_client(scan_service=service)

    # Act.
    client.post(
        "/api/v1/scans",
        json={"source": "inline", "content": "x==1\n"},
    )

    # Assert: no hay veredicto que guardar.
    assert repo.persisted_count == 0
