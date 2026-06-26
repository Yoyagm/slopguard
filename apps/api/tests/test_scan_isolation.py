"""Tests de AISLAMIENTO cross-user del histórico de escaneos (H5-T21, R5.3).

Este es el test ESTRELLA de la tarea: verifica la propiedad de seguridad multi-tenant
"cada escaneo se expone SOLO a su propietario" (R5.3). El usuario B nunca debe ver, listar
ni acceder a los escaneos del usuario A —y el SaaS responde 404 (no 403) para no filtrar
existencia—.

Estrategia de doblado (hermético, sin Postgres/Redis/red):
- Un ÚNICO `FakeScanRepository` compartido entre los dos usuarios: A y B escriben/leen el
  mismo almacén, igual que comparten la tabla `scans` en producción. El aislamiento debe
  venir del filtro `user_id`, NO de tener repos separados (eso ocultaría una fuga real).
- Un override de `require_user` conmutable: `_ActiveUser` apunta al usuario "logueado" en
  cada momento, de modo que un mismo cliente puede actuar como A y luego como B contra el
  mismo grafo de dependencias (mismo `app`), simulando dos sesiones distintas.

Patrón AAA en cada test. Asserts sobre comportamiento observable (status + cuerpo), nunca
sobre detalles internos del repositorio.
"""

from __future__ import annotations

import asyncio
import datetime
import uuid
from dataclasses import dataclass

from fastapi.testclient import TestClient

from app.api.scans import get_scan_repository, get_scan_service
from app.auth.deps import get_session_store, get_user_repository
from app.auth.guard import require_user
from app.db.models import User
from app.main import create_app
from app.scans.scan_repo import FakeScanRepository
from app.schemas.scan import ScanDTO, ScanSummaryDTO
from tests.conftest import FakeSessionStore, FakeUser, FakeUserRepository

# Dos identidades fijas y distinguibles. UUID con prefijo legible para diagnósticos claros.
_USER_A = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
_USER_B = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")


# ---------------------------------------------------------------------------
# Harness de dos usuarios sobre un repositorio compartido
# ---------------------------------------------------------------------------


@dataclass
class _ActiveUser:
    """Puntero mutable al usuario "logueado" en el momento de cada request.

    Permite que un único `TestClient` actúe como A o como B sin reconstruir la app:
    el override de `require_user` lee SIEMPRE este puntero, así que basta con cambiarlo
    entre requests para simular sesiones distintas contra el mismo repositorio compartido.
    """

    user: FakeUser


class _TwoUserHarness:
    """Encapsula app + cliente + repo compartido + conmutador de usuario activo."""

    def __init__(self) -> None:
        self.repo = FakeScanRepository()
        self._user_a = FakeUser(_USER_A, login="alice")
        self._user_b = FakeUser(_USER_B, login="bob")
        self._active = _ActiveUser(user=self._user_a)

        app = create_app()

        fake_user_repo = FakeUserRepository()
        fake_user_repo.add_user(self._user_a)
        fake_user_repo.add_user(self._user_b)

        async def _require_active_user() -> User:
            # Resuelve el usuario actualmente "logueado" (conmutable por los tests).
            return self._active.user  # type: ignore[return-value]

        app.dependency_overrides[get_scan_repository] = lambda: self.repo
        app.dependency_overrides[get_scan_service] = _unused_scan_service
        app.dependency_overrides[get_user_repository] = lambda: fake_user_repo
        app.dependency_overrides[get_session_store] = lambda: FakeSessionStore()
        app.dependency_overrides[require_user] = _require_active_user

        self.client = TestClient(app, raise_server_exceptions=False)

    def act_as_a(self) -> None:
        self._active.user = self._user_a

    def act_as_b(self) -> None:
        self._active.user = self._user_b

    def seed_for_a(self, dto: ScanDTO) -> uuid.UUID:
        return asyncio.run(self.repo.persist(dto, user_id=_USER_A))

    def seed_for_b(self, dto: ScanDTO) -> uuid.UUID:
        return asyncio.run(self.repo.persist(dto, user_id=_USER_B))


def _unused_scan_service() -> object:
    """Provider del scan service que NO debe invocarse en los tests de aislamiento (solo GETs).

    Si algún GET intentara escanear, esto explotaría y delataría una regresión de rutas.
    """

    class _Boom:
        async def scan_text(self, content: str, *, ecosystem: str | None = None) -> object:
            raise AssertionError("scan_text no debe invocarse en tests de aislamiento")

    return _Boom()


# ---------------------------------------------------------------------------
# Factoría de DTOs de prueba
# ---------------------------------------------------------------------------


def _summary() -> ScanSummaryDTO:
    return ScanSummaryDTO(
        total=1, allow=1, warn=0, block=0, unverifiable=0, llm_unavailable=0, exit_code=0
    )


def _make_dto(
    *,
    ecosystem: str = "pypi",
    created_at: datetime.datetime | None = None,
) -> ScanDTO:
    """Construye un ScanDTO minimal (sin secretos) para poblar el repo compartido."""
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
        scan_id=uuid.uuid4(),
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


# ---------------------------------------------------------------------------
# GET /scans — el listado nunca cruza usuarios (R5.3)
# ---------------------------------------------------------------------------


def test_list_returns_only_own_scans_when_both_users_have_scans() -> None:
    """Con A y B poblados en el MISMO repo, cada uno lista solo lo suyo (R5.3)."""
    # Arrange: A tiene 2 escaneos, B tiene 3 — todos en el mismo almacén.
    harness = _TwoUserHarness()
    for _ in range(2):
        harness.seed_for_a(_make_dto())
    for _ in range(3):
        harness.seed_for_b(_make_dto())

    # Act + Assert: A ve 2.
    harness.act_as_a()
    data_a = harness.client.get("/api/v1/scans").json()
    assert data_a["total"] == 2
    assert len(data_a["items"]) == 2

    # Act + Assert: B ve 3 (mismo cliente, usuario conmutado).
    harness.act_as_b()
    data_b = harness.client.get("/api/v1/scans").json()
    assert data_b["total"] == 3
    assert len(data_b["items"]) == 3


def test_list_for_b_excludes_every_scan_id_belonging_to_a() -> None:
    """Ningún scan_id de A aparece en el listado de B (aislamiento estricto, R5.3)."""
    # Arrange.
    harness = _TwoUserHarness()
    id_a1 = harness.seed_for_a(_make_dto())
    id_a2 = harness.seed_for_a(_make_dto())
    harness.seed_for_b(_make_dto())

    # Act.
    harness.act_as_b()
    items_b = harness.client.get("/api/v1/scans").json()["items"]

    # Assert: los ids de A no se filtran al listado de B.
    seen_ids = {item["scan_id"] for item in items_b}
    assert str(id_a1) not in seen_ids
    assert str(id_a2) not in seen_ids


def test_list_for_user_without_scans_is_empty_even_if_others_have_scans() -> None:
    """B no tiene escaneos: su listado es vacío aunque A tenga muchos (estado vacío + R5.3)."""
    # Arrange: solo A tiene escaneos.
    harness = _TwoUserHarness()
    for _ in range(5):
        harness.seed_for_a(_make_dto())

    # Act: B consulta su histórico.
    harness.act_as_b()
    data_b = harness.client.get("/api/v1/scans").json()

    # Assert: estado vacío para B.
    assert data_b["total"] == 0
    assert data_b["items"] == []


# ---------------------------------------------------------------------------
# GET /scans/{id} — acceder al detalle de otro usuario → 404 (no 403)
# ---------------------------------------------------------------------------


def test_get_detail_of_a_scan_as_b_returns_404_not_403() -> None:
    """B no puede abrir el detalle de un escaneo de A: 404, jamás 403 (R5.3)."""
    # Arrange: el escaneo pertenece a A.
    harness = _TwoUserHarness()
    scan_id = harness.seed_for_a(_make_dto())

    # Act: B intenta abrirlo.
    harness.act_as_b()
    resp = harness.client.get(f"/api/v1/scans/{scan_id}")

    # Assert: 404 con forma de error estable. 403 filtraría que el recurso existe.
    assert resp.status_code == 404
    assert resp.status_code != 403
    assert resp.json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_owner_can_open_detail_that_b_cannot() -> None:
    """El mismo escaneo: A (dueño) → 200; B → 404. Aislamiento simétrico (R5.3)."""
    # Arrange.
    harness = _TwoUserHarness()
    scan_id = harness.seed_for_a(_make_dto())

    # Act + Assert: dueño accede.
    harness.act_as_a()
    assert harness.client.get(f"/api/v1/scans/{scan_id}").status_code == 200

    # Act + Assert: ajeno es rechazado como inexistente.
    harness.act_as_b()
    assert harness.client.get(f"/api/v1/scans/{scan_id}").status_code == 404


def test_404_for_other_user_is_indistinguishable_from_nonexistent() -> None:
    """El 404 de "ajeno" y el de "no existe" son idénticos: no se filtra existencia (R5.3)."""
    # Arrange: un escaneo de A y un id que no existe en absoluto.
    harness = _TwoUserHarness()
    scan_id_of_a = harness.seed_for_a(_make_dto())
    nonexistent_id = uuid.uuid4()

    # Act: B pide ambos.
    harness.act_as_b()
    resp_foreign = harness.client.get(f"/api/v1/scans/{scan_id_of_a}")
    resp_missing = harness.client.get(f"/api/v1/scans/{nonexistent_id}")

    # Assert: respuestas indistinguibles (mismo status y mismo código de error).
    assert resp_foreign.status_code == resp_missing.status_code == 404
    assert resp_foreign.json()["error"]["code"] == resp_missing.json()["error"]["code"]


# ---------------------------------------------------------------------------
# GET /scans/{id}/raw — el report crudo de otro usuario tampoco se expone (R5.3)
# ---------------------------------------------------------------------------


def test_raw_report_of_a_as_b_returns_404() -> None:
    """B no puede leer el report_json crudo de A: 404 (R5.3)."""
    # Arrange.
    harness = _TwoUserHarness()
    scan_id = harness.seed_for_a(_make_dto())

    # Act.
    harness.act_as_b()
    resp = harness.client.get(f"/api/v1/scans/{scan_id}/raw")

    # Assert.
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_owner_reads_raw_that_b_cannot() -> None:
    """El report crudo: dueño A → 200 con JSON schema 1.2; B → 404 (R5.3)."""
    # Arrange.
    harness = _TwoUserHarness()
    scan_id = harness.seed_for_a(_make_dto())

    # Act + Assert: dueño obtiene el JSON crudo.
    harness.act_as_a()
    resp_owner = harness.client.get(f"/api/v1/scans/{scan_id}/raw")
    assert resp_owner.status_code == 200
    assert resp_owner.json()["schema_version"] == "1.2"

    # Act + Assert: ajeno rechazado.
    harness.act_as_b()
    assert harness.client.get(f"/api/v1/scans/{scan_id}/raw").status_code == 404


def test_raw_of_a_as_b_does_not_leak_report_body() -> None:
    """El 404 de raw ajeno no debe filtrar NADA del report del dueño (R5.3, no-fuga)."""
    # Arrange: marcamos el report de A con una aguja detectable.
    needle = "NEEDLE_RAW_REPORT_OF_ALICE_DO_NOT_LEAK"
    dto = _make_dto()
    tampered = dict(dto.report_dict)
    tampered["tool_version"] = needle
    dto = dto.model_copy(update={"report_dict": tampered})

    harness = _TwoUserHarness()
    scan_id = harness.seed_for_a(dto)

    # Act: B intenta leer el raw de A.
    harness.act_as_b()
    resp = harness.client.get(f"/api/v1/scans/{scan_id}/raw")

    # Assert: 404 y ni rastro del contenido del report de A en la respuesta.
    assert resp.status_code == 404
    assert needle not in resp.text


# ---------------------------------------------------------------------------
# Bidireccionalidad: el aislamiento opera en ambos sentidos (A↔B)
# ---------------------------------------------------------------------------


def test_isolation_is_symmetric_b_scan_hidden_from_a() -> None:
    """Simetría del aislamiento: A tampoco puede abrir un escaneo de B (R5.3)."""
    # Arrange: ahora el escaneo es de B.
    harness = _TwoUserHarness()
    scan_id_of_b = harness.seed_for_b(_make_dto())

    # Act: A intenta abrirlo.
    harness.act_as_a()
    resp = harness.client.get(f"/api/v1/scans/{scan_id_of_b}")

    # Assert: A recibe 404 igual que B con los de A.
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "SCAN_NOT_FOUND"
