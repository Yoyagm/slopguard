"""Aceptación integral de la GitHub App (H5-T25, R2.1-R2.5, R6.1, NFR-Seg-2/3).

Suite hermética (sin red, sin Postgres, sin Redis) que fija el COMPORTAMIENTO observable de los
cinco escenarios de la tarea, mapeados a sus criterios EARS:

  1. (R2.1/R2.2) Webhook `installation` con HMAC VÁLIDO persiste instalación + repos;
     HMAC INVÁLIDO ⇒ 204 sin efecto (ningún parseo, nada persistido).
  2. (R2.4 — TEST ESTRELLA) DESINSTALACIÓN (`action=deleted`) marca `status=revoked` y CONSERVA
     el histórico de `scans`. Probado contra el `SqlInstallationRepository` REAL sobre SQLite
     en memoria (no solo el doble): demuestra la invariante en el SQL de producción.
  3. (R2.3) GET /repos lista SOLO los repos accesibles del usuario (aislamiento por usuario).
  4. (R2.5) El installation token se renueva bajo demanda y NUNCA aparece en respuestas ni logs.
  5. (R2.5) source=repo de POST /scans funciona end-to-end con clientes fake (lee manifiesto →
     escanea → persiste); repo no disponible ⇒ 422 REPO_UNAVAILABLE accionable.

Y un guardia de regresión sobre la verificación HMAC en TIEMPO CONSTANTE (NFR-Seg-2): la
comparación final debe delegar en `hmac.compare_digest`, nunca en `==` (fuga por timing).

Decisión de diseño de los tests (pirámide de tests):
  - Unidad/SQL para la invariante crítica R2.4 (SQLite + ORM real, sin mocks de la lógica).
  - Integración de router con dobles en memoria para los flujos HTTP (webhook, /repos, /scans).
  - Sin nada dependiente de reloj real, orden de tests ni red: deterministas y no flaky.
"""

from __future__ import annotations

import datetime
import hmac
import json
import uuid
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from slopguard.core import ScanReport, ScanSummary
from sqlalchemy import Engine, create_engine, event, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import webhooks as webhooks_module
from app.api.scans import (
    get_contents_client,
    get_scan_repository,
    get_scan_service,
    get_scan_token_client,
)
from app.api.scans import get_installation_repository as scans_get_installation_repository
from app.auth.deps import get_session_store, get_user_repository
from app.auth.guard import require_user
from app.db import models as models
from app.db.base import Base
from app.db.models import User
from app.github_app.contents_client import FakeGitHubContentsClient
from app.github_app.deps import get_installation_repository
from app.github_app.installation_repo import (
    STATUS_ACTIVE,
    STATUS_REVOKED,
    FakeInstallationRepository,
    InstallationData,
    RepoData,
    SqlInstallationRepository,
)
from app.github_app.token_client import HttpxGitHubAppTokenClient
from app.main import create_app
from app.security import webhook_signature as webhook_signature_module
from app.security.webhook_signature import expected_signature, verify_signature
from tests.conftest import FakeSessionStore, FakeUser, FakeUserRepository

_API = "/api/v1"
# Secretos SINTÉTICOS de prueba (nunca reales). Sirven de "aguja" para los tests de no-fuga.
_WEBHOOK_SECRET = "t25-webhook-secret-synthetic"
_FAKE_INSTALL_TOKEN = "ghs_T25_INSTALL_TOKEN_DO_NOT_LEAK_0xBEEF"
# `sender.id` del instalador conocido (ya logueado): el repo lo resuelve a un users.id interno.
_INSTALLER_GH_ID = 4242


# ===========================================================================
# Escenario 1 — Webhook installation con HMAC: válido persiste, inválido no-op
# (R2.1/R2.2, R6.1, NFR-Seg-2)
# ===========================================================================


def _build_webhook_client(
    repo: FakeInstallationRepository, *, secret: str | None = _WEBHOOK_SECRET
) -> TestClient:
    """TestClient del router de webhooks con el repo doblado y un secreto inyectado."""
    app: FastAPI = create_app()
    app.dependency_overrides[get_installation_repository] = lambda: repo

    patched = webhooks_module.get_settings().model_copy(
        update={"github_webhook_secret": SecretStr(secret) if secret is not None else None}
    )
    app.dependency_overrides[webhooks_module._settings_dep] = lambda: patched
    return TestClient(app, raise_server_exceptions=True)


def _installation_payload(
    *, action: str, installation_id: int, repos: list[dict[str, object]] | None = None
) -> dict[str, object]:
    payload: dict[str, object] = {
        "action": action,
        "installation": {
            "id": installation_id,
            "account": {"login": "octo-owner", "id": 1},
        },
        "sender": {"id": _INSTALLER_GH_ID, "login": "octo-owner"},
    }
    if repos is not None:
        payload["repositories"] = repos
    return payload


def _post_signed(
    client: TestClient,
    *,
    event_name: str,
    payload: dict[str, object],
    secret: str = _WEBHOOK_SECRET,
) -> Any:
    """POST firmado con HMAC sobre los bytes EXACTOS enviados (canónicos)."""
    body = json.dumps(payload).encode("utf-8")
    signature = expected_signature(secret, body)
    return client.post(
        f"{_API}/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": event_name,
            "X-Hub-Signature-256": signature,
            "Content-Type": "application/json",
        },
    )


@pytest.fixture
def webhook_repo() -> FakeInstallationRepository:
    repo = FakeInstallationRepository()
    # Instalador ya logueado: sembramos su mapping github_user_id → users.id interno.
    repo.seed_owner(_INSTALLER_GH_ID, uuid.uuid4())
    return repo


def test_webhook_hmac_valido_persiste_instalacion_y_repos(
    webhook_repo: FakeInstallationRepository,
) -> None:
    """R2.1/R2.2: con firma HMAC válida, la instalación y sus repos quedan persistidos."""
    client = _build_webhook_client(webhook_repo)
    payload = _installation_payload(
        action="created",
        installation_id=1001,
        repos=[
            {"id": 11, "full_name": "octo-owner/api", "private": False},
            {"id": 12, "full_name": "octo-owner/web", "private": True},
        ],
    )

    resp = _post_signed(client, event_name="installation", payload=payload)

    assert resp.status_code == 202
    state = webhook_repo.get_state(1001)
    assert state is not None
    assert state.status == STATUS_ACTIVE
    assert set(state.repos.keys()) == {11, 12}
    # El repo privado conserva su flag (metadata necesaria para el dashboard).
    assert state.repos[12].private is True


def test_webhook_hmac_invalido_no_persiste_nada(
    webhook_repo: FakeInstallationRepository,
) -> None:
    """R6.1: firma incorrecta ⇒ 204 y NADA se persiste (no se parsea el cuerpo)."""
    client = _build_webhook_client(webhook_repo)
    payload = _installation_payload(action="created", installation_id=1002, repos=[])
    body = json.dumps(payload).encode("utf-8")

    resp = client.post(
        f"{_API}/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": "installation",
            "X-Hub-Signature-256": "sha256=" + "0" * 64,  # firma que no corresponde
        },
    )

    assert resp.status_code == 204
    assert webhook_repo.get_state(1002) is None


def test_webhook_hmac_ausente_no_persiste_nada(
    webhook_repo: FakeInstallationRepository,
) -> None:
    """R6.1: sin cabecera de firma ⇒ 204 sin efecto (fail-closed)."""
    client = _build_webhook_client(webhook_repo)
    payload = _installation_payload(action="created", installation_id=1003, repos=[])
    body = json.dumps(payload).encode("utf-8")

    resp = client.post(
        f"{_API}/webhooks/github",
        content=body,
        headers={"X-GitHub-Event": "installation"},  # sin X-Hub-Signature-256
    )

    assert resp.status_code == 204
    assert webhook_repo.get_state(1003) is None


# ===========================================================================
# Verificación HMAC en TIEMPO CONSTANTE (NFR-Seg-2)
# Guardia de regresión: la comparación final debe usar hmac.compare_digest,
# nunca `==` (que filtraría la firma byte a byte por timing).
# ===========================================================================


def test_verify_signature_usa_comparacion_de_tiempo_constante(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """La verificación delega en `hmac.compare_digest` (constante en tiempo), no en `==`.

    Espiamos `compare_digest`: si `verify_signature` lo invoca para la comparación final,
    el espía registra la llamada. Un refactor accidental a `==` haría fallar este test.
    """
    calls: list[tuple[str, str]] = []
    real_compare = hmac.compare_digest

    def _spy_compare(a: Any, b: Any) -> bool:
        calls.append((str(a), str(b)))
        return real_compare(a, b)

    monkeypatch.setattr(webhook_signature_module.hmac, "compare_digest", _spy_compare)

    secret = _WEBHOOK_SECRET
    body = b'{"action":"created"}'
    sig = expected_signature(secret, body)

    result = verify_signature(secret=secret, raw_body=body, signature_header=sig)

    assert result is True
    assert calls, "verify_signature debe usar hmac.compare_digest para la comparación final"


# ===========================================================================
# Escenario 2 — TEST ESTRELLA (R2.4): desinstalar NO borra el histórico de scans.
# Probado contra el SqlInstallationRepository REAL sobre SQLite en memoria.
# ===========================================================================


# Render de los tipos Postgres-específicos como equivalentes SQLite SOLO para el engine de test.
# No tocan producción: son fallbacks de compilación a nivel de dialecto "sqlite".
@compiles(PGUUID, "sqlite")
def _compile_pg_uuid_sqlite(type_: Any, compiler: Any, **kw: Any) -> str:
    return "CHAR(32)"


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_: Any, compiler: Any, **kw: Any) -> str:
    return "JSON"


@event.listens_for(Base, "before_insert", propagate=True)
def _sqlite_server_defaults(mapper: Any, connection: Any, target: Any) -> None:
    """SQLite no tiene `gen_random_uuid()` ni `now()` server-side: los suplimos en Python.

    Replica el efecto de los server_default de Postgres para que las inserciones de los tests
    funcionen sin reescribir los modelos. Solo actúa si el dialecto es SQLite (engine de test).
    """
    if connection.dialect.name != "sqlite":
        return
    for column in mapper.columns:
        if column.primary_key and getattr(target, column.key, None) is None:
            setattr(target, column.key, uuid.uuid4())
    now = datetime.datetime.now(tz=datetime.UTC)
    for key in ("created_at", "updated_at"):
        if hasattr(target, key) and getattr(target, key, None) is None:
            setattr(target, key, now)


def _make_sqlite_engine() -> Engine:
    """Engine SQLite en memoria con una ÚNICA conexión compartida (StaticPool).

    StaticPool es imprescindible: con `sqlite://` cada conexión nueva abriría una DB vacía.
    El repo bajo prueba abre sus propias sesiones desde el `session_factory`; deben ver la
    misma DB donde se crearon las tablas y se sembraron las filas.
    """
    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


def _seed_installation_with_scan(
    session_factory: sessionmaker[Session],
    *,
    github_installation_id: int,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Siembra user + instalación activa + repo + un scan asociado. Devuelve (user_id, repo_id)."""
    user_id = uuid.uuid4()
    repo_internal_id = uuid.uuid4()
    with session_factory() as session:
        session.add(
            User(
                id=user_id,
                github_user_id=777,
                login="dev",
                access_token_enc=b"encrypted-blob",
            )
        )
        installation_internal_id = uuid.uuid4()
        session.add(
            models.GithubInstallation(
                id=installation_internal_id,
                installation_id=github_installation_id,
                user_id=user_id,
                account_login="dev-org",
                status=STATUS_ACTIVE,
            )
        )
        session.add(
            models.Repo(
                id=repo_internal_id,
                installation_id=installation_internal_id,
                github_repo_id=9001,
                full_name="dev-org/with-history",
                private=False,
            )
        )
        session.flush()
        # Un escaneo histórico ligado al repo: es exactamente lo que R2.4 prohíbe perder.
        session.add(
            models.Scan(
                id=uuid.uuid4(),
                user_id=user_id,
                repo_id=repo_internal_id,
                origin="pull_request",
                ecosystem="pypi",
                schema_version="1.2",
                tool_version="0.0.0-test",
                exit_code=2,
                summary={"total": 1, "block": 1},
                error_category=None,
                report_json={"schema_version": "1.2", "results": []},
            )
        )
        session.commit()
    return user_id, repo_internal_id


async def test_desinstalacion_conserva_el_historico_de_scans_sql_real() -> None:
    """TEST ESTRELLA (R2.4): `set_status(revoked)` cambia status y NO toca `scans`.

    Ejercita el `SqlInstallationRepository` real sobre SQLite: si la implementación borrara
    el histórico (o cascada de la instalación a los scans), este test lo detectaría.
    """
    engine = _make_sqlite_engine()
    session_factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    _user_id, repo_internal_id = _seed_installation_with_scan(
        session_factory, github_installation_id=5005
    )
    repo = SqlInstallationRepository(session_factory)

    # Acto: la App se desinstala (webhook installation/deleted → status=revoked).
    changed = await repo.set_status(installation_id=5005, status=STATUS_REVOKED)

    assert changed is True
    with session_factory() as session:
        # 1) El status cambió a revoked (la instalación ya no es operativa).
        installation = session.execute(
            select(models.GithubInstallation).where(
                models.GithubInstallation.installation_id == 5005
            )
        ).scalar_one()
        assert installation.status == STATUS_REVOKED

        # 2) INVARIANTE R2.4: el escaneo histórico SIGUE existiendo (no se borró).
        surviving = session.execute(
            select(func.count())
            .select_from(models.Scan)
            .where(models.Scan.repo_id == repo_internal_id)
        ).scalar_one()
        assert surviving == 1, "el histórico de scans NUNCA debe borrarse al desinstalar (R2.4)"

    engine.dispose()


async def test_desinstalacion_revocada_oculta_repos_pero_conserva_filas() -> None:
    """R2.4 + R2.3: tras revocar, los repos no se listan, pero las filas siguen en DB.

    Confirma que la 'ocultación' es por filtro de status (no por borrado): el repo persiste
    para no romper la FK del histórico, y `list_repos_for_user` deja de devolverlo.
    """
    engine = _make_sqlite_engine()
    session_factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    user_id, _repo_internal_id = _seed_installation_with_scan(
        session_factory, github_installation_id=5006
    )
    repo = SqlInstallationRepository(session_factory)

    repos_before = await repo.list_repos_for_user(user_id)
    assert len(repos_before) == 1  # activa → visible

    await repo.set_status(installation_id=5006, status=STATUS_REVOKED)

    repos_after = await repo.list_repos_for_user(user_id)
    assert repos_after == []  # revocada → no se lista (R2.3)

    with session_factory() as session:
        repo_rows = session.execute(
            select(func.count()).select_from(models.Repo)
        ).scalar_one()
        assert repo_rows == 1  # la fila del repo persiste (no se borró)

    engine.dispose()


async def test_remove_repo_con_historico_se_conserva_sin_borrar_scans() -> None:
    """R2.4: quitar un repo (installation_repositories) que TIENE scans no borra su fila.

    Un repo con histórico se conserva para no romper la FK `scans.repo_id` ni perder escaneos.
    Ejercita `_remove_repos` del SqlInstallationRepository real (SQLite).
    """
    engine = _make_sqlite_engine()
    session_factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    _user_id, repo_internal_id = _seed_installation_with_scan(
        session_factory, github_installation_id=5007
    )
    repo = SqlInstallationRepository(session_factory)

    # GitHub notifica que el repo (github_repo_id=9001) deja de ser accesible.
    synced = await repo.sync_repos(
        installation_id=5007,
        added=(),
        removed_repo_ids=(9001,),
    )

    assert synced is True
    with session_factory() as session:
        # La fila del repo se conserva (tiene scans): R2.4 prima sobre la limpieza.
        repo_rows = session.execute(
            select(func.count()).select_from(models.Repo)
        ).scalar_one()
        assert repo_rows == 1
        scan_rows = session.execute(
            select(func.count())
            .select_from(models.Scan)
            .where(models.Scan.repo_id == repo_internal_id)
        ).scalar_one()
        assert scan_rows == 1

    engine.dispose()


# ===========================================================================
# Escenario 3 — GET /repos lista SOLO los repos del usuario (aislamiento, R2.3)
# ===========================================================================


_OWNER_ID = uuid.uuid4()
_OTHER_USER_ID = uuid.uuid4()


def _build_repos_client(repo: FakeInstallationRepository, *, user_id: uuid.UUID) -> TestClient:
    """App con el repo de instalaciones doblado y un usuario autenticado concreto."""
    app: FastAPI = create_app()
    app.dependency_overrides[get_installation_repository] = lambda: repo
    fake_user = FakeUser(user_id, login="dev-test")
    app.dependency_overrides[require_user] = lambda: fake_user
    return TestClient(app, raise_server_exceptions=True)


def _seed_active_installation(
    repo: FakeInstallationRepository,
    *,
    user_id: uuid.UUID,
    installation_id: int,
    account_login: str,
    repos: list[RepoData],
) -> None:
    import asyncio

    data = InstallationData(
        installation_id=installation_id,
        account_login=account_login,
        repos=tuple(repos),
    )
    asyncio.run(repo.upsert_installation(data, user_id=user_id))


def test_repos_solo_devuelve_los_del_usuario_autenticado() -> None:
    """R2.3: GET /repos aísla por usuario — no se filtran repos de otros usuarios."""
    repo = FakeInstallationRepository()
    _seed_active_installation(
        repo,
        user_id=_OWNER_ID,
        installation_id=2001,
        account_login="mine",
        repos=[RepoData(github_repo_id=1, full_name="mine/alpha", private=False)],
    )
    # Repo de OTRO usuario: nunca debe aparecer en la respuesta del dueño autenticado.
    _seed_active_installation(
        repo,
        user_id=_OTHER_USER_ID,
        installation_id=2002,
        account_login="theirs",
        repos=[RepoData(github_repo_id=2, full_name="theirs/secret", private=True)],
    )

    client = _build_repos_client(repo, user_id=_OWNER_ID)
    resp = client.get(f"{_API}/repos")

    assert resp.status_code == 200
    full_names = {item["full_name"] for item in resp.json()}
    assert full_names == {"mine/alpha"}
    assert "theirs/secret" not in full_names


def test_repos_excluye_instalaciones_revocadas() -> None:
    """R2.3/R2.4: una instalación revocada deja de dar acceso a sus repos en /repos."""
    repo = FakeInstallationRepository()
    _seed_active_installation(
        repo,
        user_id=_OWNER_ID,
        installation_id=2003,
        account_login="mine",
        repos=[RepoData(github_repo_id=3, full_name="mine/revoked-repo", private=False)],
    )
    import asyncio

    asyncio.run(repo.set_status(installation_id=2003, status=STATUS_REVOKED))

    client = _build_repos_client(repo, user_id=_OWNER_ID)
    resp = client.get(f"{_API}/repos")

    assert resp.status_code == 200
    assert resp.json() == []


def test_repos_sin_sesion_responde_401() -> None:
    """R2.3: la ruta requiere sesión; sin usuario autenticado ⇒ 401, no fuga de datos."""
    repo = FakeInstallationRepository()

    class _NoSessionStore:
        async def create(self, user_id: uuid.UUID) -> str:
            return "no-session"

        async def resolve(self, cookie_value: str) -> uuid.UUID | None:
            return None

        async def destroy(self, cookie_value: str) -> None:
            return None

    class _NoUserRepo:
        async def upsert_from_oauth(self, identity: object, access_token: str) -> uuid.UUID:
            raise NotImplementedError

        async def get_by_id(self, user_id: uuid.UUID) -> None:
            return None

    app: FastAPI = create_app()
    app.dependency_overrides[get_installation_repository] = lambda: repo
    app.dependency_overrides[get_session_store] = lambda: _NoSessionStore()
    app.dependency_overrides[get_user_repository] = lambda: _NoUserRepo()
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get(f"{_API}/repos")
    assert resp.status_code == 401


# ===========================================================================
# Escenario 4 — Installation token: renovación bajo demanda + NUNCA en respuestas/logs (R2.5)
# ===========================================================================


class _StubRedis:
    """Redis stub en memoria: registra accesos para verificar la lógica de renovación/caché."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self.get_calls = 0
        self.setex_calls = 0

    async def get(self, key: str) -> bytes | str | None:
        self.get_calls += 1
        return self._store.get(key)

    async def setex(self, key: str, time: int, value: str | bytes) -> object:
        self.setex_calls += 1
        self._store[key] = value if isinstance(value, str) else value.decode("latin-1")
        return True


def _make_httpx_mock() -> Any:
    """Mock de httpx.AsyncClient como context manager async que devuelve el token fake."""
    from unittest.mock import AsyncMock, MagicMock

    response = MagicMock()
    response.status_code = 201
    response.json.return_value = {
        "token": _FAKE_INSTALL_TOKEN,
        "expires_at": "2099-01-01T00:00:00Z",
    }
    client = AsyncMock()
    client.post = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return MagicMock(return_value=client)


@pytest.fixture(scope="module")
def rsa_pem() -> bytes:
    """Clave RSA privada generada en memoria (sin relación con producción)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())


async def test_token_se_renueva_bajo_demanda_desde_github(rsa_pem: bytes) -> None:
    """R2.5: sin caché, `get_installation_token` llama a GitHub y obtiene un token vigente."""
    from unittest.mock import patch

    client = HttpxGitHubAppTokenClient(app_id="999", private_key_pem=rsa_pem, redis_client=None)
    with patch("app.github_app.token_client.httpx.AsyncClient", _make_httpx_mock()):
        token = await client.get_installation_token(98765)

    assert token == _FAKE_INSTALL_TOKEN


async def test_token_cacheado_evita_segunda_llamada_a_github(
    rsa_pem: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2.5: una segunda solicitud reusa el token cacheado (cifrado) sin volver a GitHub."""
    from unittest.mock import patch

    from app.security.crypto import reset_cipher_cache

    # Clave AEAD válida para que el cache cifrado funcione (32 bytes base64).
    monkeypatch.setenv("ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    from app.settings import get_settings

    get_settings.cache_clear()
    reset_cipher_cache()

    redis = _StubRedis()
    client = HttpxGitHubAppTokenClient(
        app_id="999",
        private_key_pem=rsa_pem,
        redis_client=redis,  # type: ignore[arg-type]
    )
    http_mock = _make_httpx_mock()
    with patch("app.github_app.token_client.httpx.AsyncClient", http_mock):
        first = await client.get_installation_token(55555)
        second = await client.get_installation_token(55555)

    assert first == _FAKE_INSTALL_TOKEN
    assert second == _FAKE_INSTALL_TOKEN
    # La segunda vez sale de la caché: GitHub se llamó una sola vez.
    assert http_mock.call_count == 1
    assert redis.setex_calls == 1

    get_settings.cache_clear()
    reset_cipher_cache()


async def test_token_nunca_aparece_en_logs(
    rsa_pem: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    """R2.5/NFR-Seg-3: el installation token JAMÁS se escribe en logs (ni a nivel DEBUG)."""
    from unittest.mock import patch

    client = HttpxGitHubAppTokenClient(app_id="999", private_key_pem=rsa_pem, redis_client=None)
    with patch("app.github_app.token_client.httpx.AsyncClient", _make_httpx_mock()):
        with caplog.at_level("DEBUG", logger="app.github_app.token_client"):
            await client.get_installation_token(98765)

    for record in caplog.records:
        assert _FAKE_INSTALL_TOKEN not in record.getMessage(), (
            f"Token filtrado en log: {record.getMessage()!r}"
        )


async def test_token_no_se_persiste_en_caja_de_caché_en_claro(
    rsa_pem: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R2.5/NFR-Seg-3: si se cachea en Redis, va CIFRADO — nunca en texto plano."""
    from unittest.mock import patch

    from app.security.crypto import reset_cipher_cache

    monkeypatch.setenv("ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    from app.settings import get_settings

    get_settings.cache_clear()
    reset_cipher_cache()

    redis = _StubRedis()
    client = HttpxGitHubAppTokenClient(
        app_id="999",
        private_key_pem=rsa_pem,
        redis_client=redis,  # type: ignore[arg-type]
    )
    with patch("app.github_app.token_client.httpx.AsyncClient", _make_httpx_mock()):
        await client.get_installation_token(44444)

    stored_values = "".join(redis._store.values())
    assert _FAKE_INSTALL_TOKEN not in stored_values, "token en claro filtrado a la caché Redis"

    get_settings.cache_clear()
    reset_cipher_cache()


# ===========================================================================
# Escenario 5 — source=repo end-to-end con GitHubAppClient fake (R2.5)
# ===========================================================================


_SCAN_USER_ID = uuid.UUID("cccccccc-0000-0000-0000-000000000005")
_REPO_MANIFEST = "requests==2.28.0\n"


def _clean_report() -> ScanReport:
    return ScanReport(
        schema_version="1.2",
        tool_version="0.0.0-test",
        ecosystem="pypi",
        summary=ScanSummary(total=1, allow=1, warn=0, block=0, unverifiable=0, exit_code=0),
        results=(),
        error_category=None,
    )


class _FakeScanServiceOK:
    """Motor doblado: devuelve un reporte limpio sin tocar registros externos."""

    async def scan_text(self, content: str, *, ecosystem: str | None = None) -> ScanReport:
        # Capturamos el contenido leído para verificar el flujo lee-manifiesto → escanea.
        self.scanned_content = content
        return _clean_report()

    async def scan_path(self, path: Any, *, ecosystem: str | None = None) -> ScanReport:
        return _clean_report()

    def check_deps_count(self, count: int) -> None:
        return None

    wrapper_timeout_s: float = 5.0
    max_manifest_bytes: int = 5_000_000
    max_deps: int = 5000
    enable_layer4: bool = False


class _FakeAppTokenClientOK:
    """GitHubAppClient (token) fake: devuelve un installation token sin red."""

    async def get_installation_token(self, installation_id: int) -> str:
        return _FAKE_INSTALL_TOKEN


def _make_scan_repo_with_repo() -> tuple[FakeInstallationRepository, uuid.UUID]:
    """Repo fake con una instalación activa y un repo; devuelve (repo, repo_uuid_interno)."""
    import asyncio

    inst_repo = FakeInstallationRepository()
    data = InstallationData(
        installation_id=606,
        account_login="octocat",
        repos=(RepoData(github_repo_id=12345, full_name="octocat/hello", private=False),),
    )
    asyncio.run(inst_repo.upsert_installation(data, user_id=_SCAN_USER_ID))
    repos = asyncio.run(inst_repo.list_repos_for_user(_SCAN_USER_ID))
    assert repos, "el repo debería estar en la instalación"
    return inst_repo, repos[0].id


def _make_scan_client(
    *,
    installation_repo: FakeInstallationRepository,
    contents_client: FakeGitHubContentsClient,
    scan_service: _FakeScanServiceOK,
    scan_repo: Any,
    token_client: Any,
) -> TestClient:
    app = create_app()
    fake_user = FakeUser(_SCAN_USER_ID)

    async def _require_user() -> User:
        return fake_user  # type: ignore[return-value]

    app.dependency_overrides[require_user] = _require_user
    app.dependency_overrides[get_scan_service] = lambda: scan_service
    app.dependency_overrides[get_scan_repository] = lambda: scan_repo
    app.dependency_overrides[scans_get_installation_repository] = lambda: installation_repo
    app.dependency_overrides[get_contents_client] = lambda: contents_client
    app.dependency_overrides[get_scan_token_client] = lambda: token_client
    app.dependency_overrides[get_user_repository] = lambda: FakeUserRepository()
    app.dependency_overrides[get_session_store] = lambda: FakeSessionStore()
    return TestClient(app, raise_server_exceptions=False)


def test_source_repo_end_to_end_lee_escanea_persiste() -> None:
    """R2.5: source=repo lee el manifiesto del repo, lo escanea y persiste (200 con scan_id)."""
    from app.scans.scan_repo import FakeScanRepository

    inst_repo, repo_uuid = _make_scan_repo_with_repo()
    contents = FakeGitHubContentsClient(content=_REPO_MANIFEST)
    scan_service = _FakeScanServiceOK()
    scan_repo = FakeScanRepository()
    client = _make_scan_client(
        installation_repo=inst_repo,
        contents_client=contents,
        scan_service=scan_service,
        scan_repo=scan_repo,
        token_client=_FakeAppTokenClientOK(),
    )

    resp = client.post(
        "/api/v1/scans",
        json={"source": "repo", "repo_id": str(repo_uuid), "path": "requirements.txt"},
    )

    assert resp.status_code == 200
    data = resp.json()
    uuid.UUID(data["scan_id"])  # scan_id válido → persistido
    assert data["origin"] == "on_demand"
    # El flujo leyó el manifiesto del repo (no un contenido inventado) y lo pasó al motor.
    assert contents.fetch_calls[0]["full_name"] == "octocat/hello"
    assert contents.fetch_calls[0]["path"] == "requirements.txt"
    assert scan_service.scanned_content == _REPO_MANIFEST
    # Se persistió con el repo_id interno correcto.
    assert scan_repo.persisted_count == 1
    assert scan_repo.last_call()["repo_id"] == repo_uuid


def test_source_repo_token_nunca_aparece_en_la_respuesta() -> None:
    """R2.5/NFR-Seg-3: el installation token nunca viaja en el body de la respuesta."""
    from app.scans.scan_repo import FakeScanRepository

    inst_repo, repo_uuid = _make_scan_repo_with_repo()
    client = _make_scan_client(
        installation_repo=inst_repo,
        contents_client=FakeGitHubContentsClient(content=_REPO_MANIFEST),
        scan_service=_FakeScanServiceOK(),
        scan_repo=FakeScanRepository(),
        token_client=_FakeAppTokenClientOK(),
    )

    resp = client.post(
        "/api/v1/scans",
        json={"source": "repo", "repo_id": str(repo_uuid), "path": "requirements.txt"},
    )

    assert _FAKE_INSTALL_TOKEN not in resp.text


def test_source_repo_no_disponible_devuelve_error_accionable() -> None:
    """R2.5: repo/archivo no disponible ⇒ 422 REPO_UNAVAILABLE accionable (nunca 'limpio')."""
    from app.scans.scan_repo import FakeScanRepository

    inst_repo, repo_uuid = _make_scan_repo_with_repo()
    failing_contents = FakeGitHubContentsClient(
        fail=True, fail_message="El archivo no existe en el repo."
    )
    scan_repo = FakeScanRepository()
    client = _make_scan_client(
        installation_repo=inst_repo,
        contents_client=failing_contents,
        scan_service=_FakeScanServiceOK(),
        scan_repo=scan_repo,
        token_client=_FakeAppTokenClientOK(),
    )

    resp = client.post(
        "/api/v1/scans",
        json={"source": "repo", "repo_id": str(repo_uuid), "path": "requirements.txt"},
    )

    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "REPO_UNAVAILABLE"
    assert body["error"]["message"]  # mensaje accionable, no vacío
    # Fail-closed: ante repo no disponible NO se persiste escaneo (nunca un veredicto silencioso).
    assert scan_repo.persisted_count == 0
    # Saneado: sin trazas ni secretos.
    assert "Traceback" not in resp.text


def test_source_repo_de_otro_usuario_es_repo_unavailable() -> None:
    """R2.5 + aislamiento R5.3: un repo que no es del usuario ⇒ 422 REPO_UNAVAILABLE.

    No se distingue 'no existe' de 'no es tuyo' (no enumerar repos ajenos): mismo 422 saneado.
    """
    from app.scans.scan_repo import FakeScanRepository

    inst_repo, _repo_uuid = _make_scan_repo_with_repo()
    # repo_id aleatorio que no pertenece al usuario autenticado.
    foreign_repo_id = uuid.uuid4()
    client = _make_scan_client(
        installation_repo=inst_repo,
        contents_client=FakeGitHubContentsClient(content=_REPO_MANIFEST),
        scan_service=_FakeScanServiceOK(),
        scan_repo=FakeScanRepository(),
        token_client=_FakeAppTokenClientOK(),
    )

    resp = client.post(
        "/api/v1/scans",
        json={"source": "repo", "repo_id": str(foreign_repo_id), "path": "requirements.txt"},
    )

    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "REPO_UNAVAILABLE"
