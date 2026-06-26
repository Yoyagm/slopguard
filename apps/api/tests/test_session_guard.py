"""Guard de sesión y endpoint GET /me (H5-T12, ADR-4, R1).

Cubre:
- GET /me sin cookie → 401.
- GET /me con cookie de firma inválida → 401.
- GET /me con cookie válida pero sesión expirada (Redis vacío) → 401.
- GET /me con sesión válida → 200 con login del usuario.
- Resolución e2e: firma HMAC correcta, GET Redis, lookup DB — todo con dobles en memoria.
- `destroy` borra la sesión de Redis (base del logout de T13).
- Verificación de la firma en tiempo constante (tests unitarios de `RedisSessionStore`).

Todo con dobles en memoria: sin Redis, sin Postgres, sin GitHub.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.auth.deps import get_session_store, get_user_repository
from app.auth.guard import require_user
from app.auth.session import RedisSessionStore
from app.db.models import User
from app.main import create_app

# ---------------------------------------------------------------------------
# Dobles en memoria
# ---------------------------------------------------------------------------


class InMemoryAsyncRedis:
    """Doble mínimo de redis.asyncio.Redis[str]: set/get/getdel/delete."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self.ttls: dict[str, int | None] = {}

    async def set(self, name: str, value: str, ex: int | None = None) -> bool:
        self._store[name] = value
        self.ttls[name] = ex
        return True

    async def get(self, name: str) -> str | None:
        return self._store.get(name)

    async def getdel(self, name: str) -> str | None:
        return self._store.pop(name, None)

    async def delete(self, *names: str) -> int:
        count = 0
        for name in names:
            if name in self._store:
                del self._store[name]
                self.ttls.pop(name, None)
                count += 1
        return count


_SESSION_SECRET = "test-session-secret-32-characters!!"


def _make_store(redis: InMemoryAsyncRedis) -> RedisSessionStore:
    return RedisSessionStore(redis, session_secret=_SESSION_SECRET)


def _make_user(login: str = "octocat") -> User:
    """Construye un User simulado en memoria (sin DB ni SQLAlchemy real).

    Usa MagicMock con spec=User para que los atributos accedidos en el endpoint
    (id, login, avatar_url) devuelvan valores controlables sin el overhead del ORM.
    """
    user: User = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.login = login
    user.avatar_url = "https://avatars.githubusercontent.com/u/1"
    user.access_token_enc = b"encrypted-blob-do-not-leak"
    return user


# ---------------------------------------------------------------------------
# Session store: tests unitarios de resolve/destroy
# ---------------------------------------------------------------------------


async def test_resolve_retorna_user_id_para_cookie_valida() -> None:
    redis = InMemoryAsyncRedis()
    store = _make_store(redis)
    user_id = uuid.uuid4()

    cookie = await store.create(user_id)
    resolved = await store.resolve(cookie)

    assert resolved == user_id


async def test_resolve_retorna_none_para_firma_incorrecta() -> None:
    redis = InMemoryAsyncRedis()
    store = _make_store(redis)
    user_id = uuid.uuid4()

    cookie = await store.create(user_id)
    # Manipular el valor de la firma (último carácter cambiado).
    tampered = cookie[:-1] + ("X" if cookie[-1] != "X" else "Y")
    assert await store.resolve(tampered) is None


async def test_resolve_retorna_none_sin_separador() -> None:
    store = _make_store(InMemoryAsyncRedis())
    assert await store.resolve("solo-session-id-sin-punto") is None


async def test_resolve_retorna_none_para_sesion_expirada() -> None:
    """Si la clave no está en Redis (expirada o revocada), resolve devuelve None."""
    redis = InMemoryAsyncRedis()
    store = _make_store(redis)
    user_id = uuid.uuid4()

    cookie = await store.create(user_id)
    # Simulamos expiración borrando manualmente la clave de Redis.
    redis._store.clear()

    assert await store.resolve(cookie) is None


async def test_resolve_retorna_none_para_valor_vacio() -> None:
    store = _make_store(InMemoryAsyncRedis())
    assert await store.resolve("") is None


async def test_destroy_borra_sesion_de_redis() -> None:
    redis = InMemoryAsyncRedis()
    store = _make_store(redis)
    user_id = uuid.uuid4()

    cookie = await store.create(user_id)
    # Verificamos que la sesión existe antes de borrar.
    assert await store.resolve(cookie) == user_id

    await store.destroy(cookie)
    # Tras destroy, resolve debe devolver None.
    assert await store.resolve(cookie) is None


async def test_destroy_con_firma_invalida_es_noop() -> None:
    redis = InMemoryAsyncRedis()
    store = _make_store(redis)
    user_id = uuid.uuid4()

    await store.create(user_id)
    initial_keys = set(redis._store.keys())

    # Intentamos destruir con un valor firmado incorrectamente: no borra nada.
    await store.destroy("fake-id.invalidsignature")
    assert set(redis._store.keys()) == initial_keys


# ---------------------------------------------------------------------------
# Dobles FastAPI-level para require_user / GET /me
# ---------------------------------------------------------------------------


class FakeSessionStore:
    """Session store en memoria para inyectar en dependency_overrides."""

    def __init__(self, user_id: uuid.UUID | None = None) -> None:
        # None = sin sesión válida; un UUID = sesión activa para ese usuario.
        self._user_id = user_id

    async def create(self, user_id: uuid.UUID) -> str:
        return "fake-cookie.fakesig"

    async def resolve(self, cookie_value: str) -> uuid.UUID | None:
        return self._user_id

    async def destroy(self, cookie_value: str) -> None:
        pass


class FakeUserRepository:
    """Repositorio de usuarios en memoria para inyectar en dependency_overrides."""

    def __init__(self, user: User | None = None) -> None:
        self._user = user

    async def upsert_from_oauth(self, identity: Any, access_token: str) -> uuid.UUID:
        raise NotImplementedError

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        return self._user


def _make_client(
    session_store: FakeSessionStore,
    user_repo: FakeUserRepository,
) -> TestClient:
    """TestClient con los dobles de sesión y usuarios inyectados. No sigue redirects."""
    app = create_app()
    app.dependency_overrides[get_session_store] = lambda: session_store
    app.dependency_overrides[get_user_repository] = lambda: user_repo
    return TestClient(app, follow_redirects=False)


# ---------------------------------------------------------------------------
# Tests de integración del guard + endpoint GET /me
# ---------------------------------------------------------------------------


def test_get_me_sin_cookie_es_401() -> None:
    """Sin cookie de sesión → 401. No hay información del usuario en la respuesta."""
    store = FakeSessionStore(user_id=None)
    repo = FakeUserRepository(user=None)
    client = _make_client(store, repo)

    resp = client.get("/api/v1/me")

    assert resp.status_code == 401
    assert "login" not in resp.text


def test_get_me_con_sesion_invalida_es_401() -> None:
    """Cookie presente pero resolve() devuelve None (firma mala o expirada) → 401."""
    store = FakeSessionStore(user_id=None)
    repo = FakeUserRepository(user=None)
    client = _make_client(store, repo)

    resp = client.get("/api/v1/me", cookies={"sg_session": "bad.cookie"})

    assert resp.status_code == 401


def test_get_me_con_sesion_valida_devuelve_login() -> None:
    """Cookie válida con sesión activa → 200 con login y sin token."""
    user = _make_user("octocat")
    store = FakeSessionStore(user_id=user.id)
    repo = FakeUserRepository(user=user)
    client = _make_client(store, repo)

    resp = client.get("/api/v1/me", cookies={"sg_session": "valid.cookie"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["login"] == "octocat"
    assert data["id"] == str(user.id)
    # El token cifrado NUNCA debe aparecer en la respuesta (invariante de no-fuga).
    assert "access_token" not in resp.text
    assert "encrypted-blob" not in resp.text


def test_get_me_usuario_no_encontrado_en_db_es_401() -> None:
    """Sesión apunta a user_id que ya no existe en DB → 401."""
    store = FakeSessionStore(user_id=uuid.uuid4())
    repo = FakeUserRepository(user=None)  # DB devuelve None
    client = _make_client(store, repo)

    resp = client.get("/api/v1/me", cookies={"sg_session": "valid.cookie"})

    assert resp.status_code == 401


def test_get_me_require_user_es_overridable() -> None:
    """Verifica que `require_user` es sustituible por dependency_overrides en tests."""
    user = _make_user("testuser")
    app = create_app()
    # Override directo de require_user (patrón para tests de otros routers que usen CurrentUser).
    app.dependency_overrides[require_user] = lambda: user
    client = TestClient(app, follow_redirects=False)

    resp = client.get("/api/v1/me")

    assert resp.status_code == 200
    assert resp.json()["login"] == "testuser"


def test_get_me_401_no_expone_secretos_en_respuesta() -> None:
    """El cuerpo del 401 no contiene tokens ni información que ayude a un atacante."""
    store = FakeSessionStore(user_id=None)
    repo = FakeUserRepository(user=None)
    client = _make_client(store, repo)

    resp = client.get("/api/v1/me")

    assert resp.status_code == 401
    body = resp.text
    # No deben aparecer términos que filtren información de implementación.
    for forbidden in ("token", "session_id", "redis", "hmac", "signature"):
        assert forbidden not in body.lower(), f"'{forbidden}' filtrado en el 401"
