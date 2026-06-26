"""Fixtures y dobles compartidos para los tests de auth (H5-T14, R1.1-R1.5).

Centraliza los dobles en memoria del flujo OAuth para que los tests de aceptación corran
SIN servicios externos (sin Redis, sin Postgres, sin GitHub). Las clases imitan la semántica
observable de las implementaciones reales (single-use del `state`, revocación real de la sesión
en `destroy`), no sus detalles internos: así los tests verifican comportamiento, no implementación.

Centinela de no-fuga: `FAKE_GITHUB_TOKEN` es el valor que NUNCA debe aparecer en una respuesta
HTTP ni en los logs (R1.5). Los tests lo usan como aguja a buscar en cuerpo/headers/logs.
"""

from __future__ import annotations

import uuid
from typing import Protocol

import pytest

from app.services.github import GitHubAuthError, GitHubIdentity

# Token sintético de GitHub: aguja del centinela de no-fuga (R1.5). Marcado para que sea
# trivialmente detectable si se filtrara a cualquier respuesta o log.
FAKE_GITHUB_TOKEN = "gho_ACCEPTANCE_secret_token_DO_NOT_LEAK_0xCAFE"
# Code OAuth válido por defecto que el `FakeGitHubClient` canjea por el token.
FAKE_OAUTH_CODE = "valid-oauth-code"
# Login de la identidad de GitHub devuelta por el doble (no es secreto).
FAKE_GITHUB_LOGIN = "octocat"


class _UserLike(Protocol):
    """Mínimo que el guard/endpoint necesita de un User (sin acoplar al ORM real)."""

    id: uuid.UUID
    login: str
    avatar_url: str | None


class FakeStateStore:
    """State store en memoria con la semántica single-use real (consume = GETDEL).

    `issue` registra un `state`; `consume` lo devuelve True solo la primera vez (y lo borra),
    replicando el GETDEL de Redis que corta la reutilización (defensa CSRF, R1.3).
    """

    def __init__(self) -> None:
        self._issued: set[str] = set()
        self.issue_calls = 0

    async def issue(self) -> str:
        self.issue_calls += 1
        state = f"state-{self.issue_calls}"
        self._issued.add(state)
        return state

    async def consume(self, state: str) -> bool:
        if state in self._issued:
            self._issued.discard(state)  # single-use: el segundo consume devuelve False
            return True
        return False

    def seed(self, state: str) -> None:
        """Inyecta un `state` ya emitido (atajo para tests que no pasan por /login)."""
        self._issued.add(state)


class FakeGitHubClient:
    """Cliente OAuth doble: canjea el code por un token fijo y devuelve identidad fija.

    Con `fail=True` lanza `GitHubAuthError` en el intercambio para ejercitar el camino de error
    saneado (502) sin red real. `exchange_calls` permite afirmar que GitHub NO se contacta cuando
    el `state` es inválido (el code solo se canjea tras validar el state).
    """

    def __init__(self, *, fail: bool = False) -> None:
        self._fail = fail
        self.exchange_calls = 0
        self.identity = GitHubIdentity(
            github_user_id=42, login=FAKE_GITHUB_LOGIN, avatar_url=None
        )

    async def exchange_code(self, code: str) -> str:
        self.exchange_calls += 1
        if self._fail:
            raise GitHubAuthError("code inválido (doble de prueba).")
        return FAKE_GITHUB_TOKEN

    async def fetch_identity(self, access_token: str) -> GitHubIdentity:
        # El doble solo conoce el token que él mismo emitió: detecta un canje incoherente.
        assert access_token == FAKE_GITHUB_TOKEN
        return self.identity


class FakeUser:
    """Doble de `app.db.models.User` con solo los campos públicos que el endpoint usa.

    `access_token_enc` simula el blob cifrado en reposo: NUNCA debe serializarse a una respuesta.
    """

    def __init__(self, user_id: uuid.UUID, login: str = FAKE_GITHUB_LOGIN) -> None:
        self.id = user_id
        self.login = login
        self.avatar_url = "https://avatars.githubusercontent.com/u/1"
        self.access_token_enc = b"encrypted-aead-blob-NEVER-serialize-this"


class FakeUserRepository:
    """Repo en memoria: hace upsert del usuario y lo indexa por id para `get_by_id`.

    Captura el token recibido (`received_token`) para verificar que el repo —y no el cliente—
    es quien custodia el secreto; el router nunca lo devuelve. `upsert_from_oauth` registra al
    usuario para que el guard pueda resolverlo después (login → ruta protegida, mismo proceso).
    """

    def __init__(self) -> None:
        self.received_token: str | None = None
        self.received_identity: GitHubIdentity | None = None
        self._users: dict[uuid.UUID, FakeUser] = {}

    async def upsert_from_oauth(
        self, identity: GitHubIdentity, access_token: str
    ) -> uuid.UUID:
        self.received_identity = identity
        self.received_token = access_token
        user_id = uuid.uuid4()
        self._users[user_id] = FakeUser(user_id, login=identity.login)
        return user_id

    async def get_by_id(self, user_id: uuid.UUID) -> FakeUser | None:
        return self._users.get(user_id)

    def add_user(self, user: FakeUser) -> None:
        """Inserta un usuario directamente (atajo para tests del guard sin pasar por OAuth)."""
        self._users[user.id] = user


class FakeSessionStore:
    """Session store en memoria con revocación REAL (mapea cookie→user_id, `destroy` borra).

    Modela la propiedad clave para R1.4: tras `destroy`, `resolve` devuelve None — la sesión
    queda invalidada server-side, no solo la cookie del cliente. Firma opaca; el detalle HMAC
    se prueba aparte en los tests unitarios de `RedisSessionStore`.
    """

    def __init__(self) -> None:
        # cookie firmada (opaca) → user_id activo.
        self._sessions: dict[str, uuid.UUID] = {}
        self.destroyed_cookies: list[str] = []
        self._counter = 0

    async def create(self, user_id: uuid.UUID) -> str:
        self._counter += 1
        cookie_value = f"session-{self._counter}.signature"
        self._sessions[cookie_value] = user_id
        return cookie_value

    async def resolve(self, cookie_value: str) -> uuid.UUID | None:
        return self._sessions.get(cookie_value)

    async def destroy(self, cookie_value: str) -> None:
        # Revocación server-side: la cookie ya no resuelve a ningún usuario.
        self.destroyed_cookies.append(cookie_value)
        self._sessions.pop(cookie_value, None)


@pytest.fixture
def state_store() -> FakeStateStore:
    return FakeStateStore()


@pytest.fixture
def github_client() -> FakeGitHubClient:
    return FakeGitHubClient()


@pytest.fixture
def user_repo() -> FakeUserRepository:
    return FakeUserRepository()


@pytest.fixture
def session_store() -> FakeSessionStore:
    return FakeSessionStore()
