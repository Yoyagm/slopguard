"""Flujo OAuth GitHub (H5-T11, R1.1/R1.2/R1.3, NFR-Seg-1).

Cubre: login emite `state` y redirige a GitHub; callback con `state` válido abre sesión y
redirige al dashboard; `state` ausente/no-coincidente/reusado ⇒ 401 sin sesión (CSRF); errores
de GitHub saneados; y la invariante crítica: el `access_token` NUNCA aparece en la respuesta
(cuerpo, headers ni cookie). Todo con dobles en memoria (sin Redis/GitHub/Postgres reales).
"""

from __future__ import annotations

import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.api import auth as auth_module
from app.auth.deps import (
    get_github_client,
    get_session_store,
    get_state_store,
    get_user_repository,
)
from app.main import create_app
from app.services.github import GitHubAuthError, GitHubIdentity

# Token sintético que NO debe filtrarse a ninguna respuesta (centinela de no-fuga).
_FAKE_TOKEN = "gho_fake_secret_token_value_DO_NOT_LEAK"
_FAKE_CODE = "valid-oauth-code"


# --- Dobles en memoria de las abstracciones inyectables -----------------------------------


class FakeStateStore:
    """State store en memoria con la misma semántica single-use (consume borra)."""

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
            self._issued.discard(state)  # single-use: el segundo consume falla
            return True
        return False

    def seed(self, state: str) -> None:
        self._issued.add(state)


class FakeGitHubClient:
    """Cliente OAuth doble: devuelve un token e identidad fijos, o lanza `GitHubAuthError`."""

    def __init__(self, *, fail: bool = False) -> None:
        self._fail = fail
        self.exchange_calls = 0
        self.identity = GitHubIdentity(github_user_id=42, login="octocat", avatar_url=None)

    async def exchange_code(self, code: str) -> str:
        self.exchange_calls += 1
        if self._fail:
            raise GitHubAuthError("code inválido (doble de prueba).")
        return _FAKE_TOKEN

    async def fetch_identity(self, access_token: str) -> GitHubIdentity:
        assert access_token == _FAKE_TOKEN
        return self.identity


class FakeUserRepository:
    """Repo doble: captura el token recibido para verificar que se cifró/no se filtró."""

    def __init__(self) -> None:
        self.received_token: str | None = None
        self.received_identity: GitHubIdentity | None = None
        self.user_id = uuid.uuid4()

    async def upsert_from_oauth(self, identity: GitHubIdentity, access_token: str) -> uuid.UUID:
        self.received_identity = identity
        self.received_token = access_token
        return self.user_id


class FakeSessionStore:
    """Session store doble: registra el user_id y devuelve un valor de cookie opaco."""

    def __init__(self) -> None:
        self.created_for: uuid.UUID | None = None

    async def create(self, user_id: uuid.UUID) -> str:
        self.created_for = user_id
        return "opaque-session-cookie-value.signature"


# --- Fixtures -----------------------------------------------------------------------------


@pytest.fixture
def fakes() -> dict[str, object]:
    return {
        "state": FakeStateStore(),
        "github": FakeGitHubClient(),
        "users": FakeUserRepository(),
        "sessions": FakeSessionStore(),
    }


def _client(fakes: dict[str, object], *, github: object | None = None) -> TestClient:
    """TestClient con las 4 abstracciones sustituidas por dobles. NO sigue redirects (302)."""
    app = create_app()
    app.dependency_overrides[get_state_store] = lambda: fakes["state"]
    app.dependency_overrides[get_github_client] = lambda: github or fakes["github"]
    app.dependency_overrides[get_user_repository] = lambda: fakes["users"]
    app.dependency_overrides[get_session_store] = lambda: fakes["sessions"]
    return TestClient(app, follow_redirects=False)


@pytest.fixture(autouse=True)
def _github_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """`/auth/login` exige `github_client_id` (público); lo inyectamos para los tests."""
    from app import settings as settings_module

    base = settings_module.get_settings()
    patched = base.model_copy(update={"github_client_id": "client-id-public"})
    monkeypatch.setattr(auth_module, "get_settings", lambda: patched)


# --- /auth/login --------------------------------------------------------------------------


def test_login_emite_state_y_redirige_a_github(fakes: dict[str, object]) -> None:
    client = _client(fakes)
    resp = client.get("/api/v1/auth/login")

    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://github.com/login/oauth/authorize?")
    query = parse_qs(urlparse(location).query)
    # El `state` emitido viaja en la query y NO en una cookie.
    assert query["state"] == ["state-1"]
    assert query["client_id"] == ["client-id-public"]
    assert "set-cookie" not in {k.lower() for k in resp.headers}
    state_store = fakes["state"]
    assert isinstance(state_store, FakeStateStore)
    assert state_store.issue_calls == 1


def test_login_sin_client_id_redirige_a_login_con_error(
    fakes: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    from app import settings as settings_module

    sin_id = settings_module.get_settings().model_copy(update={"github_client_id": None})
    monkeypatch.setattr(auth_module, "get_settings", lambda: sin_id)
    client = _client(fakes)
    resp = client.get("/api/v1/auth/login")
    # Sin OAuth configurado: en lugar de un JSON 503 crudo, redirige a la pantalla de login del
    # front con un código de error que esta traduce a un mensaje legible (UX profesional).
    assert resp.status_code == 302
    assert (
        resp.headers["location"] == "http://localhost:3000/login?error=oauth_unavailable"
    )


# --- /auth/callback feliz -----------------------------------------------------------------


def test_callback_valido_abre_sesion_y_redirige_al_dashboard(fakes: dict[str, object]) -> None:
    state_store = fakes["state"]
    assert isinstance(state_store, FakeStateStore)
    state_store.seed("good-state")

    client = _client(fakes)
    resp = client.get("/api/v1/auth/callback", params={"state": "good-state", "code": _FAKE_CODE})

    assert resp.status_code == 302
    assert resp.headers["location"] == "http://localhost:3000/dashboard"

    # Cookie de sesión httpOnly + SameSite=Lax presente.
    set_cookie = resp.headers["set-cookie"]
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()

    sessions = fakes["sessions"]
    users = fakes["users"]
    assert isinstance(sessions, FakeSessionStore)
    assert isinstance(users, FakeUserRepository)
    # La sesión se abrió para el user del upsert.
    assert sessions.created_for == users.user_id
    # El repo recibió el token (que cifra internamente) y la identidad correcta.
    assert users.received_token == _FAKE_TOKEN
    assert users.received_identity is not None
    assert users.received_identity.login == "octocat"


def test_callback_token_nunca_aparece_en_la_respuesta(fakes: dict[str, object]) -> None:
    """Invariante de no-fuga (R1.5): el access_token no sale en cuerpo, headers ni cookie."""
    state_store = fakes["state"]
    assert isinstance(state_store, FakeStateStore)
    state_store.seed("good-state")

    client = _client(fakes)
    resp = client.get("/api/v1/auth/callback", params={"state": "good-state", "code": _FAKE_CODE})

    haystack = resp.text + "".join(f"{k}:{v}" for k, v in resp.headers.items())
    assert _FAKE_TOKEN not in haystack
    # Aunque el centinela se haya consumido, el código real cifra; el cliente jamás lo ve.


# --- /auth/callback CSRF (R1.3) -----------------------------------------------------------


def test_callback_state_ausente_es_401_sin_sesion(fakes: dict[str, object]) -> None:
    client = _client(fakes)
    resp = client.get("/api/v1/auth/callback", params={"code": _FAKE_CODE})

    assert resp.status_code == 401
    assert "set-cookie" not in {k.lower() for k in resp.headers}
    github = fakes["github"]
    assert isinstance(github, FakeGitHubClient)
    # Sin state válido, GitHub NUNCA se contacta (no se canjea el code).
    assert github.exchange_calls == 0


def test_callback_state_no_coincidente_es_401(fakes: dict[str, object]) -> None:
    client = _client(fakes)
    resp = client.get(
        "/api/v1/auth/callback", params={"state": "no-emitido", "code": _FAKE_CODE}
    )
    assert resp.status_code == 401
    github = fakes["github"]
    assert isinstance(github, FakeGitHubClient)
    assert github.exchange_calls == 0


def test_callback_state_es_single_use(fakes: dict[str, object]) -> None:
    """El `state` se consume (GETDEL): un segundo callback con el mismo state es 401."""
    state_store = fakes["state"]
    assert isinstance(state_store, FakeStateStore)
    state_store.seed("one-shot")

    client = _client(fakes)
    first = client.get("/api/v1/auth/callback", params={"state": "one-shot", "code": _FAKE_CODE})
    assert first.status_code == 302

    second = client.get("/api/v1/auth/callback", params={"state": "one-shot", "code": _FAKE_CODE})
    assert second.status_code == 401


def test_callback_con_error_de_github_es_401(fakes: dict[str, object]) -> None:
    """GitHub redirige con `error` (acceso denegado): 401 sin sesión, sin contactar a GitHub."""
    client = _client(fakes)
    resp = client.get("/api/v1/auth/callback", params={"error": "access_denied"})
    assert resp.status_code == 401
    github = fakes["github"]
    assert isinstance(github, FakeGitHubClient)
    assert github.exchange_calls == 0


def test_callback_state_valido_pero_sin_code_es_401(fakes: dict[str, object]) -> None:
    state_store = fakes["state"]
    assert isinstance(state_store, FakeStateStore)
    state_store.seed("good-state")
    client = _client(fakes)
    resp = client.get("/api/v1/auth/callback", params={"state": "good-state"})
    assert resp.status_code == 401


# --- /auth/callback errores de GitHub (R9.2) ----------------------------------------------


def test_callback_github_error_es_502_saneado(fakes: dict[str, object]) -> None:
    """Code inválido / red caída en GitHub ⇒ 502 saneado, sin sesión, sin secretos."""
    state_store = fakes["state"]
    assert isinstance(state_store, FakeStateStore)
    state_store.seed("good-state")

    failing_github = FakeGitHubClient(fail=True)
    client = _client(fakes, github=failing_github)
    resp = client.get(
        "/api/v1/auth/callback", params={"state": "good-state", "code": "bad-code"}
    )

    assert resp.status_code == 502
    assert "set-cookie" not in {k.lower() for k in resp.headers}
    sessions = fakes["sessions"]
    assert isinstance(sessions, FakeSessionStore)
    assert sessions.created_for is None  # no se abrió sesión
    # El mensaje saneado no expone el detalle interno del doble.
    assert "code inválido" not in resp.text
