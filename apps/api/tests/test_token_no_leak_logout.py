"""Token de GitHub cifrado + logout server-side (H5-T13, R1.4/R1.5, ADR-4).

Cubre:
- POST /auth/logout invalida la sesión server-side (destroy en SessionStore) y limpia cookie.
- Logout sin cookie activa es 204 (idempotente, no filtra existencia).
- El token de GitHub NUNCA aparece en ninguna respuesta ni header (verificación exhaustiva).
- `assert_no_token_leak` detecta correctamente fugas en strings arbitrarios.
- `access_token_enc` del ORM User nunca se serializa en ningún endpoint expuesto.

Todo con dobles en memoria: sin Redis, sin Postgres, sin GitHub.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.auth.deps import get_session_store, get_user_repository
from app.db.models import User
from app.main import create_app
from app.security.crypto import assert_no_token_leak

# Centinela de no-fuga: valor que no debe aparecer en ninguna respuesta HTTP.
_FAKE_TOKEN = "gho_test_secret_MUST_NOT_LEAK_1234567890"


# ---------------------------------------------------------------------------
# Dobles
# ---------------------------------------------------------------------------


class FakeSessionStore:
    """Store de sesión en memoria. Registra llamadas a `destroy` para aserción."""

    def __init__(self, user_id: uuid.UUID | None = None) -> None:
        self._user_id = user_id
        self.destroyed_cookies: list[str] = []

    async def create(self, user_id: uuid.UUID) -> str:
        return "fake-cookie.fakesig"

    async def resolve(self, cookie_value: str) -> uuid.UUID | None:
        return self._user_id

    async def destroy(self, cookie_value: str) -> None:
        """Registra el cookie_value para verificar que logout invocó destroy."""
        self.destroyed_cookies.append(cookie_value)


class FakeUserRepository:
    """Repositorio de usuarios en memoria."""

    def __init__(self, user: User | None = None) -> None:
        self._user = user

    async def upsert_from_oauth(self, identity: Any, access_token: str) -> uuid.UUID:
        raise NotImplementedError

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        return self._user


def _make_user(login: str = "octocat") -> User:
    """Construye un User simulado en memoria con un token cifrado ficticio."""
    user: User = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.login = login
    user.avatar_url = "https://avatars.githubusercontent.com/u/1"
    # El token cifrado NUNCA debe aparecer en ninguna respuesta (incluso en bytes no decodificados).
    user.access_token_enc = b"encrypted-aead-blob-NEVER-serialize-this"
    return user


def _make_client(
    session_store: FakeSessionStore,
    user_repo: FakeUserRepository,
) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_session_store] = lambda: session_store
    app.dependency_overrides[get_user_repository] = lambda: user_repo
    return TestClient(app, follow_redirects=False)


# ---------------------------------------------------------------------------
# Tests: POST /auth/logout
# ---------------------------------------------------------------------------


def test_logout_con_sesion_activa_devuelve_204() -> None:
    """Logout con cookie válida → 204. No hay cuerpo en la respuesta."""
    user = _make_user()
    store = FakeSessionStore(user_id=user.id)
    repo = FakeUserRepository(user=user)
    client = _make_client(store, repo)

    resp = client.post("/api/v1/auth/logout", cookies={"sg_session": "valid.cookie"})

    assert resp.status_code == 204
    assert resp.content == b""


def test_logout_invoca_destroy_en_session_store() -> None:
    """Logout llama a `SessionStore.destroy` con el valor de cookie → invalidación server-side."""
    user = _make_user()
    store = FakeSessionStore(user_id=user.id)
    repo = FakeUserRepository(user=user)
    client = _make_client(store, repo)

    client.post("/api/v1/auth/logout", cookies={"sg_session": "valid.cookie.sig"})

    # El store debe haber recibido exactamente una llamada a destroy con el cookie enviado.
    assert len(store.destroyed_cookies) == 1
    assert store.destroyed_cookies[0] == "valid.cookie.sig"


def test_logout_sin_cookie_es_204_noop() -> None:
    """Logout sin cookie de sesión → 204 sin errores (idempotente, no filtra existencia)."""
    store = FakeSessionStore(user_id=None)
    repo = FakeUserRepository(user=None)
    client = _make_client(store, repo)

    resp = client.post("/api/v1/auth/logout")

    assert resp.status_code == 204
    # Sin cookie, destroy nunca se invoca.
    assert len(store.destroyed_cookies) == 0


def test_logout_limpia_la_cookie_en_el_cliente() -> None:
    """La respuesta 204 incluye Set-Cookie con Max-Age=0 para borrar la cookie del navegador."""
    user = _make_user()
    store = FakeSessionStore(user_id=user.id)
    repo = FakeUserRepository(user=user)
    client = _make_client(store, repo)

    resp = client.post("/api/v1/auth/logout", cookies={"sg_session": "valid.sig"})

    # Debe haber al menos una directiva Set-Cookie en la respuesta.
    assert "set-cookie" in {k.lower() for k in resp.headers}
    set_cookie_values = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
    # Al menos una cookie debe tener Max-Age=0 (expiración inmediata) o path.
    # `delete_cookie` de FastAPI/Starlette fija Max-Age=0 y Expires en el pasado.
    assert any("max-age=0" in c.lower() for c in set_cookie_values)


def test_logout_borra_host_prefix_cookie_siempre_con_secure_en_dev() -> None:
    """SEC: la variante `__Host-` se borra SIEMPRE con `Secure`, incluso en desarrollo.

    Un `Set-Cookie` de borrado para una cookie con prefijo `__Host-` SIN `Secure` es inválido
    (RFC 6265bis): el navegador lo ignora y la cookie no se borraría. La app de test corre en
    `development` (secure=False); aun así, la directiva de la variante `__Host-` debe llevar
    `Secure`. La variante de nombre llano (dev) se borra sin `Secure`.
    """
    user = _make_user()
    store = FakeSessionStore(user_id=user.id)
    repo = FakeUserRepository(user=user)
    client = _make_client(store, repo)

    resp = client.post("/api/v1/auth/logout", cookies={"sg_session": "valid.sig"})

    # `get_list` separa cada Set-Cookie en su propia directiva (items() las une por coma).
    set_cookies = resp.headers.get_list("set-cookie")
    host_directive = next(c for c in set_cookies if c.startswith("__Host-sg_session="))
    dev_directive = next(c for c in set_cookies if c.startswith("sg_session="))
    # La variante con prefijo `__Host-` DEBE llevar Secure aunque el entorno sea dev.
    assert "secure" in host_directive.lower()
    # La variante de nombre llano (dev) se borra sin Secure (coherente con su Set-Cookie original).
    assert "secure" not in dev_directive.lower()


def test_logout_no_filtra_token_en_respuesta() -> None:
    """Logout no expone el token ni ningún secreto en cuerpo ni headers."""
    user = _make_user()
    store = FakeSessionStore(user_id=user.id)
    repo = FakeUserRepository(user=user)
    client = _make_client(store, repo)

    resp = client.post(
        "/api/v1/auth/logout",
        cookies={"sg_session": _FAKE_TOKEN + ".fakesig"},
    )

    # El centinela no debe aparecer en cuerpo ni headers de la respuesta.
    assert_no_token_leak(_FAKE_TOKEN, resp.text, *resp.headers.values())


def test_logout_sesion_ya_destruida_es_204() -> None:
    """Logout sobre sesión ya revocada → 204 sin errores (idempotencia)."""
    store = FakeSessionStore(user_id=None)  # resolve devuelve None: sesión inexistente
    repo = FakeUserRepository(user=None)
    client = _make_client(store, repo)

    # Aunque la cookie esté presente, la sesión ya no existe en servidor.
    resp = client.post("/api/v1/auth/logout", cookies={"sg_session": "expired.sig"})

    # Destroy se llama (es no-op en el store real), pero la respuesta sigue siendo 204.
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Tests: token nunca en respuestas de la API (no-serialización en DTOs)
# ---------------------------------------------------------------------------


def test_get_me_no_expone_access_token_enc() -> None:
    """GET /me nunca serializa `access_token_enc` del ORM User (R1.5, NFR-Seg-3)."""
    user = _make_user()
    store = FakeSessionStore(user_id=user.id)
    repo = FakeUserRepository(user=user)
    client = _make_client(store, repo)

    resp = client.get("/api/v1/me", cookies={"sg_session": "valid.sig"})

    assert resp.status_code == 200
    # El blob cifrado (incluso como repr parcial) nunca debe aparecer en la respuesta.
    assert "access_token" not in resp.text
    assert "access_token_enc" not in resp.text
    assert "encrypted-aead-blob" not in resp.text
    # Verificación con helper de no-fuga (simula que el token crudo fuera "encrypted-aead-blob").
    assert_no_token_leak("encrypted-aead-blob", resp.text, *resp.headers.values())


def test_get_me_campos_devueltos_son_exactamente_id_login_avatar() -> None:
    """GET /me devuelve SOLO id, login y avatar_url — nada más (schema sellado)."""
    user = _make_user("sectest")
    store = FakeSessionStore(user_id=user.id)
    repo = FakeUserRepository(user=user)
    client = _make_client(store, repo)

    resp = client.get("/api/v1/me", cookies={"sg_session": "valid.sig"})

    assert resp.status_code == 200
    data = resp.json()
    # El schema solo tiene estos tres campos; cualquier campo extra rompe la invariante.
    assert set(data.keys()) == {"id", "login", "avatar_url"}


# ---------------------------------------------------------------------------
# Tests: helper assert_no_token_leak
# ---------------------------------------------------------------------------


def test_assert_no_token_leak_pasa_cuando_no_hay_fuga() -> None:
    """No lanza cuando el token no aparece en ningún haystack."""
    assert_no_token_leak("secret-token", "body sin el token", "otro header", "")


def test_assert_no_token_leak_detecta_fuga_en_cuerpo() -> None:
    """Lanza AssertionError cuando el token aparece en el cuerpo."""
    with pytest.raises(AssertionError, match="Fuga de token"):
        assert_no_token_leak("mi-secreto", "la respuesta contiene mi-secreto aquí")


def test_assert_no_token_leak_detecta_fuga_en_segundo_haystack() -> None:
    """Detecta fuga incluso cuando está en el segundo haystack (no solo el primero)."""
    with pytest.raises(AssertionError, match="haystack\\[1\\]"):
        assert_no_token_leak("tk", "cuerpo limpio", "header-con-tk-filtrado")


def test_assert_no_token_leak_mensaje_no_expone_token() -> None:
    """El AssertionError no expone el token en claro en su mensaje."""
    token = "super-secret-value-xyz"
    try:
        assert_no_token_leak(token, f"text con {token}")
        pytest.fail("Debía haber lanzado AssertionError")
    except AssertionError as exc:
        # El mensaje contiene redact(...) del token, nunca el valor en claro.
        assert token not in str(exc), (
            f"El token en claro aparece en el mensaje de error: {exc}"
        )
