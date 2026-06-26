"""Suite de aceptación de autenticación (H5-T14, cubre R1.1-R1.5).

Verifica el COMPORTAMIENTO observable del flujo OAuth de extremo a extremo, con dobles en
memoria (conftest) y SIN servicios externos (sin Redis, sin Postgres, sin GitHub real). Cada
test mapea a un criterio de aceptación EARS del Requisito 1:

- R1.1: `/auth/login` redirige a GitHub con un `state` single-use.
- R1.2: callback con `code` + `state` válidos abre sesión y redirige al dashboard.
- R1.3: `state` ausente/no-coincidente ⇒ 401 (CSRF) y NO crea sesión.
- R1.4: logout invalida la sesión server-side; un acceso protegido posterior ⇒ 401.
- R1.5: el `access_token` de GitHub NUNCA aparece en respuestas NI en logs.

Determinismo: el cliente HTTP no sigue redirects (302) y todas las dependencias externas están
sustituidas por dobles deterministas — no hay red, tiempo real ni orden de tests relevante.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import auth as auth_module
from app.auth.deps import (
    get_github_client,
    get_session_store,
    get_state_store,
    get_user_repository,
)
from app.main import create_app

from .conftest import (
    FAKE_GITHUB_LOGIN,
    FAKE_GITHUB_TOKEN,
    FAKE_OAUTH_CODE,
    FakeGitHubClient,
    FakeSessionStore,
    FakeStateStore,
    FakeUser,
    FakeUserRepository,
)

# Prefijo de versión del API: las rutas cuelgan de aquí (ver create_app).
_API = "/api/v1"


def _build_client(
    *,
    state_store: FakeStateStore,
    github_client: FakeGitHubClient,
    user_repo: FakeUserRepository,
    session_store: FakeSessionStore,
) -> TestClient:
    """TestClient con las 4 abstracciones del flujo OAuth sustituidas por dobles.

    `follow_redirects=False`: queremos inspeccionar el 302 (Location, Set-Cookie), no seguirlo.
    """
    app: FastAPI = create_app()
    app.dependency_overrides[get_state_store] = lambda: state_store
    app.dependency_overrides[get_github_client] = lambda: github_client
    app.dependency_overrides[get_user_repository] = lambda: user_repo
    app.dependency_overrides[get_session_store] = lambda: session_store
    return TestClient(app, follow_redirects=False)


@pytest.fixture(autouse=True)
def _github_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """`/auth/login` exige `github_client_id` (público): lo inyectamos para todos los tests.

    Solo se parchea el `client_id` PÚBLICO; el `client_secret` no interviene porque el cliente
    de GitHub está sustituido por un doble.
    """
    from app import settings as settings_module

    patched = settings_module.get_settings().model_copy(
        update={"github_client_id": "client-id-public"}
    )
    monkeypatch.setattr(auth_module, "get_settings", lambda: patched)


# ---------------------------------------------------------------------------
# R1.1 — login redirige a GitHub y emite un `state` single-use
# ---------------------------------------------------------------------------


def test_r1_1_login_redirige_a_github_con_state(
    state_store: FakeStateStore,
    github_client: FakeGitHubClient,
    user_repo: FakeUserRepository,
    session_store: FakeSessionStore,
) -> None:
    """AC R1.1: login emite un `state` y redirige (302) al authorize de GitHub con ese `state`."""
    client = _build_client(
        state_store=state_store,
        github_client=github_client,
        user_repo=user_repo,
        session_store=session_store,
    )

    resp = client.get(f"{_API}/auth/login")

    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://github.com/login/oauth/authorize?")
    query = parse_qs(urlparse(location).query)
    # El `state` emitido viaja en la query del authorize, NO en una cookie del cliente.
    assert query["state"] == ["state-1"]
    assert query["client_id"] == ["client-id-public"]
    assert "set-cookie" not in {k.lower() for k in resp.headers}
    assert state_store.issue_calls == 1


# ---------------------------------------------------------------------------
# R1.2 — callback válido crea/recupera cuenta, abre sesión y redirige al dashboard
# ---------------------------------------------------------------------------


def test_r1_2_callback_valido_abre_sesion_y_redirige_al_dashboard(
    state_store: FakeStateStore,
    github_client: FakeGitHubClient,
    user_repo: FakeUserRepository,
    session_store: FakeSessionStore,
) -> None:
    """AC R1.2: con `code` + `state` válidos se abre sesión (cookie httpOnly) y 302 a /dashboard."""
    state_store.seed("good-state")
    client = _build_client(
        state_store=state_store,
        github_client=github_client,
        user_repo=user_repo,
        session_store=session_store,
    )

    resp = client.get(
        f"{_API}/auth/callback", params={"state": "good-state", "code": FAKE_OAUTH_CODE}
    )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard"

    # La cookie de sesión es httpOnly + SameSite=Lax (ADR-4): no accesible por JS, anti-CSRF.
    set_cookie = resp.headers["set-cookie"]
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()

    # Se abrió exactamente una sesión, para el usuario recién upserteado con su identidad.
    assert len(session_store.destroyed_cookies) == 0
    assert user_repo.received_identity is not None
    assert user_repo.received_identity.login == FAKE_GITHUB_LOGIN
    # El repo custodia el token (lo cifra internamente); el router nunca lo expone.
    assert user_repo.received_token == FAKE_GITHUB_TOKEN


# ---------------------------------------------------------------------------
# R1.3 — `state` inválido/ausente ⇒ 401 (CSRF) y NO crea sesión
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("params", "case"),
    [
        ({"code": FAKE_OAUTH_CODE}, "state ausente"),
        ({"state": "not-issued", "code": FAKE_OAUTH_CODE}, "state no coincidente"),
        ({"error": "access_denied"}, "github devolvió error"),
    ],
)
def test_r1_3_callback_state_invalido_es_401_sin_sesion(
    params: dict[str, str],
    case: str,
    state_store: FakeStateStore,
    github_client: FakeGitHubClient,
    user_repo: FakeUserRepository,
    session_store: FakeSessionStore,
) -> None:
    """AC R1.3: callback sin `state` válido ⇒ 401, sin cookie, sin contactar GitHub, sin sesión."""
    client = _build_client(
        state_store=state_store,
        github_client=github_client,
        user_repo=user_repo,
        session_store=session_store,
    )

    resp = client.get(f"{_API}/auth/callback", params=params)

    assert resp.status_code == 401, f"caso: {case}"
    # NO se crea sesión: ni cookie en la respuesta, ni sesión en el store.
    assert "set-cookie" not in {k.lower() for k in resp.headers}
    assert session_store._sessions == {}
    # El `code` SOLO se canjea tras validar el `state`: GitHub no se contacta.
    assert github_client.exchange_calls == 0
    # El repo no persiste nada (no se llamó al upsert).
    assert user_repo.received_token is None


def test_r1_3_state_es_single_use(
    state_store: FakeStateStore,
    github_client: FakeGitHubClient,
    user_repo: FakeUserRepository,
    session_store: FakeSessionStore,
) -> None:
    """AC R1.3: un `state` ya consumido (GETDEL) no vale para un segundo callback (anti-replay)."""
    state_store.seed("one-shot")
    client = _build_client(
        state_store=state_store,
        github_client=github_client,
        user_repo=user_repo,
        session_store=session_store,
    )

    first = client.get(
        f"{_API}/auth/callback", params={"state": "one-shot", "code": FAKE_OAUTH_CODE}
    )
    assert first.status_code == 302

    # Reutilizar el mismo `state` (ataque de replay) ⇒ 401.
    second = client.get(
        f"{_API}/auth/callback", params={"state": "one-shot", "code": FAKE_OAUTH_CODE}
    )
    assert second.status_code == 401


# ---------------------------------------------------------------------------
# R1 — ruta protegida: sin sesión ⇒ 401, con sesión ⇒ 200
# ---------------------------------------------------------------------------


def test_ruta_protegida_sin_sesion_es_401(
    state_store: FakeStateStore,
    github_client: FakeGitHubClient,
    user_repo: FakeUserRepository,
    session_store: FakeSessionStore,
) -> None:
    """Sin cookie de sesión, una ruta protegida (`GET /me`) responde 401 antes del handler."""
    client = _build_client(
        state_store=state_store,
        github_client=github_client,
        user_repo=user_repo,
        session_store=session_store,
    )

    resp = client.get(f"{_API}/me")

    assert resp.status_code == 401
    # El 401 no filtra información del usuario ni del esquema interno.
    assert "login" not in resp.text


def test_ruta_protegida_con_sesion_valida_es_200(
    state_store: FakeStateStore,
    github_client: FakeGitHubClient,
    user_repo: FakeUserRepository,
    session_store: FakeSessionStore,
) -> None:
    """Con sesión activa, la ruta protegida devuelve 200 con la identidad pública del usuario."""
    user = FakeUser(uuid.uuid4(), login="sectest")
    user_repo.add_user(user)
    cookie_value = asyncio.run(session_store.create(user.id))
    client = _build_client(
        state_store=state_store,
        github_client=github_client,
        user_repo=user_repo,
        session_store=session_store,
    )
    client.cookies.set("sg_session", cookie_value)

    resp = client.get(f"{_API}/me")

    assert resp.status_code == 200
    data = resp.json()
    assert data["login"] == "sectest"
    # El blob cifrado NUNCA se serializa (R1.5).
    assert "access_token" not in resp.text


# ---------------------------------------------------------------------------
# R1.4 — logout invalida la sesión server-side: acceso protegido posterior ⇒ 401
# ---------------------------------------------------------------------------


def test_r1_4_logout_invalida_sesion_acceso_posterior_es_401(
    state_store: FakeStateStore,
    github_client: FakeGitHubClient,
    user_repo: FakeUserRepository,
    session_store: FakeSessionStore,
) -> None:
    """AC R1.4 (e2e): login → ruta protegida 200 → logout 204 → MISMA cookie en protegida ⇒ 401.

    Verifica REVOCACIÓN server-side, no solo borrado de cookie del cliente: reutilizamos el mismo
    valor de cookie tras el logout y debe dejar de resolver (la sesión ya no existe en servidor).
    """
    state_store.seed("good-state")
    client = _build_client(
        state_store=state_store,
        github_client=github_client,
        user_repo=user_repo,
        session_store=session_store,
    )

    # 1) Login completo: el callback abre sesión y fija la cookie.
    callback = client.get(
        f"{_API}/auth/callback", params={"state": "good-state", "code": FAKE_OAUTH_CODE}
    )
    assert callback.status_code == 302
    # El TestClient persiste la cookie del Set-Cookie; capturamos su valor para reutilizarlo.
    session_cookie = client.cookies.get("sg_session")
    assert session_cookie is not None

    # 2) Con la sesión activa, la ruta protegida responde 200.
    before = client.get(f"{_API}/me")
    assert before.status_code == 200

    # 3) Logout: 204 e invalidación server-side (destroy borra la sesión de Redis/del store).
    logout = client.post(f"{_API}/auth/logout")
    assert logout.status_code == 204
    assert session_cookie in session_store.destroyed_cookies

    # 4) Reusar la MISMA cookie (simulando un cliente que la conservó) ⇒ 401: sesión revocada.
    #    El logout limpió la cookie del client; la re-inyectamos a propósito para probar la
    #    revocación server-side (no basta con que el navegador la olvide).
    client.cookies.set("sg_session", session_cookie)
    after = client.get(f"{_API}/me")
    assert after.status_code == 401


def test_logout_sin_sesion_es_204_idempotente(
    state_store: FakeStateStore,
    github_client: FakeGitHubClient,
    user_repo: FakeUserRepository,
    session_store: FakeSessionStore,
) -> None:
    """Logout sin cookie de sesión ⇒ 204 (idempotente): no filtra si existía una sesión."""
    client = _build_client(
        state_store=state_store,
        github_client=github_client,
        user_repo=user_repo,
        session_store=session_store,
    )

    resp = client.post(f"{_API}/auth/logout")

    assert resp.status_code == 204
    # Sin cookie, no se invoca destroy.
    assert session_store.destroyed_cookies == []


# ---------------------------------------------------------------------------
# R1.5 — el access_token de GitHub NUNCA aparece en respuestas NI en logs
# ---------------------------------------------------------------------------


def test_r1_5_token_no_aparece_en_ninguna_respuesta(
    state_store: FakeStateStore,
    github_client: FakeGitHubClient,
    user_repo: FakeUserRepository,
    session_store: FakeSessionStore,
) -> None:
    """AC R1.5: el access_token no sale en cuerpo, headers ni cookie de ninguna respuesta."""
    state_store.seed("good-state")
    client = _build_client(
        state_store=state_store,
        github_client=github_client,
        user_repo=user_repo,
        session_store=session_store,
    )

    login = client.get(f"{_API}/auth/login")
    callback = client.get(
        f"{_API}/auth/callback", params={"state": "good-state", "code": FAKE_OAUTH_CODE}
    )
    me = client.get(f"{_API}/me")
    logout = client.post(f"{_API}/auth/logout")

    # Concatenamos cuerpo + headers (incluido Set-Cookie) de cada respuesta del flujo.
    for resp in (login, callback, me, logout):
        haystack = resp.text + "".join(f"{k}:{v}" for k, v in resp.headers.items())
        assert FAKE_GITHUB_TOKEN not in haystack


def test_r1_5_token_no_aparece_en_logs(
    state_store: FakeStateStore,
    github_client: FakeGitHubClient,
    user_repo: FakeUserRepository,
    session_store: FakeSessionStore,
) -> None:
    """AC R1.5 (OBLIGATORIO): el access_token NUNCA se escribe en los logs durante el flujo.

    Capturamos TODOS los registros emitidos a lo largo del login → callback → ruta protegida →
    logout y escaneamos tanto el mensaje formateado como los argumentos crudos. La aguja es el
    token sintético del centinela.

    No usamos `caplog`: `create_app()` ejecuta `configure_logging()`, que reemplaza los handlers
    del root logger (`root.handlers = [...]`) y descartaría el handler de caplog. En su lugar
    adjuntamos un handler propio al root DESPUÉS de construir la app, de forma determinista.
    """
    state_store.seed("good-state")

    # El cliente se construye primero: aquí corre configure_logging() (resetea root.handlers).
    client = _build_client(
        state_store=state_store,
        github_client=github_client,
        user_repo=user_repo,
        session_store=session_store,
    )

    # Handler de captura en memoria: registra cada LogRecord sin escribir a stdout. Se adjunta
    # al root DESPUÉS de configure_logging para sobrevivir al reseteo de handlers.
    records: list[logging.LogRecord] = []

    class _CapturingHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _CapturingHandler(level=logging.DEBUG)
    root_logger = logging.getLogger()
    previous_level = root_logger.level
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.DEBUG)
    try:
        client.get(f"{_API}/auth/login")
        client.get(
            f"{_API}/auth/callback",
            params={"state": "good-state", "code": FAKE_OAUTH_CODE},
        )
        # Re-inyectamos la cookie por si el cliente no la conservó entre llamadas.
        session_cookie = client.cookies.get("sg_session")
        if session_cookie is not None:
            client.cookies.set("sg_session", session_cookie)
        client.get(f"{_API}/me")
        client.post(f"{_API}/auth/logout")
    finally:
        root_logger.removeHandler(handler)
        root_logger.setLevel(previous_level)

    # Confirmamos que el flujo SÍ logueó algo de la app (si no, el test sería un falso verde).
    app_records = [r for r in records if r.name.startswith("app.")]
    assert app_records, "se esperaba al menos un log de la app durante el flujo de auth"

    # Escaneamos mensaje formateado + argumentos crudos de cada record (el formateo perezoso de
    # logging mantiene los args sin interpolar; ambos deben estar limpios del token).
    for record in records:
        assert FAKE_GITHUB_TOKEN not in record.getMessage()
        for arg in record.args or ():
            assert FAKE_GITHUB_TOKEN not in str(arg)
