"""Unit tests del cliente OAuth httpx de GitHub (H5-T11, R1.2, R9.2).

Usan `httpx.MockTransport` para no tocar la red: verifican el camino feliz (code→token,
token→identidad), el manejo de errores lógicos de GitHub (200 con `{"error": ...}`), respuestas
incompletas, status >= 400 y fallo de red — siempre traducidos a `GitHubAuthError` SIN filtrar
el cuerpo crudo de GitHub.
"""

from __future__ import annotations

import httpx
import pytest

from app.services import github as gh_module
from app.services.github import (
    GitHubAuthError,
    HttpxGitHubOAuthClient,
    build_authorize_url,
)


def _client_with_transport(handler: object) -> HttpxGitHubOAuthClient:
    """Construye el cliente y parcha `AsyncClient` para inyectar un `MockTransport`."""
    transport = httpx.MockTransport(handler)  # type: ignore[arg-type]

    class _PatchedAsyncClient(httpx.AsyncClient):
        def __init__(self, *args: object, **kwargs: object) -> None:
            kwargs.pop("timeout", None)
            super().__init__(transport=transport, timeout=5.0)

    gh_module.httpx.AsyncClient = _PatchedAsyncClient  # type: ignore[misc, attr-defined]
    return HttpxGitHubOAuthClient(
        client_id="id", client_secret="secret", redirect_uri="https://app/cb"
    )


@pytest.fixture(autouse=True)
def _restore_async_client() -> object:
    original = httpx.AsyncClient
    yield
    gh_module.httpx.AsyncClient = original  # type: ignore[misc, attr-defined]


# --- build_authorize_url ------------------------------------------------------------------


def test_authorize_url_incluye_state_y_client_id_sin_secreto() -> None:
    url = build_authorize_url(client_id="pub-id", redirect_uri="https://app/cb", state="nonce123")
    assert url.startswith("https://github.com/login/oauth/authorize?")
    assert "state=nonce123" in url
    assert "client_id=pub-id" in url
    # El scope del login de usuario es mínimo (identidad), no pide repos.
    assert "scope=read%3Auser" in url


# --- exchange_code ------------------------------------------------------------------------


async def test_exchange_code_feliz_devuelve_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/login/oauth/access_token"
        return httpx.Response(200, json={"access_token": "gho_real", "token_type": "bearer"})

    client = _client_with_transport(handler)
    assert await client.exchange_code("good-code") == "gho_real"


async def test_exchange_code_con_error_logico_de_github_falla_saneado() -> None:
    # GitHub responde 200 pero con `{"error": ...}`: NO debe interpretarse como éxito.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"error": "bad_verification_code"})

    client = _client_with_transport(handler)
    with pytest.raises(GitHubAuthError) as exc:
        await client.exchange_code("bad")
    # El detalle crudo de GitHub no se propaga.
    assert "bad_verification_code" not in str(exc.value)


async def test_exchange_code_status_4xx_es_error_saneado() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="secret-internal-detail")

    client = _client_with_transport(handler)
    with pytest.raises(GitHubAuthError) as exc:
        await client.exchange_code("x")
    assert "secret-internal-detail" not in str(exc.value)


async def test_exchange_code_fallo_de_red_es_error_saneado() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("conexión rechazada")

    client = _client_with_transport(handler)
    with pytest.raises(GitHubAuthError):
        await client.exchange_code("x")


# --- fetch_identity -----------------------------------------------------------------------


async def test_fetch_identity_feliz() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer tok"
        return httpx.Response(
            200, json={"id": 7, "login": "octo", "avatar_url": "https://a/x.png"}
        )

    client = _client_with_transport(handler)
    identity = await client.fetch_identity("tok")
    assert identity.github_user_id == 7
    assert identity.login == "octo"
    assert identity.avatar_url == "https://a/x.png"


async def test_fetch_identity_incompleta_es_fail_closed() -> None:
    # Sin `id`/`login` no inventamos identidad: error explícito (fail-closed).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"login": "octo"})

    client = _client_with_transport(handler)
    with pytest.raises(GitHubAuthError):
        await client.fetch_identity("tok")


async def test_fetch_identity_avatar_ausente_es_none() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 9, "login": "octo"})

    client = _client_with_transport(handler)
    identity = await client.fetch_identity("tok")
    assert identity.avatar_url is None
