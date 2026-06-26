"""Cliente OAuth de GitHub (frontera con GitHub) — H5-T11, R1.2, ADR-4.

Responsabilidad acotada al login OAuth: (1) intercambiar el `code` por un `access_token`
de usuario y (2) leer la identidad pública del usuario (`id`, `login`, `avatar_url`). NO
gestiona installation tokens ni Checks (eso es Ola 4); NO persiste; NO cifra.

Invariante de NO-FUGA (NFR-Seg-3): ni el `access_token` ni el `client_secret` aparecen jamás
en mensajes de error, `repr` ni logs. Los errores de GitHub se traducen a `GitHubAuthError`
con un mensaje saneado y estable; el detalle crudo de GitHub se descarta.

El contrato `GitHubOAuthClient` (Protocol) permite inyectar un doble en tests sin tocar la red.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx

# Endpoints de GitHub. El intercambio de code vive en github.com; la API de identidad en
# api.github.com. Ambos sobre TLS (httpx fuerza https por la URL absoluta).
_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"  # noqa: S105 (URL, no secreto)
_USER_URL = "https://api.github.com/user"
_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"

# Timeout duro por request a GitHub: una red lenta no debe colgar el handler del callback.
_HTTP_TIMEOUT_S = 10.0
# Scope mínimo del login OAuth de usuario: solo identidad básica. La App (installation) pide
# sus permisos por separado (mínimo privilegio, R2.1/NFR-Seg-4); aquí NO pedimos repos.
_OAUTH_SCOPE = "read:user"


class GitHubAuthError(Exception):
    """Falla saneada del flujo OAuth (code inválido, identidad incompleta, red).

    Su mensaje es estable y NUNCA contiene secretos ni el cuerpo crudo de GitHub.
    """


@dataclass(frozen=True, slots=True)
class GitHubIdentity:
    """Identidad pública mínima necesaria para el upsert de `users` (design §3.1)."""

    github_user_id: int
    login: str
    avatar_url: str | None


class GitHubOAuthClient(Protocol):
    """Contrato del cliente OAuth: inyectable para poder doblarlo en tests."""

    async def exchange_code(self, code: str) -> str:
        """Cambia el `code` del callback por un `access_token` de usuario. Devuelve el token."""
        ...

    async def fetch_identity(self, access_token: str) -> GitHubIdentity:
        """Lee la identidad pública del usuario dueño del `access_token`."""
        ...


def build_authorize_url(*, client_id: str, redirect_uri: str, state: str) -> str:
    """URL de autorización a la que redirige `/auth/login` (R1.1).

    `state` es el nonce anti-CSRF de un solo uso; viaja en la query y GitHub lo devuelve tal
    cual en el callback. No incluye secretos (el `client_id` es público).
    """
    params = httpx.QueryParams(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": _OAUTH_SCOPE,
            "state": state,
            # `allow_signup=false`: el login es para cuentas existentes (demo single-tenant).
            "allow_signup": "false",
        }
    )
    return f"{_AUTHORIZE_URL}?{params}"


class HttpxGitHubOAuthClient:
    """Implementación real con httpx async. Cumple `GitHubOAuthClient`.

    El `client_secret` se mantiene en memoria del servidor y solo viaja a GitHub por TLS en el
    cuerpo del POST de intercambio; nunca se loguea ni se devuelve.
    """

    def __init__(self, *, client_id: str, client_secret: str, redirect_uri: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri

    async def exchange_code(self, code: str) -> str:
        """POST a GitHub para canjear `code`→`access_token` (R1.2).

        GitHub responde 200 incluso en error lógico (devuelve `{"error": ...}` en el JSON), así
        que NO basta con el status: se valida la presencia de `access_token`.
        """
        payload = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code": code,
            "redirect_uri": self._redirect_uri,
        }
        data = await self._post_json(_ACCESS_TOKEN_URL, payload)

        token = data.get("access_token")
        if not isinstance(token, str) or not token:
            # `data` puede traer `{"error": "bad_verification_code"}`; NO lo propagamos al cliente.
            raise GitHubAuthError("GitHub no devolvió un access_token para el code recibido.")
        return token

    async def fetch_identity(self, access_token: str) -> GitHubIdentity:
        """GET /user autenticado con el token de usuario; extrae la identidad mínima."""
        data = await self._get_json(_USER_URL, access_token)

        raw_id = data.get("id")
        login = data.get("login")
        if not isinstance(raw_id, int) or not isinstance(login, str) or not login:
            # Respuesta de identidad incompleta/inesperada: fail-closed, no inventamos identidad.
            raise GitHubAuthError("GitHub devolvió una identidad de usuario incompleta.")

        avatar = data.get("avatar_url")
        avatar_url = avatar if isinstance(avatar, str) and avatar else None
        return GitHubIdentity(github_user_id=raw_id, login=login, avatar_url=avatar_url)

    async def _post_json(self, url: str, payload: dict[str, str]) -> dict[str, object]:
        """POST con `Accept: application/json` y manejo saneado de fallos de red/HTTP."""
        headers = {"Accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S) as client:
                response = await client.post(url, data=payload, headers=headers)
        except httpx.HTTPError as exc:
            # Timeout/DNS/TLS: error genérico saneado. No incluimos `exc` (puede traer la URL con
            # query sensible en otros call-sites); el tipo concreto no aporta al cliente.
            raise GitHubAuthError(
                "No se pudo contactar a GitHub para el intercambio OAuth."
            ) from exc
        return self._parse_json(response)

    async def _get_json(self, url: str, access_token: str) -> dict[str, object]:
        """GET autenticado con Bearer token; manejo saneado de fallos de red/HTTP."""
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {access_token}",
        }
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise GitHubAuthError("No se pudo contactar a GitHub para leer la identidad.") from exc
        return self._parse_json(response)

    @staticmethod
    def _parse_json(response: httpx.Response) -> dict[str, object]:
        """Valida status y decodifica un objeto JSON; nunca filtra el cuerpo crudo en errores."""
        if response.status_code >= 400:
            # No exponemos `response.text`: podría contener pistas o, peor, headers reflejados.
            raise GitHubAuthError(f"GitHub respondió con estado {response.status_code}.")
        try:
            body = response.json()
        except ValueError as exc:
            raise GitHubAuthError("GitHub devolvió una respuesta no-JSON.") from exc
        if not isinstance(body, dict):
            raise GitHubAuthError("GitHub devolvió un JSON con forma inesperada.")
        return body
