"""Tests de defensa SSRF / path-injection vía `full_name` (SEC MINOR 4, NFR-Seg-3, ADR-4).

`full_name` ("owner/repo") proviene del webhook y se persiste; luego se interpola al construir la
URL de la GitHub Contents API. Un `full_name` anómalo ('..', '%2F', '@host', '?', múltiples '/')
podría reescribir host/path (SSRF). Estos tests fijan dos barreras independientes:

1. BORDE del webhook (`events._parse_repo` / `parse_installation_event`): un repo con `full_name`
   malformado hace fallar el parseo con `MalformedEventError`, de modo que NUNCA se persiste.
2. Cliente real (`HttpxGitHubContentsClient.fetch_manifest`): aunque algo malicioso llegara a la
   capa de red, se rechaza con `RepoUnavailableError` ANTES de tocar httpx (sin salir a la red).

Las cadenas maliciosas son sintéticas; ninguna llega a producir una petición HTTP.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.github_app.contents_client import (
    HttpxGitHubContentsClient,
    RepoUnavailableError,
    validate_full_name,
)
from app.github_app.events import MalformedEventError, parse_installation_event

# Catálogo de `full_name` maliciosos/anómalos: cada uno intenta reescribir host o path, escapar la
# autoridad de api.github.com, o inyectar query/fragment/encoding.
_MALICIOUS_FULL_NAMES = [
    "..",  # traversal sin segundo segmento
    "../etc",  # traversal con prefijo
    "owner/..",  # segundo segmento traversal
    "../../owner/repo",  # demasiados segmentos + traversal
    "owner/repo/extra",  # tres segmentos (path injection)
    "owner%2Frepo",  # slash codificado (sin '/' literal → un solo segmento)
    "owner/repo%2F..",  # encoding + traversal en segundo segmento
    "evil.host/repo?x=1",  # query string
    "evil.host/repo#frag",  # fragmento
    "@evil.host/repo",  # userinfo/host injection
    "evil.host:443/repo",  # puerto/host injection
    "owner /repo",  # espacio (no es char seguro)
    "owner/repo\n",  # CRLF / salto de línea
    "",  # vacío
    "/repo",  # owner vacío
    "owner/",  # repo vacío
    "http://evil.host/repo",  # esquema embebido
]


# ---------------------------------------------------------------------------
# validate_full_name — unidad
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("full_name", _MALICIOUS_FULL_NAMES)
def test_validate_full_name_rejects_malicious(full_name: str) -> None:
    """Cualquier `full_name` anómalo se rechaza con `RepoUnavailableError` saneado."""
    with pytest.raises(RepoUnavailableError) as exc_info:
        validate_full_name(full_name)
    # El mensaje no debe ecoar el valor crudo del input (no input reflection).
    assert full_name not in str(exc_info.value) or full_name == ""


@pytest.mark.parametrize(
    "full_name",
    ["octocat/hello-world", "Org_1/repo.name", "a/b", "user-name/repo-123", "x.y/z_w"],
)
def test_validate_full_name_accepts_legit(full_name: str) -> None:
    """Nombres legítimos de GitHub (owner/repo con chars seguros) se aceptan."""
    owner, repo = validate_full_name(full_name)
    assert f"{owner}/{repo}" == full_name


# ---------------------------------------------------------------------------
# Barrera 1 — el webhook NO persiste un full_name malicioso
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("full_name", _MALICIOUS_FULL_NAMES)
def test_webhook_parse_rejects_malicious_full_name(full_name: str) -> None:
    """`parse_installation_event` falla (MalformedEventError) ante un repo con full_name anómalo.

    Como el router hace ack sin persistir ante `MalformedEventError`, un full_name malicioso jamás
    llega a la DB ni, por extensión, a la Contents API.
    """
    payload = {
        "action": "created",
        "installation": {"id": 1, "account": {"login": "octo", "id": 9}},
        "repositories": [{"id": 5, "full_name": full_name, "private": False}],
    }
    with pytest.raises(MalformedEventError):
        parse_installation_event(payload)


def test_webhook_parse_accepts_legit_full_name() -> None:
    """Un repo con full_name legítimo se parsea correctamente (no falso positivo)."""
    payload = {
        "action": "created",
        "installation": {"id": 1, "account": {"login": "octo", "id": 9}},
        "repositories": [{"id": 5, "full_name": "octo/legit-repo", "private": True}],
    }
    _action, data = parse_installation_event(payload)
    assert data.repos[0].full_name == "octo/legit-repo"


# ---------------------------------------------------------------------------
# Barrera 2 — el cliente real rechaza sin salir a la red
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("full_name", _MALICIOUS_FULL_NAMES)
async def test_fetch_manifest_rejects_malicious_without_network(full_name: str) -> None:
    """`fetch_manifest` con un full_name malicioso lanza RepoUnavailableError SIN llamar a httpx."""
    client = HttpxGitHubContentsClient()
    http_spy = MagicMock()
    with patch("app.github_app.contents_client.httpx.AsyncClient", http_spy):
        with pytest.raises(RepoUnavailableError):
            await client.fetch_manifest(
                token="ghs_FAKE_TOKEN_DO_NOT_LEAK",
                full_name=full_name,
                path="requirements.txt",
            )
    # La validación ocurre ANTES de construir el cliente HTTP: no se salió a la red.
    http_spy.assert_not_called()


async def test_fetch_manifest_token_not_in_error(caplog: pytest.LogCaptureFixture) -> None:
    """El token nunca aparece en el error ni en los logs al rechazar un full_name malicioso."""
    client = HttpxGitHubContentsClient()
    secret_token = "ghs_SUPER_SECRET_DO_NOT_LEAK_0xFEED"
    http_spy = MagicMock()
    with caplog.at_level("WARNING", logger="app.github_app.contents_client"):
        with patch("app.github_app.contents_client.httpx.AsyncClient", http_spy):
            with pytest.raises(RepoUnavailableError) as exc_info:
                await client.fetch_manifest(
                    token=secret_token,
                    full_name="@evil.host/repo",
                    path="requirements.txt",
                )
    assert secret_token not in str(exc_info.value)
    for record in caplog.records:
        assert secret_token not in record.getMessage()
