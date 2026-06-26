"""Tests del GitHubAppTokenClient y endpoints /installations + /repos (H5-T23, R2.3/R2.5).

Cubre:
  - Firma JWT RS256: payload correcto (`iss`, `iat`, `exp`), algoritmo RS256, verificable con
    la clave pública correspondiente.
  - `HttpxGitHubAppTokenClient.get_installation_token`: llama a GitHub una sola vez; si hay caché
    Redis no vuelve a llamar; si falla la caché, hace fetch normalmente.
  - Token nunca aparece en logs (invariante ADR-4).
  - GET /api/v1/installations: sin sesión→401; con sesión→lista; instalación revocada→incluida.
  - GET /api/v1/repos: sin sesión→401; repos solo de instalaciones activas; filtro por
    `installation_id` correcto.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import jwt  # PyJWT
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.deps import get_session_store, get_user_repository
from app.auth.guard import require_user
from app.github_app.deps import get_installation_repository
from app.github_app.installation_repo import (
    FakeInstallationRepository,
    InstallationData,
    RepoData,
)
from app.github_app.token_client import (
    HttpxGitHubAppTokenClient,
    InstallationTokenError,
    _aad_for_installation,
    _pem_bytes_from_setting,
    _sign_app_jwt,
)
from app.main import create_app
from app.security.crypto import decrypt_str, encrypt_str, reset_cipher_cache
from tests.conftest import FakeUser

# ---------------------------------------------------------------------------
# Fixtures de clave RSA (generadas en memoria, sin relación con producción)
# ---------------------------------------------------------------------------

_APP_ID = "999"
_INSTALLATION_ID = 12345
_FAKE_TOKEN = "ghs_FAKE_INSTALL_TOKEN_DO_NOT_LEAK"


@pytest.fixture(scope="session")
def rsa_private_key_pem() -> bytes:
    """Clave RSA privada generada para los tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())


@pytest.fixture(scope="session")
def rsa_public_key_pem(rsa_private_key_pem: bytes) -> bytes:
    """Clave pública correspondiente para verificar la firma en tests."""
    key = load_pem_private_key(rsa_private_key_pem, password=None)
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


# ---------------------------------------------------------------------------
# Tests de firma JWT
# ---------------------------------------------------------------------------


class TestSignAppJwt:
    """Tests unitarios de la función `_sign_app_jwt`."""

    def test_payload_fields(
        self, rsa_private_key_pem: bytes, rsa_public_key_pem: bytes
    ) -> None:
        """El JWT debe contener `iss`, `iat`, `exp` verificables con la clave pública."""
        before = int(time.time())
        token = _sign_app_jwt(_APP_ID, rsa_private_key_pem)
        after = int(time.time())

        # Verificamos con la clave pública (RS256).
        claims = jwt.decode(
            token,
            rsa_public_key_pem,
            algorithms=["RS256"],
            # PyJWT verifica exp; leeway para cubrir el margen de reloj (-60s en iat).
            leeway=120,
        )
        assert claims["iss"] == _APP_ID
        # `iat` debe estar en el pasado (se resta 60s para tolerancia de reloj).
        assert claims["iat"] <= before
        # `exp` debe ser futuro.
        assert claims["exp"] > after

    def test_algorithm_is_rs256(self, rsa_private_key_pem: bytes) -> None:
        """El encabezado debe declarar RS256."""
        token = _sign_app_jwt(_APP_ID, rsa_private_key_pem)
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"

    def test_invalid_key_raises(self) -> None:
        """Una clave PEM malformada debe lanzar excepción (no silencia errores criptográficos)."""
        with pytest.raises(Exception):  # noqa: B017 — cualquier excepción cripto
            _sign_app_jwt(_APP_ID, b"not-a-valid-pem-key")


# ---------------------------------------------------------------------------
# Tests de normalización de PEM
# ---------------------------------------------------------------------------


class TestPemBytesFromSetting:
    def test_replaces_escaped_newlines(self) -> None:
        """\\n literales en variables de entorno se convierten en saltos reales."""
        raw = "-----BEGIN RSA PRIVATE KEY-----\\nMIIE...\\n-----END RSA PRIVATE KEY-----\\n"
        result = _pem_bytes_from_setting(raw)
        assert b"\\n" not in result
        assert b"\n" in result

    def test_idempotent_with_real_newlines(self) -> None:
        """Si ya tiene saltos reales, no cambia nada."""
        raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
        result = _pem_bytes_from_setting(raw)
        assert result == raw.encode("utf-8")


# ---------------------------------------------------------------------------
# Helpers para mockear httpx.AsyncClient como context manager async
# ---------------------------------------------------------------------------


def _make_httpx_mock(token: str = _FAKE_TOKEN, status_code: int = 201) -> Any:
    """Construye un mock de httpx.AsyncClient que actúa como context manager async.

    El patrón `async with httpx.AsyncClient(...) as client:` necesita que el mock
    soporte `__aenter__` devolviendo el propio mock y `__aexit__` retornando False.
    """
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = {"token": token, "expires_at": "2099-01-01T00:00:00Z"}

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=response)
    # El context manager async devuelve el mock_client al hacer `async with ... as c`.
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    # La clase mockeada debe devolver el mock_client al ser instanciada.
    mock_cls = MagicMock(return_value=mock_client)
    return mock_cls


# ---------------------------------------------------------------------------
# Tests del HttpxGitHubAppTokenClient (sin red)
# ---------------------------------------------------------------------------


class FakeRedis:
    """Redis stub en memoria para tests del caché de tokens."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self.get_calls: int = 0
        self.setex_calls: int = 0

    async def get(self, key: str) -> bytes | str | None:
        self.get_calls += 1
        return self._store.get(key)

    async def setex(self, key: str, time: int, value: str | bytes) -> object:
        self.setex_calls += 1
        self._store[key] = value if isinstance(value, str) else value.decode("latin-1")
        return True

    def seed(self, key: str, value: str) -> None:
        self._store[key] = value


class TestHttpxGitHubAppTokenClient:
    """Tests unitarios del cliente (mockeando httpx para no ir a red)."""

    def _make_client(
        self,
        pem: bytes,
        redis: FakeRedis | None = None,
    ) -> HttpxGitHubAppTokenClient:
        return HttpxGitHubAppTokenClient(
            app_id=_APP_ID,
            private_key_pem=pem,
            redis_client=redis,  # type: ignore[arg-type]
        )

    async def test_returns_token_from_github(self, rsa_private_key_pem: bytes) -> None:
        """Sin caché, el cliente llama a GitHub y devuelve el token."""
        client = self._make_client(rsa_private_key_pem)
        with patch("app.github_app.token_client.httpx.AsyncClient", _make_httpx_mock()):
            token = await client.get_installation_token(_INSTALLATION_ID)
        assert token == _FAKE_TOKEN

    async def test_token_not_in_logs(
        self, rsa_private_key_pem: bytes, caplog: pytest.LogCaptureFixture
    ) -> None:
        """El token NO debe aparecer en los logs (invariante ADR-4)."""
        client = self._make_client(rsa_private_key_pem)
        with patch("app.github_app.token_client.httpx.AsyncClient", _make_httpx_mock()):
            with caplog.at_level("DEBUG", logger="app.github_app.token_client"):
                await client.get_installation_token(_INSTALLATION_ID)
        for record in caplog.records:
            assert _FAKE_TOKEN not in record.getMessage(), (
                f"Token filtrado en log: {record.getMessage()!r}"
            )

    async def test_github_error_status_raises(self, rsa_private_key_pem: bytes) -> None:
        """Un status != 200/201 de GitHub debe lanzar `InstallationTokenError`."""
        client = self._make_client(rsa_private_key_pem)
        with patch(
            "app.github_app.token_client.httpx.AsyncClient",
            _make_httpx_mock(status_code=401),
        ):
            with pytest.raises(InstallationTokenError):
                await client.get_installation_token(_INSTALLATION_ID)

    async def test_cache_hit_skips_github(
        self,
        rsa_private_key_pem: bytes,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Si hay token cifrado en caché Redis, no debe llamar a GitHub."""
        # Necesitamos una clave AEAD válida: la inyectamos con monkeypatch para que
        # get_settings() la vea. Luego limpiamos las cachés de settings y crypto.
        _ENC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        monkeypatch.setenv("ENCRYPTION_KEY", _ENC_KEY)
        from app.settings import get_settings as _gs

        _gs.cache_clear()
        reset_cipher_cache()

        redis = FakeRedis()
        aad = _aad_for_installation(_INSTALLATION_ID)
        blob = encrypt_str(_FAKE_TOKEN, associated_data=aad)
        cache_key = f"sg:itoken:{_INSTALLATION_ID}"
        redis.seed(cache_key, blob.decode("latin-1"))

        client = self._make_client(rsa_private_key_pem, redis=redis)
        mock_cls = _make_httpx_mock()

        with patch("app.github_app.token_client.httpx.AsyncClient", mock_cls):
            token = await client.get_installation_token(_INSTALLATION_ID)
            mock_cls.assert_not_called()

        assert token == _FAKE_TOKEN
        # Restaurar la caché de settings (otros tests no deben ver la clave inyectada).
        _gs.cache_clear()
        reset_cipher_cache()

    async def test_cache_miss_calls_github_and_stores(
        self,
        rsa_private_key_pem: bytes,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Cache miss: llama a GitHub y almacena el token cifrado en Redis."""
        _ENC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        monkeypatch.setenv("ENCRYPTION_KEY", _ENC_KEY)
        from app.settings import get_settings as _gs

        _gs.cache_clear()
        reset_cipher_cache()

        redis = FakeRedis()
        client = self._make_client(rsa_private_key_pem, redis=redis)

        with patch("app.github_app.token_client.httpx.AsyncClient", _make_httpx_mock()):
            token = await client.get_installation_token(_INSTALLATION_ID)

        assert token == _FAKE_TOKEN
        assert redis.setex_calls == 1

        cache_key = f"sg:itoken:{_INSTALLATION_ID}"
        stored = redis._store.get(cache_key)
        assert stored is not None
        assert _FAKE_TOKEN not in stored, "Token en claro filtrado al caché Redis"

        aad = _aad_for_installation(_INSTALLATION_ID)
        decrypted = decrypt_str(stored.encode("latin-1"), associated_data=aad)
        assert decrypted == _FAKE_TOKEN

        _gs.cache_clear()
        reset_cipher_cache()

    async def test_redis_failure_on_get_degrades_gracefully(
        self, rsa_private_key_pem: bytes
    ) -> None:
        """Si Redis falla al leer, el cliente llama a GitHub sin lanzar excepción."""

        class BrokenRedis:
            async def get(self, key: str) -> None:
                raise ConnectionError("Redis down")

            async def setex(self, key: str, time: int, value: str | bytes) -> object:
                raise ConnectionError("Redis down")

        client = self._make_client(rsa_private_key_pem, redis=BrokenRedis())  # type: ignore[arg-type]

        with patch("app.github_app.token_client.httpx.AsyncClient", _make_httpx_mock()):
            token = await client.get_installation_token(_INSTALLATION_ID)

        assert token == _FAKE_TOKEN


# ---------------------------------------------------------------------------
# Helpers para tests de endpoints
# ---------------------------------------------------------------------------

_API = "/api/v1"
_USER_ID = uuid.uuid4()
_FAKE_USER = FakeUser(_USER_ID, login="dev-test")


class _NoSessionStore:
    """Store de sesión que nunca resuelve un usuario (simula ausencia de cookie activa)."""

    async def create(self, user_id: uuid.UUID) -> str:
        return "no-session"

    async def resolve(self, cookie_value: str) -> uuid.UUID | None:
        return None  # siempre sin sesión → guard lanza 401

    async def destroy(self, cookie_value: str) -> None:
        pass


class _NoUserRepository:
    async def upsert_from_oauth(self, identity: object, access_token: str) -> uuid.UUID:
        raise NotImplementedError

    async def get_by_id(self, user_id: uuid.UUID) -> None:
        return None


def _build_client_with_auth(repo: FakeInstallationRepository) -> TestClient:
    """App con el repo de instalaciones y el guard de sesión doblados (usuario autenticado)."""
    app: FastAPI = create_app()
    app.dependency_overrides[get_installation_repository] = lambda: repo
    app.dependency_overrides[require_user] = lambda: _FAKE_USER
    return TestClient(app, raise_server_exceptions=True)


def _build_client_no_auth(repo: FakeInstallationRepository) -> TestClient:
    """App con el repo doblado y un session store que nunca da sesión → guard retorna 401."""
    app: FastAPI = create_app()
    app.dependency_overrides[get_installation_repository] = lambda: repo
    # Inyectamos un store de sesión y repo de usuario en memoria que no resuelven sesión.
    # Esto activa el path real del guard (verifica firma, ve None, lanza 401) sin Redis.
    app.dependency_overrides[get_session_store] = lambda: _NoSessionStore()
    app.dependency_overrides[get_user_repository] = lambda: _NoUserRepository()
    return TestClient(app, raise_server_exceptions=False)


def _setup_installation(
    repo: FakeInstallationRepository,
    *,
    installation_id: int,
    account_login: str = "org",
    repos: list[RepoData] | None = None,
) -> None:
    """Planta una instalación activa en el repo en memoria."""
    data = InstallationData(
        installation_id=installation_id,
        account_login=account_login,
        repos=tuple(repos or []),
    )
    asyncio.run(repo.upsert_installation(data, user_id=_USER_ID))


# ---------------------------------------------------------------------------
# Tests de GET /installations
# ---------------------------------------------------------------------------


class TestGetInstallations:
    """Aceptación del endpoint GET /api/v1/installations."""

    def test_unauthenticated_returns_401(self) -> None:
        """Sin sesión (sin override del guard) → 401."""
        repo = FakeInstallationRepository()
        client = _build_client_no_auth(repo)
        resp = client.get(f"{_API}/installations")
        assert resp.status_code == 401

    def test_empty_when_no_installations(self) -> None:
        """Usuario sin instalaciones → lista vacía."""
        repo = FakeInstallationRepository()
        client = _build_client_with_auth(repo)
        resp = client.get(f"{_API}/installations")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_lists_user_installations(self) -> None:
        """Lista las instalaciones del usuario autenticado con su status."""
        repo = FakeInstallationRepository()
        _setup_installation(
            repo,
            installation_id=100,
            account_login="my-org",
            repos=[RepoData(github_repo_id=1, full_name="my-org/repo-a", private=False)],
        )
        client = _build_client_with_auth(repo)
        resp = client.get(f"{_API}/installations")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["installation_id"] == 100
        assert body[0]["account_login"] == "my-org"
        assert body[0]["status"] == "active"

    def test_includes_revoked_installation(self) -> None:
        """Instalaciones revocadas se incluyen en la lista (el usuario ve su historial)."""
        repo = FakeInstallationRepository()
        _setup_installation(repo, installation_id=200, account_login="old-org")
        asyncio.run(repo.set_status(installation_id=200, status="revoked"))

        client = _build_client_with_auth(repo)
        resp = client.get(f"{_API}/installations")
        assert resp.status_code == 200
        body = resp.json()
        assert any(i["status"] == "revoked" for i in body)

    def test_does_not_include_other_user_installations(self) -> None:
        """No se devuelven instalaciones de otro usuario."""
        repo = FakeInstallationRepository()
        other_user_id = uuid.uuid4()
        # Instalación de otro usuario: mismo repo pero distinto user_id.
        asyncio.run(
            repo.upsert_installation(
                InstallationData(
                    installation_id=300,
                    account_login="other-org",
                    repos=(),
                ),
                user_id=other_user_id,
            )
        )
        client = _build_client_with_auth(repo)
        resp = client.get(f"{_API}/installations")
        assert resp.status_code == 200
        assert resp.json() == []


# ---------------------------------------------------------------------------
# Tests de GET /repos
# ---------------------------------------------------------------------------


class TestGetRepos:
    """Aceptación del endpoint GET /api/v1/repos."""

    def test_unauthenticated_returns_401(self) -> None:
        """Sin sesión → 401."""
        repo = FakeInstallationRepository()
        client = _build_client_no_auth(repo)
        resp = client.get(f"{_API}/repos")
        assert resp.status_code == 401

    def test_empty_when_no_repos(self) -> None:
        """Sin repos accesibles → lista vacía."""
        repo = FakeInstallationRepository()
        client = _build_client_with_auth(repo)
        resp = client.get(f"{_API}/repos")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_lists_repos_of_active_installation(self) -> None:
        """Lista repos de instalaciones activas."""
        repo = FakeInstallationRepository()
        _setup_installation(
            repo,
            installation_id=400,
            repos=[
                RepoData(github_repo_id=1, full_name="org/alpha", private=False),
                RepoData(github_repo_id=2, full_name="org/beta", private=True),
            ],
        )
        client = _build_client_with_auth(repo)
        resp = client.get(f"{_API}/repos")
        assert resp.status_code == 200
        body = resp.json()
        full_names = {r["full_name"] for r in body}
        assert "org/alpha" in full_names
        assert "org/beta" in full_names

    def test_revoked_installation_repos_excluded(self) -> None:
        """Repos de instalaciones revocadas NO se incluyen."""
        repo = FakeInstallationRepository()
        _setup_installation(
            repo,
            installation_id=500,
            repos=[RepoData(github_repo_id=10, full_name="org/secret", private=True)],
        )
        asyncio.run(repo.set_status(installation_id=500, status="revoked"))

        client = _build_client_with_auth(repo)
        resp = client.get(f"{_API}/repos")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_filter_by_installation_id(self) -> None:
        """El parámetro `installation_id` filtra repos a esa instalación concreta."""
        repo = FakeInstallationRepository()
        _setup_installation(
            repo,
            installation_id=600,
            account_login="org-a",
            repos=[RepoData(github_repo_id=10, full_name="org-a/x", private=False)],
        )
        _setup_installation(
            repo,
            installation_id=700,
            account_login="org-b",
            repos=[RepoData(github_repo_id=20, full_name="org-b/y", private=False)],
        )
        client = _build_client_with_auth(repo)
        resp = client.get(f"{_API}/repos", params={"installation_id": 600})
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["full_name"] == "org-a/x"

    def test_repo_private_field_preserved(self) -> None:
        """El campo `private` se devuelve correctamente."""
        repo = FakeInstallationRepository()
        _setup_installation(
            repo,
            installation_id=800,
            repos=[RepoData(github_repo_id=99, full_name="org/private-repo", private=True)],
        )
        client = _build_client_with_auth(repo)
        resp = client.get(f"{_API}/repos")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["private"] is True
