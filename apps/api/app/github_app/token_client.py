"""Cliente de installation tokens de la GitHub App (H5-T23, R2.5, ADR-4).

Responsabilidad:
  - Firmar un JWT RS256 de corta vida (~10min) con la clave privada del App.
  - Canjearlo por un installation access token (~1h) llamando a la GitHub API.
  - Cachear opcionalmente el token cifrado en Redis (AEAD, TTL < expiración) para no
    llamar a GitHub en cada request.  Si Redis no está configurado, opera sin caché.

Invariantes de seguridad (NFR-Seg-3, ADR-4):
  - El installation token NUNCA se persiste en DB.
  - El installation token NUNCA sale al cliente ni a logs.
  - Si se cachea en Redis, se cifra con AEAD (reusa `app.security.crypto`).
  - La clave privada del App solo se desempaqueta en el momento de firmar.
  - En caso de error el cliente falla de forma explícita con `InstallationTokenError`;
    el mensaje es saneado (sin el token ni la clave).

Formato de la clave privada: PEM RSA (variable de entorno `GITHUB_APP_PRIVATE_KEY`,
con los saltos de línea literales o codificados en \\n).
"""

from __future__ import annotations

import logging
import time
from typing import Protocol

import httpx
import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from ..security.crypto import decrypt_str, encrypt_str, redact

logger = logging.getLogger(__name__)

# Endpoints de la GitHub API (REST v3).
_GH_API_BASE = "https://api.github.com"
_ACCESS_TOKENS_PATH = "/app/installations/{installation_id}/access_tokens"

# Vida del JWT de la App (máx 10 min según GitHub; usamos 9 para margen de reloj).
_JWT_TTL_S = 9 * 60
# Timeout para llamadas a GitHub (no debe bloquear el flujo de API).
_HTTP_TIMEOUT_S = 10.0
# Margen de seguridad: el token caduca 60s antes de su `expires_at` real para renovar
# con holgura ante retrasos de red o diferencias de reloj.
_EXPIRY_SLACK_S = 60
# Prefijo de clave en Redis: namespace limpio y legible en inspección de operaciones.
_REDIS_KEY_PREFIX = "sg:itoken:"
# AAD para el cifrado: liga el blob al contexto (columna conceptual + installation_id).
_AAD_PREFIX = b"installation_token:"


class InstallationTokenError(RuntimeError):
    """Falla saneada al obtener el installation token. Sin material secreto en el mensaje."""


class GitHubAppTokenClient(Protocol):
    """Contrato inyectable: permite doblarlo en tests sin tocar la red."""

    async def get_installation_token(self, installation_id: int) -> str:
        """Devuelve un installation access token válido para `installation_id`.

        Si hay uno cacheado y vigente, lo devuelve. Si no, llama a GitHub y
        renueva. El token nunca sale de esta capa a los logs ni al caller en texto
        claro (se devuelve la cadena, pero el caller NO debe loguearlo).
        """
        ...


def _pem_bytes_from_setting(raw_value: str) -> bytes:
    """Normaliza la clave PEM: reemplaza \\n literales por saltos reales.

    Las variables de entorno no pueden contener saltos de línea reales en muchos sistemas,
    así que la convención es codificarlos como \\n. Si ya vienen como saltos literales,
    la operación es idempotente.
    """
    normalized = raw_value.replace("\\n", "\n")
    return normalized.encode("utf-8")


def _sign_app_jwt(app_id: str, private_key_pem: bytes) -> str:
    """Firma y devuelve un JWT RS256 de corta vida autenticado como la GitHub App.

    El JWT es el credential de primer factor: solo acredita la identidad de la App,
    no el acceso a un repo concreto (eso lo da el installation token).

    Formato exigido por GitHub:
      - `iss`: App ID (str o int, GitHub acepta ambos)
      - `iat`: ahora menos 60s (margen de reloj entre servidores)
      - `exp`: ahora + TTL (máx 10 min)
      - algoritmo: RS256
    """
    now = int(time.time())
    payload = {
        "iss": app_id,
        # Restar 60s para tolerar diferencias de reloj entre nuestra máquina y GitHub.
        "iat": now - 60,
        "exp": now + _JWT_TTL_S,
    }
    # Cargamos la clave en memoria solo para firmar; la dejamos salir del scope al retornar.
    # PyJWT acepta DIRECTAMENTE el objeto private key de `cryptography` para RS256 (usa
    # `cryptography` por debajo). Evitamos re-serializarla a PEM/DER en claro (private_bytes):
    # eso creaba una copia adicional del material sensible en memoria (NFR-Seg-3, ADR-4).
    private_key = load_pem_private_key(private_key_pem, password=None)
    # RS256 exige una clave RSA. Validamos el tipo (fail-closed): una clave de otra familia
    # (Ed25519, EC, ...) configurada por error se rechaza con un error de tipo claro, en vez de
    # propagarse a PyJWT como un fallo opaco. El mensaje NO incluye material de la clave.
    if not isinstance(private_key, RSAPrivateKey):
        raise InstallationTokenError(
            "La clave privada de la GitHub App no es RSA; RS256 requiere una clave RSA."
        )
    return jwt.encode(payload, private_key, algorithm="RS256")


def _aad_for_installation(installation_id: int) -> bytes:
    """AAD que liga el blob cifrado al installation_id concreto (defensa anti-reutilización)."""
    return _AAD_PREFIX + str(installation_id).encode("ascii")


class HttpxGitHubAppTokenClient:
    """Implementación real: firma JWT + canjea por installation token + caché Redis AEAD.

    El cache es opt-in: si `redis_client` es None la instancia opera en modo sin caché
    (llama a GitHub en cada `get_installation_token`). En Redis el token se cifra con AEAD.
    """

    def __init__(
        self,
        *,
        app_id: str,
        private_key_pem: bytes,
        redis_client: RedisClientProtocol | None = None,
    ) -> None:
        self._app_id = app_id
        self._private_key_pem = private_key_pem
        self._redis = redis_client

    async def get_installation_token(self, installation_id: int) -> str:
        """Devuelve un token vigente: caché Redis cifrado si disponible, o renueva desde GitHub."""
        # Intento de caché primero: evita llamadas innecesarias a GitHub.
        cached = await self._try_cache_get(installation_id)
        if cached is not None:
            return cached

        token = await self._fetch_from_github(installation_id)
        await self._try_cache_set(installation_id, token)
        return token

    async def _fetch_from_github(self, installation_id: int) -> str:
        """Firma el JWT y llama a GitHub para obtener un nuevo installation access token."""
        app_jwt = _sign_app_jwt(self._app_id, self._private_key_pem)
        url = f"{_GH_API_BASE}{_ACCESS_TOKENS_PATH.format(installation_id=installation_id)}"
        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S) as client:
                response = await client.post(url, headers=headers)
        except httpx.HTTPError as exc:
            raise InstallationTokenError(
                f"No se pudo contactar a GitHub para obtener el installation token "
                f"(installation_id={installation_id})."
            ) from exc

        if response.status_code not in (200, 201):
            # No incluimos el cuerpo crudo: podría contener información diagnóstica sensible.
            raise InstallationTokenError(
                f"GitHub respondió {response.status_code} al solicitar el installation token "
                f"(installation_id={installation_id})."
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise InstallationTokenError(
                "GitHub devolvió una respuesta no-JSON al solicitar el installation token."
            ) from exc

        if not isinstance(body, dict):
            raise InstallationTokenError(
                "GitHub devolvió un JSON con forma inesperada para el installation token."
            )

        token = body.get("token")
        if not isinstance(token, str) or not token:
            raise InstallationTokenError(
                "GitHub no devolvió un 'token' válido en el installation token response."
            )

        # El token existe y es string; NO lo logueamos. Solo su longitud para correlación.
        logger.debug(
            "Installation token obtenido para installation_id=%d (%s).",
            installation_id,
            redact(token),
        )
        return token

    async def _try_cache_get(self, installation_id: int) -> str | None:
        """Intenta leer el token cifrado de Redis. Devuelve None en cualquier fallo."""
        if self._redis is None:
            return None
        key = f"{_REDIS_KEY_PREFIX}{installation_id}"
        try:
            raw = await self._redis.get(key)
        except Exception:
            # Fallo de Redis: degradar sin caché (no interrumpir el flujo de negocio).
            logger.warning("Redis no disponible al leer caché de installation token.")
            return None

        if raw is None:
            return None

        try:
            # El valor guardado es el blob AEAD en bytes (codificado en latin-1 desde Redis).
            if isinstance(raw, str):
                blob = raw.encode("latin-1")
            else:
                blob = raw
            return decrypt_str(blob, associated_data=_aad_for_installation(installation_id))
        except Exception:
            # Blob corrupto, clave rotada o expirado fuera de banda: renovar.
            logger.warning(
                "No se pudo descifrar el installation token cacheado para "
                "installation_id=%d; renovando.",
                installation_id,
            )
            return None

    async def _try_cache_set(self, installation_id: int, token: str) -> None:
        """Cifra el token con AEAD y lo guarda en Redis con TTL conservador.

        TTL = vida nominal del installation token (3600s) - margen de seguridad (_EXPIRY_SLACK_S).
        Esto garantiza que el token en caché siempre expira ANTES de que GitHub lo invalide,
        evitando devolver un token caducado desde la caché.
        """
        if self._redis is None:
            return
        key = f"{_REDIS_KEY_PREFIX}{installation_id}"
        ttl = 3600 - _EXPIRY_SLACK_S  # GitHub emite tokens de 1h; renovamos con margen.
        try:
            blob = encrypt_str(
                token, associated_data=_aad_for_installation(installation_id)
            )
            # Redis acepta bytes directamente; guardamos el blob AEAD como bytes.
            await self._redis.setex(key, ttl, blob.decode("latin-1"))
        except Exception:
            # Fallo al cachear: no crítico — el próximo request llamará a GitHub.
            logger.warning(
                "No se pudo cachear el installation token para installation_id=%d.",
                installation_id,
            )


# ---------------------------------------------------------------------------
# Protocol mínimo de cliente Redis async (para tipado sin acoplar a redis-py).
# Solo los métodos que este módulo necesita.
# ---------------------------------------------------------------------------


class RedisClientProtocol(Protocol):
    """Subconjunto de la API de `redis.asyncio.Redis` que este módulo usa."""

    async def get(self, key: str) -> bytes | str | None: ...

    async def setex(self, key: str, time: int, value: str | bytes) -> object: ...
