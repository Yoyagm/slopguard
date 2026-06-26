"""Sesión de servidor: cookie opaca httpOnly + estado en Redis (R1.2, ADR-4).

La cookie **no** contiene el token de GitHub ni claims sensibles: transporta un id de sesión
opaco **firmado** (HMAC-SHA256 con `session_secret`) para detectar manipulación antes de tocar
Redis. El estado real (qué usuario es) vive en servidor (Redis) → permite revocación inmediata
en el logout (R1.4).

Formato del valor de cookie:  ``<session_id>.<sig_b64url>``  (sin padding base64url en la firma).

H5-T11 crea la sesión en el callback. H5-T12 añade `resolve` (verifica firma + lee Redis) y
`destroy` (borrado para logout de T13): ambas operaciones viven aquí para no duplicar el esquema
de firma/verificación.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from typing import Protocol

import redis.asyncio as aioredis

# Nombres de la cookie de sesión. En producción se usa el prefijo `__Host-`, que el navegador
# SOLO acepta con Secure + Path=/ + sin Domain (refuerza ADR-4). En desarrollo (http://localhost
# sin Secure) ese prefijo haría que el navegador descartara la cookie, así que se usa el nombre
# llano. `session_cookie_name(secure)` resuelve cuál aplica.
_SESSION_COOKIE_NAME_SECURE = "__Host-sg_session"
_SESSION_COOKIE_NAME_DEV = "sg_session"
# Fuente única de verdad de los nombres de cookie. Los routers/guard NO deben hardcodear estos
# literales: importan estas constantes (evita que producción y dev diverjan por un typo). El
# nombre de producción usa el prefijo `__Host-`; el de dev, el nombre llano (sin prefijo).
SESSION_COOKIE_NAME = _SESSION_COOKIE_NAME_SECURE
SESSION_COOKIE_NAME_DEV = _SESSION_COOKIE_NAME_DEV
# Vida de la sesión de servidor (y max-age de la cookie): 7 días. Coincide TTL de Redis y cookie
# para que ambas caduquen juntas (sin sesiones "fantasma" en servidor).
_SESSION_TTL_SECONDS = 7 * 24 * 3600
_SESSION_KEY_PREFIX = "session:"
# Entropía del id de sesión: 32 bytes urlsafe. La firma HMAC añade integridad, no entropía.
_SESSION_ID_BYTES = 32

_ENCODING = "ascii"
_SEPARATOR = "."


class SessionStore(Protocol):
    """Contrato del store de sesiones de servidor."""

    async def create(self, user_id: uuid.UUID) -> str:
        """Crea una sesión para `user_id` y devuelve el VALOR FIRMADO para la cookie."""
        ...

    async def resolve(self, cookie_value: str) -> uuid.UUID | None:
        """Verifica la firma del valor de cookie y, si es válida, devuelve el `user_id`.

        Devuelve `None` si la firma no coincide, el formato es inválido o la sesión
        expiró/no existe en Redis. NUNCA lanza por firma inválida: early-return con None.
        """
        ...

    async def destroy(self, cookie_value: str) -> None:
        """Borra la sesión de Redis (logout, R1.4). No-op si ya no existe o la firma falla."""
        ...


class RedisSessionStore:
    """Implementación con Redis. Cumple `SessionStore`.

    El `session_secret` solo firma/verifica; nunca se persiste ni se loguea. La firma usa
    `hmac.compare_digest` en la verificación (tiempo constante) — la verificación vive en T12,
    aquí se expone el helper para no duplicar el esquema de firma.
    """

    def __init__(self, client: aioredis.Redis[str], *, session_secret: str) -> None:
        self._redis = client
        # Clave HMAC en bytes: derivada del secreto de configuración (no del valor crudo en str).
        self._secret = session_secret.encode("utf-8")

    async def create(self, user_id: uuid.UUID) -> str:
        session_id = secrets.token_urlsafe(_SESSION_ID_BYTES)
        # El estado de servidor mapea sesión→usuario. Guardamos el UUID como str canónico.
        await self._redis.set(
            self._key(session_id), str(user_id), ex=_SESSION_TTL_SECONDS
        )
        return self._sign(session_id)

    async def resolve(self, cookie_value: str) -> uuid.UUID | None:
        """Verifica firma (tiempo constante) y resuelve el user_id desde Redis.

        Orden: primero la firma (evita tocar Redis con un valor manipulado); luego GET
        (sesión pudo expirar). Devuelve None en cualquier caso de fallo.
        """
        session_id = self._verify_signature(cookie_value)
        if session_id is None:
            return None
        stored = await self._redis.get(self._key(session_id))
        if stored is None:
            # Sesión expirada o inexistente en servidor (revocada por logout).
            return None
        try:
            return uuid.UUID(stored)
        except ValueError:
            # Corrupción inesperada en Redis: tratamos como sesión inválida.
            return None

    async def destroy(self, cookie_value: str) -> None:
        """Borra la clave de sesión en Redis. No-op si la firma falla o ya no existe."""
        session_id = self._verify_signature(cookie_value)
        if session_id is None:
            return
        await self._redis.delete(self._key(session_id))

    def _verify_signature(self, cookie_value: str) -> str | None:
        """Extrae y verifica el session_id del valor firmado de la cookie.

        Verificación en tiempo constante (hmac.compare_digest) para no filtrar
        información por timing sobre si la firma es válida o inválida.
        Devuelve el session_id si es válido, None en caso contrario.
        """
        if _SEPARATOR not in cookie_value:
            return None
        # Separamos solo en el PRIMER punto: el session_id puede (en teoría) no contener
        # puntos, pero la firma en base64url tampoco; un solo split es suficiente y robusto.
        session_id, _, received_sig = cookie_value.partition(_SEPARATOR)
        if not session_id or not received_sig:
            return None
        expected_sig = self._compute_signature(session_id)
        # compare_digest: tiempo constante aunque las longitudes difieran no hay garantía
        # de atomicidad, pero es el estándar de Python para HMAC. Ambos deben ser str.
        if not hmac.compare_digest(expected_sig, received_sig):
            return None
        return session_id

    def _sign(self, session_id: str) -> str:
        """Devuelve ``<session_id>.<firma>`` para la cookie (integridad anti-manipulación)."""
        signature = self._compute_signature(session_id)
        return f"{session_id}{_SEPARATOR}{signature}"

    def _compute_signature(self, session_id: str) -> str:
        digest = hmac.new(self._secret, session_id.encode(_ENCODING), hashlib.sha256).digest()
        # base64url sin padding: compacto y seguro en cookies (sin '=' que requiera escaping).
        return _b64url_nopad(digest)

    @staticmethod
    def _key(session_id: str) -> str:
        return f"{_SESSION_KEY_PREFIX}{session_id}"


def _b64url_nopad(raw: bytes) -> str:
    """base64url sin relleno (`=`), apto para valores de cookie."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode(_ENCODING)


def cookie_max_age_seconds() -> int:
    """Max-Age de la cookie de sesión, alineado con el TTL del estado de servidor."""
    return _SESSION_TTL_SECONDS


def session_cookie_name(*, secure: bool) -> str:
    """Nombre de cookie a usar: `__Host-` en producción (Secure), llano en desarrollo.

    El prefijo `__Host-` solo es válido con Secure; servirlo sin Secure (http local) haría que el
    navegador descartara la cookie. En dev se degrada al nombre llano para no romper el flujo.
    """
    return _SESSION_COOKIE_NAME_SECURE if secure else _SESSION_COOKIE_NAME_DEV
