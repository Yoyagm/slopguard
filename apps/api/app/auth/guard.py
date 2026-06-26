"""Guard de sesión: dependencia `require_user` para proteger rutas (H5-T12, ADR-4, R1).

La cookie httpOnly de servidor transporta un valor firmado ``<session_id>.<sig>``. Este
módulo:
  1. Lee la cookie del request (nombre varía según `is_production`).
  2. Delega la verificación de firma + resolución de `user_id` al `SessionStore` (T11).
  3. Busca el usuario en DB por su `user_id` (`UserRepository.get_by_id`, nuevo en T12).
  4. Devuelve el `User` ORM o lanza HTTP 401.

Diseño de inyectabilidad: `require_user` recibe sus dependencias por parámetro para que los
tests puedan hacer `dependency_overrides` sin tocar Redis ni Postgres.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, status

from ..auth.deps import get_session_store, get_user_repository
from ..auth.session import (
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME_DEV,
    SessionStore,
)
from ..auth.user_repo import UserRepository
from ..db.models import User
from ..settings import Settings, get_settings

logger = logging.getLogger(__name__)


def _settings_dep() -> Settings:
    return get_settings()


SettingsDep = Annotated[Settings, Depends(_settings_dep)]
SessionStoreDep = Annotated[SessionStore, Depends(get_session_store)]
UserRepoDep = Annotated[UserRepository, Depends(get_user_repository)]

# Cookies de sesión, declaradas con el patrón `Annotated[..., Cookie(...)]` (no `Cookie()` en el
# default): evita el falso positivo B008 de ruff sin per-file-ignore. Los alias reusan las
# constantes de `session.py` (fuente única de verdad de los nombres de cookie).
SecureSessionCookie = Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)]
DevSessionCookie = Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME_DEV)]


async def require_user(
    settings: SettingsDep,
    sessions: SessionStoreDep,
    users: UserRepoDep,
    # Nombre de cookie dinámico según entorno (producción usa prefijo `__Host-`). FastAPI
    # lee la cookie por su nombre; pasamos ambas posibles nombres y tomamos la que tenga valor.
    cookie_secure: SecureSessionCookie = None,
    cookie_dev: DevSessionCookie = None,
) -> User:
    """Resuelve el usuario autenticado a partir de la cookie de sesión.

    Flujo:
      1. Elige el valor de cookie (producción prefiere `__Host-sg_session`, dev usa `sg_session`).
      2. Llama a `sessions.resolve(cookie_value)` — verifica firma HMAC en tiempo constante
         y lee el `user_id` de Redis. Devuelve None si firma inválida o sesión expirada.
      3. Busca el `User` en DB. Si la sesión apunta a un usuario borrado → 401.
      4. Lanza 401 en cualquier caso de fallo (sin distinguir entre "sin cookie", "firma mala"
         o "usuario no encontrado": no filtramos información de existencia).
    """
    # Tomamos el valor de cookie según entorno: en producción el prefijo `__Host-` fuerza
    # el atributo Secure, así que la cookie llega con ese nombre. En dev, el nombre llano.
    cookie_value: str | None
    if settings.is_production:
        cookie_value = cookie_secure
    else:
        # En dev aceptamos cualquiera de los dos (facilita pruebas con distintos entornos).
        cookie_value = cookie_secure or cookie_dev

    if not cookie_value:
        raise _unauthorized()

    user_id = await sessions.resolve(cookie_value)
    if user_id is None:
        # Firma inválida o sesión expirada/revocada. No logueamos el valor de la cookie.
        logger.debug("Sesión no resuelta: firma inválida o sesión expirada.")
        raise _unauthorized()

    user = await users.get_by_id(user_id)
    if user is None:
        # Sesión apuntaba a un usuario ya eliminado de la DB (caso raro pero posible).
        logger.warning("Sesión con user_id %s sin usuario correspondiente en DB.", user_id)
        raise _unauthorized()

    return user


def _unauthorized() -> HTTPException:
    """401 estable para cualquier fallo de sesión. Mensaje genérico (no filtra causa)."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Autenticación requerida.",
    )
