"""Auth Router: flujo OAuth GitHub (R1.1/R1.2/R1.3, NFR-Seg-1, design §2.1/§4.1).

Endpoints (H5-T11):
- `GET /auth/login`    → emite `state` single-use y redirige (302) a GitHub.
- `GET /auth/callback` → valida `state` (GETDEL), canjea `code`→token, lee identidad, upsert del
  usuario con token CIFRADO, abre sesión de servidor y redirige (302) a `/dashboard` con cookie
  httpOnly+Secure+SameSite=Lax.

Reglas de seguridad cableadas aquí:
- `state` ausente/no-coincidente/expirado ⇒ 401 (CSRF), sin crear sesión (R1.3).
- El `access_token` JAMÁS viaja al cliente ni a logs: se cifra y queda en servidor (R1.5).
- Errores de GitHub (code inválido, identidad incompleta, red) ⇒ respuesta saneada, sin filtrar
  secretos ni el cuerpo crudo de GitHub (R9.2).

El router es delgado: la lógica de state/sesión/identidad/persistencia vive tras abstracciones
inyectables (`app.auth.deps`), sustituibles en tests.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse, Response

from ..auth.deps import (
    AuthConfigError,
    callback_redirect_uri,
    get_github_client,
    get_session_store,
    get_state_store,
    get_user_repository,
)
from ..auth.session import (
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME_DEV,
    SessionStore,
    cookie_max_age_seconds,
    session_cookie_name,
)
from ..auth.state_store import StateStore
from ..auth.user_repo import UserRepository
from ..services.github import (
    GitHubAuthError,
    GitHubOAuthClient,
    build_authorize_url,
)
from ..settings import Settings, get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Destino tras un login exitoso. Es un path relativo del front; el navegador lo resuelve contra
# su propio origen (no incrustamos un origen para evitar open-redirect).
_DASHBOARD_PATH = "/dashboard"


def _settings_dep() -> Settings:
    return get_settings()


SettingsDep = Annotated[Settings, Depends(_settings_dep)]
StateStoreDep = Annotated[StateStore, Depends(get_state_store)]
SessionStoreDep = Annotated[SessionStore, Depends(get_session_store)]
GitHubClientDep = Annotated[GitHubOAuthClient, Depends(get_github_client)]
UserRepoDep = Annotated[UserRepository, Depends(get_user_repository)]

# Cookies de sesión (patrón `Annotated[..., Cookie(...)]` para no disparar B008). Los alias
# reusan las constantes de `session.py` — misma fuente única de verdad que el guard.
SecureSessionCookie = Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)]
DevSessionCookie = Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME_DEV)]


@router.get("/login")
async def login(settings: SettingsDep, state_store: StateStoreDep) -> RedirectResponse:
    """Inicia OAuth: emite `state` single-use y redirige a GitHub (R1.1)."""
    client_id = settings.github_client_id
    if not client_id:
        # Sin credenciales no hay login posible: fail-closed con error saneado.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Login con GitHub no disponible (configuración incompleta).",
        )

    state = await state_store.issue()
    redirect_uri = callback_redirect_uri(settings)
    authorize_url = build_authorize_url(
        client_id=client_id, redirect_uri=redirect_uri, state=state
    )
    # 302 a GitHub. El `state` viaja en la query del authorize_url, no en cookie.
    return RedirectResponse(authorize_url, status_code=status.HTTP_302_FOUND)


@router.get("/callback")
async def callback(
    settings: SettingsDep,
    state_store: StateStoreDep,
    github: GitHubClientDep,
    users: UserRepoDep,
    sessions: SessionStoreDep,
    state: Annotated[str | None, Query()] = None,
    code: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
) -> RedirectResponse:
    """Cierra OAuth: valida `state`, canjea `code`, abre sesión y redirige al dashboard (R1.2/R1.3).

    Defensa CSRF (R1.3): el `state` se consume con GETDEL (single-use); ausente/no-coincidente
    ⇒ 401 sin crear sesión. El `code` SOLO se canjea tras validar el `state`.
    """
    # GitHub puede redirigir con `error` (p.ej. el usuario denegó el acceso): no es un CSRF, pero
    # tampoco hay sesión que abrir. Se trata como 401 sin filtrar el detalle de GitHub.
    if error:
        logger.info("Callback OAuth con error de GitHub (acceso denegado o similar).")
        raise _csrf_error()

    # 1) Consumir el state ANTES de tocar GitHub (corta el ataque CSRF lo antes posible).
    if not state or not await state_store.consume(state):
        logger.warning("Callback OAuth rechazado: state ausente o no coincidente (posible CSRF).")
        raise _csrf_error()

    # 2) Solo con state válido exigimos el code y lo canjeamos por el token.
    if not code:
        raise _csrf_error()

    try:
        access_token = await github.exchange_code(code)
        identity = await github.fetch_identity(access_token)
        user_id = await users.upsert_from_oauth(identity, access_token)
    except GitHubAuthError as exc:
        # Error saneado de GitHub (code inválido, identidad incompleta, red): nunca filtra el
        # token ni el cuerpo crudo. `str(exc)` es un mensaje estable definido por nosotros.
        logger.warning("Fallo en el intercambio OAuth con GitHub: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No se pudo completar el login con GitHub.",
        ) from exc
    except AuthConfigError as exc:
        logger.error("Login OAuth abortado por configuración incompleta.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Login con GitHub no disponible (configuración incompleta).",
        ) from exc

    # 3) Abrir sesión de servidor y redirigir al dashboard con la cookie httpOnly.
    cookie_value = await sessions.create(user_id)
    response = RedirectResponse(_DASHBOARD_PATH, status_code=status.HTTP_302_FOUND)
    _set_session_cookie(response, cookie_value, secure=settings.is_production)
    # Nota de no-fuga: NO logueamos `identity.login` con el token; el token nunca se loguea.
    logger.info("Sesión iniciada para usuario %s.", user_id)
    return response


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    settings: SettingsDep,
    sessions: SessionStoreDep,
    # Leemos las dos formas del nombre de cookie (producción y desarrollo) igual que el guard.
    cookie_secure: SecureSessionCookie = None,
    cookie_dev: DevSessionCookie = None,
) -> Response:
    """Invalida la sesión de servidor y limpia la cookie del cliente (R1.4, ADR-4).

    Flujo:
      1. Determina el valor de cookie según entorno (prefijo `__Host-` en producción).
      2. Llama a `sessions.destroy()` — borra la clave en Redis (revocación inmediata).
         Es no-op si la cookie está ausente, la firma falla o la sesión ya expiró.
      3. Devuelve 204 siempre: no filtrar si la sesión existía o no.

    La respuesta 204 lleva `Set-Cookie` con `Max-Age=0` para instruir al navegador a borrar
    la cookie. El borrado definitivo es server-side (Redis); la cookie vaciada es la señal
    al cliente.

    No requiere sesión válida previa: un logout de una sesión inexistente/ya revocada
    es igualmente 204 (idempotente, sin información de existencia).
    """
    cookie_value: str | None
    if settings.is_production:
        cookie_value = cookie_secure
    else:
        cookie_value = cookie_secure or cookie_dev

    if cookie_value:
        # Delegar a SessionStore.destroy: verifica firma antes de tocar Redis.
        await sessions.destroy(cookie_value)
        logger.info("Sesión invalidada server-side (logout).")
    else:
        # Sin cookie: logout de un cliente sin sesión — igualmente 204, sin información.
        logger.debug("Logout sin cookie de sesión presente (no-op).")

    # Construimos la respuesta 204 y añadimos la directiva de borrado de cookie.
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    # `Max-Age=0` instruye al navegador a expirar la cookie inmediatamente.
    # Enviamos ambos posibles nombres para limpiar tanto producción como desarrollo.
    _clear_session_cookie(response, secure=settings.is_production)
    return response


def _clear_session_cookie(response: Response, *, secure: bool) -> None:
    """Fija `Set-Cookie` con `Max-Age=0` para eliminar la cookie de sesión en el cliente.

    Se limpian AMBAS variantes del nombre (producción `__Host-` y desarrollo) para no dejar
    cookies huérfanas si el cliente cambió de entorno (p.ej. upgrade local→prod).

    Sutileza RFC 6265bis (§4.1.3.1): el prefijo `__Host-` SOLO es válido con el atributo
    `Secure`. Un `Set-Cookie` de borrado para `__Host-sg_session` SIN `Secure` es rechazado
    por el navegador, así que la cookie NO se borraría en dev. Por eso la variante con prefijo
    se borra SIEMPRE con `secure=True` (y `httponly=True`), independientemente del entorno; la
    variante de nombre llano (dev) se borra con los atributos normales del entorno.
    """
    # Variante de producción (`__Host-`): atributos requeridos por el prefijo, siempre fijos.
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    # Variante de desarrollo (nombre llano): atributos coherentes con el entorno actual.
    response.delete_cookie(
        key=SESSION_COOKIE_NAME_DEV,
        path="/",
        # `secure` y `httponly` deben coincidir con el Set-Cookie original para que el
        # navegador los reconozca como la misma cookie y la borre (RFC 6265 §5.3).
        secure=secure,
        httponly=True,
        samesite="lax",
    )


def _csrf_error() -> HTTPException:
    """401 estable para fallos de `state` (CSRF). Mensaje saneado, sin pistas explotables."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Parámetro de seguridad inválido o expirado.",
    )


def _set_session_cookie(response: RedirectResponse, value: str, *, secure: bool) -> None:
    """Fija la cookie de sesión httpOnly + SameSite=Lax (+ Secure en producción), ADR-4.

    `secure` se relaja en desarrollo (http://localhost) para no romper el flujo local; en
    producción es siempre True. El prefijo `__Host-` del nombre exige Secure+Path=/ en navegador.
    """
    response.set_cookie(
        key=session_cookie_name(secure=secure),
        value=value,
        max_age=cookie_max_age_seconds(),
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
