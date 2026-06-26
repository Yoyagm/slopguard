"""Siembra un usuario de prueba + sesión de servidor y emite la cookie firmada (E2E, H5-T40).

Pensado para el self-host LOCAL: permite ejercitar los flujos AUTENTICADOS (escaneo on-demand,
histórico) sin pasar por el OAuth real de GitHub —que exige github.com y queda fuera del
"self-host completo, sin cloud externo"—. NO introduce ningún seam de auth en el API de
producción: es un script externo que se ejecuta dentro del contenedor (mismo `session_secret`,
misma DB/Redis), así que la cookie resultante es indistinguible de una real para el backend.

Uso (contra el stack de docker-compose en marcha):

    docker compose exec -T api python - < apps/api/scripts/seed_e2e_session.py

Imprime en stdout (una línea cada uno):

    COOKIE_NAME=sg_session
    COOKIE_VALUE=<id_sesion>.<firma>
    USER_ID=<uuid>

El runner de Playwright toma `COOKIE_VALUE` y lo inyecta como storageState (ver
apps/web/e2e/README.md).
"""

from __future__ import annotations

import asyncio
import os
import uuid

import redis.asyncio as aioredis

from app.auth.session import RedisSessionStore, session_cookie_name
from app.db.base import get_sessionmaker
from app.db.models import User
from app.settings import get_settings

# Identidad sintética estable: idempotente entre corridas (no duplica el usuario de prueba).
_E2E_GITHUB_USER_ID = int(os.getenv("SG_E2E_GITHUB_USER_ID", "999999"))
_E2E_LOGIN = os.getenv("SG_E2E_LOGIN", "smoke-tester")


def _ensure_user() -> uuid.UUID:
    """Crea (o reutiliza) el usuario de prueba y devuelve su PK interna.

    El `access_token_enc` es un placeholder: el flujo on-demand escanea el manifiesto subido
    por el motor in-process y NUNCA descifra el token (solo lo usarían /repos y /installations).
    """
    session_factory = get_sessionmaker()
    with session_factory() as session:
        existing = (
            session.query(User)
            .filter(User.github_user_id == _E2E_GITHUB_USER_ID)
            .one_or_none()
        )
        if existing is not None:
            return existing.id
        user_id = uuid.uuid4()
        session.add(
            User(
                id=user_id,
                github_user_id=_E2E_GITHUB_USER_ID,
                login=_E2E_LOGIN,
                avatar_url=None,
                access_token_enc=b"e2e-placeholder-not-a-real-token",
            )
        )
        session.commit()
        return user_id


async def _mint_cookie(user_id: uuid.UUID) -> tuple[str, str]:
    """Crea la sesión de servidor en Redis y devuelve (nombre_cookie, valor_firmado)."""
    settings = get_settings()
    client: aioredis.Redis[str] = aioredis.from_url(
        settings.redis_url, decode_responses=True
    )
    try:
        store = RedisSessionStore(
            client, session_secret=settings.session_secret.get_secret_value()
        )
        cookie_value = await store.create(user_id)
    finally:
        await client.aclose()
    return session_cookie_name(secure=settings.is_production), cookie_value


async def main() -> None:
    user_id = _ensure_user()
    cookie_name, cookie_value = await _mint_cookie(user_id)
    print(f"COOKIE_NAME={cookie_name}")
    print(f"COOKIE_VALUE={cookie_value}")
    print(f"USER_ID={user_id}")


if __name__ == "__main__":
    asyncio.run(main())
