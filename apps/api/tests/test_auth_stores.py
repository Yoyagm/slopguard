"""Unit tests de los stores de auth: state single-use y sesión firmada (H5-T11, ADR-4).

Usan un doble en memoria de Redis async que implementa solo `set`/`get`/`getdel` con la
semántica que los stores requieren (incluido el TTL como metadato observable). Verifican la
invariante CSRF (consumo atómico de un solo uso) y el esquema de cookie de sesión firmada.
"""

from __future__ import annotations

import uuid

import pytest

from app.auth.session import RedisSessionStore, session_cookie_name
from app.auth.state_store import RedisStateStore


class InMemoryAsyncRedis:
    """Doble mínimo de `redis.asyncio.Redis[str]`: set/get/getdel/delete + registro de TTLs."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self.ttls: dict[str, int | None] = {}

    async def set(self, name: str, value: str, ex: int | None = None) -> bool:
        self._store[name] = value
        self.ttls[name] = ex
        return True

    async def get(self, name: str) -> str | None:
        return self._store.get(name)

    async def getdel(self, name: str) -> str | None:
        # Lectura+borrado atómico (en un solo hilo de test, la atomicidad es trivial).
        return self._store.pop(name, None)

    async def delete(self, *names: str) -> int:
        count = 0
        for name in names:
            if name in self._store:
                del self._store[name]
                self.ttls.pop(name, None)
                count += 1
        return count


# --- StateStore ---------------------------------------------------------------------------


async def test_issue_guarda_state_con_ttl_y_devuelve_nonce_unico() -> None:
    redis = InMemoryAsyncRedis()
    store = RedisStateStore(redis)

    first = await store.issue()
    second = await store.issue()

    assert first and second and first != second  # nonces aleatorios distintos
    # Ambos quedan persistidos con un TTL positivo (single-use con expiración).
    keys = list(redis.ttls)
    assert len(keys) == 2
    assert all(redis.ttls[k] == 600 for k in keys)


async def test_consume_state_emitido_es_true_y_single_use() -> None:
    redis = InMemoryAsyncRedis()
    store = RedisStateStore(redis)
    state = await store.issue()

    assert await store.consume(state) is True
    # Segundo consumo del mismo state ⇒ ya borrado (single-use, defensa anti-replay CSRF).
    assert await store.consume(state) is False


async def test_consume_state_inexistente_es_false() -> None:
    store = RedisStateStore(InMemoryAsyncRedis())
    assert await store.consume("nunca-emitido") is False


async def test_consume_state_vacio_es_false_sin_tocar_redis() -> None:
    redis = InMemoryAsyncRedis()
    store = RedisStateStore(redis)
    assert await store.consume("") is False
    assert redis.ttls == {}  # no se generó ninguna lectura/clave


# --- SessionStore -------------------------------------------------------------------------


async def test_create_persiste_sesion_y_devuelve_cookie_firmada() -> None:
    redis = InMemoryAsyncRedis()
    store = RedisSessionStore(redis, session_secret="unit-test-session-secret-32-chars!!")
    user_id = uuid.uuid4()

    cookie_value = await store.create(user_id)

    # La cookie es `<session_id>.<firma>` (dos partes separadas por punto).
    session_id, _, signature = cookie_value.partition(".")
    assert session_id and signature
    # El estado de servidor mapea la sesión al usuario (permite revocación inmediata en logout).
    stored = await redis.get(f"session:{session_id}")
    assert stored == str(user_id)
    # TTL positivo (cookie y servidor caducan juntos).
    assert redis.ttls[f"session:{session_id}"] == 7 * 24 * 3600


async def test_create_firma_depende_del_secreto() -> None:
    """Dos stores con secretos distintos producen firmas distintas para el mismo session_id."""
    redis_a = InMemoryAsyncRedis()
    redis_b = InMemoryAsyncRedis()
    store_a = RedisSessionStore(redis_a, session_secret="secret-A-padding-to-32-characters!")
    store_b = RedisSessionStore(redis_b, session_secret="secret-B-padding-to-32-characters!")

    # Firmamos el MISMO session_id con ambos secretos (accedemos al helper interno de firma).
    signed_a = store_a._sign("fixed-session-id")
    signed_b = store_b._sign("fixed-session-id")
    assert signed_a != signed_b


@pytest.mark.parametrize(
    ("secure", "expected"), [(True, "__Host-sg_session"), (False, "sg_session")]
)
def test_cookie_name_usa_host_prefix_solo_con_secure(secure: bool, expected: str) -> None:
    # `__Host-` exige Secure; en dev (http) se degrada al nombre llano para no perder la cookie.
    assert session_cookie_name(secure=secure) == expected
