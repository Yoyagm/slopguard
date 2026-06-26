"""Store del `state` OAuth anti-CSRF de un solo uso (R1.1/R1.3, NFR-Seg-1, ADR-4).

El `state` es un nonce aleatorio (`secrets.token_urlsafe`, CSPRNG) que `/auth/login` emite y
guarda con TTL corto (10 min). El callback lo consume con **GETDEL** (lectura+borrado atómico):
así el `state` es de un solo uso aunque dos callbacks compitan — solo uno obtiene el valor.

Contrato `StateStore` (Protocol) inyectable: en tests se dobla con un store en memoria sin Redis.
"""

from __future__ import annotations

import secrets
from typing import Protocol

import redis.asyncio as aioredis

# TTL del state: ventana corta entre login y callback (design §2.1: "TTL 10m").
_STATE_TTL_SECONDS = 600
# Prefijo de namespace en Redis: aísla los states de otras claves (cola, rate-limit).
_STATE_KEY_PREFIX = "oauth:state:"
# Entropía del nonce: 32 bytes → ~43 chars urlsafe, ≥256 bits (imposible de adivinar).
_STATE_NONCE_BYTES = 32

# Valor marcador: el state no transporta datos, solo su existencia importa. Usamos un valor
# fijo y NO el propio nonce (la clave ya es el nonce); evita razonar sobre encoding de Redis.
_STATE_PRESENT = "1"


class StateStore(Protocol):
    """Contrato del store de state OAuth de un solo uso."""

    async def issue(self) -> str:
        """Genera un `state` aleatorio, lo guarda con TTL y lo devuelve."""
        ...

    async def consume(self, state: str) -> bool:
        """Consume el `state` de forma atómica (single-use). True si existía y era válido."""
        ...


class RedisStateStore:
    """Implementación con Redis. Cumple `StateStore`.

    GETDEL garantiza el consumo atómico de un solo uso: dos callbacks concurrentes con el mismo
    `state` no pueden ambos verlo presente. Un `state` ausente/expirado ⇒ `consume` devuelve False.
    """

    def __init__(self, client: aioredis.Redis[str]) -> None:
        self._redis = client

    async def issue(self) -> str:
        state = secrets.token_urlsafe(_STATE_NONCE_BYTES)
        # `nx=True` no es necesario (colisión de 256 bits es despreciable) pero `ex` fija el TTL.
        await self._redis.set(self._key(state), _STATE_PRESENT, ex=_STATE_TTL_SECONDS)
        return state

    async def consume(self, state: str) -> bool:
        if not state:
            # State vacío/ausente en el callback ⇒ tratamiento idéntico a no-coincidencia (CSRF).
            return False
        # GETDEL: devuelve el valor previo (o None) y borra la clave en una sola operación atómica.
        previous = await self._redis.getdel(self._key(state))
        return previous is not None

    @staticmethod
    def _key(state: str) -> str:
        return f"{_STATE_KEY_PREFIX}{state}"
