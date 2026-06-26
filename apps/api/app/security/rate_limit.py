"""Rate limiting por IP para endpoints públicos (H5-T42, NFR-Seg, anti-abuso).

Contador de ventana fija sobre Redis: por cada `(categoría, ip)` se incrementa un contador con
TTL = ventana; al superar el `limit` se responde 429. La categoría agrupa rutas equivalentes
(`auth`, `webhook`) para que el límite no se evada saltando entre endpoints hermanos.

DECISIÓN — FAIL-OPEN (deliberada): el rate limiting es PROTECCIÓN contra abuso, no autenticación.
Si Redis no está configurado o falla, NO bloqueamos el tráfico (degradaría la disponibilidad por
un problema de infraestructura nuestro); se loguea un warning y se deja pasar. El control de
acceso real (sesión, HMAC del webhook) sigue intacto. Como efecto colateral, la suite de tests
—que corre sin Redis— no se ve afectada (el limiter es no-op sin `redis_url`).

`RateLimiter` es un Protocol → en tests se sustituye por `InMemoryRateLimiter` sin tocar Redis.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

import redis.asyncio as aioredis

# Namespace en Redis para no colisionar con state/sesión/cola.
_KEY_PREFIX = "ratelimit:"


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """Resultado de contabilizar una petición contra el límite."""

    allowed: bool
    limit: int
    remaining: int
    reset_seconds: int  # segundos hasta que la ventana se reinicie (para X-RateLimit-Reset)


class RateLimiter(Protocol):
    """Contrato del contador de rate limit (inyectable, fakeable)."""

    async def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitResult:
        """Contabiliza una petición para `key`. Nunca debe filtrar detalles de la infra."""
        ...


def _result(count: int, limit: int, ttl: int, window_seconds: int) -> RateLimitResult:
    """Construye el `RateLimitResult` a partir del contador y el TTL observados."""
    reset = ttl if ttl > 0 else window_seconds
    return RateLimitResult(
        allowed=count <= limit,
        limit=limit,
        remaining=max(0, limit - count),
        reset_seconds=reset,
    )


class RedisRateLimiter:
    """Ventana fija sobre Redis (INCR + EXPIRE). Cumple `RateLimiter`.

    Atomicidad: `INCR` crea la clave en 0→1; en el primer hit fijamos el TTL. Si por una caída
    entre INCR y EXPIRE la clave quedara sin expiración (`ttl == -1`), el siguiente hit la repara
    (idempotente). Así un contador nunca queda "pegado" sin ventana de reinicio.
    """

    def __init__(self, client: aioredis.Redis[str]) -> None:
        self._redis = client

    async def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitResult:
        redis_key = f"{_KEY_PREFIX}{key}"
        count = await self._redis.incr(redis_key)
        ttl = await self._redis.ttl(redis_key)
        if ttl < 0:
            # Clave recién creada (o sin TTL por una caída previa): fija/repara la ventana.
            await self._redis.expire(redis_key, window_seconds)
            ttl = window_seconds
        return _result(count, limit, ttl, window_seconds)


class InMemoryRateLimiter:
    """Contador de ventana fija en memoria del proceso. Doble de pruebas (sin Redis).

    NO apto para producción multi-proceso (cada worker tendría su propio contador); existe para
    los tests y para razonar sobre la semántica observable del `RedisRateLimiter`.
    """

    def __init__(self) -> None:
        # key -> (count, expiry_monotonic)
        self._buckets: dict[str, tuple[int, float]] = {}

    async def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitResult:
        now = time.monotonic()
        count, expiry = self._buckets.get(key, (0, 0.0))
        if now >= expiry:
            count, expiry = 0, now + window_seconds
        count += 1
        self._buckets[key] = (count, expiry)
        ttl = max(1, round(expiry - now))
        return _result(count, limit, ttl, window_seconds)
