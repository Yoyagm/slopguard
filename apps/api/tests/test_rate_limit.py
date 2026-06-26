"""Rate limiting de endpoints públicos (H5-T42, NFR-Seg, anti-abuso).

Verifica el comportamiento OBSERVABLE con un limiter en memoria (sin Redis):
- Tras superar el límite por IP ⇒ 429 con envelope estable, `Retry-After` y `X-RateLimit-*`.
- FAIL-OPEN sin `redis_url`: el provider real devuelve `None` ⇒ NUNCA se limita (clave para que
  los 460 tests existentes —que corren sin Redis— sigan verdes).
- Categorías independientes: el límite de `auth` no se mezcla con el de `webhook`.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.deps import get_state_store
from app.main import create_app
from app.security import rate_limit_deps as rl_deps
from app.security.rate_limit import InMemoryRateLimiter
from app.settings import get_settings

_API = "/api/v1"


class _FakeStateStore:
    """State store en memoria: evita que `/auth/login` exija Redis al resolver sus deps.

    El rate limit corre como dependencia de ruta ANTES del handler, así que para ejercitarlo no
    nos importa el resultado de OAuth; solo que el endpoint no reviente por falta de Redis.
    """

    async def issue(self) -> str:
        return "fake-state"

    async def consume(self, state: str) -> bool:
        return False


def _base_app() -> FastAPI:
    """App con el state store doblado (deja /auth/login operable sin Redis)."""
    app: FastAPI = create_app()
    app.dependency_overrides[get_state_store] = _FakeStateStore
    return app


def _client_with_limiter(
    *, per_minute: int = 3, webhook_per_minute: int = 2, enabled: bool = True
) -> TestClient:
    """TestClient con un InMemoryRateLimiter inyectado (simula 'Redis configurado')."""
    app = _base_app()
    # UNA sola instancia compartida entre requests: el contador debe persistir entre llamadas.
    limiter = InMemoryRateLimiter()
    app.dependency_overrides[rl_deps.get_rate_limiter] = lambda: limiter
    patched = get_settings().model_copy(
        update={
            "rate_limit_enabled": enabled,
            "rate_limit_per_minute": per_minute,
            "rate_limit_webhook_per_minute": webhook_per_minute,
        }
    )
    app.dependency_overrides[rl_deps._settings_dep] = lambda: patched
    return TestClient(app)


def test_auth_login_se_limita_tras_superar_el_umbral() -> None:
    client = _client_with_limiter(per_minute=3)
    # Las primeras 3 peticiones pasan la barrera de rate limit (el handler luego responda lo que
    # sea, pero NUNCA 429). La 4ª excede el límite por IP ⇒ 429.
    for _ in range(3):
        assert client.get(f"{_API}/auth/login").status_code != 429
    resp = client.get(f"{_API}/auth/login")
    assert resp.status_code == 429


def test_429_lleva_envelope_estable_retry_after_y_headers() -> None:
    client = _client_with_limiter(per_minute=1)
    assert client.get(f"{_API}/auth/login").status_code != 429
    resp = client.get(f"{_API}/auth/login")

    assert resp.status_code == 429
    body = resp.json()
    assert body["error"]["code"] == "RATE_LIMITED"
    assert "request_id" in body["error"]
    # Cabeceras de control de tasa + Retry-After (segundos hasta el reinicio de ventana).
    assert resp.headers["X-RateLimit-Limit"] == "1"
    assert resp.headers["X-RateLimit-Remaining"] == "0"
    assert int(resp.headers["X-RateLimit-Reset"]) >= 1
    assert int(resp.headers["Retry-After"]) >= 1


def test_webhook_usa_su_propio_limite_mas_holgado() -> None:
    client = _client_with_limiter(per_minute=3, webhook_per_minute=2)
    for _ in range(2):
        assert client.post(f"{_API}/webhooks/github").status_code != 429
    resp = client.post(f"{_API}/webhooks/github")
    assert resp.status_code == 429
    assert resp.headers["X-RateLimit-Limit"] == "2"


def test_categorias_independientes_no_se_mezclan() -> None:
    # Mismo limiter compartido, pero distinta categoría/clave: agotar `webhook` no afecta a `auth`.
    client = _client_with_limiter(per_minute=3, webhook_per_minute=1)
    assert client.post(f"{_API}/webhooks/github").status_code != 429
    assert client.post(f"{_API}/webhooks/github").status_code == 429
    # auth tiene su propio contador intacto.
    assert client.get(f"{_API}/auth/login").status_code != 429


def test_fail_open_sin_redis_nunca_limita() -> None:
    # Sin override de `get_rate_limiter`: el provider real ve que NO hay redis_url ⇒ None ⇒
    # la dependencia es no-op. Aun con rate_limit_enabled=True (default), no se limita jamás.
    assert not get_settings().redis_url  # precondición del entorno de test
    client = TestClient(_base_app())
    for _ in range(30):
        assert client.get(f"{_API}/auth/login").status_code != 429


def test_deshabilitado_por_flag_no_limita() -> None:
    client = _client_with_limiter(per_minute=1, enabled=False)
    for _ in range(5):
        assert client.get(f"{_API}/auth/login").status_code != 429
