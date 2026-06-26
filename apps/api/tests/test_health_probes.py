"""Healthchecks reales con ping a dependencias (H5-T42, design §4.1).

Dos niveles:
- Endpoint: con probes doblados (ok/down/not_configured) verifica la agregación 200/503.
- Probe: ejercita el ping REAL (sqlite para Postgres, puerto cerrado para Redis) y confirma que
  un fallo se traduce a `down` SIN lanzar (nunca filtra detalles de la infra).
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from app.api import health as health_module
from app.api.health import (
    DepStatus,
    PostgresProbe,
    RedisProbe,
    get_db_probe,
    get_redis_probe,
)
from app.main import create_app

_API = "/api/v1"


class _FakeProbe:
    def __init__(self, status: DepStatus) -> None:
        self._status = status

    async def check(self) -> DepStatus:
        return self._status


def _client(*, db: DepStatus, redis: DepStatus) -> TestClient:
    app: FastAPI = create_app()
    app.dependency_overrides[get_db_probe] = lambda: _FakeProbe(db)
    app.dependency_overrides[get_redis_probe] = lambda: _FakeProbe(redis)
    return TestClient(app)


def test_ambas_ok_responde_200() -> None:
    resp = _client(db="ok", redis="ok").get(f"{_API}/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "db": "ok", "redis": "ok"}


def test_db_down_responde_503_degraded() -> None:
    resp = _client(db="down", redis="ok").get(f"{_API}/health")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["db"] == "down"


def test_redis_down_responde_503_degraded() -> None:
    resp = _client(db="ok", redis="down").get(f"{_API}/health")
    assert resp.status_code == 503
    assert resp.json()["redis"] == "down"


def test_not_configured_cuando_faltan_urls() -> None:
    # Sin DATABASE_URL/REDIS_URL en el entorno de test: los providers reales devuelven
    # NotConfiguredProbe ⇒ not_configured, y el servicio sigue 200 (no hay dep caída).
    resp = TestClient(create_app()).get(f"{_API}/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["db"] == "not_configured"
    assert body["redis"] == "not_configured"


async def test_postgres_probe_ok_con_engine_real(monkeypatch: pytest.MonkeyPatch) -> None:
    # Engine sqlite en memoria: `SELECT 1` ejecuta de verdad ⇒ ok (sin Postgres real).
    engine = create_engine("sqlite://")
    monkeypatch.setattr(health_module, "get_engine", lambda: engine)
    assert await PostgresProbe().check() == "ok"


async def test_postgres_probe_down_no_lanza(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom() -> object:
        raise RuntimeError("DATABASE_URL no configurada")

    monkeypatch.setattr(health_module, "get_engine", _boom)
    # NUNCA lanza: el fallo se traduce a "down".
    assert await PostgresProbe().check() == "down"


async def test_redis_probe_down_no_lanza_puerto_cerrado() -> None:
    # Puerto cerrado: el PING falla rápido y se traduce a "down" sin lanzar ni colgar.
    assert await RedisProbe("redis://127.0.0.1:1").check() == "down"
