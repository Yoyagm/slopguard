"""Smoke del esqueleto FastAPI (H5-T03): el healthcheck responde sin DB configurada."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def test_health_ok_sin_dependencias_configuradas() -> None:
    client = TestClient(create_app())
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    # En la Ola 0, sin DATABASE_URL/REDIS_URL, las dependencias salen "not_configured".
    assert body["db"] == "not_configured"
    assert body["redis"] == "not_configured"
