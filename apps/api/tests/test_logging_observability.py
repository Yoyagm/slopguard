"""Logging estructurado + redacción de secretos + correlación request-id (H5-T42, NFR-Seg-3).

Cubre:
- El formatter emite JSON con los campos base y NO filtra secretos (redacción por clave sensible
  y por valor con forma de token).
- El `request_id` del contextvar se estampa en cada línea.
- El middleware propaga/expone `X-Request-ID` (reusa el del cliente si es seguro; genera si no).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi.testclient import TestClient

from app.logging_config import JsonLogFormatter
from app.main import create_app
from app.request_context import reset_request_id, set_request_id

_API = "/api/v1"
# Aguja sintética: un token con forma de GitHub PAT que NUNCA debe aparecer en claro en el log.
_LEAKY_TOKEN = "gho_DEADBEEFdeadbeef0123456789ABCDEF"


def _format(msg: str, **extra: Any) -> dict[str, Any]:
    """Formatea un LogRecord con `extra` y devuelve el objeto JSON resultante."""
    formatter = JsonLogFormatter()
    record = logging.LogRecord("test.logger", logging.INFO, __file__, 10, msg, None, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return json.loads(formatter.format(record))


def test_formatter_emite_campos_base() -> None:
    out = _format("hola mundo")
    assert out["level"] == "INFO"
    assert out["logger"] == "test.logger"
    assert out["message"] == "hola mundo"
    assert "timestamp" in out
    assert "request_id" in out


def test_redaccion_por_clave_sensible() -> None:
    out = _format(
        "evento con extras",
        authorization="Bearer super-secreto",
        access_token=_LEAKY_TOKEN,
        password="hunter2",
        github_webhook_secret="whsec_xyz",
        user="octocat",
    )
    assert out["authorization"] == "***"
    assert out["access_token"] == "***"
    assert out["password"] == "***"
    assert out["github_webhook_secret"] == "***"
    # Campo NO sensible: se conserva.
    assert out["user"] == "octocat"


def test_redaccion_en_dict_anidado() -> None:
    out = _format(
        "request entrante",
        headers={"Authorization": "Bearer x", "X-Request-ID": "req-123"},
    )
    assert out["headers"]["Authorization"] == "***"
    # El id de correlación NO es sensible: se conserva.
    assert out["headers"]["X-Request-ID"] == "req-123"


def test_redaccion_de_token_en_el_mensaje() -> None:
    out = _format(f"fallo procesando token {_LEAKY_TOKEN} del cliente")
    assert _LEAKY_TOKEN not in json.dumps(out)
    assert "***" in out["message"]


def test_request_id_se_estampa_desde_el_contextvar() -> None:
    token = set_request_id("corr-abc-123")
    try:
        out = _format("con correlación")
    finally:
        reset_request_id(token)
    assert out["request_id"] == "corr-abc-123"


def test_middleware_genera_y_expone_request_id() -> None:
    resp = TestClient(create_app()).get(f"{_API}/health")
    request_id = resp.headers.get("x-request-id")
    assert request_id is not None
    assert len(request_id) == 32  # uuid4().hex


def test_middleware_reusa_request_id_seguro_del_cliente() -> None:
    client = TestClient(create_app())
    resp = client.get(f"{_API}/health", headers={"X-Request-ID": "client-abc-123"})
    assert resp.headers["x-request-id"] == "client-abc-123"


def test_middleware_descarta_request_id_inseguro() -> None:
    client = TestClient(create_app())
    unsafe = "bad id with spaces"  # espacios fuera del alfabeto seguro [A-Za-z0-9_-]
    resp = client.get(f"{_API}/health", headers={"X-Request-ID": unsafe})
    # Valor inseguro (alfabeto/longitud) ⇒ se ignora y se genera uno propio.
    assert resp.headers["x-request-id"] != unsafe
    assert len(resp.headers["x-request-id"]) == 32
