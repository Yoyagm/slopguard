"""Tests de seguridad de la Capa 4 (Hito 3, T22, §5.1 #6/#8/#9).

Verifican invariantes que el gate estatico no cubre:
- la ANTHROPIC_API_KEY NUNCA aparece en una excepcion (ni en su cadena `__cause__`);
- `api.anthropic.com` entra al allowlist SOLO bajo `enable_layer4` + clave presente;
- la cache L4 (sello 'llm-1') esta separada por construccion de la cache L3 ('ti-1').
"""

from __future__ import annotations

import traceback
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from slopguard.cli.main import _warn_if_layer4_sin_clave
from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config
from slopguard.core.errors import NetworkUnverifiableError
from slopguard.core.llm.registry import get_llm_evaluator
from slopguard.core.net.http_client import SecureHttpClient

_SECRET = "sk-ant-SECRETO-NO-DEBE-FILTRARSE-0123456789abcdef"  # noqa: S105 (clave FALSA de prueba)


class _BoomOpener:
    """Opener falso que simula un fallo de red al abrir la conexion."""

    def open(self, request: object, timeout: float) -> object:
        raise urllib.error.URLError("fallo de red simulado")


def test_api_key_no_se_filtra_en_excepcion() -> None:
    """§5.1 #6: la x-api-key jamas aparece en el mensaje ni en la cadena de la excepcion.

    El Request porta la cabecera, pero `NetworkUnverifiableError` solo usa el nombre de
    la clase de error y `exc.code`; ni el mensaje ni `__cause__` (URLError) contienen la
    clave. Se verifica tambien el traceback formateado completo (defensa en profundidad).
    """
    client = SecureHttpClient(extra_allowed_hosts=frozenset({"api.anthropic.com"}))
    client._opener = _BoomOpener()  # type: ignore[assignment]
    try:
        client.post_json(
            "https://api.anthropic.com/v1/messages",
            {"model": "claude-opus-4-8"},
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
            extra_headers={"x-api-key": _SECRET, "anthropic-version": "2023-06-01"},
        )
    except NetworkUnverifiableError as exc:
        chain = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        assert _SECRET not in str(exc)
        assert _SECRET not in repr(exc)
        assert _SECRET not in str(exc.__cause__ or "")
        assert _SECRET not in chain
    else:
        raise AssertionError("post_json debio lanzar NetworkUnverifiableError")


def test_cabecera_no_permitida_no_refleja_valor() -> None:
    """Una cabecera fuera del allowlist se rechaza sin reflejar su nombre/valor."""
    client = SecureHttpClient(extra_allowed_hosts=frozenset({"api.anthropic.com"}))
    client._opener = _BoomOpener()  # type: ignore[assignment]
    try:
        client.post_json(
            "https://api.anthropic.com/v1/messages",
            {"model": "x"},
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
            extra_headers={"x-evil-header": _SECRET},
        )
    except NetworkUnverifiableError as exc:
        assert _SECRET not in str(exc)
        assert "x-evil-header" not in str(exc)
    else:
        raise AssertionError("una cabecera no permitida debio rechazarse")


def test_allowlist_solo_bajo_enable_layer4(monkeypatch: pytest.MonkeyPatch) -> None:
    """§5.1 #9: api.anthropic.com entra al allowlist SOLO con enable_layer4 + clave."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", _SECRET)
    # enable_layer4=False -> sin evaluador (no se anade host).
    assert get_llm_evaluator(Config(enable_layer4=False), use_cache=False) is None
    # enable_layer4=True + clave -> evaluador con el host en el allowlist efectivo.
    evaluator = get_llm_evaluator(Config(enable_layer4=True), use_cache=False)
    assert evaluator is not None
    assert any(host == "api.anthropic.com" for host in evaluator._http._allowed_hosts)  # type: ignore[attr-defined]


def test_sin_clave_no_hay_evaluador(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sin ANTHROPIC_API_KEY no se construye evaluador aunque enable_layer4=True (R4.1)."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert get_llm_evaluator(Config(enable_layer4=True), use_cache=False) is None


def test_cache_llm_separada_de_threatintel(tmp_path: Path) -> None:
    """§5.1 #8: un blob con sello 'llm-1' no es legible como 'ti-1' ni viceversa."""
    cache = DiskCache(tmp_path, ttl_horas=168, enabled=True)
    payload: dict[str, Any] = {"clasificacion": "fabricacion", "confianza": 0.9}

    def _validator(p: dict[str, Any]) -> str | None:
        value = p.get("clasificacion")
        return value if isinstance(value, str) else None

    cache.put_blob("llm", "k1", payload, schema_version="llm-1", now=1000.0)
    # Mismo sello -> hit.
    assert cache.get_blob("llm", "k1", _validator, ttl_segundos=10**9,
                          schema_version="llm-1", now=1000.0) == "fabricacion"
    # Sello distinto ('ti-1', el de threat-intel) -> miss, no mezcla contratos.
    assert cache.get_blob("llm", "k1", _validator, ttl_segundos=10**9,
                          schema_version="ti-1", now=1000.0) is None
    # Y al reves: un blob 'ti-1' no se lee como 'llm-1'.
    cache.put_blob("osv", "k2", {"state": "clean"}, schema_version="ti-1", now=1000.0)
    assert cache.get_blob("osv", "k2", _validator, ttl_segundos=10**9,
                          schema_version="llm-1", now=1000.0) is None


def test_aviso_layer4_sin_clave(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4.1: --enable-layer4 sin clave ⇒ aviso unico a stderr (no finge 'todo limpio')."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _warn_if_layer4_sin_clave(Config(enable_layer4=True))
    err = capsys.readouterr().err
    assert "ANTHROPIC_API_KEY" in err
    assert "Capa 4" in err


def test_sin_aviso_si_layer4_off(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Capa 4 desactivada ⇒ sin aviso (comportamiento identico al Hito 2)."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _warn_if_layer4_sin_clave(Config(enable_layer4=False))
    assert capsys.readouterr().err == ""


def test_sin_aviso_con_clave(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Con clave presente no se advierte (la Capa 4 si correra)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", _SECRET)
    _warn_if_layer4_sin_clave(Config(enable_layer4=True))
    assert capsys.readouterr().err == ""
