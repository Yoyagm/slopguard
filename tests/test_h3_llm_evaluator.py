"""Tests de AnthropicEvaluator (Hito 3, T09) con un SecureHttpClient FALSO (sin red).

Cubre el contrato claude-api y la postura de seguridad (ADR-15/R4): clasificacion
valida, abstencion ante stop_reason/contenido/confianza invalidos, ausencia de clave,
reintento solo de fallos transitorios, y que ninguna excepcion escape de evaluate().
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from slopguard.core.errors import NetworkUnverifiableError
from slopguard.core.llm.anthropic import AnthropicEvaluator, AnthropicSettings
from slopguard.core.models import Clasificacion, HallucinationContext

_API_KEY = "sk-test-NUNCA-DEBE-FILTRARSE-1234567890"

_CTX = HallucinationContext(
    existe=True,
    edad_dias=12,
    typo_vecino=None,
    typo_distancia=None,
    tiene_repo=False,
    tiene_metadata=False,
    senales_blandas=("new_package",),
)


def _settings(**over: Any) -> AnthropicSettings:
    base: dict[str, Any] = {
        "llm_host": "api.anthropic.com",
        "llm_api_path": "/v1/messages",
        "llm_api_version": "2023-06-01",
        "llm_model": "claude-opus-4-8",
        "llm_effort": "low",
        "llm_max_tokens": 512,
        "llm_timeout_total_s": 100.0,
        "llm_reintentos": 2,
        "connect_timeout_s": 5.0,
        "read_timeout_s": 10.0,
        "max_response_bytes": 10_000_000,
        "max_json_depth": 50,
        "prompt_version": "h3-v1",
        "llm_max_text_patron": 280,
        "llm_max_text_rationale": 1000,
    }
    base.update(over)
    return AnthropicSettings(**base)


class _FakeHttp:
    """Doble de SecureHttpClient: devuelve un sobre fijo o lanza, y cuenta llamadas."""

    def __init__(self, *, envelope: dict[str, object] | None = None,
                 raises: Exception | None = None) -> None:
        self.calls = 0
        self.last_headers: dict[str, str] | None = None
        self._envelope = envelope
        self._raises = raises

    def post_json(self, url: str, body: dict[str, object], *, connect_timeout_s: float,
                  read_timeout_s: float, max_response_bytes: int, max_json_depth: int,
                  extra_headers: dict[str, str] | None = None) -> dict[str, object]:
        self.calls += 1
        self.last_headers = extra_headers
        if self._raises is not None:
            raise self._raises
        assert self._envelope is not None
        return self._envelope


def _envelope(text_json: str, *, stop_reason: str = "end_turn") -> dict[str, object]:
    return {"stop_reason": stop_reason, "content": [{"type": "text", "text": text_json}]}


def _valid_text(clasificacion: str = "fabricacion", confianza: float = 0.9) -> str:
    return json.dumps({
        "clasificacion": clasificacion,
        "confianza": confianza,
        "patron": "nombre sin correspondencia en PyPI",
        "rationale": "el contexto indica paquete inexistente reciente",
    })


def _evaluator(http: _FakeHttp, **over: Any) -> AnthropicEvaluator:
    return AnthropicEvaluator(http, _settings(**over))  # type: ignore[arg-type]


def test_clasificacion_valida(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _FakeHttp(envelope=_envelope(_valid_text()))
    result = _evaluator(http).evaluate("reqursts", _CTX)
    assert result is not None
    assert result.clasificacion is Clasificacion.FABRICACION
    assert result.confianza == 0.9
    assert result.modelo == "claude-opus-4-8"
    assert result.prompt_version == "h3-v1"
    # La clave viaja SOLO en extra_headers (transporte), no se pierde ni se altera.
    assert http.last_headers == {"x-api-key": _API_KEY, "anthropic-version": "2023-06-01"}


@pytest.mark.parametrize("stop_reason", ["refusal", "max_tokens", "pause_turn", "otro"])
def test_stop_reason_no_end_turn_abstiene(
    monkeypatch: pytest.MonkeyPatch, stop_reason: str
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _FakeHttp(envelope=_envelope(_valid_text(), stop_reason=stop_reason))
    assert _evaluator(http).evaluate("x", _CTX) is None


@pytest.mark.parametrize("content", [[], [{"type": "tool_use"}], "no-es-lista", None])
def test_content_sin_bloque_text_abstiene(
    monkeypatch: pytest.MonkeyPatch, content: object
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _FakeHttp(envelope={"stop_reason": "end_turn", "content": content})
    assert _evaluator(http).evaluate("x", _CTX) is None


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_confianza_no_finita_abstiene(monkeypatch: pytest.MonkeyPatch, token: str) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    raw = ('{"clasificacion":"fabricacion","confianza":' + token
           + ',"patron":"p","rationale":"r"}')
    http = _FakeHttp(envelope=_envelope(raw))
    assert _evaluator(http).evaluate("x", _CTX) is None


@pytest.mark.parametrize("confianza", [1.5, -0.1, 2.0])
def test_confianza_fuera_de_rango_abstiene(
    monkeypatch: pytest.MonkeyPatch, confianza: float
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _FakeHttp(envelope=_envelope(_valid_text(confianza=confianza)))
    assert _evaluator(http).evaluate("x", _CTX) is None


def test_clasificacion_fuera_del_enum_abstiene(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _FakeHttp(envelope=_envelope(_valid_text(clasificacion="malicioso")))
    assert _evaluator(http).evaluate("x", _CTX) is None


def test_sin_api_key_abstiene_sin_llamar(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    http = _FakeHttp(envelope=_envelope(_valid_text()))
    assert _evaluator(http).evaluate("x", _CTX) is None
    assert http.calls == 0  # no se contacta a la red sin clave


def test_transitorio_reintenta_y_abstiene(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    monkeypatch.setattr(time, "sleep", lambda _s: None)  # backoff sin dormir
    http = _FakeHttp(raises=NetworkUnverifiableError("5xx", is_transient=True))
    assert _evaluator(http, llm_reintentos=2).evaluate("x", _CTX) is None
    assert http.calls == 3  # 1 intento + 2 reintentos


def test_permanente_no_reintenta(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _FakeHttp(raises=NetworkUnverifiableError("401", status_code=401, is_transient=False))
    assert _evaluator(http, llm_reintentos=2).evaluate("x", _CTX) is None
    assert http.calls == 1  # un fallo permanente NO se reintenta


def test_ninguna_excepcion_escapa(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _FakeHttp(raises=RuntimeError("fallo inesperado"))
    # Una excepcion inesperada (no NetworkUnverifiableError) tambien degrada a None.
    assert _evaluator(http).evaluate("x", _CTX) is None
