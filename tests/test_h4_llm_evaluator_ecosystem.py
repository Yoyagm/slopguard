"""Tests de H4-T30: firma del Protocol `LlmEvaluator.evaluate` con `ecosystem_id`
y propagacion en `AnthropicEvaluator` hasta `build_prompt` (ADR-6 ptos 2-3, §3.7).

Verifica que:
- La firma del Protocol acepta `ecosystem_id` y un fake conforme cumple `LlmEvaluator`.
- `evaluate`/`_build_body` propagan `ecosystem_id` hasta `build_prompt`, de modo que el
  cuerpo enviado contiene el texto del ecosistema correcto ("npm" para npm, "PyPI"
  para pypi y por default).
- El contrato "evaluate NUNCA lanza" se preserva: un `ecosystem_id` fuera de la tabla
  cerrada (que hace lanzar a `build_prompt`) degrada a `None`, no propaga la excepcion.
- No hay fuga de `ANTHROPIC_API_KEY` (ni en el cuerpo, ni en `self`, ni ante un fallo
  por `ecosystem_id` invalido).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from slopguard.core.llm.anthropic import AnthropicEvaluator, AnthropicSettings
from slopguard.core.llm.evaluator import LlmEvaluator
from slopguard.core.models import Clasificacion, HallucinationContext, LlmAssessment

_API_KEY = "sk-test-NUNCA-DEBE-FILTRARSE-h4t30-0987654321"

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
        "prompt_version": "h4-v1",
        "llm_max_text_patron": 280,
        "llm_max_text_rationale": 1000,
    }
    base.update(over)
    return AnthropicSettings(**base)


class _CapturingHttp:
    """Doble de SecureHttpClient: captura el cuerpo enviado y devuelve un sobre fijo."""

    def __init__(self, envelope: dict[str, object]) -> None:
        self.calls = 0
        self.last_body: dict[str, object] | None = None
        self.last_headers: dict[str, str] | None = None
        self._envelope = envelope

    def post_json(
        self,
        url: str,
        body: dict[str, object],
        *,
        connect_timeout_s: float,
        read_timeout_s: float,
        max_response_bytes: int,
        max_json_depth: int,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, object]:
        self.calls += 1
        self.last_body = body
        self.last_headers = extra_headers
        return self._envelope


def _valid_envelope() -> dict[str, object]:
    text = json.dumps({
        "clasificacion": "fabricacion",
        "confianza": 0.9,
        "patron": "p",
        "rationale": "r",
    })
    return {"stop_reason": "end_turn", "content": [{"type": "text", "text": text}]}


def _evaluator(http: _CapturingHttp, **over: Any) -> AnthropicEvaluator:
    return AnthropicEvaluator(http, _settings(**over))  # type: ignore[arg-type]


def _prompt_text(http: _CapturingHttp) -> str:
    """Extrae el texto del prompt (messages[0].content) del ultimo body capturado."""
    assert http.last_body is not None
    messages = http.last_body["messages"]
    assert isinstance(messages, list)
    content = messages[0]["content"]
    assert isinstance(content, str)
    return content


# --- Conformidad de firma del Protocol (frontera de interfaz, §3.7) ---

class _FakeNewSignatureEvaluator:
    """Implementacion minima que cumple la firma ampliada del Protocol."""

    def __init__(self) -> None:
        self.seen_ecosystem: str | None = None

    def evaluate(
        self, name: str, context: HallucinationContext, ecosystem_id: str = "pypi"
    ) -> LlmAssessment | None:
        self.seen_ecosystem = ecosystem_id
        return None


def test_protocol_acepta_firma_con_ecosystem_id() -> None:
    fake = _FakeNewSignatureEvaluator()
    # runtime_checkable: el fake con la firma nueva satisface el Protocol.
    assert isinstance(fake, LlmEvaluator)
    assert fake.evaluate("x", _CTX, "npm") is None
    assert fake.seen_ecosystem == "npm"


def test_anthropic_evaluator_cumple_protocol() -> None:
    http = _CapturingHttp(_valid_envelope())
    assert isinstance(_evaluator(http), LlmEvaluator)


# --- Propagacion de ecosystem_id hasta build_prompt ---

def test_evaluate_npm_propaga_texto_npm_al_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _CapturingHttp(_valid_envelope())
    result = _evaluator(http).evaluate("reqursts", _CTX, "npm")
    assert result is not None
    assert result.clasificacion is Clasificacion.FABRICACION
    prompt = _prompt_text(http)
    assert "npm" in prompt
    assert "PyPI" not in prompt  # el texto del ecosistema es npm, no PyPI


def test_evaluate_pypi_propaga_texto_pypi_al_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _CapturingHttp(_valid_envelope())
    assert _evaluator(http).evaluate("x", _CTX, "pypi") is not None
    prompt = _prompt_text(http)
    assert "PyPI" in prompt


def test_evaluate_default_es_pypi(monkeypatch: pytest.MonkeyPatch) -> None:
    """El default `ecosystem_id="pypi"` preserva el comportamiento existente (cero regresion)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _CapturingHttp(_valid_envelope())
    assert _evaluator(http).evaluate("x", _CTX) is not None
    prompt = _prompt_text(http)
    assert "PyPI" in prompt


def test_build_body_propaga_ecosystem_id() -> None:
    http = _CapturingHttp(_valid_envelope())
    evaluator = _evaluator(http)
    body = evaluator._build_body("x", _CTX, "npm")
    messages = body["messages"]
    assert isinstance(messages, list)
    content = messages[0]["content"]
    assert isinstance(content, str)
    assert "npm" in content
    assert "PyPI" not in content


# --- Contrato "evaluate NUNCA lanza" preservado (ecosystem_id invalido) ---

def test_ecosystem_id_invalido_degrada_a_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un `ecosystem_id` fuera de la tabla cerrada de `build_prompt` (ValueError) NO
    escapa de `evaluate`: degrada a `None` (contrato R4/ADR-15), sin tocar la red."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _CapturingHttp(_valid_envelope())
    assert _evaluator(http).evaluate("x", _CTX, "golang") is None
    # build_prompt lanza al armar el cuerpo, antes de cualquier POST.
    assert http.calls == 0


# --- No-fuga de ANTHROPIC_API_KEY (NFR-Seg.2) ---

def test_api_key_no_en_self_ni_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _CapturingHttp(_valid_envelope())
    evaluator = _evaluator(http)
    assert _API_KEY not in repr(evaluator.__dict__)  # la clave nunca se guarda en self
    assert evaluator.evaluate("x", _CTX, "npm") is not None
    # La clave viaja SOLO en extra_headers, nunca en el cuerpo del request.
    assert _API_KEY not in json.dumps(http.last_body)
    assert http.last_headers == {"x-api-key": _API_KEY, "anthropic-version": "2023-06-01"}


def test_api_key_no_se_filtra_ante_ecosystem_invalido(monkeypatch: pytest.MonkeyPatch) -> None:
    """Aun con `ecosystem_id` invalido (build_prompt lanza), la clave no escapa: el
    fallo se atrapa en evaluate() y la clave nunca llega a una traza visible."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    http = _CapturingHttp(_valid_envelope())
    evaluator = _evaluator(http)
    # No lanza (atrapado) y la clave no quedo en self ni en el http (no hubo POST).
    assert evaluator.evaluate("x", _CTX, "golang") is None
    assert _API_KEY not in repr(evaluator.__dict__)
    assert http.last_body is None
