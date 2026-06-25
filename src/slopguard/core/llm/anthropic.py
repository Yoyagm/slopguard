"""Adaptador HTTPS crudo del evaluador LLM de la Capa 4 sobre la API de Anthropic.

Implementa `LlmEvaluator` (ADR-17) contra `POST {llm_host}{llm_api_path}` usando el
transporte endurecido `SecureHttpClient.post_json` (TLS verificado, allowlist, sin
redirects, lectura acotada, anti JSON-bomb). Toda respuesta es entrada NO confiable:

- Doble parseo (design §2.2): el sobre (parseo 1) lo devuelve `post_json` ya como
  `dict`; su `content[0].text` lleva el JSON estructurado como STRING (parseo 2) que
  se valida con `safe_json_loads(reject_nonfinite=True)` para rechazar NaN/Infinity.
- `stop_reason != "end_turn"` (incl. refusal/max_tokens/pause_turn) o `content` sin
  bloque `text` ⇒ abstencion (`None`).
- `confianza` se valida con `math.isfinite(c) and 0.0 <= c <= 1.0` EN ESE ORDEN (un
  NaN evade un chequeo de rango: `NaN<0` y `NaN>1` son ambos False).
- `patron`/`rationale` pasan por `sanitize_and_truncate` ANTES de construir el modelo
  (ADR-19, defensa contra inyeccion de 2do orden).

SEGURIDAD (ADR-15): la `ANTHROPIC_API_KEY` se lee de `os.environ` en `evaluate()` y
viaja SOLO via `extra_headers`; NUNCA se guarda en `self`, ni se loguea, ni aparece en
mensajes de excepcion/JSON. NINGUNA excepcion escapa de `evaluate()`: cualquier fallo
o abstencion devuelve `None` (el resolver lo mapea a `LLM_UNAVAILABLE`).

Frontera (ADR-17): este modulo importa solo `core.models`, `core.net`, `core.errors`,
`core.normalize` y `core.llm.{prompt,evaluator}`. NO importa `core.config` (recibe los
escalares via `AnthropicSettings`), `core.layers`, `core.scoring` ni `cli`.
"""

from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from slopguard.core.errors import NetworkUnverifiableError
from slopguard.core.llm.prompt import RESPONSE_SCHEMA, build_prompt
from slopguard.core.models import Clasificacion, LlmAssessment
from slopguard.core.net.safe_json import safe_json_loads
from slopguard.core.normalize import sanitize_and_truncate

if TYPE_CHECKING:
    from slopguard.core.models import HallucinationContext
    from slopguard.core.net.http_client import SecureHttpClient

# Variable de entorno con la clave del API. Se lee en evaluate(), nunca en self.
_API_KEY_ENV: Final[str] = "ANTHROPIC_API_KEY"

# Valor de stop_reason que indica una respuesta utilizable; cualquier otro
# (refusal/max_tokens/pause_turn/ausente) ⇒ abstension (design §2.7, R4).
_STOP_REASON_OK: Final[str] = "end_turn"

# Tipo del bloque de contenido que lleva el JSON estructurado como string.
_TEXT_BLOCK_TYPE: Final[str] = "text"

# Base del backoff exponencial del reintento (0.5s, 1s, 2s...), misma semantica
# que `osv._sleep_within_budget` (Hito 1/2): determinista, reloj monotonico.
_BACKOFF_BASE_S: Final[float] = 0.5


@dataclass(frozen=True, slots=True)
class AnthropicSettings:
    """Escalares de configuracion del adaptador (subconjunto de `Config`, ADR-17).

    Se inyecta en vez del `Config` entero para no acoplar `core.llm` a `core.config`
    (frontera import-linter): el engine traduce los campos `llm_*` de `Config` a este
    dataclass local al construir el `AnthropicEvaluator`.
    """

    llm_host: str
    llm_api_path: str
    llm_api_version: str
    llm_model: str
    llm_effort: str
    llm_max_tokens: int
    llm_timeout_total_s: float
    llm_reintentos: int
    connect_timeout_s: float
    read_timeout_s: float
    max_response_bytes: int
    max_json_depth: int
    prompt_version: str
    llm_max_text_patron: int
    llm_max_text_rationale: int


class AnthropicEvaluator:
    """Evaluador LLM concreto sobre la API de Anthropic (implementa `LlmEvaluator`)."""

    def __init__(self, http: SecureHttpClient, settings: AnthropicSettings) -> None:
        """Recibe un `SecureHttpClient` ya construido y los escalares de config.

        El `http` debe tener `api.anthropic.com` (o el `llm_host` configurado) en su
        allowlist efectiva (`extra_allowed_hosts`); su construccion la hace el engine.
        La URL del endpoint se compone una vez y se guarda; la clave NO se guarda aqui.
        """
        self._http: Final[SecureHttpClient] = http
        self._settings: Final[AnthropicSettings] = settings
        self._url: Final[str] = f"https://{settings.llm_host}{settings.llm_api_path}"

    def evaluate(
        self, name: str, context: HallucinationContext, ecosystem_id: str = "pypi"
    ) -> LlmAssessment | None:
        """Clasifica `name`; `None` ante CUALQUIER abstencion. NUNCA lanza (ADR-15/R4).

        Lee la clave de entorno (ausente ⇒ None), arma el request, reintenta solo
        fallos transitorios dentro del presupuesto, valida el doble parseo y el
        esquema, y devuelve un `LlmAssessment` saneado. Cualquier excepcion inesperada
        se atrapa y degrada a `None` (la clave jamas escapa en una traza).

        `ecosystem_id` (``"pypi"``/``"npm"``) se propaga hasta `build_prompt` para
        emitir el texto del ecosistema correcto (ADR-6, H4); el default ``"pypi"``
        preserva el comportamiento existente. `build_prompt` valida `ecosystem_id`
        contra su tabla cerrada y lanza `ValueError` ante un id de cableado invalido;
        ese fallo cae en el `except Exception` y degrada a `None` (la clave no escapa).
        """
        api_key = os.environ.get(_API_KEY_ENV)
        if not api_key:
            return None
        try:
            envelope = self._post_with_retries(name, context, api_key, ecosystem_id)
            if envelope is None:
                return None
            return self._parse_envelope(envelope)
        except NetworkUnverifiableError:
            # Defensa en profundidad: cualquier NetworkUnverifiableError no atrapado
            # por _post_with_retries (p.ej. del 2do parseo) degrada a abstension.
            return None
        except Exception:  # R4: ninguna excepcion escapa de evaluate(); la clave no se filtra
            return None

    def _post_with_retries(
        self, name: str, context: HallucinationContext, api_key: str, ecosystem_id: str
    ) -> dict[str, object] | None:
        """Envia el POST con reintentos solo de fallos transitorios; `None` si abstiene.

        Mismo patron que `osv._retry_batch`: `deadline = monotonic + llm_timeout_total_s`,
        `max_attempts = llm_reintentos + 1`. Solo reintenta `NetworkUnverifiableError`
        con `is_transient=True` (5xx/429/timeout/conexion caida). Un fallo permanente
        (400 por payload, 401/403 por clave invalida, anomalia de seguridad) corta sin
        reintentar. Agotado el presupuesto o los reintentos ⇒ `None`.

        `ecosystem_id` se propaga a `_build_body`/`build_prompt`. El cuerpo se arma UNA
        vez antes del bucle: el texto del prompt es estable entre reintentos.
        """
        body = self._build_body(name, context, ecosystem_id)
        headers = {"x-api-key": api_key, "anthropic-version": self._settings.llm_api_version}
        deadline = time.monotonic() + self._settings.llm_timeout_total_s
        max_attempts = self._settings.llm_reintentos + 1
        attempt = 0
        while True:
            if time.monotonic() >= deadline:
                return None  # presupuesto rebasado: no se inicia un nuevo intento
            try:
                return self._post_once(body, headers)
            except NetworkUnverifiableError as exc:
                if not exc.is_transient:
                    return None  # 4xx!=429 / anomalia permanente: no se reintenta
            attempt += 1
            if attempt >= max_attempts or not _sleep_within_budget(attempt - 1, deadline):
                return None  # reintentos agotados o sin margen de backoff ⇒ abstension

    def _post_once(self, body: dict[str, object], headers: dict[str, str]) -> dict[str, object]:
        """Una llamada a `post_json` con los limites de transporte (puede lanzar)."""
        return self._http.post_json(
            self._url,
            body,
            connect_timeout_s=self._settings.connect_timeout_s,
            read_timeout_s=self._settings.read_timeout_s,
            max_response_bytes=self._settings.max_response_bytes,
            max_json_depth=self._settings.max_json_depth,
            extra_headers=headers,
        )

    def _build_body(
        self, name: str, context: HallucinationContext, ecosystem_id: str
    ) -> dict[str, object]:
        """Arma el cuerpo del request (design §2.7); SIN temperature/top_p/thinking.

        `output_config.format` fija la salida estructurada via `RESPONSE_SCHEMA`. El
        nombre+contexto se encajonan como datos en `build_prompt` (ADR-19). El
        `ecosystem_id` se reenvia a `build_prompt`, que emite el texto del ecosistema
        desde su tabla cerrada (nunca refleja el valor crudo; ADR-6, H4).
        """
        return {
            "model": self._settings.llm_model,
            "max_tokens": self._settings.llm_max_tokens,
            "output_config": {
                "effort": self._settings.llm_effort,
                "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA},
            },
            "messages": [
                {"role": "user", "content": build_prompt(name, context, ecosystem_id)}
            ],
        }

    def _parse_envelope(self, envelope: dict[str, object]) -> LlmAssessment | None:
        """Valida `stop_reason`, extrae el JSON estructurado y construye el assessment.

        Acceso DEFENSIVO al sobre (ausencia/typo de clave ⇒ `None`, nunca KeyError):
        - `stop_reason != "end_turn"` ⇒ abstension.
        - El primer bloque `content` con `type=="text"` lleva el JSON como string;
          ausencia ⇒ abstension. Segundo parseo con `reject_nonfinite=True`.
        """
        if envelope.get("stop_reason") != _STOP_REASON_OK:
            return None
        text = _extract_text_block(envelope.get("content"))
        if text is None:
            return None
        parsed = safe_json_loads(
            text.encode("utf-8"), self._settings.max_json_depth, reject_nonfinite=True
        )
        if not isinstance(parsed, dict):
            return None
        return self._validate_assessment(parsed)

    def _validate_assessment(self, parsed: dict[str, object]) -> LlmAssessment | None:
        """Valida tipos/dominio del JSON estructurado y construye el `LlmAssessment`.

        Reglas (entrada NO confiable, design §2.2):
        - `clasificacion` debe ser un valor valido del enum `Clasificacion`.
        - `confianza` debe ser un numero (no bool) con `isfinite` y en [0, 1] EN ESE
          ORDEN (un NaN evadiria el chequeo de rango).
        - `patron`/`rationale` deben ser `str`; se sanean+truncan ANTES de construir.
        Cualquier desviacion ⇒ `None` (abstension).
        """
        clasificacion = _parse_clasificacion(parsed.get("clasificacion"))
        confianza = _parse_confianza(parsed.get("confianza"))
        patron_raw = parsed.get("patron")
        rationale_raw = parsed.get("rationale")
        if clasificacion is None or confianza is None:
            return None
        if not isinstance(patron_raw, str) or not isinstance(rationale_raw, str):
            return None
        return LlmAssessment(
            clasificacion=clasificacion,
            confianza=confianza,
            patron=sanitize_and_truncate(patron_raw, self._settings.llm_max_text_patron),
            rationale=sanitize_and_truncate(rationale_raw, self._settings.llm_max_text_rationale),
            modelo=self._settings.llm_model,
            prompt_version=self._settings.prompt_version,
        )


def _extract_text_block(content: object) -> str | None:
    """Devuelve el `text` del primer bloque `type=="text"` de `content`, o `None`.

    Acceso defensivo: `content` debe ser lista de dicts; el primer bloque con
    `type=="text"` y un campo `text` de tipo `str` se devuelve. Ausencia/typo de
    clave, bloque no-dict o `text` no-str ⇒ `None` (nunca KeyError/IndexError).
    """
    if not isinstance(content, list):
        return None
    for block in content:
        if not isinstance(block, dict) or block.get("type") != _TEXT_BLOCK_TYPE:
            continue
        text = block.get("text")
        return text if isinstance(text, str) else None
    return None


def _parse_clasificacion(value: object) -> Clasificacion | None:
    """Convierte `value` a un `Clasificacion` valido, o `None` si no esta en el enum."""
    if not isinstance(value, str):
        return None
    try:
        return Clasificacion(value)
    except ValueError:
        return None


def _parse_confianza(value: object) -> float | None:
    """Valida `confianza`: numero (no bool) con `isfinite` y en [0, 1] EN ESE ORDEN.

    El orden importa: `math.isfinite` se evalua ANTES del rango porque `NaN<0` y
    `NaN>1` son ambos False, asi que un NaN evadiria un chequeo de rango aislado.
    `bool` se excluye explicitamente (es subclase de `int`: `True` valdria 1.0).
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    confianza = float(value)
    if not math.isfinite(confianza) or not (0.0 <= confianza <= 1.0):
        return None
    return confianza


def _sleep_within_budget(attempt: int, deadline: float) -> bool:
    """Espera el backoff del intento `attempt` (0.5s, 1s, 2s...) sin rebasar el deadline.

    Si la espera completa no cabe en el presupuesto restante, NO duerme y reporta False
    para cortar a abstension antes que exceder `llm_timeout_total_s` (misma semantica
    que `osv._sleep_within_budget`). Determinista: reloj monotonico, sin reloj de pared.
    """
    backoff = _BACKOFF_BASE_S * (2**attempt)
    if backoff > deadline - time.monotonic():
        return False
    time.sleep(backoff)
    return True
