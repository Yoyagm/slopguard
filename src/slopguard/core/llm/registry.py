"""Factory de la Capa 4 (Hito 3): construye el evaluador LLM y su cache.

Mirror de `threatintel.registry.get_threatintel_source`. El evaluador concreto
(`AnthropicEvaluator`) es puro-HTTP (sin cache); la cache la posee el resolver para
que el presupuesto de llamadas distinga aciertos de cache (que NO cuentan) de
llamadas de red. Devuelve `None` si la Capa 4 esta desactivada o falta la clave
(en ambos casos el engine omite la Capa 4 y el flujo es identico al Hito 2).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.llm.anthropic import AnthropicEvaluator, AnthropicSettings
from slopguard.core.net.http_client import SecureHttpClient

if TYPE_CHECKING:
    from slopguard.core.config import Config
    from slopguard.core.llm.evaluator import LlmEvaluator

_API_KEY_ENV = "ANTHROPIC_API_KEY"


def get_llm_evaluator(config: Config, *, use_cache: bool) -> LlmEvaluator | None:
    """Devuelve el evaluador LLM activo, o `None` si Capa 4 off o sin clave.

    `None` ⇒ el engine omite la Capa 4 (sin host nuevo en el allowlist, sin senales
    L4): comportamiento identico al Hito 2 (R5.3/R8.2). `use_cache` se acepta por
    simetria con el resto de factories; la cache la construye `build_llm_cache`.
    """
    if not config.enable_layer4:
        return None
    if not os.environ.get(_API_KEY_ENV):
        return None
    http = SecureHttpClient(extra_allowed_hosts=frozenset({config.llm_host}))
    return AnthropicEvaluator(http, _settings(config))


def build_llm_cache(config: Config, *, enabled: bool) -> DiskCache:
    """Construye la `DiskCache` de la Capa 4 (mismo root que el Hito 1, TTL propio)."""
    cache_root = Path.home() / ".cache" / "slopguard"
    return DiskCache(cache_root, config.llm_ttl_cache_horas, enabled=enabled)


def _settings(config: Config) -> AnthropicSettings:
    """Traduce los campos `llm_*` de `Config` al dataclass local del adaptador (ADR-17)."""
    return AnthropicSettings(
        llm_host=config.llm_host,
        llm_api_path=config.llm_api_path,
        llm_api_version=config.llm_api_version,
        llm_model=config.llm_model,
        llm_effort=config.llm_effort,
        llm_max_tokens=config.llm_max_tokens,
        llm_timeout_total_s=config.llm_timeout_total_s,
        llm_reintentos=config.llm_reintentos,
        connect_timeout_s=config.connect_timeout_s,
        read_timeout_s=config.read_timeout_s,
        max_response_bytes=config.max_response_bytes,
        max_json_depth=config.max_json_depth,
        prompt_version=config.prompt_version,
        llm_max_text_patron=config.llm_max_text_patron,
        llm_max_text_rationale=config.llm_max_text_rationale,
    )
