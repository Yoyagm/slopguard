"""Configuracion de SlopGuard: defaults, carga TOML y validacion de rangos.

`Config` es la UNICA fuente de verdad de los defaults (tabla R8 + tabla R5 Capa 3).
`load_config` resuelve con precedencia CLI > archivo (`[tool.slopguard]` en
pyproject.toml o `.slopguard.toml`) > defaults, y valida rangos: cualquier valor
fuera de dominio aborta con `InvalidConfigError` (exit 3) SIN aplicar valores a
medias (R8.3 / R5.2).
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import InvalidConfigError
from .models import LLM_SOFT_CAP, SOFT_CAP
from .normalize import sanitize_for_output

# ---------------------------------------------------------------------------
# Clasificacion de campos por tipo (explicita = sin reflexion fragil).
# Los nuevos campos de Capa 3 se anaden DESPUES de las constantes del Hito 1.
# ---------------------------------------------------------------------------

# Campos enteros: Hito 1 (sin cambios) + Capa 3.
_INT_FIELDS: frozenset[str] = frozenset({
    "umbral_block", "umbral_warn", "edad_minima_dias", "ttl_cache_horas",
    "concurrencia_max", "reintentos_red", "dl_max", "nombre_max_chars",
    "releases_min", "metadata_faltantes_min", "releases_populares", "c2_max_contrib",
    "max_manifest_bytes", "max_deps", "max_response_bytes", "npm_max_response_bytes",
    "max_json_depth", "max_include_depth",
    # Capa 3 (tabla R5):
    "osv_batch_max", "osv_ttl_cache_horas", "osv_reintentos",
    "watchlist_ttl_cache_horas",
    # Capa 4 (tabla R5, Hito 3):
    "gray_edad_max_dias", "w_base_fabricacion", "w_base_conflacion", "w_base_typo",
    "llm_max_calls_por_corrida", "llm_max_text_patron", "llm_max_text_rationale",
    "llm_ttl_cache_horas", "llm_reintentos", "llm_max_tokens",
})

# Campos float: Hito 1 (sin cambios) + Capa 3.
_FLOAT_FIELDS: frozenset[str] = frozenset({
    "connect_timeout_s", "read_timeout_s", "timeout_total_por_dep_s", "jw_min",
    # Capa 3 (tabla R5):
    "osv_timeout_total_por_lote_s", "watchlist_timeout_total_s",
    # Capa 4 (Hito 3):
    "llm_conf_min", "llm_timeout_total_s", "llm_unavailable_warn_frac",
})

# Campos string nuevos de Capa 3 (hosts, rutas, modo de degradacion).
_STR_FIELDS: frozenset[str] = frozenset({
    "osv_host", "osv_query_path",
    "watchlist_host", "watchlist_source_path",
    "threatintel_degraded_status",
    # Capa 4 (Hito 3):
    "llm_host", "llm_api_path", "llm_api_version", "llm_model",
    "llm_effort", "prompt_version",
})

# Campos booleanos nuevos de Capa 3.
_BOOL_FIELDS: frozenset[str] = frozenset({
    "enable_layer3", "enable_watchlist",
    "enable_layer4",  # Capa 4 (Hito 3)
})

# Union total de campos conocidos (rechaza cualquier clave ajena).
_KNOWN_FIELDS: frozenset[str] = _INT_FIELDS | _FLOAT_FIELDS | _STR_FIELDS | _BOOL_FIELDS

# ---------------------------------------------------------------------------
# Parametros estrictamente positivos (> 0). Los umbrales de conteo admiten 0.
# ---------------------------------------------------------------------------
_STRICTLY_POSITIVE: frozenset[str] = frozenset({
    "edad_minima_dias", "ttl_cache_horas", "concurrencia_max", "reintentos_red",
    "connect_timeout_s", "read_timeout_s", "timeout_total_por_dep_s",
    "max_manifest_bytes", "max_deps", "max_response_bytes", "npm_max_response_bytes",
    "max_json_depth", "max_include_depth", "releases_populares",
    # Capa 3:
    "osv_batch_max", "osv_ttl_cache_horas", "osv_timeout_total_por_lote_s",
    "watchlist_ttl_cache_horas", "watchlist_timeout_total_s",
    # Capa 4:
    "gray_edad_max_dias", "w_base_fabricacion", "w_base_conflacion", "w_base_typo",
    "llm_max_calls_por_corrida", "llm_max_text_patron", "llm_max_text_rationale",
    "llm_ttl_cache_horas", "llm_timeout_total_s", "llm_max_tokens",
})

# ---------------------------------------------------------------------------
# Cotas de dominio (nombradas para trazabilidad).
# ---------------------------------------------------------------------------
_UMBRAL_MAX = 100
_NOMBRE_MIN_CHARS = 4

# Conjunto cerrado de hosts de Capa 3 permitidos (ADR-09 — anti-SSRF interno).
_VALID_OSV_HOSTS: frozenset[str] = frozenset({"api.osv.dev"})
_VALID_WATCHLIST_HOSTS: frozenset[str] = frozenset({"depscope.dev"})

# Valores validos de threatintel_degraded_status (R5.2).
_VALID_DEGRADED_STATUS: frozenset[str] = frozenset({"unverifiable", "warn"})

# Capa 4 (Hito 3): host LLM permitido (conjunto cerrado, ADR-17) y niveles de effort.
_VALID_LLM_HOSTS: frozenset[str] = frozenset({"api.anthropic.com"})
_VALID_LLM_EFFORT: frozenset[str] = frozenset({"low", "medium", "high", "xhigh", "max"})

# Charset de rutas de API: solo caracteres URL seguros sin CRLF/espacios.
_PATH_RE = re.compile(r"\A/[A-Za-z0-9._~/-]*\Z")

# Charset de un label DNS (LDH: letras, digitos, guion); rechaza todo lo demas.
_FQDN_LABEL_RE = re.compile(r"\A[a-z0-9]([a-z0-9-]*[a-z0-9])?\Z")

# Minimo de labels para considerar un FQDN valido (ej: "host.tld" = 2 labels).
_FQDN_MIN_LABELS: int = 2


@dataclass(frozen=True, slots=True)
class Config:
    """Parametros de comportamiento. Defaults = tabla R8 + tabla R5 Capa 3."""

    # --- Hito 1 (sin cambios) ---
    umbral_block: int = 80
    umbral_warn: int = 50
    edad_minima_dias: int = 90
    ttl_cache_horas: int = 24
    concurrencia_max: int = 8
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 10.0
    reintentos_red: int = 2
    timeout_total_por_dep_s: float = 30.0
    jw_min: float = 0.92
    dl_max: int = 2
    nombre_max_chars: int = 100
    releases_min: int = 1
    metadata_faltantes_min: int = 2
    releases_populares: int = 10
    c2_max_contrib: int = 10
    max_manifest_bytes: int = 5_000_000
    max_deps: int = 5000
    max_response_bytes: int = 10_000_000
    # Cap npm-especifico (ADR-2, H4-T05): mayor que el de PyPI por el peso de los packuments.
    npm_max_response_bytes: int = 25_000_000
    max_json_depth: int = 50
    max_include_depth: int = 10

    # --- Capa 3 — tabla R5 (defaults identicos a la tabla, aditivos) ---
    enable_layer3: bool = True
    osv_host: str = "api.osv.dev"
    osv_query_path: str = "/v1/querybatch"
    osv_batch_max: int = 1000
    osv_ttl_cache_horas: int = 6
    osv_timeout_total_por_lote_s: float = 30.0
    osv_reintentos: int = 2
    enable_watchlist: bool = False
    watchlist_host: str = "depscope.dev"
    watchlist_source_path: str = "/api/benchmark/hallucinations"
    watchlist_ttl_cache_horas: int = 24
    watchlist_timeout_total_s: float = 30.0
    threatintel_degraded_status: str = "unverifiable"

    # --- Capa 4 — tabla R5 (Hito 3, aditivos; OFF por defecto) ---
    enable_layer4: bool = False
    llm_host: str = "api.anthropic.com"
    llm_api_path: str = "/v1/messages"
    llm_api_version: str = "2023-06-01"
    llm_model: str = "claude-opus-4-8"
    llm_effort: str = "low"
    prompt_version: str = "h4-v1"
    gray_edad_max_dias: int = 365
    w_base_fabricacion: int = 55
    w_base_conflacion: int = 45
    w_base_typo: int = 40
    llm_conf_min: float = 0.5
    llm_max_calls_por_corrida: int = 50
    llm_max_text_patron: int = 280
    llm_max_text_rationale: int = 1000
    llm_ttl_cache_horas: int = 168
    llm_timeout_total_s: float = 30.0
    llm_reintentos: int = 2
    # Reservado (R4.6): umbral de fraccion para el aviso agregado. Hoy el aviso se emite
    # con CUALQUIER llm_unavailable>0 (mas conservador: nunca finge "todo limpio"); este
    # parametro queda para una version futura que module el aviso por fraccion.
    llm_unavailable_warn_frac: float = 0.2
    llm_max_tokens: int = 512


def load_config(
    explicit_path: str | Path | None,
    cli_overrides: Mapping[str, object],
) -> Config:
    """Resuelve la config con precedencia CLI > archivo > defaults (R8.1/R8.2).

    Valida rangos; lanza `InvalidConfigError` si algo esta fuera de dominio
    (R8.3). Las claves None en `cli_overrides` se ignoran (flag no pasado).
    """
    file_values = _read_config_file(explicit_path)
    overrides = {k: v for k, v in cli_overrides.items() if v is not None}
    merged: dict[str, object] = {**file_values, **overrides}
    return _build_and_validate(merged)


def _read_config_file(explicit_path: str | Path | None) -> dict[str, object]:
    """Lee la tabla de config de un archivo TOML. {} si no hay archivo."""
    if explicit_path is not None:
        path = Path(explicit_path)
        if not path.is_file():
            raise InvalidConfigError(f"archivo de config no encontrado: '{path.name}'")
        return _extract_table(path)
    for candidate in (Path(".slopguard.toml"), Path("pyproject.toml")):
        if candidate.is_file():
            table = _extract_table(candidate)
            if table:
                return table
    return {}


def _extract_table(path: Path) -> dict[str, object]:
    """Devuelve la tabla `[tool.slopguard]` (o el nivel raiz de .slopguard.toml)."""
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        # Solo se usa path.name (sin ruta absoluta) y la clase de error sin el
        # mensaje del SO, que puede contener rutas absolutas (R6.5, NFR-Priv.1).
        raise InvalidConfigError(
            f"config TOML ilegible en '{path.name}': {type(exc).__name__}"
        ) from exc
    tool = data.get("tool")
    if isinstance(tool, dict) and isinstance(tool.get("slopguard"), dict):
        return dict(tool["slopguard"])
    if path.name == "pyproject.toml":
        return {}
    return {k: v for k, v in data.items() if not isinstance(v, dict)}


def _build_and_validate(values: Mapping[str, object]) -> Config:
    """Coacciona tipos, rechaza claves desconocidas y valida rangos."""
    coerced: dict[str, Any] = {}
    for key, raw in values.items():
        if key not in _KNOWN_FIELDS:
            raise InvalidConfigError(f"parametro de configuracion desconocido: '{key}'")
        coerced[key] = _coerce(key, raw)
    config = Config(**coerced)
    _validate_ranges(config)
    return config


def _coerce(key: str, raw: object) -> int | float | str | bool:
    """Valida el tipo de un valor. Bool antes de int (subclase); str antes de num.

    Orden de ramas: bool → str → int → float (numerico general).
    Los campos booleanos exigen `isinstance(raw, bool)` estricto: un 0/1 entero
    se rechaza. Los campos string exigen no-vacio y se sanean de controles.
    Los campos numericos del Hito 1 rechazan booleanos (subclase de int).
    """
    if key in _BOOL_FIELDS:
        if not isinstance(raw, bool):
            raise InvalidConfigError(f"'{key}' debe ser un booleano (true/false)")
        return raw
    if key in _STR_FIELDS:
        if not isinstance(raw, str) or not raw.strip():
            raise InvalidConfigError(f"'{key}' debe ser una cadena no vacia")
        return sanitize_for_output(raw)
    # Rama numerica: rechaza bool (subclase de int), igual que el Hito 1.
    if isinstance(raw, bool):
        raise InvalidConfigError(f"'{key}' no admite un booleano")
    if key in _INT_FIELDS:
        if isinstance(raw, int):
            return raw
        raise InvalidConfigError(f"'{key}' debe ser un entero")
    if isinstance(raw, int | float):
        return float(raw)
    raise InvalidConfigError(f"'{key}' debe ser numerico")


def _is_valid_https_host(host: str) -> bool:
    """True si `host` es un FQDN https-seguro sin userinfo, puerto, path o IP.

    Rechaza (anti-SSRF a host interno / metadata):
    - Userinfo (`@`), puerto (`:`), path/query/fragment (`/`, `?`, `#`).
    - Esquema embebido (`://`).
    - Literales de IP (v4 o v6) segun `ipaddress.ip_address`.
    - `localhost` y variantes.
    - Labels con caracteres fuera del LDH (letras, digitos, guion).
    - Etiquetas vacias o que empiecen/terminen en guion.
    Exige al menos dos labels (FQDN minimo: `host.tld`).
    """
    if not host or any(c in host for c in ("@", ":", "/", "?", "#", " ")):
        return False
    if "://" in host:
        return False
    normalized = host.lower()
    if normalized in ("localhost", "localhost."):
        return False
    # Rechaza literales de IP (v4 y v6).
    try:
        ipaddress.ip_address(normalized)
        return False  # es una IP literal: rechazar
    except ValueError:
        pass
    # Valida labels LDH (RFC 1123).
    labels = normalized.rstrip(".").split(".")
    if len(labels) < _FQDN_MIN_LABELS:
        return False
    return all(_FQDN_LABEL_RE.match(label) for label in labels)


def _validate_host_field(field_name: str, value: str, allowed: frozenset[str]) -> None:
    """Valida que `value` sea un host https valido y pertenezca al conjunto cerrado.

    Lanza `InvalidConfigError` si no supera `_is_valid_https_host` o si el host
    no esta en el conjunto `allowed` (dominio cerrado — ADR-09).
    """
    if not _is_valid_https_host(value):
        raise InvalidConfigError(
            f"'{field_name}' debe ser un FQDN https valido sin puerto, IP ni userinfo"
        )
    if value not in allowed:
        allowed_str = ", ".join(sorted(allowed))
        raise InvalidConfigError(
            f"'{field_name}' no reconocido; valores permitidos: {allowed_str}"
        )


def _validate_path_field(field_name: str, value: str) -> None:
    """Valida que `value` sea una ruta de API que empiece por `/`, sin '..' (R5.2 §3.6).

    Rechaza dot-segments `..` aunque el charset base los permita: un path como
    '/v1/../admin' pasaria la regex pero saldria de /v1/, violando el contrato de
    host/path cerrado anti-SSRF (design §3.6, EARS R5.2).
    """
    if not _PATH_RE.match(value):
        raise InvalidConfigError(
            f"'{field_name}' debe empezar por '/' y contener solo caracteres URL seguros"
        )
    if any(seg == ".." for seg in value.split("/")):
        raise InvalidConfigError(
            f"'{field_name}' no puede contener componentes '..'"
        )


def _validate_anti_block(config: Config) -> None:
    """Valida el invariante anti-block de la Capa 4 (R5.2.b/c, fail-closed).

    Los topes `SOFT_CAP`/`LLM_SOFT_CAP` son estructurales (no configurables); el
    unico parametro movil es `umbral_block`. Esta validacion fija por CONFIG lo
    que el gating garantiza por construccion: el canal L4 (acotado a LLM_SOFT_CAP)
    sumado al techo heuristico (SOFT_CAP) NUNCA alcanza `umbral_block` ⇒ la Capa 4
    jamas bloquea. Ademas exige `LLM_SOFT_CAP >= umbral_warn` para que el canal L4
    pueda alcanzar `warn` (si no, seria inutil). Cualquier violacion ABORTA sin
    aplicar valores a medias (InvalidConfigError ⇒ exit 3, control de seguridad).
    """
    caps_total = SOFT_CAP + LLM_SOFT_CAP
    if caps_total >= config.umbral_block:
        raise InvalidConfigError(
            f"invariante anti-block violado: SOFT_CAP+LLM_SOFT_CAP (={caps_total}) "
            f"debe ser < umbral_block (={config.umbral_block})"
        )
    if LLM_SOFT_CAP < config.umbral_warn:
        raise InvalidConfigError(
            f"LLM_SOFT_CAP (={LLM_SOFT_CAP}) debe ser >= umbral_warn "
            f"(={config.umbral_warn}) para que el canal L4 pueda alcanzar warn"
        )


def _validate_ranges(config: Config) -> None:
    """Valida dominios de R8.3 y R5.2. Cualquier violacion ⇒ InvalidConfigError."""
    # --- Hito 1 (sin cambios) ---
    if not 0 <= config.umbral_warn < config.umbral_block <= _UMBRAL_MAX:
        raise InvalidConfigError(
            "umbrales fuera de rango: requiere 0 <= umbral_warn < umbral_block <= 100"
        )
    if not 0.0 <= config.jw_min <= 1.0:
        raise InvalidConfigError("jw_min debe estar en [0, 1]")
    if config.dl_max < 1:
        raise InvalidConfigError("dl_max debe ser >= 1")
    if config.nombre_max_chars < _NOMBRE_MIN_CHARS:
        raise InvalidConfigError("nombre_max_chars debe ser >= 4")
    for name in _STRICTLY_POSITIVE:
        value = getattr(config, name)
        if value <= 0:
            raise InvalidConfigError(f"'{name}' debe ser > 0")
    # --- Capa 3 (R5.2) ---
    _validate_host_field("osv_host", config.osv_host, _VALID_OSV_HOSTS)
    _validate_host_field("watchlist_host", config.watchlist_host, _VALID_WATCHLIST_HOSTS)
    _validate_path_field("osv_query_path", config.osv_query_path)
    _validate_path_field("watchlist_source_path", config.watchlist_source_path)
    if config.threatintel_degraded_status not in _VALID_DEGRADED_STATUS:
        valid_str = ", ".join(sorted(_VALID_DEGRADED_STATUS))
        raise InvalidConfigError(
            f"'threatintel_degraded_status' debe ser uno de: {valid_str}"
        )
    # --- Capa 4 (R5.2, Hito 3) ---
    _validate_anti_block(config)
    _validate_host_field("llm_host", config.llm_host, _VALID_LLM_HOSTS)
    _validate_path_field("llm_api_path", config.llm_api_path)
    if config.llm_effort not in _VALID_LLM_EFFORT:
        valid_str = ", ".join(sorted(_VALID_LLM_EFFORT))
        raise InvalidConfigError(f"'llm_effort' debe ser uno de: {valid_str}")
    if not 0.0 < config.llm_conf_min <= 1.0:
        raise InvalidConfigError("llm_conf_min debe estar en (0, 1]")
    if not 0.0 <= config.llm_unavailable_warn_frac <= 1.0:
        raise InvalidConfigError("llm_unavailable_warn_frac debe estar en [0, 1]")
    if config.llm_reintentos < 0:
        raise InvalidConfigError("llm_reintentos debe ser >= 0")
