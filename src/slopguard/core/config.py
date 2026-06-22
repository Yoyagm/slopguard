"""Configuracion de SlopGuard: defaults, carga TOML y validacion de rangos.

`Config` es la UNICA fuente de verdad de los defaults (tabla R8). `load_config`
resuelve con precedencia CLI > archivo (`[tool.slopguard]` en pyproject.toml o
`.slopguard.toml`) > defaults, y valida rangos: cualquier valor fuera de dominio
aborta con `InvalidConfigError` (exit 3) SIN aplicar valores a medias (R8.3).
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import InvalidConfigError

# Campos numericos por tipo (clasificacion explicita = sin reflexion fragil).
_INT_FIELDS: frozenset[str] = frozenset({
    "umbral_block", "umbral_warn", "edad_minima_dias", "ttl_cache_horas",
    "concurrencia_max", "reintentos_red", "dl_max", "nombre_max_chars",
    "releases_min", "metadata_faltantes_min", "releases_populares", "c2_max_contrib",
    "max_manifest_bytes", "max_deps", "max_response_bytes", "max_json_depth",
    "max_include_depth",
})
_FLOAT_FIELDS: frozenset[str] = frozenset({
    "connect_timeout_s", "read_timeout_s", "timeout_total_por_dep_s", "jw_min",
})
_KNOWN_FIELDS: frozenset[str] = _INT_FIELDS | _FLOAT_FIELDS

# Parametros que deben ser estrictamente positivos (timeouts, limites, conteos
# de capacidad). Los umbrales de conteo (releases_min, etc.) admiten 0.
_STRICTLY_POSITIVE: frozenset[str] = frozenset({
    "edad_minima_dias", "ttl_cache_horas", "concurrencia_max", "reintentos_red",
    "connect_timeout_s", "read_timeout_s", "timeout_total_por_dep_s",
    "max_manifest_bytes", "max_deps", "max_response_bytes", "max_json_depth",
    "max_include_depth", "releases_populares",
})

# Cotas de dominio de R8.3 (nombradas para trazabilidad y claridad).
_UMBRAL_MAX = 100
_NOMBRE_MIN_CHARS = 4


@dataclass(frozen=True, slots=True)
class Config:
    """Parametros de comportamiento. Defaults = tabla R8 (unica fuente de verdad)."""

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
    max_json_depth: int = 50
    max_include_depth: int = 10


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


def _coerce(key: str, raw: object) -> int | float:
    """Valida el tipo de un valor. Rechaza booleanos (subclase de int)."""
    if isinstance(raw, bool):
        raise InvalidConfigError(f"'{key}' no admite un booleano")
    if key in _INT_FIELDS:
        if isinstance(raw, int):
            return raw
        raise InvalidConfigError(f"'{key}' debe ser un entero")
    if isinstance(raw, int | float):
        return float(raw)
    raise InvalidConfigError(f"'{key}' debe ser numerico")


def _validate_ranges(config: Config) -> None:
    """Valida los dominios de R8.3. Cualquier violacion ⇒ InvalidConfigError."""
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
