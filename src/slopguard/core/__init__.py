"""Fachada del core de SlopGuard: API publica congelada (§3.1, R10.3).

Este modulo es el UNICO punto de importacion para la CLI (`slopguard.cli`): la
frontera core/CLI se verifica con import-linter (core no importa cli). Re-exporta
las funciones de entrada del orquestador, la carga de config, la agregacion de
exit code y los modelos/enums necesarios para renderizar el resultado.

Contrato congelado (§3.1):
  - `scan_manifest(path, config, *, use_cache=True, ecosystem_id="pypi",
    manifest_type=None)`
  - `scan_stdin(text, config, *, use_cache=True, ecosystem_id="pypi")`
  - `scan_dependencies(deps, config, *, use_cache=True, ecosystem_id="pypi")`
  - `load_config(explicit_path, cli_overrides)`
  - `aggregate_exit_code(report, *, strict)`

Ampliacion de §3.1 (decision T33): `scan_manifest` admite `manifest_type` keyword
opcional (default `None` = autodeteccion, retro-compatible) para cablear el flag
`--manifest-type` de la CLI (T34) a la deteccion de T11. Es el unico camino que
respeta R10.3: la CLI importa SOLO esta fachada, asi que el override del tipo de
manifiesto debe entrar por aqui en vez de tocar `detect.py` directamente.

El `strict` NO es parametro de `scan_*` (la API §3.1 lo deja fuera): el reporte
trae un `exit_code` base en su summary y la CLI aplica `aggregate_exit_code(
report, strict=...)` con su flag `--strict`. Asi el motor permanece puro y la
politica de severidad de CI vive en una unica funcion (R7.6).
"""

from __future__ import annotations

from slopguard.core.config import Config, load_config
from slopguard.core.engine import scan_dependencies, scan_manifest, scan_stdin
from slopguard.core.errors import (
    DatasetIntegrityError,
    InvalidConfigError,
    ManifestParseError,
    NetworkUnverifiableError,
    SlopGuardError,
)
from slopguard.core.models import (
    Dependency,
    DependencyResult,
    ErrorCategory,
    Layer,
    LayerSignal,
    ScanReport,
    ScanSummary,
    SignalCode,
    Status,
    Verdict,
)
from slopguard.core.scoring.verdict import aggregate_exit_code

# Orden isort-style (RUF022): clases/enums primero, luego funciones; alfabetico.
__all__ = [
    "Config",
    # Errores del dominio (§3.6).
    "DatasetIntegrityError",
    "Dependency",
    "DependencyResult",
    "ErrorCategory",
    "InvalidConfigError",
    "Layer",
    "LayerSignal",
    "ManifestParseError",
    "NetworkUnverifiableError",
    "ScanReport",
    "ScanSummary",
    "SignalCode",
    "SlopGuardError",
    "Status",
    "Verdict",
    # Funciones de entrada de la API (§3.1).
    "aggregate_exit_code",
    "load_config",
    "scan_dependencies",
    "scan_manifest",
    "scan_stdin",
]
