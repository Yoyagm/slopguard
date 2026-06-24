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

Extension Hito 2 (H2-T13, aditiva): se re-exportan `Advisory` y `MaliceState`
(ambos en `core.models`, modulo hoja) para que la CLI (H2-T14) los use sin romper
la frontera import-linter `core ✗→ cli`. `load_config` ya expone los 13 defaults
de Capa 3 a traves de `Config` sin cambios de firma (R5.1, R5.3, tabla R5).
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
    Advisory,
    Dependency,
    DependencyResult,
    ErrorCategory,
    Layer,
    LayerSignal,
    MaliceState,
    ScanReport,
    ScanSummary,
    SignalCode,
    Status,
    Verdict,
)
from slopguard.core.scoring.verdict import aggregate_exit_code

# Orden isort-style (RUF022): clases/enums primero, luego funciones; alfabetico.
# Los simbolos de Hito 2 (Advisory, MaliceState) se insertan en orden alfabetico
# sin desplazar ni renombrar ninguno del Hito 1 (garantia de retro-compatibilidad).
__all__ = [
    # Hito 2: modelos de threat-intel (hojas en core.models, frontera segura).
    "Advisory",
    "Config",
    # Errores del dominio (§3.6).
    "DatasetIntegrityError",
    "Dependency",
    "DependencyResult",
    "ErrorCategory",
    "InvalidConfigError",
    "Layer",
    "LayerSignal",
    # Hito 2: estado de malicia (hoja en core.models).
    "MaliceState",
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
