"""Constantes de exit code de la CLI y mapeo de categorias operacionales.

Los exit codes siguen R7 / §3.5. La logica de agregacion VIVE en el core
(`aggregate_exit_code`); aqui solo se nombran las constantes para que
`main.py` no use literales magicos, y se mapea `ErrorCategory` a exit 3.

Tabla de exit codes (R7.1-7.6):
  0 — allow         todo allow, sin warn/block/unverifiable
  1 — warn          ≥1 warn, sin block ni unverifiable (sin --strict)
  2 — block         ≥1 block, o cualquier warn con --strict
  3 — operacional   error total (manifiesto/config/dataset) o ≥1 unverifiable sin block
"""

from __future__ import annotations

# Exit codes nominales (R7.1-7.6).
EXIT_ALLOW: int = 0
EXIT_WARN: int = 1
EXIT_BLOCK: int = 2
EXIT_OPERATIONAL: int = 3

# Todas las categorias de error del dominio se mapean a exit operacional (3).
# Incluye: manifest_parse, invalid_config, dataset_integrity, network_unverifiable.
EXIT_FOR_ERROR_CATEGORY: int = EXIT_OPERATIONAL
