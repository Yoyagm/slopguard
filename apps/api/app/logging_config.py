"""Configuración de logging del servicio.

Logs a stdout (apto para contenedor). NUNCA se loguean secretos (tokens, claves, webhook
secret): los call-sites no deben pasarlos. La versión estructurada (JSON) + redacción se
endurece en la observabilidad (H5-T42); aquí queda la base.
"""

from __future__ import annotations

import logging
import sys


def configure_logging(level: str = "INFO") -> None:
    """Configura el root logger a stdout con un formato legible y sin secretos."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
