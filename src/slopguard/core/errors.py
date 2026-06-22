"""Excepciones del core, cada una mapeada a un ErrorCategory y un exit code (3).

Las tres primeras son *operacionales totales*: abortan el escaneo. En cambio
`NetworkUnverifiableError` es *por-dependencia*: marca esa dep como `unverifiable`
y el lote continua (degradacion segura, R2.5 / NFR-Degr.1).

Los mensajes deben venir ya saneados y SIN rutas absolutas ni contenido del
manifiesto (R6.5): es responsabilidad de quien lanza la excepcion construir un
mensaje apto para CI.
"""

from __future__ import annotations

from .models import ErrorCategory


class SlopGuardError(Exception):
    """Base de los errores del dominio. Lleva su categoria estable."""

    error_category: ErrorCategory

    def __init__(self, message: str, error_category: ErrorCategory) -> None:
        super().__init__(message)
        self.error_category = error_category


class ManifestParseError(SlopGuardError):
    """Manifiesto malformado, demasiado grande, o include escapado/ciclico/inexistente."""

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorCategory.MANIFEST_PARSE)


class InvalidConfigError(SlopGuardError):
    """Configuracion con tipos o rangos fuera de dominio (R8.3)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorCategory.INVALID_CONFIG)


class DatasetIntegrityError(SlopGuardError):
    """Dataset top-N ausente, no cargable o con checksum invalido (R3.9)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, ErrorCategory.DATASET_INTEGRITY)


class NetworkUnverifiableError(SlopGuardError):
    """Por-dependencia: red agotada o respuesta anomala. No aborta el lote.

    Lleva metadatos de clasificacion para que el adapter distinga sin romper la
    frontera R10.1 (las capas/scoring nunca ven esta excepcion):
    - `status_code`: codigo HTTP si la causa fue una respuesta >=400 (None si la
      causa fue un fallo de transporte: timeout, conexion caida, descompresion).
    - `is_transient`: True si el fallo es reintentable (timeout/conexion caida/5xx);
      False si es permanente (404, 4xx!=404, anomalia de seguridad como redirect o
      bomba). 404 NO es transitorio: es existencia negativa, la mapea el adapter a
      NOT_FOUND via `status_code`. Por defecto False (degradacion conservadora: ante
      la duda no se reintenta).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        is_transient: bool = False,
    ) -> None:
        super().__init__(message, ErrorCategory.NETWORK_UNVERIFIABLE)
        self.status_code = status_code
        self.is_transient = is_transient
