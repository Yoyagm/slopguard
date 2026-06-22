"""Modelos de dominio inmutables de SlopGuard (core).

Todos los modelos de resultado son `frozen=True, slots=True` y usan `tuple[...]`
para colecciones: asi el resultado es inmutable *de verdad* (un frozen dataclass
no impide mutar una lista interna; una tupla si — leccion del `password-validator`).
Los enums son StrEnum/IntEnum para que el JSON de salida sea estable y versionable.

Este modulo es hoja: no importa nada del propio paquete.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum


class Layer(IntEnum):
    """Capa de deteccion que origino una senal."""

    L0 = 0
    L1 = 1
    L2 = 2


class SignalCode(StrEnum):
    """Codigo estable de cada senal (clave en el JSON de salida)."""

    NONEXISTENT = "nonexistent"  # L0, override de inexistencia
    NEW_PACKAGE = "new_package"  # L0, blanda
    TYPOSQUAT = "typosquat"  # L1, dura
    NAME_UNTRUSTED = "name_untrusted"  # L1, dura (nombre > nombre_max_chars)
    WEAK_METADATA = "weak_metadata"  # L2, blanda
    LOW_VERIFIABILITY = "low_verifiability"  # L2, blanda (sin repo enlazado)


class Verdict(StrEnum):
    """Veredicto derivado del score o por override."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class Status(StrEnum):
    """Estado de verificacion, independiente del veredicto."""

    OK = "ok"  # verificable: la evaluacion se completo
    UNVERIFIABLE = "unverifiable"  # no se pudo verificar; sin score, nunca allow


class ErrorCategory(StrEnum):
    """Categoria estable de error, distinguible en salida/CI."""

    MANIFEST_PARSE = "manifest_parse"
    INVALID_CONFIG = "invalid_config"
    NETWORK_UNVERIFIABLE = "network_unverifiable"
    DATASET_INTEGRITY = "dataset_integrity"


@dataclass(frozen=True, slots=True)
class Dependency:
    """Dependencia parseada de un manifiesto (entrada al motor)."""

    name: str  # normalizado PEP 503
    version_pin: str | None  # version si esta pinneada (==X)
    raw: str  # original SANEADO (para mostrar)
    origin: str  # ruta RELATIVA y saneada del manifiesto de origen


@dataclass(frozen=True, slots=True)
class LayerSignal:
    """Senal individual emitida por una capa, con su explicacion saneada."""

    layer: Layer
    code: SignalCode
    weight: int  # puntos de riesgo (0 si informativa/override)
    is_soft: bool  # True=corroborante acotada; False=dura/override
    detail: str  # explicacion en espanol, SANEADA
    suspected_target: str | None = None  # paquete legitimo sospechado (typosquat)


@dataclass(frozen=True, slots=True)
class DependencyResult:
    """Resultado de evaluar una dependencia."""

    name: str
    version_pin: str | None
    status: Status
    verdict: Verdict | None  # None si unverifiable
    score: int | None  # 0-100; None si unverifiable o block-override
    signals: tuple[LayerSignal, ...]
    suspected_target: str | None
    error_category: ErrorCategory | None


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """Conteos agregados del escaneo y el exit code final."""

    total: int
    allow: int
    warn: int
    block: int
    unverifiable: int
    exit_code: int


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Reporte completo del escaneo, inmutable y ya ordenado (R6.4)."""

    schema_version: str
    tool_version: str
    ecosystem: str
    summary: ScanSummary
    results: tuple[DependencyResult, ...]
    error_category: ErrorCategory | None  # error operacional total, si lo hubo
