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
    L3 = 3  # NUEVO: threat-intel (Hito 2)


class SignalCode(StrEnum):
    """Codigo estable de cada senal (clave en el JSON de salida)."""

    NONEXISTENT = "nonexistent"  # L0, override de inexistencia
    NEW_PACKAGE = "new_package"  # L0, blanda
    TYPOSQUAT = "typosquat"  # L1, dura
    NAME_UNTRUSTED = "name_untrusted"  # L1, dura (nombre > nombre_max_chars)
    WEAK_METADATA = "weak_metadata"  # L2, blanda
    LOW_VERIFIABILITY = "low_verifiability"  # L2, blanda (sin repo enlazado)
    # --- L3: threat-intel (Hito 2, aditivos) ---
    MALICIOUS = "malicious"  # L3, DURA, override de block (ADR-06, weight=0)
    KNOWN_HALLUCINATION = "known_hallucination"  # L3, DURA, weight=85 (ADR-07)
    THREATINTEL_UNVERIFIABLE = "threatintel_unverifiable"  # L3, BLANDA, weight=0


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
class Advisory:
    """Advisory de malicia normalizado y saneado (nunca payload crudo de OSV).

    El id y la url se construyen/validan antes de crear el objeto;
    jamas se reflejan datos crudos de la red en este modelo.
    """

    id: str  # p.ej. "MAL-2025-47868" (validado: prefijo MAL-, charset acotado)
    kind: str  # "malicious" (unica clase relevante en Hito 2)
    url: str  # "https://osv.dev/vulnerability/<id>" (construido, no reflejado)
    source: str  # "osv"


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
    advisories: tuple[Advisory, ...] = ()  # NUEVO (Hito 2, aditivo, default=()==retro-compatible)


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
