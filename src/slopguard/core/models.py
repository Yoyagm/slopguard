"""Modelos de dominio inmutables de SlopGuard (core).

Todos los modelos de resultado son `frozen=True, slots=True` y usan `tuple[...]`
para colecciones: asi el resultado es inmutable *de verdad* (un frozen dataclass
no impide mutar una lista interna; una tupla si — leccion del `password-validator`).
Los enums son StrEnum/IntEnum para que el JSON de salida sea estable y versionable.

Incluye los modelos de transporte de threat-intel (`MaliceState`, `ThreatIntelResult`)
como hojas puras: asi `core.layers.layer3_threatintel` los importa sin cruzar la
frontera `core.layers ✗→ core.threatintel` (design §1.4, nota de modelado).

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
    L4 = 4  # NUEVO: superficie de alucinacion con LLM (Hito 3)


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
    # --- L4: superficie de alucinacion con LLM (Hito 3, aditivos) ---
    LLM_HALLUCINATION_SURFACE = "llm_hallucination_surface"  # L4, canal LLM (is_soft=True)
    LLM_UNAVAILABLE = "llm_unavailable"  # L4, BLANDA informativa, weight=0


class Clasificacion(StrEnum):
    """Clasificacion del LLM sobre la superficie de alucinacion (Hito 3, L4).

    Taxonomia de la investigacion de slopsquatting: `legitimo` (sin riesgo L4),
    `conflacion` (mezcla de dos paquetes reales), `typo` (variante tipografica),
    `fabricacion` (nombre confabulado puro).
    """

    LEGITIMO = "legitimo"
    CONFLACION = "conflacion"
    TYPO = "typo"
    FABRICACION = "fabricacion"


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
    is_llm_channel: bool = False  # NUEVO (Hito 3): canal de peso L4 separado (fuera de SOFT_CAP)
    advisories: tuple[Advisory, ...] = ()  # NUEVO (Hito 2): advisories MAL-* portados
    # por la senal MALICIOUS (L3). Default ()==retro-compatible: el resto de capas no
    # los lleva. `build_dependency_result` los traslada a DependencyResult.advisories.


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


class MaliceState(StrEnum):
    """Resultado de consultar malicia/alucinacion para un unico nombre normalizado.

    Representa el veredicto agregado de todas las fuentes activas (OSV + watchlist
    opcional). La Capa 3 los convierte en senales `LayerSignal`. Vive en `core.models`
    (hoja) para que `core.layers.layer3_threatintel` lo importe sin cruzar la frontera
    `core.layers ✗→ core.threatintel` (design §1.4, nota de modelado).
    """

    CLEAN = "clean"  # consultado y limpio: sin MAL-, sin match watchlist
    MALICIOUS = "malicious"  # >=1 advisory MAL-* encontrado en OSV
    KNOWN_HALLUCINATION = "known_hallucination"  # match exacto en corpus watchlist
    UNVERIFIABLE = "unverifiable"  # fuente(s) no se pudieron consultar (degradacion)


@dataclass(frozen=True, slots=True)
class ThreatIntelResult:
    """Resultado normalizado de threat-intel para UN nombre (entrada a la Capa 3).

    Modelo de transporte puro: lo construye el resolver, lo consume la Capa 3 como
    dato inyectado. Vive en `core.models` (hoja) para que `layer3_threatintel` lo
    importe sin cruzar la frontera import-linter (design §1.4, nota de modelado).

    Invariantes:
    - `advisories` es no-vacia solo si `state == MALICIOUS`.
    - `watchlist_source` / `watchlist_date` se pueblan solo si `state == KNOWN_HALLUCINATION`.
    - `unverifiable_reason` se puebla solo si `state == UNVERIFIABLE` (saneado antes).
    """

    name: str  # nombre normalizado PEP 503
    state: MaliceState
    advisories: tuple[Advisory, ...] = ()  # no vacio solo si MALICIOUS
    watchlist_source: str | None = None  # procedencia+atribucion si KNOWN_HALLUCINATION
    watchlist_date: str | None = None  # fecha del corpus (atribucion R7.2)
    unverifiable_reason: str | None = None  # motivo del fallo (saneado), si UNVERIFIABLE


@dataclass(frozen=True, slots=True)
class HallucinationContext:
    """Contexto determinista que se envia al LLM (Hito 3, R8.2).

    SOLO datos derivados de capas 0-2: existencia/edad, vecino typo y su distancia,
    presencia de repo/metadata, y los codes de las senales blandas disparadas.
    NUNCA el manifiesto, rutas locales ni identificadores del usuario.
    """

    existe: bool
    edad_dias: int | None
    typo_vecino: str | None  # paquete top-10k mas cercano (o None)
    typo_distancia: float | None  # JW/DL al vecino (o None)
    tiene_repo: bool
    tiene_metadata: bool
    senales_blandas: tuple[str, ...] = ()  # codes de blandas heuristicas disparadas


@dataclass(frozen=True, slots=True)
class LlmAssessment:
    """Veredicto del LLM validado y SANEADO (Hito 3, L4). Nunca prosa cruda.

    `confianza` es un float finito en [0, 1] (validado en cliente). `patron` y
    `rationale` ya vienen saneados+truncados. `modelo` y `prompt_version` forman
    parte de la identidad del veredicto (cache y reproducibilidad).
    """

    clasificacion: Clasificacion
    confianza: float
    patron: str
    rationale: str
    modelo: str
    prompt_version: str


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
    llm_assessment: LlmAssessment | None = None  # NUEVO (Hito 3, aditivo, default=None)


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """Conteos agregados del escaneo y el exit code final."""

    total: int
    allow: int
    warn: int
    block: int
    unverifiable: int
    exit_code: int
    llm_unavailable: int = 0  # NUEVO (Hito 3): deps en banda gris no evaluables por el LLM


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Reporte completo del escaneo, inmutable y ya ordenado (R6.4)."""

    schema_version: str
    tool_version: str
    ecosystem: str
    summary: ScanSummary
    results: tuple[DependencyResult, ...]
    error_category: ErrorCategory | None  # error operacional total, si lo hubo
