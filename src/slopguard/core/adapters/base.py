"""Frontera del adapter de ecosistema (R10): modelos normalizados + Protocol.

El motor de capas/scoring depende SOLO de este modulo (y de `core.models`), nunca
de un adapter concreto (`adapters.pypi`) ni de la red (`core.net`). Esa frontera la
verifica import-linter (R10.1). Anadir npm = un adapter nuevo que implemente este
Protocol, sin tocar capas ni scoring.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from ..models import ErrorCategory

if TYPE_CHECKING:
    from ..dataset.top_n import TopNDataset

# Predicado de elegibilidad de candidato de Capa 1: `(consultado, candidato) -> elegible`
# (ADR-4, R6.2). El adapter lo expone como DATO agnostico; la capa pura solo lo invoca,
# sin conocer su semantica (p.ej. "mismo scope" npm). `None` = identidad (todos elegibles).
CandidateFilter = Callable[[str, str], bool]


@dataclass(frozen=True, slots=True)
class PackageMetadata:
    """Metadatos normalizados, agnosticos de ecosistema (nunca payload crudo)."""

    name: str
    first_release_epoch: float | None  # epoch UTC de la primera release publicada
    releases_count: int
    has_repo_url: bool
    has_description: bool
    has_author: bool
    has_license: bool
    has_classifiers: bool
    in_top_n: bool  # pertenencia al dataset top-N (proxy de popularidad, R4.4)


class FetchState(StrEnum):
    """Resultado de una consulta de existencia/metadatos."""

    FOUND = "found"
    NOT_FOUND = "not_found"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True, slots=True)
class FetchOutcome:
    """Salida de `EcosystemAdapter.fetch`: existencia + metadatos en un viaje."""

    state: FetchState
    metadata: PackageMetadata | None = None  # solo si FOUND
    error_category: ErrorCategory | None = None  # network_unverifiable si UNVERIFIABLE


class EcosystemAdapter(Protocol):
    """Abstrae existencia, metadatos y fuente del top-N de un ecosistema.

    El motor de capas/scoring depende SOLO de esta interfaz, nunca de PyPI
    directamente (R10.1). El override de inexistencia, la edad y el scoring viven
    en el core, agnosticos del ecosistema.
    """

    ecosystem_id: str

    def normalize_name(self, raw: str) -> str:
        """Normaliza el nombre segun las reglas del ecosistema (PyPI = PEP 503)."""
        ...

    def fetch(self, name: str) -> FetchOutcome:
        """Una consulta (red o cache): existencia + metadatos normalizados.

        Mapea 404 -> NOT_FOUND; error transitorio agotado -> UNVERIFIABLE;
        ok -> FOUND(meta). Aplica TLS+allowlist+streaming+limites internamente.
        No lanza por 404.
        """
        ...

    def load_top_n(self) -> TopNDataset:
        """Carga el dataset embebido verificando su checksum.

        Aborta (DatasetIntegrityError) si falta o esta corrupto (R3.9).
        """
        ...

    @property
    def candidate_filter(self) -> CandidateFilter | None:
        """Filtro de candidatos de Capa 1, agnostico (ADR-4, R6.2); `None` = identidad.

        El engine lo inyecta en `layer1_similarity.evaluate` por el mismo canal que el
        corpus. PyPI devuelve `None` (sin scopes); npm devuelve "mismo scope para scoped".
        La capa pura solo lo invoca, sin conocer su semantica (sin `if ecosystem` en la capa).
        """
        ...

    def get_downloads(self, name: str) -> None:
        """HOOK RESERVADO. En Hito 1 retorna None SIEMPRE; la ausencia de
        descargas NO es senal de riesgo (R4.4). Reservado para el futuro.
        """
        ...
