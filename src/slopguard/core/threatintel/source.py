"""Interfaz y modelos de transporte de fuente threat-intel.

Este modulo define SOLO el contrato de abstraccion (`ThreatIntelSource` Protocol)
y los modelos de transporte normalizados (`MaliceState`, `ThreatIntelResult`).
NO define implementaciones concretas de red (frontera R8.1, design §1.3 contrato 2).

`Advisory` vive en `core.models` (modulo hoja), no aqui: asi `core.scoring.verdict`
puede importarla sin cruzar la frontera core.scoring ✗→ core.threatintel.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from slopguard.core.models import Advisory


class MaliceState(StrEnum):
    """Resultado de consultar malicia/alucinacion para un unico nombre normalizado.

    Los valores representan el veredicto agregado de TODAS las fuentes activas
    (OSV + watchlist opcional). La Capa 3 los convierte en senales `LayerSignal`.
    """

    CLEAN = "clean"  # consultado y limpio: sin MAL-, sin match watchlist
    MALICIOUS = "malicious"  # >=1 advisory MAL-* encontrado en OSV
    KNOWN_HALLUCINATION = "known_hallucination"  # match exacto en corpus watchlist
    UNVERIFIABLE = "unverifiable"  # fuente(s) no se pudieron consultar (degradacion)


@dataclass(frozen=True, slots=True)
class ThreatIntelResult:
    """Resultado normalizado de threat-intel para UN nombre (entrada a la Capa 3).

    Lo que ve la Capa 3: un objeto de datos puro, ya construido por el resolver.
    La Capa 3 NUNCA instancia fuentes ni llama a la red: solo consume este modelo.

    Invariantes:
    - `advisories` es no-vacia solo si `state == MALICIOUS`.
    - `watchlist_source` / `watchlist_date` se poblam solo si `state == KNOWN_HALLUCINATION`.
    - `unverifiable_reason` se popula solo si `state == UNVERIFIABLE` (saneado antes).
    """

    name: str  # nombre normalizado PEP 503
    state: MaliceState
    advisories: tuple[Advisory, ...] = ()  # no vacio solo si MALICIOUS
    watchlist_source: str | None = None  # procedencia+atribucion si KNOWN_HALLUCINATION
    watchlist_date: str | None = None  # fecha del corpus (atribucion R7.2)
    unverifiable_reason: str | None = None  # motivo del fallo (saneado), si UNVERIFIABLE


class ThreatIntelSource(Protocol):
    """Abstrae la consulta de malicia (por lote) y watchlist para el engine.

    El ENGINE (no las capas/scoring) depende de esta interfaz para resolver el lote
    de nombres FOUND. Las capas y el scoring NO importan este modulo: reciben el
    `ThreatIntelResult` ya construido como dato puro inyectado por el engine.

    Anadir una nueva fuente = implementar este Protocol sin tocar capas/scoring (R8.2).
    """

    source_id: str
    """Identificador unico de la fuente (p.ej. 'osv', 'composite')."""

    extra_allowed_hosts: frozenset[str]
    """Hosts adicionales que esta fuente necesita en el allowlist efectivo.

    El engine los pasa a `SecureHttpClient(extra_allowed_hosts=...)`.
    La base `{pypi.org}` permanece inmutable; cada fuente declara solo sus hosts.
    Con `enable_watchlist=false` la fuente watchlist no se instancia =>
    `depscope.dev` nunca entra al allowlist (R2.1, ADR-09 por construccion).
    """

    def query_batch(
        self, names: Sequence[str]
    ) -> dict[str, ThreatIntelResult]:
        """Resuelve malicia + watchlist para un LOTE de nombres normalizados.

        Contrato:
        - `names` ya estan normalizados PEP 503 y deduplicados por el caller.
        - Devuelve un dict indexado por nombre normalizado; el conjunto de claves
          del resultado DEBE ser igual al conjunto de `names` (cobertura total).
        - Cada valor es CLEAN / MALICIOUS / KNOWN_HALLUCINATION / UNVERIFIABLE.
        - Aplica cache, TLS, allowlist, streaming y limites internamente.
        - NO lanza por nombre limpio ni por fallo de red transitorio: degrada a
          UNVERIFIABLE (nunca CLEAN). Solo propaga errores operacionales totales
          (config invalida) -- analogo a `EcosystemAdapter.fetch`.
        """
        ...
