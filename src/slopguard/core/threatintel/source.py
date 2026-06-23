"""Interfaz de fuente threat-intel y re-exportacion de modelos de transporte.

Este modulo define SOLO el contrato de abstraccion (`ThreatIntelSource` Protocol).
NO define implementaciones concretas de red (frontera R8.1, design §1.3 contrato 2).

`MaliceState`, `ThreatIntelResult` y `Advisory` viven en `core.models` (modulo hoja)
para que `core.layers.layer3_threatintel` y `core.scoring.verdict` los importen sin
cruzar la frontera `core.layers`/`core.scoring` ✗→ `core.threatintel` (design §1.4).
Este modulo los re-exporta para compatibilidad con los imports existentes en las impls
(osv/watchlist/composite/resolver) que importan desde `.source`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from slopguard.core.models import Advisory, MaliceState, ThreatIntelResult

# Re-exportaciones explicitas: los modelos viven en core.models (hoja);
# se re-exportan aqui para compatibilidad con `from .source import MaliceState, ...`
# que usan las impls internas del paquete core.threatintel.
__all__ = ["Advisory", "MaliceState", "ThreatIntelResult", "ThreatIntelSource"]


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
