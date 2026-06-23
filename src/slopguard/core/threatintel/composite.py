"""CompositeSource: fusion de OsvSource (siempre) + WatchlistSource (opcional).

`CompositeSource` implementa `ThreatIntelSource` agrupando en un unico
`query_batch` las consultas a OSV y, si esta activa, a la watchlist. Luego
fusiona los resultados por nombre con la siguiente precedencia (design §2.2):

    MALICIOUS > KNOWN_HALLUCINATION > UNVERIFIABLE > CLEAN

La union de `extra_allowed_hosts` de ambas fuentes se expone como atributo,
de modo que el `registry` puede pasarlo al `SecureHttpClient` del engine sin
saber que fuentes concretas estan activas (ADR-09).

Frontera import-linter (§1.3): este modulo es una IMPL y SI puede usar
`core.net`/`core.cache`; las capas/scoring no lo importan.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from .source import MaliceState, ThreatIntelResult

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .source import ThreatIntelSource

# Identificador de la fuente compuesta (para trazabilidad/logs).
_SOURCE_ID: Final[str] = "composite"

# Orden de precedencia de los estados: mayor indice = mayor prioridad.
_STATE_PRECEDENCE: dict[MaliceState, int] = {
    MaliceState.CLEAN: 0,
    MaliceState.UNVERIFIABLE: 1,
    MaliceState.KNOWN_HALLUCINATION: 2,
    MaliceState.MALICIOUS: 3,
}


class CompositeSource:
    """Fuente compuesta: agrega OSV (siempre) y watchlist (opcional) en un solo query_batch.

    Fusiona los `ThreatIntelResult` de cada fuente con precedencia
    MALICIOUS > KNOWN_HALLUCINATION > UNVERIFIABLE > CLEAN (design §2.2).
    Expone `extra_allowed_hosts` como la union de los hosts de todas las fuentes
    activas (ADR-09: depscope.dev solo aparece si WatchlistSource se instancio).
    """

    source_id: str = _SOURCE_ID

    def __init__(self, sources: tuple[ThreatIntelSource, ...]) -> None:
        """Inicializa con las fuentes activas (OSV siempre; watchlist si enable_watchlist).

        `sources` no debe estar vacio: el registry garantiza al menos OsvSource.
        `extra_allowed_hosts` es la union de los hosts de todas las fuentes.
        """
        self._sources = sources
        self.extra_allowed_hosts: frozenset[str] = frozenset().union(
            *(src.extra_allowed_hosts for src in sources)
        )

    def query_batch(
        self, names: Sequence[str]
    ) -> dict[str, ThreatIntelResult]:
        """Resuelve el lote contra todas las fuentes activas y fusiona por nombre.

        Cada fuente recibe el mismo `names`; sus resultados se fusionan aplicando
        la precedencia MALICIOUS > KNOWN_HALLUCINATION > UNVERIFIABLE > CLEAN.
        El dict devuelto tiene una entrada por cada nombre de `names` (cobertura total).
        """
        name_list = list(names)
        merged: dict[str, ThreatIntelResult] = {}
        for source in self._sources:
            partial = source.query_batch(name_list)
            for name, result in partial.items():
                if name not in merged:
                    merged[name] = result
                else:
                    merged[name] = _merge(merged[name], result)
        return merged


def _merge(current: ThreatIntelResult, incoming: ThreatIntelResult) -> ThreatIntelResult:
    """Fusiona dos resultados para el mismo nombre eligiendo el de mayor precedencia.

    MALICIOUS > KNOWN_HALLUCINATION > UNVERIFIABLE > CLEAN (design §2.2).
    Cuando el estado entrante es de mayor prioridad que el actual, el resultado
    del entrante gana. En caso de empate se conserva el actual (primer-gana).
    """
    current_prio = _STATE_PRECEDENCE.get(current.state, 0)
    incoming_prio = _STATE_PRECEDENCE.get(incoming.state, 0)
    if incoming_prio > current_prio:
        return incoming
    return current
