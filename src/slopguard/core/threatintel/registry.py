"""Registry de fuentes de threat-intel: factory `get_threatintel_source`.

Punto de entrada unico para que el engine obtenga la fuente compuesta activa.
Implementa la logica de habilitacion (design §1.2, R5.3, R8.2):

- Si `config.enable_layer3` es False ⇒ devuelve `None` (modo solo-deterministas:
  sin hosts nuevos, sin senales L3, comportamiento identico al Hito 1).
- Si `enable_layer3` es True ⇒ instancia `OsvSource` (siempre) y, solo si
  `config.enable_watchlist` es True, `WatchlistSource`; los envuelve en un
  `CompositeSource` que expone la union correcta de `extra_allowed_hosts`.

`depscope.dev` NUNCA entra al allowlist cuando `enable_watchlist=false` porque
`WatchlistSource` no se instancia y, por tanto, su host no contribuye a
`CompositeSource.extra_allowed_hosts` (ADR-09 por construccion).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .composite import CompositeSource
from .osv import OsvSource
from .watchlist import WatchlistSource

if TYPE_CHECKING:
    from ..config import Config
    from .source import ThreatIntelSource


def get_threatintel_source(
    config: Config,
    *,
    use_cache: bool,
    ecosystem_id: str = "pypi",
) -> ThreatIntelSource | None:
    """Devuelve la fuente compuesta activa, o None si Capa 3 esta desactivada.

    - `config.enable_layer3 = False` ⇒ None (R5.3: modo solo-deterministas, sin
      hosts ni senales L3; comportamiento Hito 1 intacto).
    - `config.enable_layer3 = True` ⇒ `CompositeSource` con OsvSource siempre y
      WatchlistSource solo si `config.enable_watchlist = True` (R2.1, ADR-09).

    El parametro `use_cache` se propaga a todas las fuentes (--no-cache, R6.3).
    El parametro `ecosystem_id` se propaga a `OsvSource` y `WatchlistSource` para
    que seleccionen la constante OSV, el prefijo de cache y el charset correctos
    (R8.1/R8.2/ADR-5/ADR-8). Default `"pypi"` garantiza cero regresion (R8.6).
    """
    if not config.enable_layer3:
        return None
    sources: list[ThreatIntelSource] = [
        OsvSource(config, ecosystem_id=ecosystem_id, use_cache=use_cache)
    ]
    if config.enable_watchlist:
        sources.append(
            WatchlistSource(config, ecosystem_id=ecosystem_id, use_cache=use_cache)
        )
    return CompositeSource(tuple(sources))
