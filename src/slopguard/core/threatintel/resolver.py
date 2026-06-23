"""Resolucion en lote de threat-intel: dedup GLOBAL + chunking + degradacion segura.

`resolve_threatintel` es el punto que el engine intercala ENTRE la Capa 0
(existencia, concurrente) y el bucle de evaluacion por-dep (ADR-08, design §4.1).
Recibe los nombres `FOUND` (ya normalizados PEP 503, identicos a las claves de
`fetch_many`) y los resuelve contra la `ThreatIntelSource` en lotes acotados:

1. `source is None` (enable_layer3=false) ⇒ `{}` (modo solo-deterministas, R5.3):
   sin red, sin senales L3, comportamiento identico al Hito 1.
2. **Dedup GLOBAL** de los nombres ANTES del chunking (R6.4): `dict.fromkeys`
   preserva el orden de primera aparicion (determinismo) y elimina duplicados de
   modo que NINGUN nombre cae en dos chunks ⇒ claves disjuntas por construccion,
   sin riesgo de colision inter-chunk al reensamblar.
3. **Chunking** en bloques `<= osv_batch_max` (R6.5): `> osv_batch_max` ⇒ multiples
   lotes; `<= osv_batch_max` ⇒ un solo lote. La cache por-nombre vive DENTRO de la
   fuente, asi que un nombre se consulta a lo sumo una vez por corrida (R6.6).
4. Cada chunk se resuelve con `source.query_batch(chunk)`. Un chunk que LANZA o cae
   (red agotada, respuesta anomala, fuente que crashea sobre un feed envenenado)
   degrada TODOS sus nombres a `UNVERIFIABLE`, jamas CLEAN (R1.6, NFR-Degr.1): un
   feed externo no confiable nunca aborta el escaneo ni produce un falso limpio.
5. **Cobertura total** (invariante §3.2 punto 4 / §4.1 test 2): el dict devuelto
   tiene UNA entrada por cada nombre unico de `found_names`. Un nombre que la fuente
   omitio del retorno (cobertura parcial) entra como `UNVERIFIABLE`, nunca ausente.
   `set(resultado.keys()) ⊆ set(found_names)` (§4.1 test 1): la fuente nunca inyecta
   nombres fuera del lote (se descartan las claves que no se pidieron).

Determinista respecto a la cache: sin reloj de pared para el veredicto; el orden de
iteracion es el de primera aparicion. Frontera import-linter (§1.3): este modulo es
una IMPL del paquete `core.threatintel` y consume `source`/`composite` via el engine;
las capas/scoring NO lo importan.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from .source import MaliceState, ThreatIntelResult

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..config import Config
    from .source import ThreatIntelSource

# Razon de degradacion cuando un chunk entero no se pudo resolver (saneada, sin
# stacktrace ni rutas; R6.5/NFR-Seg.4). Sirve tanto para fallo total del lote como
# para cobertura parcial de la fuente: en ambos no hay senal positiva verificada.
_REASON_BATCH_UNRESOLVED: Final[str] = (
    "lote threat-intel no verificable (fuente caida o respuesta incompleta)"
)


def resolve_threatintel(
    source: ThreatIntelSource | None,
    found_names: Sequence[str],
    config: Config,
) -> dict[str, ThreatIntelResult]:
    """Resuelve threat-intel para los nombres FOUND en lotes <= osv_batch_max, deduplicado.

    PRECONDICION (§3.5, §4.1): `found_names` son los nombres YA NORMALIZADOS por
    `adapter.normalize_name`, identicos a las CLAVES de `outcomes` de `fetch_many`.
    El dict devuelto se indexa con esos mismos nombres normalizados (clave consistente),
    de modo que `ti.get(dep.name)` del engine acierta para toda dep FOUND.

    - `source is None` (enable_layer3=false) ⇒ `{}` (R5.3: solo-deterministas, sin
      hosts ni senales L3).
    - Dedup GLOBAL antes del chunking ⇒ claves disjuntas entre chunks (R6.4); chunks
      `<= osv_batch_max` (R6.5); <=1 consulta por nombre via cache de la fuente (R6.6).
    - Cualquier fallo de chunk (excepcion o cobertura parcial) ⇒ sus nombres quedan
      UNVERIFIABLE (degradacion segura, jamas CLEAN; R1.6, NFR-Degr.1).

    INVARIANTE DE COBERTURA: el dict contiene UNA entrada por cada nombre normalizado
    unico de `found_names` (CLEAN/MALICIOUS/KNOWN_HALLUCINATION/UNVERIFIABLE), nunca
    ausente; y `set(keys) ⊆ set(found_names)` (la fuente no inventa nombres). Determinista.
    """
    if source is None:
        return {}
    unique_names = _dedup_preserving_order(found_names)
    if not unique_names:
        return {}
    chunk_size = _safe_chunk_size(config.osv_batch_max)
    resolved: dict[str, ThreatIntelResult] = {}
    for chunk in _chunks(unique_names, chunk_size):
        resolved.update(_resolve_chunk(source, chunk))
    return resolved


def _dedup_preserving_order(names: Sequence[str]) -> list[str]:
    """Deduplica `names` conservando el orden de primera aparicion (determinismo, R6.4).

    `dict.fromkeys` da dedup estable O(n): el resultado es la base del chunking, de
    modo que ningun nombre cae en dos chunks (claves disjuntas por construccion).
    """
    return list(dict.fromkeys(names))


def _safe_chunk_size(osv_batch_max: int) -> int:
    """Tamano de chunk efectivo: `osv_batch_max` acotado a >=1 (defensa en profundidad).

    `config._validate_ranges` ya exige `osv_batch_max > 0` (R5.2). Este piso es defensa
    en profundidad: si un refactor dejara pasar 0/negativo, `range(.., step<=0)` lanzaria
    `ValueError` a mitad del escaneo; degradar a chunks de 1 es preferible a crashear.
    """
    return max(1, osv_batch_max)


def _chunks(names: list[str], chunk_size: int) -> list[list[str]]:
    """Parte `names` (ya deduplicado) en bloques contiguos de a lo sumo `chunk_size` (R6.5).

    Mantiene el orden global: el bloque k cubre `names[k*size:(k+1)*size]`. Como `names`
    no tiene duplicados, los bloques tienen conjuntos de nombres DISJUNTOS entre si.
    """
    return [names[start : start + chunk_size] for start in range(0, len(names), chunk_size)]


def _resolve_chunk(
    source: ThreatIntelSource, chunk: list[str]
) -> dict[str, ThreatIntelResult]:
    """Resuelve UN chunk garantizando cobertura total; degrada a UNVERIFIABLE ante fallo.

    Llama a `source.query_batch(chunk)`. Captura CUALQUIER excepcion del lote y la mapea
    a UNVERIFIABLE para todos los nombres del chunk (NFR-Degr.1): un feed externo no
    confiable jamas aborta el escaneo ni produce un falso CLEAN. `KeyboardInterrupt` y
    `SystemExit` (no son `Exception`) siguen propagando, asi que Ctrl-C interrumpe igual.
    """
    try:
        partial = source.query_batch(chunk)
    except Exception:
        # Degradacion segura deliberada (NFR-Degr.1): un feed externo no confiable
        # nunca aborta el escaneo ni produce un falso CLEAN. KeyboardInterrupt/SystemExit
        # no son Exception ⇒ Ctrl-C sigue propagando.
        return {name: _unverifiable(name) for name in chunk}
    return _cover_chunk(chunk, partial)


def _cover_chunk(
    chunk: list[str], partial: dict[str, ThreatIntelResult]
) -> dict[str, ThreatIntelResult]:
    """Reensambla el chunk por NOMBRE pedido (no posicional) con cobertura total.

    Para cada nombre del chunk toma su `ThreatIntelResult` del retorno de la fuente; si la
    fuente lo omitio (cobertura parcial) o devolvio algo que no es un `ThreatIntelResult`,
    se degrada a UNVERIFIABLE (jamas ausente, jamas CLEAN). Tomar SOLO los nombres pedidos
    descarta claves que la fuente pudiera inventar (`keys ⊆ chunk`, §4.1 test 1).
    """
    covered: dict[str, ThreatIntelResult] = {}
    for name in chunk:
        result = partial.get(name)
        if isinstance(result, ThreatIntelResult):
            covered[name] = result
        else:
            covered[name] = _unverifiable(name)
    return covered


def _unverifiable(name: str) -> ThreatIntelResult:
    """`ThreatIntelResult` UNVERIFIABLE para `name` con motivo saneado (no se cachea)."""
    return ThreatIntelResult(
        name=name,
        state=MaliceState.UNVERIFIABLE,
        unverifiable_reason=_REASON_BATCH_UNRESOLVED,
    )
