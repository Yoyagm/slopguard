"""H4-T24: propiedad de similaridad scoped end-to-end (ADR-4, R6.1/R6.2/R6.3).

Cierra la propiedad de ADR-4 *a traves del adapter real*: T23
(`tests/test_h4_layer1_candidate_filter.py`) ya verifica el MECANISMO de la capa pura
invocando el predicado `_same_scope_candidate` directamente; esta suite verifica la
PROPIEDAD observable conduciendo `layer1_similarity.evaluate` con el
`candidate_filter` que expone el `NpmAdapter` real y con el corpus npm real, sin
duplicar los casos unitarios de T23.

Propiedad scoped (ADR-4), cerrada por AMBOS prefiltros (Nota B de tasks.md):
- `@scopeA/name` vs `@scopeB/name` (mismo `name`, scopes distintos) NO produce
  TYPOSQUAT por NINGUNO de los dos prefiltros:
    * banda DL por longitud (`by_length`) — el caso que un fix solo en
      `by_first_char` dejaria pasar;
    * banda JW por primer caracter (`by_first_char`, `@` agrupa todos los scoped).
- `@scope/lodahs` vs `@scope/lodash` (mismo scope, typo real) SI produce señal.

Cero regresion PyPI (R11): el `PypiAdapter` expone `candidate_filter is None`
(identidad); con ese filtro la Capa 1 se comporta exactamente como antes del Hito 4.

Frontera (R6.3): la propiedad se ejerce SOLO inyectando el `Callable` del adapter; la
capa pura nunca ramifica por ecosistema. Se usa el corpus npm (no el de PyPI): los
casos `lodash`/scoped existen unicamente en el dataset npm.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from slopguard.core.adapters.npm import NpmAdapter
from slopguard.core.adapters.pypi import PypiAdapter
from slopguard.core.config import Config
from slopguard.core.dataset.top_n import TopNDataset, build_top_n
from slopguard.core.layers import layer1_similarity
from slopguard.core.models import SignalCode

_CONFIG = Config()  # dl_max=2, jw_min=0.92, nombre_max_chars=100

# Filtro "mismo scope" tomado del ADAPTER npm REAL (no del helper interno): es el dato
# agnostico que el engine inyecta a la Capa 1 (ADR-4). Resolverlo una sola vez evita
# reconstruir el adapter (que carga/verifica el dataset) por test.
_NPM_FILTER: Callable[[str, str], bool] = NpmAdapter(
    _CONFIG, use_cache=False
).candidate_filter


def _npm_corpus(names: list[str]) -> TopNDataset:
    """Construye un TopNDataset npm minimo (normalizacion identidad: ya estan en forma).

    Mantiene la propiedad acotada y determinista (no depende de colisiones accidentales
    del corpus de ~8k). El comportamiento end-to-end con el corpus real se cubre aparte
    en `test_corpus_npm_real_*`.
    """
    return build_top_n(names, version="test-npm", generated_at="test")


# ---------------------------------------------------------------------------
# Propiedad ADR-4 via el candidate_filter del NpmAdapter REAL.
#   FP cross-scope cerrado en AMBOS prefiltros; typo same-scope conservado.
# ---------------------------------------------------------------------------


def test_cross_scope_mismo_name_dispara_fp_sin_filtro_via_banda_dl() -> None:
    """Sin filtro, `@scopeA/name` vs `@scopeB/name` (DL=1, misma longitud 12) es un FP.

    Entra por la BANDA DL (`by_length`), el camino que un fix solo en `by_first_char`
    NO cerraria. Establece que el caso es un FP genuino antes de aplicar el filtro.
    """
    corpus = _npm_corpus(["@scopeb/name"])

    signals = layer1_similarity.evaluate("@scopea/name", corpus, _CONFIG)

    assert len(signals) == 1
    assert signals[0].code is SignalCode.TYPOSQUAT


def test_cross_scope_mismo_name_no_dispara_con_filtro_npm_banda_dl() -> None:
    """Con el `candidate_filter` del NpmAdapter, el FP de la BANDA DL queda cerrado.

    `@scopeA/name` vs `@scopeB/name`: el filtro descarta el candidato (scope distinto)
    ANTES de medir distancia, asi que la banda de longitud no produce TYPOSQUAT.
    """
    corpus = _npm_corpus(["@scopeb/name"])

    signals = layer1_similarity.evaluate(
        "@scopea/name", corpus, _CONFIG, candidate_filter=_NPM_FILTER
    )

    assert signals == []


def test_cross_scope_mismo_name_dispara_fp_sin_filtro_via_banda_jw() -> None:
    """Sin filtro, un FP cross-scope tambien entra por la BANDA JW (primer char `@`).

    `@babelcore/preset` vs `@babelcord/presto`: DL=3 (> dl_max) pero JW=0.926 (>= jw_min),
    asi que la ruta JW (`by_first_char['@']`) lo marca TYPOSQUAT. Scopes distintos.
    """
    corpus = _npm_corpus(["@babelcord/presto"])

    signals = layer1_similarity.evaluate("@babelcore/preset", corpus, _CONFIG)

    assert len(signals) == 1
    assert signals[0].code is SignalCode.TYPOSQUAT


def test_cross_scope_mismo_name_no_dispara_con_filtro_npm_banda_jw() -> None:
    """Con el filtro del NpmAdapter, el FP cross-scope de la BANDA JW tambien se cierra.

    Cubre el prefiltro que un fix solo-`by_first_char` (reindexar por `@scope/`) SI
    cerraria; junto al caso DL anterior demuestra que AMBAS bandas quedan cubiertas.
    """
    corpus = _npm_corpus(["@babelcord/presto"])

    signals = layer1_similarity.evaluate(
        "@babelcore/preset", corpus, _CONFIG, candidate_filter=_NPM_FILTER
    )

    assert signals == []


def test_same_scope_typo_si_produce_senal_con_filtro_npm() -> None:
    """El filtro NO suprime el typosquat real intra-scope: `@scope/lodahs`~`@scope/lodash`.

    Mismo scope `@scope`, DL=1: el candidato es elegible y dispara TYPOSQUAT contra el
    paquete legitimo correcto (suspected_target).
    """
    corpus = _npm_corpus(["@scope/lodash"])

    signals = layer1_similarity.evaluate(
        "@scope/lodahs", corpus, _CONFIG, candidate_filter=_NPM_FILTER
    )

    assert len(signals) == 1
    assert signals[0].code is SignalCode.TYPOSQUAT
    assert signals[0].suspected_target == "@scope/lodash"


def test_propiedad_scoped_completa_cross_scope_silenciado_typo_detectado() -> None:
    """Propiedad ADR-4 conjunta: ambos FP cross-scope mudos, el typo same-scope vivo.

    Un unico `evaluate` por caso sobre un corpus que contiene a la vez el candidato
    cross-scope (DL y JW) y el legitimo intra-scope, con el filtro del adapter npm.
    """
    corpus = _npm_corpus(["@scopeb/name", "@babelcord/presto", "@scope/lodash"])

    cross_scope_dl = layer1_similarity.evaluate(
        "@scopea/name", corpus, _CONFIG, candidate_filter=_NPM_FILTER
    )
    cross_scope_jw = layer1_similarity.evaluate(
        "@babelcore/preset", corpus, _CONFIG, candidate_filter=_NPM_FILTER
    )
    same_scope_typo = layer1_similarity.evaluate(
        "@scope/lodahs", corpus, _CONFIG, candidate_filter=_NPM_FILTER
    )

    assert cross_scope_dl == []
    assert cross_scope_jw == []
    assert len(same_scope_typo) == 1
    assert same_scope_typo[0].code is SignalCode.TYPOSQUAT
    assert same_scope_typo[0].suspected_target == "@scope/lodash"


# ---------------------------------------------------------------------------
# Cero regresion PyPI: candidate_filter=None (identidad) reproduce el comportamiento previo.
# ---------------------------------------------------------------------------


def test_pypi_candidate_filter_es_identidad_none() -> None:
    """El `PypiAdapter` expone `candidate_filter is None`: Capa 1 sin cambios (R11)."""
    adapter = PypiAdapter(Config(), use_cache=False)

    assert adapter.candidate_filter is None


def test_pypi_filtro_none_no_altera_typosquat_simple() -> None:
    """Con el filtro identidad de PyPI, un typo simple sigue disparando (sin regresion).

    `lodahs` vs `lodash` (DL=1): pasar `candidate_filter=None` debe ser indistinguible de
    no pasarlo.
    """
    corpus = _npm_corpus(["lodash"])

    con_none = layer1_similarity.evaluate(
        "lodahs", corpus, _CONFIG, candidate_filter=None
    )
    sin_kw = layer1_similarity.evaluate("lodahs", corpus, _CONFIG)

    assert con_none == sin_kw
    assert len(con_none) == 1
    assert con_none[0].code is SignalCode.TYPOSQUAT
    assert con_none[0].suspected_target == "lodash"


def test_pypi_filtro_none_no_silencia_fp_cross_scope() -> None:
    """El filtro identidad de PyPI NO cierra el FP cross-scope (es trabajo del filtro npm).

    Confirma que la diferencia observable proviene del filtro inyectado, no de la capa:
    bajo `None` el FP cross-scope de la banda DL sigue presente.
    """
    corpus = _npm_corpus(["@scopeb/name"])

    signals = layer1_similarity.evaluate(
        "@scopea/name", corpus, _CONFIG, candidate_filter=None
    )

    assert len(signals) == 1
    assert signals[0].code is SignalCode.TYPOSQUAT


# ---------------------------------------------------------------------------
# End-to-end con el corpus npm REAL: usa el dataset npm (no el de PyPI).
#   `lodash` y los nombres scoped existen SOLO en el corpus npm.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def npm_adapter() -> NpmAdapter:
    """Adapter npm real (sin cache de disco); carga/verifica el corpus npm una vez."""
    return NpmAdapter(_CONFIG, use_cache=False)


def test_corpus_npm_real_typo_de_top_n_dispara_con_filtro_del_adapter(
    npm_adapter: NpmAdapter,
) -> None:
    """Typosquat de un top-N npm real (`lodahs`~`lodash`) dispara con corpus+filtro npm.

    `lodash` esta en el corpus npm; el filtro del adapter (identidad para no-scoped) no lo
    suprime. Ejercita R6.1 (señal con dataset npm) end-to-end via el adapter real.
    """
    corpus = npm_adapter.load_top_n()
    assert "lodash" in corpus.members  # precondicion: el corpus npm contiene el legitimo

    signals = layer1_similarity.evaluate(
        "lodahs", corpus, _CONFIG, candidate_filter=npm_adapter.candidate_filter
    )

    assert len(signals) == 1
    assert signals[0].code is SignalCode.TYPOSQUAT
    assert signals[0].suspected_target == "lodash"


def test_corpus_npm_real_no_es_el_de_pypi(npm_adapter: NpmAdapter) -> None:
    """La señal proviene del corpus npm, no del de PyPI: `lodash` no esta en PyPI top-N.

    Mismo nombre consultado (`lodahs`) contra el corpus PyPI real ⇒ sin señal (PyPI no
    contiene `lodash` ni nombres scoped). Demuestra que T24 usa el corpus npm.
    """
    pypi_corpus = PypiAdapter(Config(), use_cache=False).load_top_n()
    assert "lodash" not in pypi_corpus.members
    assert not any(member.startswith("@") for member in pypi_corpus.members)

    signals_pypi = layer1_similarity.evaluate("lodahs", pypi_corpus, _CONFIG)
    signals_npm = layer1_similarity.evaluate(
        "lodahs",
        npm_adapter.load_top_n(),
        _CONFIG,
        candidate_filter=npm_adapter.candidate_filter,
    )

    assert signals_pypi == []
    assert len(signals_npm) == 1
