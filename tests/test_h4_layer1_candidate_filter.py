"""H4-T23: filtro de candidatos scoped en Capa 1 via `candidate_filter` (ADR-4, R6.2/R6.3).

Verifica el mecanismo FIJADO (vía (a) `candidate_filter`), no la propiedad sobre el corpus
real (eso es T24, `tests/layers/test_layer1_npm.py`). Tres frentes:

1. La capa pura `layer1_similarity` aplica el filtro en AMBOS prefiltros — banda DL por
   longitud Y banda JW por primer caracter (Nota B de tasks.md): un fix solo en
   `by_first_char` dejaria pasar el FP "mismo name, distinto scope" por la banda de longitud.
2. El `NpmAdapter` provee el predicado "mismo scope" como DATO agnostico (la capa no conoce
   scopes); `PypiAdapter` provee `None` (identidad) — cero regresion PyPI.
3. `candidate_filter=None` reproduce el comportamiento original (identidad).

Frontera (R6.3): la capa pura NO ramifica por ecosistema; solo invoca el `Callable`.
"""

from __future__ import annotations

from slopguard.core.adapters.npm import (
    NpmAdapter,
    _npm_scope,
    _same_scope_candidate,
)
from slopguard.core.adapters.pypi import PypiAdapter
from slopguard.core.config import Config
from slopguard.core.dataset.top_n import TopNDataset, build_top_n
from slopguard.core.layers import layer1_similarity
from slopguard.core.layers.layer1_similarity import CandidateFilter
from slopguard.core.models import SignalCode

_CONFIG = Config()  # dl_max=2, jw_min=0.92, nombre_max_chars=100


def _dataset(names: list[str]) -> TopNDataset:
    """Construye un TopNDataset npm minimo (normalizacion identidad: ya estan en forma)."""
    return build_top_n(names, version="test", generated_at="test")


# ---------------------------------------------------------------------------
# 1. Predicado del adapter: _npm_scope / _same_scope_candidate
# ---------------------------------------------------------------------------


def test_npm_scope_extrae_scope_de_nombre_scoped() -> None:
    assert _npm_scope("@types/node") == "@types"
    assert _npm_scope("@scope/lodash") == "@scope"


def test_npm_scope_devuelve_none_para_nombre_simple() -> None:
    assert _npm_scope("lodash") is None
    assert _npm_scope("node") is None


def test_same_scope_mismo_scope_es_elegible() -> None:
    # Mismo scope, typo en name -> candidato (SI compite por distancia).
    assert _same_scope_candidate("@scope/lodahs", "@scope/lodash") is True


def test_same_scope_distinto_scope_no_es_elegible() -> None:
    # Mismo name, scope distinto -> NO candidato (FP peligroso bloqueado).
    assert _same_scope_candidate("@scopea/node", "@scopeb/node") is False


def test_same_scope_dos_no_scoped_son_elegibles() -> None:
    # None == None: dos nombres simples compiten entre si (sin regresion).
    assert _same_scope_candidate("lodahs", "lodash") is True


def test_same_scope_scoped_vs_no_scoped_no_es_elegible() -> None:
    # Namespaces distintos: un scoped nunca compite contra un simple.
    assert _same_scope_candidate("@scope/node", "node") is False
    assert _same_scope_candidate("node", "@scope/node") is False


# ---------------------------------------------------------------------------
# 2. Wiring del adapter: candidate_filter
# ---------------------------------------------------------------------------


def test_pypi_candidate_filter_es_none() -> None:
    """PyPI = filtro identidad: la Capa 1 conserva el comportamiento original (R11)."""
    adapter = PypiAdapter(Config(), use_cache=False)
    assert adapter.candidate_filter is None


def test_npm_candidate_filter_es_same_scope() -> None:
    """npm expone el predicado "mismo scope" como dato agnostico para Capa 1."""
    adapter = NpmAdapter(Config(), use_cache=False)
    cf = adapter.candidate_filter
    assert cf("@scopea/node", "@scopeb/node") is False
    assert cf("@scope/lodahs", "@scope/lodash") is True


# ---------------------------------------------------------------------------
# 3. Capa pura: el filtro se aplica en AMBOS prefiltros (Nota B, lo critico)
# ---------------------------------------------------------------------------


def test_dl_band_distinto_scope_sin_filtro_dispara_fp() -> None:
    """Sin filtro, el FP "mismo name, distinto scope" entra por la BANDA DL (longitud).

    `@scopea/node` vs `@scopeb/node`: misma longitud (12), DL=1 -> TYPOSQUAT. Este es el
    caso que un fix solo en `by_first_char` (banda JW) dejaria pasar.
    """
    ds = _dataset(["@scopeb/node"])
    signals = layer1_similarity.evaluate("@scopea/node", ds, _CONFIG)
    assert len(signals) == 1
    assert signals[0].code is SignalCode.TYPOSQUAT


def test_dl_band_distinto_scope_con_filtro_no_dispara() -> None:
    """Con el filtro "mismo scope" el FP de la BANDA DL queda bloqueado (cierra Nota B)."""
    ds = _dataset(["@scopeb/node"])
    cf: CandidateFilter = _same_scope_candidate
    signals = layer1_similarity.evaluate(
        "@scopea/node", ds, _CONFIG, candidate_filter=cf
    )
    assert signals == []


def test_jw_band_distinto_scope_sin_filtro_dispara_fp() -> None:
    """Sin filtro, un FP scoped tambien puede entrar por la BANDA JW (primer char `@`).

    `@babelcore/preset` vs `@babelcord/presto`: DL=3 (> dl_max), JW=0.926 (>= jw_min) ->
    TYPOSQUAT por la ruta JW. Scopes distintos (`@babelcore` vs `@babelcord`).
    """
    ds = _dataset(["@babelcord/presto"])
    signals = layer1_similarity.evaluate("@babelcore/preset", ds, _CONFIG)
    assert len(signals) == 1
    assert signals[0].code is SignalCode.TYPOSQUAT


def test_jw_band_distinto_scope_con_filtro_no_dispara() -> None:
    """Con el filtro, el FP scoped de la BANDA JW tambien queda bloqueado."""
    ds = _dataset(["@babelcord/presto"])
    cf: CandidateFilter = _same_scope_candidate
    signals = layer1_similarity.evaluate(
        "@babelcore/preset", ds, _CONFIG, candidate_filter=cf
    )
    assert signals == []


def test_mismo_scope_typo_si_dispara_con_filtro() -> None:
    """El filtro NO suprime el typosquat real: `@scope/lodahs` vs `@scope/lodash` (DL=1)."""
    ds = _dataset(["@scope/lodash"])
    cf: CandidateFilter = _same_scope_candidate
    signals = layer1_similarity.evaluate(
        "@scope/lodahs", ds, _CONFIG, candidate_filter=cf
    )
    assert len(signals) == 1
    assert signals[0].code is SignalCode.TYPOSQUAT
    assert signals[0].suspected_target == "@scope/lodash"


def test_filtro_none_equivale_a_identidad() -> None:
    """`candidate_filter=None` reproduce exactamente el comportamiento sin filtro (R11)."""
    ds = _dataset(["@scopeb/node"])
    con_none = layer1_similarity.evaluate(
        "@scopea/node", ds, _CONFIG, candidate_filter=None
    )
    sin_kw = layer1_similarity.evaluate("@scopea/node", ds, _CONFIG)
    assert con_none == sin_kw
    assert len(con_none) == 1


def test_no_scoped_sin_regresion_con_filtro_same_scope() -> None:
    """Nombres simples (sin scope) siguen disparando typosquat bajo el filtro npm.

    `lodahs` vs `lodash` (None==None -> elegibles): el filtro no afecta a los no-scoped.
    """
    ds = _dataset(["lodash"])
    cf: CandidateFilter = _same_scope_candidate
    signals = layer1_similarity.evaluate("lodahs", ds, _CONFIG, candidate_filter=cf)
    assert len(signals) == 1
    assert signals[0].code is SignalCode.TYPOSQUAT
