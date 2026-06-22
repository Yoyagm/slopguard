"""Capa 1 — typosquatting por similaridad (R3, ADR-02).

Compara el nombre del paquete contra el dataset top-N usando dos metricas:
- Damerau-Levenshtein (DL) acotada: candidatos con longitud en [L-dl_max, L+dl_max]
  via indice `by_length` (ADR-02). Senales duras graduadas por distancia.
- Jaro-Winkler (JW): candidatos del mismo primer caracter via `by_first_char`
  (ADR-02). Senales duras graduadas por similitud.

Reglas de guarda (aplicadas en orden):
  1. `len <= 3` -> sin senal (R3.5).
  2. `len > nombre_max_chars` -> NAME_UNTRUSTED sin correr distancia (R3.6).
  3. Nombre exactamente en el top-N -> sin senal (R3.2).
  4. Mejor candidato (DL, JW) determina el tipo de senal (R3.3, ADR-01).

El candidato primario se elige por: menor DL -> mayor JW -> nombre ascendente
(desempate determinista, R3.4).

Sin red, sin adapters concretos, sin CLI. Determinista (R3.7).
Importa SOLO de: similarity, dataset.top_n, models, config.
"""

from __future__ import annotations

from slopguard.core.config import Config
from slopguard.core.dataset.top_n import TopNDataset
from slopguard.core.layers.similarity.damerau import damerau_levenshtein_bounded
from slopguard.core.layers.similarity.jaro_winkler import jaro_winkler
from slopguard.core.models import Layer, LayerSignal, SignalCode

# Umbral de longitud minima para correr analisis de similaridad (R3.5).
_MIN_NAME_LEN = 3

# Umbral de JW para senal fuerte (ADR-01, tabla de pesos).
_JW_STRONG_THRESHOLD = 0.95

# Distancia DL exacta que asigna peso maximo (ADR-01).
_DL_EXACT_ONE = 1
_DL_EXACT_TWO = 2

# Valor centinela para indicar que DL no fue calculado (candidato por JW puro).
_DL_NOT_COMPUTED = -1

# Sustituto de "infinito" para candidatos capturados solo por JW en el desempate.
_DL_FALLBACK = 9999


def evaluate(
    name: str,
    dataset: TopNDataset,
    config: Config,
) -> list[LayerSignal]:
    """Evalua la Capa 1 para `name` contra el dataset top-N.

    Devuelve una lista con 0 o 1 senales. Sin red, determinista.
    """
    # Guarda 1: nombres muy cortos -> sin senal (evita falsos positivos, R3.5).
    if len(name) <= _MIN_NAME_LEN:
        return []

    # Guarda 2: nombre excesivamente largo -> NAME_UNTRUSTED sin correr distancia (R3.6).
    if len(name) > config.nombre_max_chars:
        return [_name_untrusted_signal(name)]

    # Guarda 3: match exacto en el top-N -> paquete legitimo, sin senal (R3.2).
    if name in dataset.members:
        return []

    best = _find_best_candidate(name, dataset, config)
    if best is None:
        return []
    return [_build_signal(best)]


def _find_best_candidate(
    name: str,
    dataset: TopNDataset,
    config: Config,
) -> _Candidate | None:
    """Busca el candidato mas cercano del top-N usando prefiltros de ADR-02.

    Combina resultados de DL (banda por longitud) y JW (banda por primer caracter).
    Devuelve None si ningun candidato supera los umbrales.
    """
    dl_candidates = _dl_candidates(name, dataset, config)
    jw_candidates = _jw_candidates(name, dataset, config)

    # Union de todos los candidatos que disparan alguna senal.
    # Por construccion, un mismo target NO puede aparecer en ambas listas:
    # _dl_candidates incluye targets con dist<=dl_max y _jw_candidates los
    # excluye explicitamente (linea con `dist <= config.dl_max: continue`).
    # El primer registro por target es suficiente; el min() final decide el ganador.
    merged: dict[str, _Candidate] = {}
    for cand in dl_candidates + jw_candidates:
        if cand.target not in merged:
            merged[cand.target] = cand

    if not merged:
        return None

    # Desempate determinista: menor DL -> mayor JW -> nombre ascendente (R3.4).
    return min(
        merged.values(),
        key=lambda c: (c.dl if c.dl >= 0 else _DL_FALLBACK, -c.jw, c.target),
    )


def _dl_candidates(
    name: str,
    dataset: TopNDataset,
    config: Config,
) -> list[_Candidate]:
    """Candidatos de DL dentro de la banda de longitud [L-dl_max, L+dl_max]."""
    length = len(name)
    result: list[_Candidate] = []
    for band_len in range(length - config.dl_max, length + config.dl_max + 1):
        if band_len <= 0:
            continue
        for target in dataset.by_length.get(band_len, ()):
            dist = damerau_levenshtein_bounded(name, target, config.dl_max)
            if 1 <= dist <= config.dl_max:
                result.append(_Candidate(target=target, dl=dist, jw=jaro_winkler(name, target)))
    return result


def _jw_candidates(
    name: str,
    dataset: TopNDataset,
    config: Config,
) -> list[_Candidate]:
    """Candidatos de JW en el mismo primer caracter (prefiltro ADR-02).

    Solo se evaluan candidatos cuyo DL ya excede dl_max (para no duplicar los
    que ya detecto la banda DL). Emite senal solo si JW >= jw_min.
    """
    if not name:  # pragma: no cover  # guarda defensiva; evaluate() garantiza len>3
        return []
    result: list[_Candidate] = []
    for target in dataset.by_first_char.get(name[0], ()):
        if target == name:  # pragma: no cover  # guarda defensiva; miembros en members siempre
            continue  # ya cubierto por la guarda de match exacto
        dist = damerau_levenshtein_bounded(name, target, config.dl_max)
        # Si DL ya capturo este candidato (dist <= dl_max), no lo duplicamos.
        if dist <= config.dl_max:
            continue
        jw_score = jaro_winkler(name, target)
        if jw_score >= config.jw_min:
            result.append(_Candidate(target=target, dl=_DL_NOT_COMPUTED, jw=jw_score))
    return result


def _build_signal(cand: _Candidate) -> LayerSignal:
    """Construye la senal TYPOSQUAT con peso segun ADR-01."""
    weight, detail = _weight_and_detail(cand)
    return LayerSignal(
        layer=Layer.L1,
        code=SignalCode.TYPOSQUAT,
        weight=weight,
        is_soft=False,
        detail=detail,
        suspected_target=cand.target,
    )


def _weight_and_detail(cand: _Candidate) -> tuple[int, str]:
    """Calcula peso y detalle de la senal segun la tabla ADR-01.

    La graduacion de peso DL solo cubre dl in {1, 2} segun ADR-01.
    Si dl_max > 2 (config no-default), candidatos con dist == 3 llegan por
    la ruta DL pero se reportan con la graduacion JW (25 o 30 segun JW).
    ADR-01 no contempla pesos para dl > 2; dl_max > 2 esta fuera de spec.
    Con el default dl_max=2 esta situacion nunca ocurre.
    """
    dl = cand.dl
    jw = cand.jw
    if dl == _DL_EXACT_ONE:
        return 60, (
            f"El nombre se parece a '{cand.target}' "
            f"(distancia Damerau-Levenshtein: 1)."
        )
    if dl == _DL_EXACT_TWO:
        return 40, (
            f"El nombre se parece a '{cand.target}' "
            f"(distancia Damerau-Levenshtein: 2)."
        )
    # dl > dl_max (JW lo capturo): senal graduada por similitud JW.
    if jw >= _JW_STRONG_THRESHOLD:
        return 30, (
            f"El nombre es muy similar a '{cand.target}' "
            f"(Jaro-Winkler: {jw:.3f} >= 0.95)."
        )
    return 25, (
        f"El nombre es similar a '{cand.target}' "
        f"(Jaro-Winkler: {jw:.3f} >= {jw:.2f})."
    )


def _name_untrusted_signal(name: str) -> LayerSignal:
    """Senal dura NAME_UNTRUSTED: nombre mas largo que nombre_max_chars (R3.6)."""
    return LayerSignal(
        layer=Layer.L1,
        code=SignalCode.NAME_UNTRUSTED,
        weight=30,
        is_soft=False,
        detail=(
            f"Nombre con longitud {len(name)} supera el limite permitido: "
            "tratado como entrada no confiable."
        ),
        suspected_target=None,
    )


class _Candidate:
    """Registro interno de un candidato del top-N con sus metricas."""

    __slots__ = ("dl", "jw", "target")

    def __init__(self, *, target: str, dl: int, jw: float) -> None:
        self.target = target
        self.dl = dl  # distancia DL; _DL_NOT_COMPUTED si fue capturado solo por JW.
        self.jw = jw

