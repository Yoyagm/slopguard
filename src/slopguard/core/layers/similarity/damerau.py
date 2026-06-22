"""Damerau-Levenshtein (OSA) acotada con banda diagonal + corte de fila.

Variante *optimal string alignment* (OSA, ADR-02): cada subcadena se edita a lo
sumo una vez, lo que da los mismos resultados que el DL completo para los vectores
de typosquatting (`ab↔ba`, `attrs/attr`, `requests/reqursts` con transposicion)
siendo mas simple y bandeable sin estado mutable global.

Cota de coste: como `DL >= |len(a)-len(b)|`, si la diferencia de longitudes supera
`max_distance` se satura de inmediato; la banda restringe cada fila a las columnas
`[i-max_distance, i+max_distance]` y se aborta si el minimo de la fila supera el
limite ⇒ O(|a|*max_distance) por candidato, nunca O(|a|*|b|).

Modulo hoja: solo stdlib, sin red ni adapters. Funcion pura y determinista.
"""

from __future__ import annotations

# Defensa en profundidad: cota dura de longitud independiente del caller. Cubre con
# margen los caps de ecosistema (PyPI 214 / npm 128 chars) y de `nombre_max_chars`
# (default 100). Evita amplificacion de coste si un nombre largo no confiable llega
# aqui sin que `bound_name` lo haya acotado antes (NFR-Seg.5, hallazgo DoS).
_MAX_NAME_LEN = 256


def damerau_levenshtein_bounded(a: str, b: str, max_distance: int) -> int:
    """Distancia DL (OSA) entre `a` y `b`, saturada a `max_distance+1` si la supera.

    Devuelve la distancia exacta cuando es `<= max_distance`; en caso contrario
    devuelve `max_distance+1` (sentinela "fuera de banda") sin gastar mas computo.

    Precondiciones (validadas explicitamente; modulo security-critical):
    - `max_distance >= 1`: un valor <= 0 hace ambiguo el sentinela de saturacion y
      degradaria a reportar 'identicos' para strings distintos ⇒ `ValueError`.
    - longitudes acotadas a `_MAX_NAME_LEN`: por encima se satura sin computar, para
      no depender de que el caller haya aplicado `bound_name` (defensa en profundidad).
    """
    if max_distance < 1:
        raise ValueError("max_distance debe ser >= 1")
    saturated = max_distance + 1
    len_a, len_b = len(a), len(b)
    if len_a > _MAX_NAME_LEN or len_b > _MAX_NAME_LEN:
        return saturated  # entrada no acotada: no corremos distancia (anti-DoS).
    # Como DL >= |len_a-len_b|, una diferencia de longitudes excesiva ya satura.
    if abs(len_a - len_b) > max_distance:
        return saturated
    if a == b:
        return 0
    return _banded_distance(a, b, max_distance)


def _banded_distance(a: str, b: str, max_distance: int) -> int:
    """Nucleo de la DL bandeada con buffers reutilizados (coste O(|a|*max_distance)).

    Tres buffers rotatorios de ancho fijo `len_b+1` se reutilizan entre filas: cada
    fila solo limpia y escribe su franja `[lo-1, hi]`, de modo que la asignacion de
    memoria es O(|a|*max_distance), no O(|a|*|b|) (hallazgo DoS por amplificacion).
    Las celdas fuera de banda quedan en `inf` (inalcanzables), invariante preservado.
    """
    len_a, len_b = len(a), len(b)
    saturated = max_distance + 1
    inf = saturated
    prev2 = [inf] * (len_b + 1)  # fila i-2 (transposiciones)
    prev1 = [j if j <= max_distance else inf for j in range(len_b + 1)]
    cur = [inf] * (len_b + 1)
    for i in range(1, len_a + 1):
        lo, hi = max(1, i - max_distance), min(len_b, i + max_distance)
        for col in range(max(0, lo - 1), hi + 1):  # limpia solo la franja activa.
            cur[col] = inf
        cur[0] = i if i <= max_distance else inf
        row_min = cur[0]
        for j in range(lo, hi + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            best = min(prev1[j] + 1, cur[j - 1] + 1, prev1[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                best = min(best, prev2[j - 2] + 1)
            cur[j] = best
            row_min = min(row_min, best)
        if row_min > max_distance:  # toda la fila ya excede el limite: corte.
            return saturated
        prev2, prev1, cur = prev1, cur, prev2  # rota los tres buffers.
    result = prev1[len_b]
    return result if result <= max_distance else saturated
