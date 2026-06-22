"""Jaro-Winkler con boost de prefijo (ADR-02): similaridad de nombres.

Funcion pura y determinista, solo stdlib. Capa 1 la usa (prefiltrada por
`by_first_char`) para detectar typosquats que la distancia de edicion no captura
tan bien (transposiciones, prefijos compartidos). Rango de salida `[0.0, 1.0]`.

Modulo hoja: sin red, sin adapters, sin CLI.
"""

from __future__ import annotations

_PREFIX_SCALE = 0.1  # p: peso del boost de prefijo (Winkler estandar).
_MAX_PREFIX = 4  # l: longitud maxima de prefijo comun considerada.


def _jaro(a: str, b: str) -> float:
    """Similaridad de Jaro base (sin boost de prefijo)."""
    if a == b:
        return 1.0
    len_a, len_b = len(a), len(b)
    if len_a == 0 or len_b == 0:
        return 0.0
    # Ventana de coincidencia: caracteres a mas de `window` posiciones no casan.
    window = max(len_a, len_b) // 2 - 1
    a_matched = [False] * len_a
    b_matched = [False] * len_b
    matches = 0
    for i, char in enumerate(a):
        lo, hi = max(0, i - window), min(i + window + 1, len_b)
        for j in range(lo, hi):
            if not b_matched[j] and b[j] == char:
                a_matched[i] = b_matched[j] = True
                matches += 1
                break
    if matches == 0:
        return 0.0
    # Transposiciones: pares casados que aparecen en distinto orden, /2.
    matched_a = [a[i] for i in range(len_a) if a_matched[i]]
    matched_b = [b[j] for j in range(len_b) if b_matched[j]]
    # matched_a y matched_b tienen ambos longitud == matches (strict valido).
    transpositions = sum(x != y for x, y in zip(matched_a, matched_b, strict=True)) // 2
    m = float(matches)
    return (m / len_a + m / len_b + (m - transpositions) / m) / 3.0


def jaro_winkler(a: str, b: str) -> float:
    """Jaro-Winkler `[0.0, 1.0]`: Jaro base + boost de prefijo (p=0.1, prefijo<=4)."""
    jaro = _jaro(a, b)
    prefix = 0
    # Prefijo comun: trunca al mas corto (strict=False intencional).
    for char_a, char_b in zip(a[:_MAX_PREFIX], b[:_MAX_PREFIX], strict=False):
        if char_a != char_b:
            break
        prefix += 1
    return jaro + prefix * _PREFIX_SCALE * (1.0 - jaro)
