"""Suite del subsistema *similarity* (T24/T25): Damerau-Levenshtein y Jaro-Winkler.

Cubre los criterios de aceptacion de T24 (DL banda+cutoff, transposiciones,
off-by-one, saturacion) y T25 (Jaro-Winkler con boost de prefijo), trazados a
R3.1 y ADR-02. Tres clases de caso por requisito EARS:

- **Camino feliz:** distancia exacta para vectores de tabla; valores JW de referencia.
- **Casos borde:** identidad, vacios, simetria, saturacion por diferencia de longitud,
  corte de fila, banda al limite (`len == _MAX_NAME_LEN`).
- **Modos de fallo (defensa en profundidad, modulo security-critical):**
  precondicion `max_distance >= 1` violada ⇒ `ValueError` (no degrada a "identicos");
  entradas mayores que `_MAX_NAME_LEN` ⇒ saturan sin computar (anti-DoS por
  amplificacion cuadratica).

DISCREPANCIA DE SPEC PENDIENTE DE RECONCILIACION (escalada a critic/architect)
-----------------------------------------------------------------------------
El spec APROBADO `specs/slopguard-hito1/tasks.md` (T25) cita como vectores fijos
`jaro_winkler("requests","reqursts") ~= 0.967` y `("requests","requesocks") ~= 0.937`.
Esos valores son MATEMATICAMENTE INALCANZABLES con la formula canonica de Jaro-Winkler
(p=0.1, prefijo<=4, ventana de Jaro estandar) que el propio enunciado especifica:

  requests/reqursts: matches m=7, transposiciones=0 ⇒ jaro = (7/8 + 7/8 + 7/7)/3
                     = 0.9166667; prefijo comun "req" = 3 ⇒ jw = 0.9166667 +
                     3*0.1*(1-0.9166667) = 0.950000 EXACTO. Para jw=0.967 se
                     requeriria jaro ~= 0.945, inalcanzable con (matches, transp.)
                     enteros para strings de longitud 8.
  requests/requesocks: jaro = 0.8583333; prefijo "reques" truncado a 4 ⇒
                       jw = 0.915000 EXACTO (el spec cita 0.937).

La implementacion (`jaro_winkler.py`) es la CANONICA CORRECTA (coincide con
jellyfish / strcmp95 / Apache Commons Text); NO se modifica. Los otros 4 vectores
del spec si son consistentes y se cumplen exactos. Por tanto estos tests usan los
valores canonicos (0.950 / 0.915) y la discrepancia se ESCALA para que el critic/
architect corrija formalmente T25 en tasks.md. Hasta esa reconciliacion, T25 queda
marcado como pendiente de spec; estos asserts quedan legitimados una vez aprobado.
"""

from __future__ import annotations

import time

import pytest

from slopguard.core.layers.similarity.damerau import (
    _MAX_NAME_LEN,
    damerau_levenshtein_bounded,
)
from slopguard.core.layers.similarity.jaro_winkler import _jaro, jaro_winkler

_DL_MAX = 2  # default dl_max de la tabla R8.4.

# Valores Jaro-Winkler canonicos verificados contra la implementacion de referencia.
# Los dos primeros corrigen la cifra del spec (ver docstring del modulo): el spec
# cita 0.967 / 0.937, ambos inalcanzables; los reales son 0.950 / 0.915.
_JW_REQURSTS = 0.950  # spec T25 cita 0.967 (imposible) ⇒ reconciliacion pendiente.
_JW_REQUESOCKS = 0.915  # spec T25 cita 0.937 (imposible) ⇒ reconciliacion pendiente.


# --------------------------------------------------------------------------- #
# T24 — Damerau-Levenshtein con banda + cutoff: distancia exacta (camino feliz)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("a", "b", "esperado"),
    [
        # Vectores OBLIGATORIOS de T24 (transposiciones / eliminacion, dl=1).
        ("ab", "ba", 1),  # transposicion pura
        ("attrs", "attr", 1),  # eliminacion final
        ("requests", "reqursts", 1),  # transposicion 'ue'->'eu'
        # Identidad.
        ("requests", "requests", 0),
        ("", "", 0),
        # Una sola operacion de cada tipo (dl=1).
        ("kitten", "kittenx", 1),  # insercion final
        ("color", "colour", 1),  # insercion interna
        ("flask", "flxsk", 1),  # sustitucion 'a'->'x'
        ("hello", "hexlo", 1),  # sustitucion 'l'->'x'
        ("attrs", "attr5", 1),  # sustitucion final 's'->'5'
        # Distancia 2 dentro de banda.
        ("abcde", "abxye", 2),  # dos sustituciones contiguas
        ("requests", "reqests", 1),  # eliminacion interna
    ],
)
def test_dl_distancia_exacta(a: str, b: str, esperado: int) -> None:
    """T24: distancia DL exacta para vectores de tabla (incluye transposiciones)."""
    assert damerau_levenshtein_bounded(a, b, _DL_MAX) == esperado


def test_dl_transposicion_no_es_off_by_one() -> None:
    """T24/ADR-02: una transposicion pura es dl=1, NUNCA 2 (off-by-one critico)."""
    assert damerau_levenshtein_bounded("martha", "marhta", _DL_MAX) == 1
    assert damerau_levenshtein_bounded("abcd", "abdc", _DL_MAX) == 1  # al final
    assert damerau_levenshtein_bounded("ba", "ab", _DL_MAX) == 1  # al inicio


def test_dl_simetria() -> None:
    """ADR-02: la distancia es simetrica `d(a,b) == d(b,a)` (determinismo)."""
    pares = [
        ("requests", "reqursts"),
        ("attrs", "attr"),
        ("ab", "ba"),
        ("color", "colour"),
        ("martha", "marhta"),
    ]
    for a, b in pares:
        izq = damerau_levenshtein_bounded(a, b, _DL_MAX)
        der = damerau_levenshtein_bounded(b, a, _DL_MAX)
        assert izq == der


def test_dl_determinismo() -> None:
    """NFR-Det.1: misma entrada ⇒ mismo resultado en llamadas repetidas."""
    valor = damerau_levenshtein_bounded("requests", "reqursts", _DL_MAX)
    for _ in range(5):
        assert damerau_levenshtein_bounded("requests", "reqursts", _DL_MAX) == valor


# --------------------------------------------------------------------------- #
# T24 — Casos borde: saturacion por banda/cutoff y entradas vacias
# --------------------------------------------------------------------------- #
def test_dl_satura_por_diferencia_de_longitud() -> None:
    """ADR-02: |len(a)-len(b)| > max_distance ⇒ satura a max_distance+1 sin computar."""
    # diff de longitudes 4 > 2 ⇒ valor saturado (2+1), no la distancia real.
    assert damerau_levenshtein_bounded("abc", "abcdefg", _DL_MAX) == _DL_MAX + 1


def test_dl_satura_por_corte_de_fila() -> None:
    """ADR-02: misma longitud pero todo distinto ⇒ corte de fila ⇒ valor saturado."""
    resultado = damerau_levenshtein_bounded("abcde", "vwxyz", _DL_MAX)
    assert resultado == _DL_MAX + 1


def test_dl_distancia_exacta_si_esta_dentro_del_limite() -> None:
    """Con max_distance amplio, la distancia real (no saturada) se reporta entera."""
    assert damerau_levenshtein_bounded("abcde", "vwxyz", 5) == 5


def test_dl_vacio_contra_no_vacio() -> None:
    """Casos borde con cadena vacia: distancia = longitud de la otra, con saturacion."""
    assert damerau_levenshtein_bounded("", "ab", _DL_MAX) == 2
    assert damerau_levenshtein_bounded("ab", "", _DL_MAX) == 2  # simetrico
    assert damerau_levenshtein_bounded("", "abc", _DL_MAX) == _DL_MAX + 1  # saturado


def test_dl_no_cuenta_doble_edicion_osa() -> None:
    """OSA: una subcadena se edita a lo sumo una vez ⇒ 'ca'->'abc' es 3, no menos."""
    assert damerau_levenshtein_bounded("ca", "abc", 5) == 3


def test_dl_max_distance_uno_solo_acepta_una_edicion() -> None:
    """Banda estrecha (max_distance=1): una edicion pasa, dos saturan a 2."""
    assert damerau_levenshtein_bounded("attrs", "attr", 1) == 1
    assert damerau_levenshtein_bounded("abcde", "abxye", 1) == 2  # dos subst. ⇒ saturado


def test_dl_caso_canonico_typosquat_dispara_dl_uno() -> None:
    """R3.3: typosquats reales de un solo error quedan en dl=1 (señal dura dl=1)."""
    assert damerau_levenshtein_bounded("requests", "reqursts", _DL_MAX) == 1
    assert damerau_levenshtein_bounded("urllib3", "urllib", _DL_MAX) == 1
    assert damerau_levenshtein_bounded("numpy", "numpyy", _DL_MAX) == 1


# --------------------------------------------------------------------------- #
# T24 — Modos de fallo (defensa en profundidad, modulo security-critical)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("max_distance", [0, -1, -2, -100])
def test_dl_precondicion_max_distance_invalido_lanza(max_distance: int) -> None:
    """Seguridad: max_distance <= 0 ⇒ ValueError, NO degradar a 'identicos'.

    Con la precondicion rota, `dl('ab','ba',-1)` retornaba 0 (reportaba identicos
    para strings distintos), lo que en Capa 1 silenciaria un typosquat. La guarda
    falla ruidosamente (manejo explicito de errores) en vez de devolver un resultado
    engañoso.
    """
    with pytest.raises(ValueError, match="max_distance debe ser >= 1"):
        damerau_levenshtein_bounded("ab", "ba", max_distance)


def test_dl_precondicion_lanza_incluso_para_strings_iguales() -> None:
    """La guarda se evalua antes de cualquier atajo: max_distance<1 siempre lanza."""
    with pytest.raises(ValueError, match="max_distance debe ser >= 1"):
        damerau_levenshtein_bounded("igual", "igual", 0)


def test_dl_guarda_de_longitud_maxima_satura_sin_computar() -> None:
    """Anti-DoS: entradas > _MAX_NAME_LEN saturan sin correr el algoritmo cuadratico.

    No depende de que el caller haya aplicado `bound_name`: defensa en profundidad
    contra amplificacion de coste por un nombre largo no confiable (NFR-Seg.5).
    """
    largo = "a" * (_MAX_NAME_LEN + 1)
    casi = largo[:-1] + "b"  # difiere en 1 char pero excede la cota
    assert damerau_levenshtein_bounded(largo, casi, _DL_MAX) == _DL_MAX + 1
    # Tambien satura si solo una de las dos entradas excede la cota.
    assert damerau_levenshtein_bounded(largo, "requests", _DL_MAX) == _DL_MAX + 1


def test_dl_guarda_de_longitud_es_rapida() -> None:
    """La guarda dura debe cortar en microsegundos, no en segundos (evita DoS)."""
    enorme = "x" * 100_000
    inicio = time.perf_counter()
    resultado = damerau_levenshtein_bounded(enorme, enorme[:-1] + "y", _DL_MAX)
    transcurrido = time.perf_counter() - inicio
    assert resultado == _DL_MAX + 1
    assert transcurrido < 0.1  # sin la guarda tardaria ~18s (hallazgo DoS)


def test_dl_en_el_limite_de_longitud_computa_normal() -> None:
    """Frontera: longitud == _MAX_NAME_LEN si se computa (la guarda es estricta >)."""
    base = "x" * _MAX_NAME_LEN
    assert damerau_levenshtein_bounded(base, base, _DL_MAX) == 0  # identicos
    distinto = base[:-1] + "y"
    assert damerau_levenshtein_bounded(base, distinto, _DL_MAX) == 1  # una sustitucion


def test_dl_unicode_no_crashea() -> None:
    """Robustez: caracteres unicode/multibyte no rompen el algoritmo (NFR-Seg.5)."""
    assert damerau_levenshtein_bounded("café", "cafe", _DL_MAX) == 1
    assert damerau_levenshtein_bounded("naïve", "naive", _DL_MAX) == 1
    assert damerau_levenshtein_bounded("日本語", "日本語", _DL_MAX) == 0


# --------------------------------------------------------------------------- #
# T25 — Jaro-Winkler: vectores de referencia (camino feliz)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("a", "b", "esperado"),
    [
        # Los 6 vectores de T25. Los dos primeros usan el valor CANONICO real
        # (spec cita 0.967/0.937, inalcanzables; ver docstring del modulo).
        ("requests", "reqursts", _JW_REQURSTS),  # spec: 0.967 ⇒ real 0.950
        ("requests", "requesocks", _JW_REQUESOCKS),  # spec: 0.937 ⇒ real 0.915
        ("dwayne", "duane", 0.840),  # vector del spec, consistente
        ("martha", "marhta", 0.961),  # vector del spec, consistente
        ("abc", "xyz", 0.0),  # sin coincidencia
        ("requests", "requests", 1.0),  # identidad
    ],
)
def test_jaro_winkler_vectores_de_referencia(a: str, b: str, esperado: float) -> None:
    """T25: JW contra los 6 vectores de referencia con tolerancia +-0.001 (R3.1)."""
    assert jaro_winkler(a, b) == pytest.approx(esperado, abs=0.001)


def test_jaro_winkler_boost_de_prefijo_se_aplica() -> None:
    """T25/ADR-02: el boost de prefijo eleva JW por encima del Jaro base.

    'requests'/'reqursts' comparte prefijo 'req' (3 chars). El boost (p=0.1) debe
    elevar el resultado por encima del Jaro base 0.9167, confirmando que el prefijo
    se aplica (no es JW == Jaro plano).
    """
    base = _jaro("requests", "reqursts")
    con_boost = jaro_winkler("requests", "reqursts")
    assert con_boost > base  # el prefijo comun aumenta la similaridad
    assert con_boost == pytest.approx(0.950, abs=0.001)


def test_jaro_winkler_prefijo_se_trunca_a_cuatro() -> None:
    """T25: el boost de prefijo solo cuenta hasta 4 chars (l<=4, Winkler estandar).

    'requesocks' comparte 6 chars de prefijo con 'requests' pero el boost solo usa 4.
    """
    valor = jaro_winkler("requests", "requesocks")
    assert valor == pytest.approx(0.915, abs=0.001)


def test_jaro_winkler_sin_coincidencia_es_cero() -> None:
    """Casos borde: sin caracteres comunes ⇒ 0.0 exacto (R3.1)."""
    assert jaro_winkler("abc", "xyz") == 0.0


def test_jaro_winkler_identidad_es_uno() -> None:
    """Casos borde: cadenas identicas ⇒ 1.0 exacto."""
    assert jaro_winkler("requests", "requests") == 1.0
    assert jaro_winkler("a", "a") == 1.0


def test_jaro_winkler_vacios() -> None:
    """Casos borde: vacios. Dos vacios son identicos (1.0); vacio vs no-vacio = 0.0."""
    assert jaro_winkler("", "") == 1.0
    assert jaro_winkler("", "abc") == 0.0
    assert jaro_winkler("abc", "") == 0.0


def test_jaro_winkler_rango_acotado() -> None:
    """ADR-02: la salida siempre cae en [0.0, 1.0] (invariante de rango)."""
    pares = [
        ("requests", "reqursts"),
        ("requests", "requesocks"),
        ("dwayne", "duane"),
        ("martha", "marhta"),
        ("abc", "xyz"),
        ("a", "completamentedistinto"),
    ]
    for a, b in pares:
        valor = jaro_winkler(a, b)
        assert 0.0 <= valor <= 1.0


def test_jaro_winkler_determinismo() -> None:
    """NFR-Det.1: misma entrada ⇒ mismo valor en llamadas repetidas (sin red)."""
    for a, b in [("requests", "reqursts"), ("dwayne", "duane"), ("abc", "xyz")]:
        valor = jaro_winkler(a, b)
        for _ in range(5):
            assert jaro_winkler(a, b) == valor


def test_jaro_winkler_simetria() -> None:
    """JW es simetrico: el boost de prefijo no depende del orden de los argumentos."""
    pares = [("requests", "reqursts"), ("martha", "marhta"), ("dwayne", "duane")]
    for a, b in pares:
        assert jaro_winkler(a, b) == pytest.approx(jaro_winkler(b, a), abs=1e-12)


def test_jaro_winkler_dispara_umbral_jw_min() -> None:
    """R3.3: typosquats por transposicion superan jw_min=0.92 (señal JW debil/fuerte).

    'requests'/'reqursts' (jw=0.950) cruza jw_min=0.92, mientras 'abc'/'xyz' no.
    """
    jw_min = 0.92
    assert jaro_winkler("requests", "reqursts") >= jw_min
    assert jaro_winkler("abc", "xyz") < jw_min
