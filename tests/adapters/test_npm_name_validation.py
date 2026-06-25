"""Tests del nucleo de charset npm: casos tabla (H4-T01) + propiedad cruzada y URL
anti-traversal (H4-T04, C1, §3.4/§4.1, §7.1).

Verifica que `_is_valid_npm_name` (pre-fetch, <=214) y `_is_valid_npm_osv_name`
(pre-POST OSV, <=100) derivan del MISMO nucleo (`_NPM_NAME_RE`) y solo difieren en el
tope de longitud: aceptan lo legitimo, rechazan los vectores peligrosos (CRLF/ANSI/
C0-C1/`%`/espacio/unicode/`:`, `/` extra, segmentos `.`/`..`, inicio por `.`/`_`,
vacio) y nunca divergen en su charset/estructura.

Estructura del archivo:
- Casos tabla deterministas del nucleo (H4-T01): aceptacion/rechazo puntual.
- **Propiedad cruzada de validez (H4-T04, R3.3/R8.3/NFR-Seg.4, §7.3):** sobre un
  espacio de inputs generado de forma DETERMINISTA (sin hypothesis: el proyecto no usa
  esa dependencia y un generador propio acotado evita flakiness y deps nuevas), todo
  nombre cuya estructura/charset peligroso rechace `_is_valid_npm_name` lo rechaza
  TAMBIEN `_is_valid_npm_osv_name` — los dos predicados NO divergen salvo por el tope de
  longitud. Cierra §7.3 (divergencia de predicados): no hay bypass por un canal si y
  otro no.
- **Propiedad URL anti-traversal (H4-T04, R4.5, §4.1):** un nombre con `/` extra, `..`,
  `.`, CRLF/ANSI/C0-C1/`%`/espacio/unicode es rechazado por el predicado pre-fetch ⇒
  NUNCA elegible para la red (UNVERIFIABLE sin viajar); y un nombre scoped legitimo,
  url-encodeado con el contrato del adapter `quote(name, safe='')` (§4.1), produce un
  UNICO segmento opaco `%40scope%2Fname` sin `/` ni `..` interpretables por el registry.

Se prueba COMPORTAMIENTO/propiedad observable de los predicados y del contrato de
encoding de URL, no detalles internos del fetch (que H4-T07 implementa despues).
"""

from __future__ import annotations

import itertools
from urllib.parse import quote

import pytest

from slopguard.core.adapters import npm

# Nombres legitimos npm: simples y scoped, con todo el charset del nucleo.
_VALID_NAMES: tuple[str, ...] = (
    "lodash",
    "react",
    "left-pad",
    "a",
    "a.b.c",
    "foo_bar",  # `_` interno valido; solo se prohibe al INICIO de segmento.
    "foo~bar",
    "a..b",  # puntos consecutivos internos validos; solo el segmento `.`/`..` se prohibe.
    "@scope/name",
    "@types/node",
    "@scope/sub.name_x~y-z",
)

# Estructura peligrosa / charset no permitido: ambos predicados DEBEN rechazar.
_INVALID_NAMES: tuple[str, ...] = (
    "",  # vacio.
    ".hidden",  # inicio por `.`.
    "_private",  # inicio por `_`.
    ".",  # segmento `.`.
    "..",  # segmento `..` (traversal por segmento).
    "@scope/.hidden",  # name-seg inicia por `.`.
    "@scope/..",  # name-seg `..`.
    "@.scope/name",  # scope-seg inicia por `.`.
    "a/b/c",  # `/` extra (no scoped): traversal por path.
    "@a/b/c",  # `/` extra dentro de scoped.
    "scope/name",  # `/` sin `@` inicial.
    "@scope",  # scoped sin name-seg.
    "react\n",  # LF terminal (bypass CRLF que `^...$` dejaria pasar).
    "react\r\n",  # CRLF.
    "@scope/name\n",  # LF terminal en scoped.
    "foo bar",  # espacio.
    "foo%2e",  # `%` (encoding crudo).
    "Foo",  # mayuscula (no normalizada).
    "naivé",  # unicode combinante.
    "café",  # unicode.
    "a:b",  # `:`.
    "a\x00b",  # NUL (C0).
    "\x1b[31mx",  # ANSI/ESC (C1 escape).
    "a\tb",  # tab (C0).
)


@pytest.mark.parametrize("name", _VALID_NAMES)
def test_predicados_aceptan_nombres_legitimos(name: str) -> None:
    assert npm._is_valid_npm_name(name) is True
    assert npm._is_valid_npm_osv_name(name) is True


@pytest.mark.parametrize("name", _INVALID_NAMES)
def test_predicados_rechazan_estructura_peligrosa(name: str) -> None:
    assert npm._is_valid_npm_name(name) is False
    assert npm._is_valid_npm_osv_name(name) is False


@pytest.mark.parametrize("name", _INVALID_NAMES)
def test_predicados_no_divergen_en_el_nucleo(name: str) -> None:
    # Mismo nucleo de charset/estructura: lo que uno rechaza por charset/estructura, el
    # otro tambien (NFR-Seg.4, §7.3). No pueden divergir salvo por longitud.
    assert npm._is_valid_npm_name(name) == npm._is_valid_npm_osv_name(name)


def test_diferencia_es_solo_el_tope_de_longitud() -> None:
    # Un nombre estructuralmente valido entre 101 y 214 chars: valido pre-fetch (<=214),
    # invalido pre-POST OSV (<=100). Es la UNICA divergencia permitida entre predicados.
    name_150 = "a" * 150
    assert npm._is_valid_npm_name(name_150) is True
    assert npm._is_valid_npm_osv_name(name_150) is False


def test_topes_de_longitud_son_inclusivos_y_exclusivos() -> None:
    assert npm._is_valid_npm_name("a" * 214) is True
    assert npm._is_valid_npm_name("a" * 215) is False
    assert npm._is_valid_npm_osv_name("a" * 100) is True
    assert npm._is_valid_npm_osv_name("a" * 101) is False


def test_crlf_terminal_no_pasa_por_ancla_absoluta() -> None:
    # Regresion del bypass clasico: con `^...$` un `\n` terminal pasaria; con `\Z` no.
    for bad in ("lodash\n", "lodash\r", "lodash\r\n", "@scope/name\n"):
        assert npm._is_valid_npm_name(bad) is False
        assert npm._is_valid_npm_osv_name(bad) is False


# ===========================================================================
# H4-T04 — Propiedad cruzada de validez (R3.3/R8.3/NFR-Seg.4, §7.3)
# ===========================================================================
#
# Invariante a verificar sobre MUCHOS inputs (no solo la tabla puntual de arriba):
#   para todo nombre `n` de longitud <= 100 (donde el tope no introduce divergencia),
#   `_is_valid_npm_name(n) == _is_valid_npm_osv_name(n)`.
# Es decir: ambos predicados comparten EXACTAMENTE el mismo nucleo de charset/estructura
# y solo pueden diferir por el limite de longitud. Un nombre que uno rechace por
# charset/estructura peligrosa, el otro tambien lo rechaza (sin bypass por un canal).
#
# Generador determinista (sin hypothesis: el proyecto no la trae como dependencia y un
# corpus generado de forma reproducible cubre el espacio peligroso sin flakiness, sin
# red, sin reloj ni orden). Se mezclan caracteres legitimos del nucleo con vectores
# peligrosos para que el espacio incluya tanto aceptaciones como rechazos.

# Caracteres legitimos del nucleo de segmento npm (`[a-z0-9._~-]`) + estructura scoped.
_SAFE_CHARS: tuple[str, ...] = ("a", "z", "0", "9", ".", "_", "~", "-", "@", "/")
# Vectores peligrosos que NINGUN segmento valido puede contener (charset/estructura).
_DANGEROUS_CHARS: tuple[str, ...] = (
    "\n",  # LF (CRLF / inyeccion de header).
    "\r",  # CR.
    "\t",  # tab (C0).
    "\x00",  # NUL (C0).
    "\x1b",  # ESC (ANSI / C1).
    "\x7f",  # DEL (C1).
    " ",  # espacio.
    "%",  # encoding crudo.
    ":",  # separador de scheme/puerto.
    "/",  # separador de path (un `/` extra rompe la estructura scoped).
    "\\",  # backslash.
    "é",  # unicode.
    "ñ",  # unicode.
    "A",  # mayuscula (fuera del nucleo en minuscula).
    "..",  # segmento traversal (como fragmento inyectado).
)


def _deterministic_name_corpus() -> tuple[str, ...]:
    """Corpus determinista y reproducible de nombres candidatos (<=100 chars).

    Combina prefijos legitimos con un caracter/fragmento (legitimo o peligroso) en
    varias posiciones, y agrega construcciones scoped. La semilla del orden de
    `itertools.product` es fija ⇒ el mismo corpus en cada corrida (sin flakiness).
    """
    names: list[str] = []
    bases = ("lodash", "react", "a", "left-pad", "@scope/name", "@types/node")
    injectables = _SAFE_CHARS + _DANGEROUS_CHARS
    for base, ch in itertools.product(bases, injectables):
        names.append(base + ch)  # sufijo.
        names.append(ch + base)  # prefijo.
        mid = len(base) // 2
        names.append(base[:mid] + ch + base[mid:])  # interior.
    # Construcciones scoped explicitas con fragmentos peligrosos en cada segmento.
    for ch in injectables:
        names.append(f"@scope/{ch}name")
        names.append(f"@{ch}scope/name")
        names.append(f"@scope/name{ch}")
    # Filtra a <=100 chars: por encima de 100 el tope SI introduce la divergencia legitima
    # (que se cubre aparte en test_diferencia_es_solo_el_tope_de_longitud).
    return tuple(n for n in names if len(n) <= 100)


_NAME_CORPUS: tuple[str, ...] = _deterministic_name_corpus()


def test_corpus_determinista_no_esta_vacio() -> None:
    # Guarda contra un generador roto que dejara el property test sin inputs (assert vacio).
    assert len(_NAME_CORPUS) > 200


@pytest.mark.parametrize("name", _NAME_CORPUS)
def test_propiedad_cruzada_predicados_no_divergen_bajo_tope_comun(name: str) -> None:
    # PROPIEDAD (R3.3/R8.3/NFR-Seg.4, §7.3): para nombres <=100 chars los dos predicados
    # coinciden SIEMPRE. Comparten un unico nucleo (`_NPM_NAME_RE`); no pueden divergir en
    # charset/estructura, solo en el tope de longitud (que aqui no aplica por construccion).
    pre_fetch = npm._is_valid_npm_name(name)
    pre_post_osv = npm._is_valid_npm_osv_name(name)
    assert pre_fetch == pre_post_osv


def test_propiedad_el_corpus_ejercita_ambos_veredictos() -> None:
    # Sanidad del corpus: contiene tanto nombres aceptados como rechazados, de modo que la
    # propiedad de coincidencia no es trivial (no es "todos False"). Si el corpus solo
    # produjera rechazos, la igualdad seria vacua.
    veredictos = {npm._is_valid_npm_name(n) for n in _NAME_CORPUS}
    assert veredictos == {True, False}


def test_propiedad_todo_peligroso_inyectado_se_rechaza_por_ambos() -> None:
    # Refuerzo dirigido: cualquier nombre que contenga un caracter peligroso de control/
    # charset (excluido el caso estructural `..` que ya esta cubierto) es rechazado por los
    # DOS predicados, sin divergencia. Cierra el invariante "ningun canal deja pasar lo que
    # el otro bloquea".
    control_y_charset = tuple(c for c in _DANGEROUS_CHARS if c != "..")
    for base in ("lodash", "@scope/name"):
        for ch in control_y_charset:
            tainted = base + ch
            assert npm._is_valid_npm_name(tainted) is False
            assert npm._is_valid_npm_osv_name(tainted) is False


# ===========================================================================
# H4-T04 — Propiedad URL anti-traversal (R4.5, §4.1)
# ===========================================================================
#
# Contrato del adapter (§4.1): el nombre se valida con `_is_valid_npm_name` ANTES de
# construir URL (estructura peligrosa ⇒ jamas viaja a la red) y, si es valido, se
# url-encodea con `quote(name, safe='')` de modo que `@`→`%40` y `/`→`%2F`. El path del
# registry queda como un UNICO segmento opaco, sin `/` ni `..` interpretables (cierra el
# path-traversal/SSRF por path que `SecureHttpClient._validate_url` no atrapa).

# Nombres con estructura/charset peligroso para el path: deben quedar fuera de la red.
_TRAVERSAL_VECTORS: tuple[str, ...] = (
    "a/b/c",  # `/` extra (no scoped) ⇒ multiples segmentos / traversal.
    "@a/b/c",  # `/` extra dentro de scoped.
    "..",  # segmento traversal.
    ".",  # segmento `.`.
    "@scope/..",  # `..` en el name-seg de un scoped.
    "@scope/../x",  # `..` + `/` extra (intento de subir un nivel del path).
    "scope/name",  # `/` sin `@` inicial.
    "react\n",  # CRLF terminal (inyeccion de header / split de request).
    "react\r\n",  # CRLF.
    "\x1b[31mx",  # ANSI/ESC.
    "a\x00b",  # NUL (C0).
    "foo bar",  # espacio.
    "foo%2e",  # `%` (doble-encoding crudo de `.`).
    "café",  # unicode.
    "a:b",  # `:`.
)


@pytest.mark.parametrize("name", _TRAVERSAL_VECTORS)
def test_vector_de_traversal_es_rechazado_antes_de_la_red(name: str) -> None:
    # PROPIEDAD (R4.5/§4.1): un nombre con estructura peligrosa para el path NO pasa el
    # predicado pre-fetch ⇒ en el flujo cae a UNVERIFIABLE y NUNCA se construye una URL de
    # red con path manipulado. La validacion estructural es la primera barrera anti-traversal.
    assert npm._is_valid_npm_name(name) is False


# Nombres scoped legitimos: deben validar Y producir un unico segmento opaco al encodear.
_LEGIT_SCOPED: tuple[tuple[str, str], ...] = (
    ("@scope/name", "%40scope%2Fname"),
    ("@types/node", "%40types%2Fnode"),
    ("@my.scope/sub.name_x~y-z", "%40my.scope%2Fsub.name_x~y-z"),
)


@pytest.mark.parametrize(("name", "expected_encoded"), _LEGIT_SCOPED)
def test_scoped_legitimo_url_encodea_a_un_unico_segmento(
    name: str, expected_encoded: str
) -> None:
    # El scoped legitimo PASA el predicado (es elegible para la red)...
    assert npm._is_valid_npm_name(name) is True
    # ...y el contrato `quote(name, safe='')` lo colapsa a un unico segmento opaco:
    # `@`→`%40`, `/`→`%2F`. El path resultante NO contiene `/` ni `..` interpretables por
    # el registry, cerrando el traversal/ambiguedad de ruta (§4.1).
    encoded = quote(name, safe="")
    assert encoded == expected_encoded
    assert "/" not in encoded
    assert ".." not in encoded


def test_encoding_de_traversal_no_produciria_path_navegable() -> None:
    # Defensa en profundidad de la propiedad: aun si un vector de traversal se encodeara
    # (no deberia llegar, lo frena el predicado), `quote(safe='')` neutraliza el `/` y el
    # path no seria navegable. Esto documenta por que el encoding es la 2a barrera tras la
    # validacion estructural (§4.1): ambas se sostienen por separado.
    for vector in ("@scope/../x", "a/b/c", "@a/b/c"):
        encoded = quote(vector, safe="")
        assert "/" not in encoded  # el `/` quedo como `%2F`, no como separador de path.
