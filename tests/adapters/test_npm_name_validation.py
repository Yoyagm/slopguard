"""Tests del nucleo de charset npm + predicados derivados (H4-T01, C1, §3.4).

Verifica que `_is_valid_npm_name` (pre-fetch, <=214) y `_is_valid_npm_osv_name`
(pre-POST OSV, <=100) derivan del MISMO nucleo (`_NPM_NAME_RE`) y solo difieren en el
tope de longitud: aceptan lo legitimo, rechazan los vectores peligrosos (CRLF/ANSI/
C0-C1/`%`/espacio/unicode/`:`, `/` extra, segmentos `.`/`..`, inicio por `.`/`_`,
vacio) y nunca divergen en su charset/estructura.

La propiedad cruzada formal (hypothesis) y la URL anti-traversal del fetch las cierra
H4-T04 (rol tester); aqui se fijan los casos tabla deterministas del nucleo de T01.
"""

from __future__ import annotations

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
