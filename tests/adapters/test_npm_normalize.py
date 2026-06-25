"""Tests de `NpmAdapter.normalize_name` (H4-T03, C1, §3.4, §7.1).

Cubre los criterios EARS R3.1/R3.2/R3.3 mas la cero-regresion de
`PypiAdapter.normalize_name` (R3.4):

- R3.1: minusculas, scoped `@scope/name` sin colapsar el `/`, `@` inicial preservado;
  NO se aplica el colapso PEP 503 de `._-` (eso es PyPI).
- R3.2: idempotencia `normalize(normalize(x)) == normalize(x)`.
- R3.3 (fail-closed, defensa en profundidad): un nombre estructuralmente invalido
  (vacio, inicio por `.`/`_`, >214, charset no permitido, `/` extra) NUNCA produce un
  CLEAN espurio: tras normalizar no pasa `_is_valid_npm_name`, de modo que en el flujo
  cae a UNVERIFIABLE sin viajar a la red.
- R3.4: `PypiAdapter.normalize_name` (PEP 503: colapso `._-`→`-`) queda intacto.

Se prueba COMPORTAMIENTO observable de `normalize_name` (la API publica del adapter) y
la PROPIEDAD de seguridad "invalido ⇒ nunca CLEAN" via el predicado fail-closed que el
flujo consulta tras normalizar (sin tocar internals de fetch).

La propiedad cruzada formal de los predicados y la URL anti-traversal del fetch las
cierra H4-T04/T09; aqui se fija la normalizacion y su consecuencia fail-closed.
"""

from __future__ import annotations

import pytest

from slopguard.core.adapters import npm
from slopguard.core.adapters.npm import NpmAdapter
from slopguard.core.adapters.pypi import PypiAdapter
from slopguard.core.config import Config


@pytest.fixture
def adapter() -> NpmAdapter:
    # H4-T07 dio a NpmAdapter un __init__(config, *, use_cache); `normalize_name` es puro
    # pero la construccion ahora exige Config. use_cache=False evita tocar el disco.
    return NpmAdapter(Config(), use_cache=False)


# ---------------------------------------------------------------------------
# R3.1 — reglas npm: minusculas, scoped sin colapsar `/`, sin colapso PEP 503
# ---------------------------------------------------------------------------


def test_baja_a_minusculas(adapter: NpmAdapter) -> None:
    # Arrange / Act
    result = adapter.normalize_name("LoDash")
    # Assert
    assert result == "lodash"


def test_recorta_espacios_envolventes(adapter: NpmAdapter) -> None:
    assert adapter.normalize_name("  react  ") == "react"


def test_scoped_preserva_el_separador_de_scope(adapter: NpmAdapter) -> None:
    # El `/` del scope NO se colapsa ni se elimina (R3.1).
    result = adapter.normalize_name("@Scope/Name")
    assert result == "@scope/name"
    assert result.count("/") == 1
    assert result.startswith("@")


def test_scoped_normaliza_ambos_segmentos_por_separado(adapter: NpmAdapter) -> None:
    # Mayusculas y espacios en scope y name se normalizan en cada parte, sin colapsar `/`.
    assert adapter.normalize_name("  @TYPES / Node  ") == "@types/node"


@pytest.mark.parametrize(
    "raw",
    [
        "left-pad",
        "foo_bar",
        "a.b.c",
        "foo~bar",
        "@scope/sub.name_x~y-z",
    ],
)
def test_no_colapsa_separadores_pep503(adapter: NpmAdapter, raw: str) -> None:
    # npm conserva `._-~` como caracteres validos del nombre; a diferencia de PyPI NO los
    # colapsa a `-` (R3.1/R3.4). Como ya estan en minuscula sin espacios, son punto fijo.
    assert adapter.normalize_name(raw) == raw


def test_caso_mixto_completo(adapter: NpmAdapter) -> None:
    # Mayusculas + espacios + scoped + separadores conservados, todo a la vez.
    assert adapter.normalize_name("  @MyScope/My_Cool.Pkg-2  ") == "@myscope/my_cool.pkg-2"


# ---------------------------------------------------------------------------
# R3.2 — idempotencia: normalize(normalize(x)) == normalize(x)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "LoDash",
        "  React  ",
        "@TYPES/Node",
        "  @MyScope / My_Cool.Pkg-2 ",
        "left-pad",
        "foo_bar",
        "a.b.c",
        "@scope/sub.name_x~y-z",
    ],
)
def test_idempotencia(adapter: NpmAdapter, raw: str) -> None:
    once = adapter.normalize_name(raw)
    twice = adapter.normalize_name(once)
    assert twice == once


# ---------------------------------------------------------------------------
# R3.3 — fail-closed: nombre invalido => nunca CLEAN (cae a UNVERIFIABLE)
# ---------------------------------------------------------------------------

# Nombres que, tras normalizar, son estructuralmente invalidos para npm. El predicado
# pre-fetch `_is_valid_npm_name` (que el flujo consulta sobre el nombre normalizado antes
# de viajar a la red) debe rechazarlos => no se consultan como "CLEAN".
_INVALID_AFTER_NORMALIZE: tuple[str, ...] = (
    "",  # vacio.
    "   ",  # solo espacios => "" tras strip.
    ".hidden",  # inicio por `.`.
    "_private",  # inicio por `_`.
    ".",  # segmento `.`.
    "..",  # segmento `..` (traversal por segmento).
    "@scope/.hidden",  # name-seg inicia por `.`.
    "a/b/c",  # `/` extra (no scoped): traversal por path.
    "@a/b/c",  # `/` extra dentro de scoped.
    "scope/name",  # `/` sin `@` inicial.
    "foo bar",  # espacio interno (sobrevive a strip).
    "foo%2e",  # `%` (encoding crudo).
    "café",  # unicode.
    "a:b",  # `:`.
    "a\x00b",  # NUL (C0).
    "\x1b[31mx",  # ANSI/ESC.
    "rea\nct",  # LF INTERNO: strip solo recorta extremos, este `\n` sobrevive => invalido.
)


@pytest.mark.parametrize("raw", _INVALID_AFTER_NORMALIZE)
def test_invalido_no_pasa_el_predicado_prefetch(adapter: NpmAdapter, raw: str) -> None:
    # Propiedad de seguridad (R3.3): por mucho que se normalice, un nombre estructuralmente
    # invalido no supera `_is_valid_npm_name` => en el flujo cae a UNVERIFIABLE, jamas CLEAN,
    # y no viaja a la red. normalize_name NO es un saneador que "limpie" lo peligroso.
    normalized = adapter.normalize_name(raw)
    assert npm._is_valid_npm_name(normalized) is False


def test_excede_214_invalido(adapter: NpmAdapter) -> None:
    # >214 chars: aunque normalize lo deje en minusculas, supera el tope npm => invalido
    # pre-fetch (nunca CLEAN). El de 214 exacto si es valido (limite inclusivo).
    en_limite = "a" * 214
    sobre_limite = "a" * 215
    assert npm._is_valid_npm_name(adapter.normalize_name(en_limite)) is True
    assert npm._is_valid_npm_name(adapter.normalize_name(sobre_limite)) is False


def test_nombre_legitimo_si_pasa_el_predicado_prefetch(adapter: NpmAdapter) -> None:
    # Contraprueba: un nombre legitimo (simple y scoped) tras normalizar SI es elegible
    # para la red. Asegura que el predicado no rechaza de mas (no convierte todo en UNVERIFIABLE).
    assert npm._is_valid_npm_name(adapter.normalize_name("LoDash")) is True
    assert npm._is_valid_npm_name(adapter.normalize_name("@TYPES/Node")) is True


# ---------------------------------------------------------------------------
# R3.4 — cero regresion de PypiAdapter.normalize_name (PEP 503 intacto)
# ---------------------------------------------------------------------------


def test_pypi_normalize_colapsa_separadores_pep503() -> None:
    # PyPI SI colapsa runs de `._-` a un unico `-` (PEP 503): comportamiento divergente y
    # deliberado frente a npm. Esta diferencia es el corazon de R3.4 (no se contamina npm↔PyPI).
    pypi = PypiAdapter.__new__(PypiAdapter)  # evita I/O del __init__ (dataset/red/cache).
    assert pypi.normalize_name("Foo.Bar_Baz--Qux") == "foo-bar-baz-qux"


def test_npm_y_pypi_difieren_en_el_mismo_nombre(adapter: NpmAdapter) -> None:
    # Mismo input, distinta regla: npm conserva `._-`, PyPI los colapsa. Garantiza que el
    # nuevo adapter no altero la normalizacion PyPI existente.
    pypi = PypiAdapter.__new__(PypiAdapter)
    raw = "My_Cool.Pkg"
    assert adapter.normalize_name(raw) == "my_cool.pkg"
    assert pypi.normalize_name(raw) == "my-cool-pkg"
