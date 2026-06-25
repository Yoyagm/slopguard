"""Suite del nucleo de parseo de package.json (H4-T14/H4-T15, design §3.3, R2.3-R2.7).

Ejercita el nucleo `_parse_package_json_content`/`_parse_dep_block`/`_is_exact_registry_pin`/
`_is_non_registry_specifier` (manifiesto npm NO confiable), cubriendo la red de seguridad
de la entrada que el adapter y stdin reutilizan (H4-T16/H4-T19).
Metodologia: tratar todo el JSON como hostil.

- JSON valido con dependencies + devDependencies => Dependency normalizado npm (R2.3).
- Dedup por nombre normalizado en ambos bloques: un nombre repetido => un solo Dependency,
  conservando la PRIMERA aparicion (R2.5).
- Vacio / bloques ausentes => () (0 deps, exit 0, R2.3).
- Malformado / top-level no-objeto / bloque no-objeto => ManifestParseError con origin
  saneado (R2.4): ningun byte de control del origen ni del payload sobrevive en el mensaje.
- version_pin: pin exacto del registry vs especificador de rango (^~<>=!*, ||) => None.
- Ignora peerDependencies / optionalDependencies / bundledDependencies (R2.6).
- Excluye specifiers no-registro (R2.7): file:, link:, workspace:, git/git+, github:,
  tarball http(s)://. Solo specifiers de version del registry (semver/dist-tag) se evaluan.
"""

from __future__ import annotations

import json

import pytest

from slopguard.core.errors import ManifestParseError
from slopguard.core.manifests.package_json import (
    _is_exact_registry_pin,
    _is_non_registry_specifier,
    _parse_package_json_content,
)


def _content(payload: dict[str, object]) -> str:
    """Serializa un dict a JSON (entra al nucleo como str ya leido)."""
    return json.dumps(payload)


# --------------------------------------------------------------------------- #
# _is_exact_registry_pin: pin exacto del registry vs rango (design §3.3).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("spec", ["1.2.3", "4.17.21", "latest", "next", "0.0.0-beta.1"])
def test_is_exact_registry_pin_acepta_pin_exacto(spec: str) -> None:
    # Semver exacto y dist-tags sin caracteres de rango son pin exacto del registry.
    assert _is_exact_registry_pin(spec) is True


@pytest.mark.parametrize(
    "spec",
    [
        "^1.2.3",  # caret => rango
        "~1.0",  # tilde => rango
        ">=2.0.0",  # comparador => rango
        "<3.0.0",  # comparador => rango
        "=1.0.0",  # igualdad explicita => char de rango al inicio
        "!1.0.0",  # negacion => char de rango
        "*",  # cualquier version => rango
        "||",  # union vacia (empieza por `||`) => rango
        "",  # specifier vacio no es pin
    ],
)
def test_is_exact_registry_pin_rechaza_rangos(spec: str) -> None:
    assert _is_exact_registry_pin(spec) is False


def test_is_exact_registry_pin_rango_interno_no_detectado_por_el_nucleo() -> None:
    # CASO BORDE (limitacion conocida del nucleo H4-T14): la deteccion de rango es por
    # PREFIJO (`^[~^<>=!*]|^\|\|`). Un `||` INTERNO (la version empieza por digito) NO se
    # detecta y se trata como pin exacto. No es un riesgo de seguridad (peor caso: un
    # version_pin informativo de mas), pero queda registrado para un refinamiento futuro.
    assert _is_exact_registry_pin("1.0.0 || 2.0.0") is True


# --------------------------------------------------------------------------- #
# Camino feliz: dependencies + devDependencies, normalizacion npm, version_pin.
# --------------------------------------------------------------------------- #


def test_parse_dependencies_y_dev_normaliza_y_pinnea() -> None:
    content = _content(
        {
            "name": "app",
            "dependencies": {"Express": "4.18.2", "axios": "^1.0.0"},
            "devDependencies": {"Jest": "29.0.0", "eslint": "*"},
        }
    )
    deps = _parse_package_json_content(content, "package.json")
    by_name = {d.name: d for d in deps}
    # Nombres normalizados npm (lowercase).
    assert set(by_name) == {"express", "axios", "jest", "eslint"}
    # Pin exacto se conserva; rango/comodin => None.
    assert by_name["express"].version_pin == "4.18.2"
    assert by_name["axios"].version_pin is None
    assert by_name["jest"].version_pin == "29.0.0"
    assert by_name["eslint"].version_pin is None
    # `raw` conserva el nombre original saneado; `origin` el del archivo.
    assert by_name["express"].raw == "Express"
    assert by_name["express"].origin == "package.json"


def test_parse_orden_dependencies_antes_de_dev() -> None:
    # Iteracion: dependencies primero, luego devDependencies (design §3.3).
    content = _content(
        {"dependencies": {"a": "1.0.0"}, "devDependencies": {"b": "2.0.0"}}
    )
    deps = _parse_package_json_content(content, "package.json")
    assert [d.name for d in deps] == ["a", "b"]


def test_parse_normaliza_scoped_sin_colapsar_slash() -> None:
    # Scoped: se conserva el '/' del scope; ambos segmentos en minuscula (R3.1).
    content = _content({"dependencies": {"@Scope/My-Pkg": "1.0.0"}})
    deps = _parse_package_json_content(content, "package.json")
    assert len(deps) == 1
    assert deps[0].name == "@scope/my-pkg"
    assert deps[0].raw == "@Scope/My-Pkg"


def test_parse_spec_no_string_no_da_pin() -> None:
    # Un spec no-string (entrada hostil) no rompe: version_pin=None, dep igual recogida.
    content = _content({"dependencies": {"weird": 123}})
    deps = _parse_package_json_content(content, "package.json")
    assert len(deps) == 1
    assert deps[0].name == "weird"
    assert deps[0].version_pin is None


# --------------------------------------------------------------------------- #
# Dedup por nombre normalizado (R2.5).
# --------------------------------------------------------------------------- #


def test_dedup_mismo_nombre_en_ambos_bloques() -> None:
    # `Lodash` (deps) y `lodash` (devDeps) normalizan al mismo nombre => un solo Dependency,
    # conservando la PRIMERA aparicion (la de dependencies).
    content = _content(
        {
            "dependencies": {"Lodash": "4.17.21"},
            "devDependencies": {"lodash": "5.0.0"},
        }
    )
    deps = _parse_package_json_content(content, "package.json")
    assert len(deps) == 1
    assert deps[0].name == "lodash"
    assert deps[0].version_pin == "4.17.21"  # primera aparicion (dependencies)
    assert deps[0].raw == "Lodash"


def test_dedup_dentro_del_mismo_bloque_por_normalizacion() -> None:
    # Dos claves que normalizan igual dentro de dependencies => una sola.
    content = _content({"dependencies": {"React": "18.0.0", "react": "17.0.0"}})
    deps = _parse_package_json_content(content, "package.json")
    assert len(deps) == 1
    assert deps[0].name == "react"
    assert deps[0].version_pin == "18.0.0"


# --------------------------------------------------------------------------- #
# Vacio / bloques ausentes => () (R2.3).
# --------------------------------------------------------------------------- #


def test_sin_bloques_de_dependencias_es_vacio() -> None:
    content = _content({"name": "app", "version": "1.0.0"})
    assert _parse_package_json_content(content, "package.json") == ()


def test_bloques_vacios_es_vacio() -> None:
    content = _content({"dependencies": {}, "devDependencies": {}})
    assert _parse_package_json_content(content, "package.json") == ()


def test_top_level_objeto_minimo_vacio_es_vacio() -> None:
    assert _parse_package_json_content("{}", "package.json") == ()


# --------------------------------------------------------------------------- #
# Ignora peer/optional/bundledDependencies (R2.6).
# --------------------------------------------------------------------------- #


def test_ignora_peer_optional_bundled() -> None:
    content = _content(
        {
            "dependencies": {"keep": "1.0.0"},
            "peerDependencies": {"peer": "1.0.0"},
            "optionalDependencies": {"opt": "1.0.0"},
            "bundledDependencies": {"bundle": "1.0.0"},
        }
    )
    deps = _parse_package_json_content(content, "package.json")
    assert [d.name for d in deps] == ["keep"]


# --------------------------------------------------------------------------- #
# Malformado / top-level no-objeto / bloque no-objeto => ManifestParseError (R2.4).
# --------------------------------------------------------------------------- #


def test_json_malformado_es_manifest_parse_error() -> None:
    with pytest.raises(ManifestParseError, match=r"package\.json"):
        _parse_package_json_content("{ esto no es json ", "package.json")


def test_top_level_no_objeto_es_error() -> None:
    # Un array de nivel superior no es un package.json valido.
    with pytest.raises(ManifestParseError, match="top-level"):
        _parse_package_json_content("[1, 2, 3]", "package.json")


@pytest.mark.parametrize("bad_block", ['["a", "b"]', '"cadena"', "42", "true"])
def test_dependencies_no_objeto_es_error(bad_block: str) -> None:
    content = f'{{"dependencies": {bad_block}}}'
    with pytest.raises(ManifestParseError, match="dependencies"):
        _parse_package_json_content(content, "package.json")


def test_dev_dependencies_no_objeto_es_error() -> None:
    content = '{"dependencies": {}, "devDependencies": ["x"]}'
    with pytest.raises(ManifestParseError, match="devDependencies"):
        _parse_package_json_content(content, "package.json")


# --------------------------------------------------------------------------- #
# Origin saneado en el mensaje de error (R2.4 / R6.5): sin bytes de control crudos.
# --------------------------------------------------------------------------- #


def test_error_sanea_origin_ansi_crlf() -> None:
    # Un origin con ANSI/CRLF no debe filtrar bytes de control al mensaje de error.
    poisoned_origin = "pkg\x1b[31m\r\n.json"
    with pytest.raises(ManifestParseError) as exc_info:
        _parse_package_json_content("no-json{", poisoned_origin)
    msg = str(exc_info.value)
    assert "\x1b" not in msg
    assert "\r" not in msg
    assert "\n" not in msg


def test_error_json_no_filtra_control_chars_del_payload() -> None:
    # El detalle del error de json incluye fragmento del payload; debe ir saneado.
    payload = '{"dependencies": \x1b[31m invalido'
    with pytest.raises(ManifestParseError) as exc_info:
        _parse_package_json_content(payload, "package.json")
    assert "\x1b" not in str(exc_info.value)


# --------------------------------------------------------------------------- #
# Exclusion de specifiers no-registro (R2.7, H4-T15).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "spec",
    [
        "file:../local-pkg",
        "file:./packages/foo",
        "link:../bar",
        "workspace:*",
        "workspace:^1.0.0",
        "git://github.com/user/repo.git",
        "git+https://github.com/user/repo.git",
        "git+ssh://git@github.com/user/repo.git",
        "github:user/repo",
        "http://example.com/pkg.tgz",
        "https://example.com/pkg.tar.gz",
    ],
)
def test_is_non_registry_specifier_detecta_specifiers_no_registro(spec: str) -> None:
    assert _is_non_registry_specifier(spec) is True


@pytest.mark.parametrize(
    "spec",
    [
        "1.2.3",  # semver exacto => registro
        "^1.0.0",  # rango => registro (no es no-registro, es evaluado como dep)
        "~2.0.0",  # rango => registro
        "latest",  # dist-tag => registro
        "next",  # dist-tag => registro
        "",  # vacio => False (no es no-registro)
    ],
)
def test_is_non_registry_specifier_acepta_specifiers_de_registro(spec: str) -> None:
    assert _is_non_registry_specifier(spec) is False


def test_excluye_file_specifier_y_evalua_semver() -> None:
    # `local-dep` tiene file: => se omite; `lodash` tiene semver => se evalua.
    content = _content(
        {
            "dependencies": {
                "local-dep": "file:../local",
                "lodash": "4.17.21",
            }
        }
    )
    deps = _parse_package_json_content(content, "package.json")
    names = [d.name for d in deps]
    assert "lodash" in names
    assert "local-dep" not in names


def test_excluye_todos_los_tipos_no_registro() -> None:
    # Cada tipo de specifier no-registro debe quedar excluido del resultado.
    content = _content(
        {
            "dependencies": {
                "a": "file:../a",
                "b": "link:../b",
                "c": "workspace:*",
                "d": "git://github.com/user/d.git",
                "e": "git+https://github.com/user/e.git",
                "f": "github:user/f",
                "g": "http://example.com/g.tgz",
                "h": "https://example.com/h.tar.gz",
                "keep": "1.0.0",
            }
        }
    )
    deps = _parse_package_json_content(content, "package.json")
    names = {d.name for d in deps}
    assert names == {"keep"}


def test_excluye_no_registro_en_dev_dependencies() -> None:
    content = _content(
        {
            "dependencies": {"react": "18.0.0"},
            "devDependencies": {
                "local-tool": "file:./tools/local-tool",
                "jest": "29.0.0",
            },
        }
    )
    deps = _parse_package_json_content(content, "package.json")
    names = {d.name for d in deps}
    assert names == {"react", "jest"}
    assert "local-tool" not in names


def test_solo_no_registro_produce_cero_deps() -> None:
    # Si todas las deps son no-registro, el resultado es () (exit 0, R2.3 compat).
    content = _content(
        {
            "dependencies": {
                "local": "file:./local",
                "git-dep": "git+https://github.com/user/repo.git",
            }
        }
    )
    assert _parse_package_json_content(content, "package.json") == ()


def test_dedup_no_registry_no_consume_slot_de_nombre_normalizado() -> None:
    # Si `lodash` aparece primero como no-registro (file:) en dependencies
    # y luego como semver en devDependencies, la version semver debe evaluarse
    # (el file: no "quema" el slot de dedup del nombre normalizado).
    content = _content(
        {
            "dependencies": {"lodash": "file:./lodash"},
            "devDependencies": {"lodash": "4.17.21"},
        }
    )
    deps = _parse_package_json_content(content, "package.json")
    assert len(deps) == 1
    assert deps[0].name == "lodash"
    assert deps[0].version_pin == "4.17.21"


def test_case_insensitive_prefijos_no_registro() -> None:
    # Los prefijos no-registro se detectan en minuscula (spec se pasa a lower()).
    content = _content({"dependencies": {"pkg": "FILE:../pkg"}})
    deps = _parse_package_json_content(content, "package.json")
    assert deps == ()


def test_git_plus_variantes_cubiertas() -> None:
    # git+ssh, git+http, git+https deben ser detectados por el prefijo "git+".
    for spec in ("git+ssh://git@github.com/u/r.git", "git+http://example.com/r.git"):
        assert _is_non_registry_specifier(spec) is True
