"""Seleccion de parser y ecosistema en el core de deteccion (H4-T22, §7.1).

Cierra los criterios EARS R1.2/R1.3/R1.4/R1.5/R2.1 a nivel de las funciones de
`core/manifests/detect.py` (despacho por ecosistema), complementando la suite
de wiring CLI de `test_cli.py` (H4-T20) sin duplicarla: aqui se prueba el
COMPORTAMIENTO observable del despacho de parser y de la precedencia de
`detect_ecosystem`, no su cableado en el CLI.

Casos cubiertos (design §3.6, §4.2):
- `detect_and_parse(ecosystem_id="npm")` despacha a `parse_package_json`: un
  `package.json` NO cae en la rama requirements/pyproject ni lanza "tipo no
  reconocido" (R2.1).
- `detect_and_parse_stdin(ecosystem_id="npm")` parsea el texto como
  package.json en texto, NO como pip-freeze (§3.6).
- `detect_ecosystem` auto-detecta por nombre: package.json => npm;
  requirements*.txt / pyproject.toml / .txt => pypi (R1.2).
- Override gana SIEMPRE, incluso contradiciendo el nombre del archivo y para
  stdin (path None) (R1.3).
- stdin sin override => error de configuracion accionable (R1.5).
- ecosystem_id no soportado => error listando los disponibles (R1.4).
- Rama pypi con ecosystem_id explicito o por default: identica (R11, cero
  regresion).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from slopguard.core.config import Config
from slopguard.core.errors import InvalidConfigError, ManifestParseError
from slopguard.core.manifests.detect import (
    detect_and_parse,
    detect_and_parse_stdin,
    detect_ecosystem,
)

CFG = Config()


def _write_pkg(tmp_path: Path, payload: dict[str, object], name: str = "package.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# detect_and_parse(ecosystem_id="npm") despacha a parse_package_json (R2.1).
# --------------------------------------------------------------------------- #


def test_detect_and_parse_npm_despacha_a_package_json(tmp_path: Path) -> None:
    # AC R2.1: con ecosystem_id="npm" un package.json se parsea como tal
    # (nombres de dependencies + devDependencies normalizados npm).
    path = _write_pkg(
        tmp_path,
        {
            "dependencies": {"Express": "4.18.2", "axios": "^1.0.0"},
            "devDependencies": {"jest": "29.0.0"},
        },
    )
    deps = detect_and_parse(path, CFG, ecosystem_id="npm")
    assert {d.name for d in deps} == {"express", "axios", "jest"}


def test_detect_and_parse_npm_no_cae_en_tipo_no_reconocido(tmp_path: Path) -> None:
    # Un package.json en rama npm NO pasa por _resolve_type (requirements/
    # pyproject/freeze): no debe lanzar "tipo no reconocido" pese a no ser .txt/.toml.
    path = _write_pkg(tmp_path, {"dependencies": {"react": "18.0.0"}})
    deps = detect_and_parse(path, CFG, ecosystem_id="npm")
    assert [d.name for d in deps] == ["react"]


def test_detect_and_parse_npm_ignora_manifest_type(tmp_path: Path) -> None:
    # manifest_type es exclusivo del flujo pypi; en la rama npm se ignora por
    # completo (no altera el parseo del package.json).
    path = _write_pkg(tmp_path, {"dependencies": {"lodash": "4.17.21"}})
    con_mt = detect_and_parse(path, CFG, ecosystem_id="npm", manifest_type="requirements")
    sin_mt = detect_and_parse(path, CFG, ecosystem_id="npm")
    assert con_mt == sin_mt
    assert [d.name for d in con_mt] == ["lodash"]


def test_detect_and_parse_npm_scoped_sin_colapsar_slash(tmp_path: Path) -> None:
    # El despacho npm preserva la normalizacion scoped (R3.1) hasta el resultado.
    path = _write_pkg(tmp_path, {"dependencies": {"@Scope/My-Pkg": "1.0.0"}})
    deps = detect_and_parse(path, CFG, ecosystem_id="npm")
    assert [d.name for d in deps] == ["@scope/my-pkg"]


def test_detect_and_parse_npm_malformado_es_manifest_parse_error(tmp_path: Path) -> None:
    # Un JSON malformado en rama npm => ManifestParseError saneado (R2.4),
    # no un error de "tipo de manifiesto".
    path = tmp_path / "package.json"
    path.write_text("{ no es json ", encoding="utf-8")
    with pytest.raises(ManifestParseError, match=r"package\.json"):
        detect_and_parse(path, CFG, ecosystem_id="npm")


# --------------------------------------------------------------------------- #
# detect_and_parse_stdin(ecosystem_id="npm") = package.json en texto, no freeze.
# --------------------------------------------------------------------------- #


def test_detect_and_parse_stdin_npm_parsea_package_json_no_freeze() -> None:
    # §3.6: stdin npm es un package.json en texto, NO pip-freeze. El JSON con
    # dependencies se interpreta como tal (no como lineas freeze "pkg==X").
    text = json.dumps(
        {"dependencies": {"Express": "4.18.2"}, "devDependencies": {"jest": "29.0.0"}}
    )
    deps = detect_and_parse_stdin(text, CFG, ecosystem_id="npm")
    assert {d.name for d in deps} == {"express", "jest"}


def test_detect_and_parse_stdin_npm_origin_es_stdin() -> None:
    # El origin de las deps de stdin npm es "stdin" (saneado), no un nombre de archivo.
    text = json.dumps({"dependencies": {"react": "18.0.0"}})
    deps = detect_and_parse_stdin(text, CFG, ecosystem_id="npm")
    assert deps[0].origin == "stdin"


def test_detect_and_parse_stdin_npm_no_interpreta_freeze() -> None:
    # Un texto pip-freeze ("requests==2.0") NO es JSON valido: en rama npm
    # debe fallar como package.json malformado, probando que NO se trata como freeze.
    text = "requests==2.0\nflask==2.3.1\n"
    with pytest.raises(ManifestParseError):
        detect_and_parse_stdin(text, CFG, ecosystem_id="npm")


def test_detect_and_parse_stdin_npm_objeto_vacio_es_cero_deps() -> None:
    # package.json minimo en texto => 0 deps, sin error (R2.3).
    assert detect_and_parse_stdin("{}", CFG, ecosystem_id="npm") == ()


def test_detect_and_parse_stdin_pypi_sigue_siendo_freeze() -> None:
    # Cero regresion (R11): pypi por default sigue parseando como pip-freeze.
    text = "requests==2.28.0\nflask==2.3.1\n"
    deps = detect_and_parse_stdin(text, CFG, ecosystem_id="pypi")
    assert {d.name for d in deps} == {"requests", "flask"}


# --------------------------------------------------------------------------- #
# detect_ecosystem: auto-deteccion por nombre (R1.2).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("package.json", "npm"),
        ("requirements.txt", "pypi"),
        ("requirements-dev.txt", "pypi"),
        ("pyproject.toml", "pypi"),
        ("constraints.txt", "pypi"),
    ],
)
def test_detect_ecosystem_autodetecta_por_nombre(filename: str, expected: str) -> None:
    # R1.2: sin override, el ecosistema se infiere del nombre del archivo.
    assert detect_ecosystem(Path(filename), None) == expected


def test_detect_ecosystem_package_json_case_insensitive() -> None:
    # El nombre se compara en minuscula: PACKAGE.JSON tambien es npm.
    assert detect_ecosystem(Path("PACKAGE.JSON"), None) == "npm"


def test_detect_ecosystem_nombre_no_reconocido_es_error() -> None:
    # Nombre sin extension conocida y sin override => error accionable (no default silencioso).
    with pytest.raises(ManifestParseError, match=r"ecosistema|--ecosystem"):
        detect_ecosystem(Path("Pipfile"), None)


# --------------------------------------------------------------------------- #
# detect_ecosystem: override gana SIEMPRE, incluso contra el nombre (R1.3).
# --------------------------------------------------------------------------- #


def test_override_npm_gana_sobre_nombre_pypi() -> None:
    # R1.3: --ecosystem npm sobre un requirements.txt fuerza npm pese al nombre.
    assert detect_ecosystem(Path("requirements.txt"), "npm") == "npm"


def test_override_pypi_gana_sobre_nombre_npm() -> None:
    # R1.3 (simetrico): --ecosystem pypi sobre un package.json fuerza pypi.
    assert detect_ecosystem(Path("package.json"), "pypi") == "pypi"


def test_override_npm_gana_para_stdin() -> None:
    # R1.3: el override gana incluso para stdin (path None): retorna ANTES del
    # guard de stdin, sin exigir nombre de archivo del que inferir.
    assert detect_ecosystem(None, "npm") == "npm"


def test_override_pypi_gana_para_stdin() -> None:
    assert detect_ecosystem(None, "pypi") == "pypi"


# --------------------------------------------------------------------------- #
# detect_ecosystem: guard de stdin sin override (R1.5) y override invalido (R1.4).
# --------------------------------------------------------------------------- #


def test_stdin_sin_override_exige_ecosystem_explicito() -> None:
    # R1.5: stdin (path None) sin --ecosystem => InvalidConfigError accionable,
    # sin asumir un ecosistema por defecto.
    with pytest.raises(InvalidConfigError, match=r"stdin|--ecosystem|ecosystem"):
        detect_ecosystem(None, None)


def test_override_no_soportado_lista_disponibles() -> None:
    # R1.4: un ecosistema no soportado => InvalidConfigError que lista los disponibles.
    with pytest.raises(InvalidConfigError) as exc_info:
        detect_ecosystem(Path("package.json"), "cargo")
    msg = str(exc_info.value)
    assert "cargo" in msg
    assert "npm" in msg and "pypi" in msg


def test_override_no_soportado_para_stdin_tambien_lista() -> None:
    # El override invalido se valida ANTES del guard de stdin: con path None y un
    # override no soportado, el error es el de ecosistema invalido (no el de stdin).
    with pytest.raises(InvalidConfigError, match="cargo"):
        detect_ecosystem(None, "cargo")


def test_override_invalido_con_ansi_no_filtra_control_chars() -> None:
    # Defensa en profundidad (R6.5): el nombre del ecosistema invalido se sanea
    # en el mensaje de error (no filtra ANSI/CRLF crudos).
    with pytest.raises(InvalidConfigError) as exc_info:
        detect_ecosystem(Path("package.json"), "\x1b[31mcargo\x1b[0m")
    msg = str(exc_info.value)
    assert "\x1b" not in msg
    assert "cargo" in msg


# --------------------------------------------------------------------------- #
# Cero regresion rama pypi: ecosystem_id="pypi" explicito == default (R11).
# --------------------------------------------------------------------------- #


def test_detect_and_parse_pypi_explicito_igual_que_default(tmp_path: Path) -> None:
    # R11: pasar ecosystem_id="pypi" explicito produce el MISMO resultado que el
    # default (la rama pypi no cambia su comportamiento por la parametrizacion).
    (tmp_path / "requirements.txt").write_text("flask==2.3.1\nrequests==2.28.0\n", encoding="utf-8")
    path = tmp_path / "requirements.txt"
    explicito = detect_and_parse(path, CFG, ecosystem_id="pypi")
    por_default = detect_and_parse(path, CFG)
    assert explicito == por_default
    assert {d.name for d in explicito} == {"flask", "requests"}


def test_detect_and_parse_pypi_pyproject_intacto(tmp_path: Path) -> None:
    # R11: la deteccion por nombre dentro de la rama pypi (pyproject.toml) sigue
    # funcionando con ecosystem_id="pypi".
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests"]\n', encoding="utf-8"
    )
    deps = detect_and_parse(tmp_path / "pyproject.toml", CFG, ecosystem_id="pypi")
    assert any(d.name == "requests" for d in deps)


def test_detect_and_parse_stdin_pypi_explicito_igual_que_default() -> None:
    # R11 (stdin): pypi explicito == default para el flujo pip-freeze.
    text = "requests==2.28.0\nflask==2.3.1\n"
    explicito = detect_and_parse_stdin(text, CFG, ecosystem_id="pypi")
    por_default = detect_and_parse_stdin(text, CFG)
    assert explicito == por_default
