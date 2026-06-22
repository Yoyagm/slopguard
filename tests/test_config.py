"""Pruebas de configuracion: defaults, precedencia y validacion de rangos (T08, R8)."""

from __future__ import annotations

from pathlib import Path

import pytest

from slopguard.core.config import Config, load_config
from slopguard.core.errors import InvalidConfigError


def test_defaults_coinciden_con_tabla_r8() -> None:
    cfg = Config()
    assert cfg.umbral_block == 80
    assert cfg.umbral_warn == 50
    assert cfg.edad_minima_dias == 90
    assert cfg.jw_min == 0.92
    assert cfg.dl_max == 2
    assert cfg.nombre_max_chars == 100
    assert cfg.releases_populares == 10
    assert cfg.c2_max_contrib == 10
    assert cfg.max_json_depth == 50


def test_sin_archivo_ni_overrides_usa_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)  # dir limpio sin .slopguard.toml ni pyproject
    assert load_config(None, {}) == Config()


def test_precedencia_cli_sobre_archivo_sobre_default(tmp_path: Path) -> None:
    archivo = tmp_path / ".slopguard.toml"
    archivo.write_text("umbral_block = 70\numbral_warn = 40\n", encoding="utf-8")
    cfg = load_config(archivo, {"umbral_block": 90})
    assert cfg.umbral_block == 90  # CLI gana
    assert cfg.umbral_warn == 40  # archivo gana sobre default
    assert cfg.edad_minima_dias == 90  # default


def test_overrides_none_se_ignoran(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    cfg = load_config(None, {"umbral_block": None, "dl_max": 3})
    assert cfg.umbral_block == 80
    assert cfg.dl_max == 3


def test_lee_tool_slopguard_de_pyproject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.slopguard]\nconcurrencia_max = 4\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert load_config(None, {}).concurrencia_max == 4


def test_archivo_inexistente_es_error(tmp_path: Path) -> None:
    with pytest.raises(InvalidConfigError):
        load_config(tmp_path / "no-existe.toml", {})


def test_clave_desconocida_es_error() -> None:
    with pytest.raises(InvalidConfigError):
        load_config(None, {"parametro_inventado": 1})


def test_booleano_rechazado() -> None:
    with pytest.raises(InvalidConfigError):
        load_config(None, {"dl_max": True})


@pytest.mark.parametrize(
    "overrides",
    [
        {"umbral_warn": 80, "umbral_block": 80},  # warn no < block
        {"umbral_block": 120},  # > 100
        {"jw_min": 1.5},  # fuera de [0,1]
        {"dl_max": 0},  # < 1
        {"nombre_max_chars": 3},  # < 4
        {"connect_timeout_s": 0},  # no > 0
        {"max_deps": 0},  # no > 0
    ],
)
def test_rangos_invalidos_abortan(overrides: dict[str, object]) -> None:
    with pytest.raises(InvalidConfigError):
        load_config(None, overrides)


def test_toml_malformado_es_error(tmp_path: Path) -> None:
    archivo = tmp_path / ".slopguard.toml"
    archivo.write_text("esto no = es = toml valido", encoding="utf-8")
    with pytest.raises(InvalidConfigError):
        load_config(archivo, {})
