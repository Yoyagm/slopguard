"""Invariante anti-block en la validacion de config (Hito 3, R5.2.b/c, fail-closed).

El critic detecto que `_validate_ranges` validaba solo `0 <= umbral_warn <
umbral_block <= 100` pero NO el invariante anti-block: con `--umbral-block 75`
una dep en banda gris (max_hard=0) podia llegar a `0 + SOFT_CAP(25) +
LLM_SOFT_CAP(50) = 75 >= 75` ⇒ BLOCK solo por la Capa 4, rompiendo la garantia
"L4 nunca bloquea" (R3.1/R3.2).

Estos tests fijan el control de seguridad de configuracion:
  - `SOFT_CAP + LLM_SOFT_CAP (=75) < umbral_block`  (R5.2.b)
  - `LLM_SOFT_CAP (=50) >= umbral_warn`             (R5.2.c)
Cualquier violacion ⇒ `InvalidConfigError` (fail-closed) y, en la CLI, exit 3.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from slopguard.cli import main as cli_main
from slopguard.cli.exit_codes import EXIT_OPERATIONAL
from slopguard.core.config import Config, load_config
from slopguard.core.errors import InvalidConfigError
from slopguard.core.scoring.scorer import LLM_SOFT_CAP, SOFT_CAP

# Suma de los topes estructurales: con los defaults vale 75 (25 + 50).
_CAPS_TOTAL = SOFT_CAP + LLM_SOFT_CAP


def test_caps_total_es_75() -> None:
    """Ancla: los topes estructurales suman 75 (25 + 50), base del invariante."""
    assert _CAPS_TOTAL == 75


# --------------------------------------------------------------------------- #
# R5.2.b — SOFT_CAP + LLM_SOFT_CAP < umbral_block
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("umbral_block", [75, 74, 70, 51])
def test_umbral_block_que_permite_block_por_l4_aborta(umbral_block: int) -> None:
    """R5.2.b: si `caps_total >= umbral_block`, la Capa 4 podria bloquear ⇒ aborta."""
    with pytest.raises(InvalidConfigError, match="anti-block"):
        load_config(None, {"umbral_block": umbral_block})


def test_umbral_block_igual_a_caps_total_aborta() -> None:
    """R5.2.b: `umbral_block == 75` es el borde inseguro (75 >= 75) ⇒ aborta."""
    with pytest.raises(InvalidConfigError, match="anti-block"):
        load_config(None, {"umbral_block": _CAPS_TOTAL})


def test_umbral_block_76_es_valido() -> None:
    """R5.2.b: `umbral_block == 76` es el primer valor seguro (75 < 76) ⇒ valido."""
    config = load_config(None, {"umbral_block": 76})
    assert config.umbral_block == 76


def test_defaults_siguen_siendo_validos() -> None:
    """R5.2.b: los defaults (umbral_block=80, warn=50) cumplen el invariante (75 < 80)."""
    config = load_config(None, {})
    assert config.umbral_block == 80
    assert config.umbral_warn == 50


# --------------------------------------------------------------------------- #
# R5.2.c — LLM_SOFT_CAP >= umbral_warn (el canal L4 debe poder alcanzar warn)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("umbral_warn", [51, 60, 79])
def test_umbral_warn_mayor_que_llm_soft_cap_aborta(umbral_warn: int) -> None:
    """R5.2.c: si `umbral_warn > LLM_SOFT_CAP`, el canal L4 nunca llega a warn ⇒ aborta."""
    with pytest.raises(InvalidConfigError, match="umbral_warn"):
        load_config(None, {"umbral_warn": umbral_warn})


def test_umbral_warn_igual_a_llm_soft_cap_es_valido() -> None:
    """R5.2.c: `umbral_warn == 50 == LLM_SOFT_CAP` es valido (>=, no estrictamente >)."""
    config = load_config(None, {"umbral_warn": LLM_SOFT_CAP})
    assert config.umbral_warn == LLM_SOFT_CAP


# --------------------------------------------------------------------------- #
# Mapeo CLI: una config insegura ⇒ exit 3 (error_category=invalid_config)
# --------------------------------------------------------------------------- #


def test_cli_umbral_block_inseguro_mapea_a_exit_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R5.2: `--umbral-block 75` aborta en load_config y la CLI mapea a exit 3 (fail-closed).

    El manifiesto no llega a leerse: la validacion de config falla ANTES (no se
    aplican valores a medias). Se cambia el cwd a un directorio vacio para que no
    se descubra ningun `.slopguard.toml`/`pyproject.toml` del entorno.
    """
    monkeypatch.chdir(tmp_path)
    code = cli_main.main(["scan", "manifiesto-inexistente.txt", "--umbral-block", "75"])
    assert code == EXIT_OPERATIONAL  # 3
    err = capsys.readouterr().err
    assert "configuracion" in err.lower()


def test_construir_config_directo_no_valida() -> None:
    """`Config(umbral_block=75)` directo NO ejecuta la validacion (solo load_config lo hace).

    Documenta el limite del control: el invariante se aplica en la frontera de
    carga (load_config), no en el constructor del dataclass (usado en fixtures de
    tests de scoring que arman configs arbitrarias sin pasar por la validacion).
    """
    cfg = Config(umbral_block=75)
    assert cfg.umbral_block == 75  # el constructor no aborta; la validacion vive en load_config
