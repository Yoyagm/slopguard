"""Seleccion de parser por ecosistema end-to-end via fachada (H4-T22, §7.1).

Complementa `test_cli.py` (H4-T20, wiring CLI + exit codes) y
`test_h4_detect_ecosystem.py` (despacho a nivel de detect.py) probando la
PROPIEDAD observable de seleccion de parser a traves de la fachada del engine
(`scan_manifest`/`scan_stdin`): segun el `ecosystem_id`, el texto/archivo se
enruta al parser correcto (package.json vs requirements/freeze) y las
dependencias que llegan a la capa de evaluacion son las que ese parser produce.

Para aislar el test de la red y del dataset npm, se sustituye la construccion del
adapter (`engine.get_adapter`) por un doble inerte y se intercepta `engine._scan`
para capturar las deps parseadas sin evaluar capas. Asi el parseo real corre, pero
no se toca red, disco de cache ni dataset (test rapido y determinista).

Casos (design §3.6, R1.3/R2.1, R11):
- `scan - --ecosystem npm` enruta a parse_package_json (NO pip-freeze) sin
  disparar el guard de stdin (override gana siempre, R1.3).
- `scan package.json --ecosystem npm` enruta a parse_package_json (R2.1).
- Rama pypi (stdin freeze y requirements.txt) intacta (R11).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from slopguard.core import engine
from slopguard.core.config import Config
from slopguard.core.models import Dependency, ScanReport, ScanSummary

CFG = Config()


class _InertAdapter:
    """Adapter falso: solo expone ecosystem_id, nunca toca la red ni el dataset."""

    def __init__(self, ecosystem_id: str) -> None:
        self.ecosystem_id = ecosystem_id


@pytest.fixture
def captured_deps(monkeypatch: pytest.MonkeyPatch) -> dict[str, tuple[Dependency, ...]]:
    """Intercepta la construccion del adapter y _scan para capturar deps parseadas.

    Devuelve un dict que tras llamar a la fachada contiene:
      - "deps": las dependencias que el parser selecciona y entrega a _scan.
      - "adapter_eco": el ecosystem_id del adapter construido por la fachada.
    """
    captured: dict[str, Any] = {}

    def _fake_get_adapter(ecosystem_id: str, **_kw: object) -> _InertAdapter:
        captured["adapter_eco"] = ecosystem_id
        return _InertAdapter(ecosystem_id)

    def _fake_scan(
        deps: tuple[Dependency, ...], _config: Config, adapter: Any, **_kw: object
    ) -> ScanReport:
        captured["deps"] = tuple(deps)
        return ScanReport(
            schema_version="1.2",
            tool_version="test",
            ecosystem=adapter.ecosystem_id,
            summary=ScanSummary(
                total=0, allow=0, warn=0, block=0, unverifiable=0, exit_code=0
            ),
            results=(),
            error_category=None,
        )

    monkeypatch.setattr(engine, "get_adapter", _fake_get_adapter)
    monkeypatch.setattr(engine, "_scan", _fake_scan)
    return captured


def _names(captured: dict[str, Any]) -> set[str]:
    return {d.name for d in captured["deps"]}


# --------------------------------------------------------------------------- #
# scan_stdin: override npm => package.json en texto (no freeze), R1.3 + §3.6.
# --------------------------------------------------------------------------- #


def test_scan_stdin_npm_enruta_a_package_json_no_freeze(
    captured_deps: dict[str, Any],
) -> None:
    # 'scan - --ecosystem npm': el texto se parsea como package.json, NO freeze.
    text = json.dumps(
        {"dependencies": {"Express": "4.18.2"}, "devDependencies": {"jest": "29.0.0"}}
    )
    engine.scan_stdin(text, CFG, ecosystem_id="npm")
    assert _names(captured_deps) == {"express", "jest"}
    assert captured_deps["adapter_eco"] == "npm"


def test_scan_stdin_npm_no_trata_texto_como_freeze(
    captured_deps: dict[str, Any],
) -> None:
    # Un texto pip-freeze NO es package.json valido: en rama npm el reporte sale
    # con error_category (parseo fallido), probando que NO se interpreto como freeze.
    report = engine.scan_stdin("requests==2.0\nflask==2.3.1\n", CFG, ecosystem_id="npm")
    assert report.error_category is not None
    # _scan no debe haberse alcanzado (no hay deps capturadas).
    assert "deps" not in captured_deps


def test_scan_stdin_pypi_sigue_siendo_freeze(
    captured_deps: dict[str, Any],
) -> None:
    # R11: pypi (default) sigue parseando stdin como pip-freeze sin regresion.
    engine.scan_stdin("requests==2.28.0\nflask==2.3.1\n", CFG, ecosystem_id="pypi")
    assert _names(captured_deps) == {"requests", "flask"}
    assert captured_deps["adapter_eco"] == "pypi"


# --------------------------------------------------------------------------- #
# scan_manifest: override npm sobre package.json => parse_package_json (R2.1).
# --------------------------------------------------------------------------- #


def test_scan_manifest_npm_enruta_a_package_json(
    captured_deps: dict[str, Any],
    tmp_path: Path,
) -> None:
    path = tmp_path / "package.json"
    path.write_text(json.dumps({"dependencies": {"react": "18.0.0"}}), encoding="utf-8")
    engine.scan_manifest(path, CFG, ecosystem_id="npm")
    assert _names(captured_deps) == {"react"}
    assert captured_deps["adapter_eco"] == "npm"


def test_scan_manifest_npm_sobre_nombre_no_json(
    captured_deps: dict[str, Any],
    tmp_path: Path,
) -> None:
    # Override npm gana sobre el nombre: un package.json renombrado a deps.dat
    # se parsea igual como package.json (no cae en "tipo no reconocido", R1.3/R2.1).
    path = tmp_path / "deps.dat"
    path.write_text(json.dumps({"dependencies": {"lodash": "4.17.21"}}), encoding="utf-8")
    engine.scan_manifest(path, CFG, ecosystem_id="npm")
    assert _names(captured_deps) == {"lodash"}


def test_scan_manifest_pypi_requirements_intacto(
    captured_deps: dict[str, Any],
    tmp_path: Path,
) -> None:
    # R11: la rama pypi (requirements.txt) no cambia su seleccion de parser.
    path = tmp_path / "requirements.txt"
    path.write_text("flask==2.3.1\nrequests==2.28.0\n", encoding="utf-8")
    engine.scan_manifest(path, CFG, ecosystem_id="pypi")
    assert _names(captured_deps) == {"flask", "requests"}
    assert captured_deps["adapter_eco"] == "pypi"
