"""H4-T20 (regresion): --manifest-type implica ecosistema pypi sin auto-deteccion.

Antes de T20, `--ecosystem` tenia default 'pypi' y `--manifest-type` (requirements/
pyproject/freeze, exclusivo de pypi) funcionaba para CUALQUIER nombre de archivo. T20
cambio el default a None e introdujo la auto-deteccion por nombre, que exige
.txt/.json/.toml. `_ecosystem_override` cierra esa brecha: con `--manifest-type` y sin
`--ecosystem`, el ecosistema es 'pypi' como override implicito, de modo que un manifiesto
pypi de nombre no estandar (deps.in, Pipfile, constraints.in) NO muere en la auto-deteccion.

Este test bloquea esa regresion (red-team de un wiring previo), a nivel unitario sin red.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from slopguard.cli.main import _ecosystem_override
from slopguard.core.manifests.detect import detect_ecosystem


def _args(ecosystem: str | None, manifest_type: str | None) -> argparse.Namespace:
    return argparse.Namespace(ecosystem=ecosystem, manifest_type=manifest_type)


def test_manifest_type_sin_ecosystem_infiere_pypi_para_nombre_no_estandar() -> None:
    override = _ecosystem_override(_args(None, "requirements"), Path("deps.in"))
    assert override == "pypi"
    # Y detect_ecosystem honra ese override SIN auto-detectar por nombre (no exit 3).
    assert detect_ecosystem(Path("deps.in"), override) == "pypi"


def test_ecosystem_explicito_conserva_precedencia_sobre_manifest_type() -> None:
    assert _ecosystem_override(_args("npm", "requirements"), Path("p.json")) == "npm"


def test_sin_ecosystem_ni_manifest_type_no_hay_override_implicito() -> None:
    # Sin pistas, el override es None y detect_ecosystem auto-detecta por nombre.
    assert _ecosystem_override(_args(None, None), Path("requirements.txt")) is None


def test_manifest_type_no_aplica_override_implicito_a_stdin() -> None:
    # stdin (path_for_detect=None): el guard R1.5 exige --ecosystem explicito; el
    # override implicito por manifest-type NO debe enmascararlo.
    assert _ecosystem_override(_args(None, "requirements"), None) is None
