"""Suite H4-T35: salida con `ecosystem` + exit codes para npm (R10.1/R10.2/R10.3).

Verifica que:
  R10.1 — el campo `ecosystem` aparece correctamente en la salida humana y JSON para
           scans npm, y que los strings externos se sanean (ANSI/control neutralizados).
  R10.2 — `schema_version` permanece en "1.2" (sin campos nuevos) para npm y PyPI.
  R10.3 — los exit codes de npm son identicos a PyPI por el peor veredicto, via
           `aggregate_exit_code`.

Los modelos se construyen a mano (sin red, sin disco, sin engine): los tests de render
son funciones puras sobre dataclasses frozen. Los tests de exit codes ejercitan
`aggregate_exit_code` directamente con `ScanReport` npm construido en memoria.
"""

from __future__ import annotations

import io
import json

from slopguard.cli.render_human import render_human
from slopguard.cli.render_json import render_json
from slopguard.core import (
    DependencyResult,
    ScanReport,
    Status,
    Verdict,
)
from slopguard.core.models import ErrorCategory, ScanSummary
from slopguard.core.scoring.verdict import aggregate_exit_code

# Secuencias de control para verificar el saneo (R10.1 / R6.5).
_ANSI = "\x1b[31m"
_OSC = "\x1b]0;titulo\x07"
_CRLF = "\r\n"


# ---------------------------------------------------------------------------
# Builders en memoria (sin red ni engine).
# ---------------------------------------------------------------------------


def _summary(
    *,
    total: int = 1,
    allow: int = 1,
    warn: int = 0,
    block: int = 0,
    unverifiable: int = 0,
    exit_code: int = 0,
) -> ScanSummary:
    """Construye un ScanSummary a mano para tests de render/exit."""
    return ScanSummary(
        total=total,
        allow=allow,
        warn=warn,
        block=block,
        unverifiable=unverifiable,
        exit_code=exit_code,
        llm_unavailable=0,
    )


def _result_allow(name: str = "lodash") -> DependencyResult:
    """DependencyResult ALLOW minimo para npm."""
    return DependencyResult(
        name=name,
        version_pin=None,
        status=Status.OK,
        verdict=Verdict.ALLOW,
        score=0,
        signals=(),
        suspected_target=None,
        error_category=None,
        advisories=(),
        llm_assessment=None,
    )


def _result_warn(name: str = "lodahs") -> DependencyResult:
    """DependencyResult WARN para npm."""
    return DependencyResult(
        name=name,
        version_pin=None,
        status=Status.OK,
        verdict=Verdict.WARN,
        score=55,
        signals=(),
        suspected_target=None,
        error_category=None,
        advisories=(),
        llm_assessment=None,
    )


def _result_block(name: str = "evilpkg") -> DependencyResult:
    """DependencyResult BLOCK para npm."""
    return DependencyResult(
        name=name,
        version_pin=None,
        status=Status.OK,
        verdict=Verdict.BLOCK,
        score=None,
        signals=(),
        suspected_target=None,
        error_category=None,
        advisories=(),
        llm_assessment=None,
    )


def _result_unverifiable(name: str = "badpkg") -> DependencyResult:
    """DependencyResult UNVERIFIABLE para npm."""
    return DependencyResult(
        name=name,
        version_pin=None,
        status=Status.UNVERIFIABLE,
        verdict=None,
        score=None,
        signals=(),
        suspected_target=None,
        error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
        advisories=(),
        llm_assessment=None,
    )


def _npm_report(
    results: tuple[DependencyResult, ...],
    *,
    ecosystem: str = "npm",
    schema_version: str = "1.2",
    summary: ScanSummary | None = None,
) -> ScanReport:
    """Construye un ScanReport npm a mano (sin engine)."""
    if summary is None:
        summary = _summary(total=len(results))
    return ScanReport(
        schema_version=schema_version,
        tool_version="0.4.0-test",
        ecosystem=ecosystem,
        summary=summary,
        results=results,
        error_category=None,
    )


# ---------------------------------------------------------------------------
# R10.1 — `ecosystem` en salida JSON
# ---------------------------------------------------------------------------


def test_json_ecosistema_npm_presente() -> None:
    """R10.1: el JSON de un scan npm incluye el campo `ecosystem` con valor 'npm'."""
    report = _npm_report((_result_allow(),))
    payload = json.loads(render_json(report))
    assert payload["ecosystem"] == "npm"


def test_json_ecosistema_pypi_no_cambia() -> None:
    """R10.1 / R11: el JSON de un scan PyPI sigue mostrando 'pypi' (cero regresion)."""
    report = _npm_report((_result_allow(),), ecosystem="pypi")
    payload = json.loads(render_json(report))
    assert payload["ecosystem"] == "pypi"


def test_json_ecosistema_distinto_de_none() -> None:
    """R10.1: el campo `ecosystem` del JSON no es null."""
    report = _npm_report((_result_allow(),))
    payload = json.loads(render_json(report))
    assert payload["ecosystem"] is not None


# ---------------------------------------------------------------------------
# R10.1 — `ecosystem` en salida humana
# ---------------------------------------------------------------------------


def test_render_humano_ecosistema_npm() -> None:
    """R10.1: el render humano de un scan npm muestra el ecosistema 'npm'."""
    report = _npm_report((_result_allow(),))
    buf = io.StringIO()
    render_human(report, out=buf)
    assert "npm" in buf.getvalue()


def test_render_humano_ecosistema_pypi_sin_regresion() -> None:
    """R10.1 / R11: el render humano de un scan PyPI sigue mostrando 'pypi'."""
    report = _npm_report((_result_allow(),), ecosystem="pypi")
    buf = io.StringIO()
    render_human(report, out=buf)
    assert "pypi" in buf.getvalue()


# ---------------------------------------------------------------------------
# R10.1 — saneo del campo `ecosystem` (ANSI/control neutralizados)
# ---------------------------------------------------------------------------


def test_json_ecosistema_saneado_ansi() -> None:
    """R10.1/R6.5: un `ecosystem` con ANSI injection se sanea en el render JSON.

    El campo ecosystem se construye internamente desde adapter.ecosystem_id
    (un string controlado del adapter); este test verifica el saneo en la
    frontera de render como defensa en profundidad (render_json aplica
    sanitize_for_output a todos los strings externos).
    """
    report = _npm_report((_result_allow(),), ecosystem=f"npm{_ANSI}")
    payload = render_json(report)
    assert "\x1b" not in payload
    assert "npm" in payload


def test_render_humano_ecosistema_saneado_ansi() -> None:
    """R10.1/R6.5: un `ecosystem` con ANSI injection se sanea en el render humano."""
    report = _npm_report((_result_allow(),), ecosystem=f"npm{_ANSI}")
    buf = io.StringIO()
    render_human(report, out=buf)
    text = buf.getvalue()
    assert "\x1b" not in text
    assert "npm" in text


def test_json_ecosistema_saneado_crlf() -> None:
    """R10.1/R6.5: CRLF en `ecosystem` se neutraliza en el render JSON."""
    report = _npm_report((_result_allow(),), ecosystem=f"npm{_CRLF}injected")
    payload = render_json(report)
    assert "\r\n" not in payload
    assert "npm" in payload


# ---------------------------------------------------------------------------
# R10.2 — `schema_version` permanece "1.2" (sin campos nuevos)
# ---------------------------------------------------------------------------


def test_json_schema_version_npm_es_1_2() -> None:
    """R10.2: el JSON de un scan npm declara schema_version == '1.2'."""
    report = _npm_report((_result_allow(),))
    payload = json.loads(render_json(report))
    assert payload["schema_version"] == "1.2"


def test_json_schema_version_estable_con_block() -> None:
    """R10.2: schema_version '1.2' se mantiene aunque haya deps BLOCK."""
    report = _npm_report(
        (_result_block(),),
        summary=_summary(total=1, allow=0, block=1, exit_code=2),
    )
    payload = json.loads(render_json(report))
    assert payload["schema_version"] == "1.2"


def test_json_no_hay_campos_nuevos_en_npm() -> None:
    """R10.2: el JSON npm tiene exactamente las mismas claves de nivel superior que PyPI.

    No se anade ninguna clave nueva al schema por el hecho de ser npm.
    """
    npm_report = _npm_report((_result_allow(),))
    pypi_report = _npm_report((_result_allow(),), ecosystem="pypi")

    npm_keys = set(json.loads(render_json(npm_report)).keys())
    pypi_keys = set(json.loads(render_json(pypi_report)).keys())

    assert npm_keys == pypi_keys


# ---------------------------------------------------------------------------
# R10.3 — exit codes por peor veredicto, identicos a PyPI
# ---------------------------------------------------------------------------


def test_exit_code_npm_todo_allow() -> None:
    """R10.3: scan npm con todas ALLOW => exit 0 (igual que PyPI)."""
    report = _npm_report(
        (_result_allow(),),
        summary=_summary(total=1, allow=1, exit_code=0),
    )
    assert aggregate_exit_code(report, strict=False) == 0


def test_exit_code_npm_con_warn() -> None:
    """R10.3: scan npm con al menos un WARN => exit 1 (igual que PyPI)."""
    report = _npm_report(
        (_result_warn(),),
        summary=_summary(total=1, allow=0, warn=1, exit_code=1),
    )
    assert aggregate_exit_code(report, strict=False) == 1


def test_exit_code_npm_con_block() -> None:
    """R10.3: scan npm con al menos un BLOCK => exit 2 (igual que PyPI)."""
    report = _npm_report(
        (_result_block(),),
        summary=_summary(total=1, allow=0, block=1, exit_code=2),
    )
    assert aggregate_exit_code(report, strict=False) == 2


def test_exit_code_npm_con_unverifiable() -> None:
    """R10.3: scan npm con al menos un UNVERIFIABLE => exit 3 (igual que PyPI)."""
    report = _npm_report(
        (_result_unverifiable(),),
        summary=_summary(total=1, allow=0, unverifiable=1, exit_code=3),
    )
    assert aggregate_exit_code(report, strict=False) == 3


def test_exit_code_npm_strict_warn_da_2() -> None:
    """R10.3: con --strict, WARN npm produce exit 2 (igual que PyPI, R7.6)."""
    report = _npm_report(
        (_result_warn(),),
        summary=_summary(total=1, allow=0, warn=1, exit_code=1),
    )
    assert aggregate_exit_code(report, strict=True) == 2


def test_exit_code_npm_peor_veredicto_block_gana_sobre_warn() -> None:
    """R10.3: peor veredicto determina el exit; BLOCK gana sobre WARN (igual que PyPI)."""
    report = _npm_report(
        (_result_warn(), _result_block()),
        summary=_summary(total=2, allow=0, warn=1, block=1, exit_code=2),
    )
    assert aggregate_exit_code(report, strict=False) == 2


def test_exit_code_npm_block_gana_sobre_unverifiable() -> None:
    """R10.3: BLOCK (exit 2) tiene precedencia sobre UNVERIFIABLE (exit 3) en la misma
    corrida, porque `aggregate_exit_code` evalua `any(BLOCK)` antes que `any(UNVERIFIABLE)`.
    Esto es identico para npm y PyPI (mismo algoritmo, R10.3).
    """
    report = _npm_report(
        (_result_block(), _result_unverifiable()),
        summary=_summary(total=2, allow=0, block=1, unverifiable=1, exit_code=2),
    )
    assert aggregate_exit_code(report, strict=False) == 2


def test_exit_code_npm_identico_a_pypi_para_mismo_summary() -> None:
    """R10.3: dado el mismo ScanSummary, el exit code es identico para npm y PyPI.

    El mecanismo `aggregate_exit_code` es agnóstico al ecosistema: solo inspecciona
    los conteos y error_category del report. npm != pypi no cambia el algoritmo.
    """
    summary = _summary(total=2, allow=1, warn=1, exit_code=1)
    npm_report = _npm_report(
        (_result_allow(), _result_warn()),
        ecosystem="npm",
        summary=summary,
    )
    pypi_report = _npm_report(
        (_result_allow(), _result_warn()),
        ecosystem="pypi",
        summary=summary,
    )
    assert aggregate_exit_code(npm_report, strict=False) == aggregate_exit_code(
        pypi_report, strict=False
    )
