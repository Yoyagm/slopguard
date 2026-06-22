"""Render humano explicable del ScanReport (R6.1-6.2, R6.5).

Cada dependencia muestra: nombre / score-o-'unverifiable' / veredicto /
explicacion de senales / suspected_target / accion sugerida. Al final,
un resumen con conteos.

TODOS los strings externos se sanean con `sanitize_for_output` antes de
escribir (R6.5): neutraliza ANSI CSI/SGR, controles C0/C1 y CR/LF.
"""

from __future__ import annotations

import sys
from typing import TextIO

from slopguard.core import DependencyResult, ScanReport, Verdict
from slopguard.core.normalize import sanitize_for_output

# Ancho maximo de linea para el render TTY.
_LINE_WIDTH = 78

# Iconos de texto (sin caracteres de control) para el render.
_ICON: dict[str | None, str] = {
    Verdict.ALLOW: "[OK]",
    Verdict.WARN: "[WARN]",
    Verdict.BLOCK: "[BLOCK]",
    None: "[UNVERIFIABLE]",
}

_ACTION: dict[str | None, str] = {
    Verdict.ALLOW: "Ninguna accion requerida.",
    Verdict.WARN: "Revisar la dependencia antes de instalar.",
    Verdict.BLOCK: "BLOQUEAR instalacion. Verificar fuente manualmente.",
    None: "No se pudo verificar. Revisar conectividad y reintentar.",
}


def _score_label(result: DependencyResult) -> str:
    """Etiqueta legible del score o 'unverifiable'."""
    if result.score is not None:
        return str(result.score)
    if result.verdict is not None:
        # score=None con verdict=block => inexistencia (override)
        return "N/A (no existe)"
    return "unverifiable"


def _render_dep(result: DependencyResult, out: TextIO) -> None:
    """Escribe una dependencia individual al stream de salida."""
    name = sanitize_for_output(result.name)
    version = f"=={sanitize_for_output(result.version_pin)}" if result.version_pin else ""
    icon = _ICON.get(result.verdict, "[?]")
    score_label = _score_label(result)
    verdict_str = result.verdict.value if result.verdict else "unverifiable"

    out.write(f"\n{icon} {name}{version}  score={score_label}  verdict={verdict_str}\n")
    out.write("-" * _LINE_WIDTH + "\n")

    if result.signals:
        out.write("  Senales detectadas:\n")
        for signal in result.signals:
            detail = sanitize_for_output(signal.detail)
            soft_tag = " [blanda]" if signal.is_soft else " [dura]"
            weight_tag = f" +{signal.weight}pts" if signal.weight > 0 else ""
            line = f"    L{signal.layer.value} {signal.code.value}{soft_tag}{weight_tag}: {detail}"
            out.write(line + "\n")
            if signal.suspected_target:
                target = sanitize_for_output(signal.suspected_target)
                out.write(f"      Objetivo sospechado: {target}\n")
    else:
        out.write("  Sin senales detectadas.\n")

    if result.suspected_target:
        target = sanitize_for_output(result.suspected_target)
        out.write(f"  Paquete legitimo sospechado: {target}\n")

    action = _ACTION.get(result.verdict, "Revisar manualmente.")
    out.write(f"  Accion: {action}\n")


def render_human(report: ScanReport, *, out: TextIO | None = None) -> None:
    """Escribe el reporte en formato humano al stream dado (default stdout).

    Imprime: cabecera, cada dependencia, y resumen final con conteos (R6.1-6.2).
    Todos los strings externos se sanean (R6.5).
    """
    stream = out if out is not None else sys.stdout
    ecosystem = sanitize_for_output(report.ecosystem)
    tool = sanitize_for_output(report.tool_version)

    stream.write("=" * _LINE_WIDTH + "\n")
    stream.write(f"SlopGuard {tool}  |  ecosistema: {ecosystem}\n")
    stream.write("=" * _LINE_WIDTH + "\n")

    if report.error_category is not None:
        error_cat = sanitize_for_output(report.error_category.value)
        stream.write(f"\nError operacional: {error_cat}\n")
        stream.write("Escaneo abortado. Revise stderr para detalles.\n")
        return

    if not report.results:
        stream.write("\nSin dependencias analizadas.\n")
        _write_summary(report, stream)
        return

    for result in report.results:
        _render_dep(result, stream)

    _write_summary(report, stream)


def _write_summary(report: ScanReport, out: TextIO) -> None:
    """Escribe el bloque de resumen con conteos y exit code sugerido."""
    s = report.summary
    out.write("\n" + "=" * _LINE_WIDTH + "\n")
    out.write(
        f"Resumen: {s.total} deps — "
        f"allow={s.allow}  warn={s.warn}  block={s.block}  unverifiable={s.unverifiable}\n"
    )
    out.write(f"Exit code sugerido: {s.exit_code}\n")
    out.write("=" * _LINE_WIDTH + "\n")
