"""Render humano explicable del ScanReport (R6.1-6.2, R6.5, R7.1-7.4).

Cada dependencia muestra: nombre / score-o-'unverifiable' / veredicto /
explicacion de senales / suspected_target / advisories MAL-* (R7.1) /
atribucion watchlist (R7.2) / accion sugerida. Al final un resumen.

TODOS los strings externos se sanean con `sanitize_for_output` antes de
escribir (R6.5/R7.4): neutraliza ANSI CSI/SGR, controles C0/C1 y CR/LF.
"""

from __future__ import annotations

import sys
from typing import TextIO

from slopguard.core import DependencyResult, ScanReport, SignalCode, Verdict
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

# Accion especifica para paquetes maliciosos confirmados (R7.1).
_ACTION_MALICIOUS = (
    "BLOQUEAR. No instalar: reportado como malicioso por inteligencia comunitaria (OSV)."
)


def _score_label(result: DependencyResult) -> str:
    """Etiqueta legible del score o 'unverifiable'."""
    if result.score is not None:
        return str(result.score)
    if result.verdict is not None:
        # score=None con verdict=block => override (malicia o inexistencia).
        if _has_malicious_signal(result):
            return "N/A (malicioso)"
        if any(s.code is SignalCode.NONEXISTENT for s in result.signals):
            return "N/A (no existe)"
        return "N/A (bloqueado)"
    return "unverifiable"


def _has_malicious_signal(result: DependencyResult) -> bool:
    """True si la dep tiene al menos una senal MALICIOUS (Capa 3, R7.1)."""
    return any(s.code is SignalCode.MALICIOUS for s in result.signals)


def _render_advisories(result: DependencyResult, out: TextIO) -> None:
    """Escribe el bloque de advisories MAL-* si los hay (R7.1, R7.4).

    Muestra id, enlace canonico y accion especifica "no instalar; reportado
    como malicioso". Todos los datos externos se sanean (R7.4).
    """
    if not result.advisories:
        return
    out.write("  Advisories de malicia (OSV):\n")
    for advisory in result.advisories:
        adv_id = sanitize_for_output(advisory.id)
        adv_url = sanitize_for_output(advisory.url)
        adv_source = sanitize_for_output(advisory.source)
        out.write(f"    [{adv_id}] {adv_url}  (fuente: {adv_source})\n")
        out.write(f"    Accion: {_ACTION_MALICIOUS}\n")


def _render_watchlist_attribution(result: DependencyResult, out: TextIO) -> None:
    """Escribe la atribucion del corpus watchlist si hay senal KNOWN_HALLUCINATION (R7.2).

    El detail de la senal porta la fuente y la fecha del corpus (construidos
    por layer3_threatintel.py); se escribe saneado como atribucion explicita.
    """
    for signal in result.signals:
        if signal.code is SignalCode.KNOWN_HALLUCINATION:
            detail = sanitize_for_output(signal.detail)
            out.write(
                f"  Atribucion watchlist: {detail} "
                "(licencia del corpus: CC-BY-NC-SA; solo consulta online, no redistribuido)\n"
            )
            return


def _render_dep(result: DependencyResult, out: TextIO) -> None:
    """Escribe una dependencia individual al stream de salida (R7.1/R7.2/R7.4)."""
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

    # Advisories MAL-* con enlace + accion especifica (R7.1).
    _render_advisories(result, out)

    # Atribucion watchlist si hay KNOWN_HALLUCINATION (R7.2).
    _render_watchlist_attribution(result, out)

    # Accion generica: para MALICIOUS usa la especifica si ya se mostro en advisories.
    if not _has_malicious_signal(result):
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
