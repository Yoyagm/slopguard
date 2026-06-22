"""Render JSON versionado y estable del ScanReport (R6.3, R6.5, §2.5).

Produce un JSON con:
  - schema_version="1.0", tool_version, ecosystem, summary, error_category, results.
  - Sin timestamps de reloj (determinismo R6.3).
  - Claves fijas en orden determinista (sort_keys=False; el orden es el del dict literal).
  - Strings externos saneados con sanitize_for_output (R6.5).

El JSON siempre va a stdout (§3.5). Llamar `render_json(report)` retorna la
cadena serializada; `render_json_to(report, out)` la escribe al stream.
"""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from slopguard.core import DependencyResult, LayerSignal, ScanReport
from slopguard.core.normalize import sanitize_for_output


def _signal_to_dict(signal: LayerSignal) -> dict[str, object]:
    """Serializa una LayerSignal con claves fijas en orden determinista."""
    return {
        "layer": signal.layer.value,
        "code": signal.code.value,
        "weight": signal.weight,
        "is_soft": signal.is_soft,
        "detail": sanitize_for_output(signal.detail),
        "suspected_target": (
            sanitize_for_output(signal.suspected_target)
            if signal.suspected_target is not None
            else None
        ),
    }


def _result_to_dict(result: DependencyResult) -> dict[str, object]:
    """Serializa un DependencyResult con claves fijas en orden determinista (§2.5)."""
    return {
        "name": sanitize_for_output(result.name),
        "version_pin": (
            sanitize_for_output(result.version_pin)
            if result.version_pin is not None
            else None
        ),
        "status": result.status.value,
        "verdict": result.verdict.value if result.verdict is not None else None,
        "score": result.score,
        "suspected_target": (
            sanitize_for_output(result.suspected_target)
            if result.suspected_target is not None
            else None
        ),
        "error_category": (
            result.error_category.value if result.error_category is not None else None
        ),
        "signals": [_signal_to_dict(s) for s in result.signals],
    }


def _report_to_dict(report: ScanReport) -> dict[str, Any]:
    """Convierte un ScanReport al diccionario JSON canonico (§2.5)."""
    summary = report.summary
    return {
        "schema_version": report.schema_version,
        "tool_version": sanitize_for_output(report.tool_version),
        "ecosystem": sanitize_for_output(report.ecosystem),
        "summary": {
            "total": summary.total,
            "allow": summary.allow,
            "warn": summary.warn,
            "block": summary.block,
            "unverifiable": summary.unverifiable,
            "exit_code": summary.exit_code,
        },
        "error_category": (
            report.error_category.value if report.error_category is not None else None
        ),
        "results": [_result_to_dict(r) for r in report.results],
    }


def render_json(report: ScanReport) -> str:
    """Retorna la cadena JSON canonica del reporte (R6.3, §2.5).

    Sin timestamps de reloj. Strings externos saneados. Orden determinista.
    """
    data = _report_to_dict(report)
    return json.dumps(data, ensure_ascii=False, indent=2)


def render_json_to(report: ScanReport, *, out: TextIO | None = None) -> None:
    """Escribe el JSON canonico al stream dado (default stdout)."""
    stream = out if out is not None else sys.stdout
    stream.write(render_json(report))
    stream.write("\n")
