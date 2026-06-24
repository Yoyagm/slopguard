"""Render JSON versionado y estable del ScanReport (R6.3, R6.5, §2.5).

Produce un JSON con:
  - schema_version (gestionado por engine), tool_version, ecosystem, summary,
    error_category, results.
  - Sin timestamps de reloj (determinismo R6.3).
  - Claves fijas en orden determinista (sort_keys=False; el orden es el del dict literal).
  - Strings externos saneados con sanitize_for_output (R6.5).
  - Clave estable `advisories` en cada result (§2.4, H2-T14): lista [] si sin malicia,
    lista de objetos {id, kind, url, source} saneados si MALICIOUS (schema 1.1).
  - Clave estable `llm_assessment` en cada result (H3-T18): null si no hay evaluacion
    LLM; dict {clasificacion, confianza, patron, rationale, modelo, prompt_version}
    saneado si presente (schema 1.2).
  - Campo `llm_unavailable` en summary (H3-T18): deps en banda gris sin evaluacion LLM.

El JSON siempre va a stdout (§3.5). Llamar `render_json(report)` retorna la
cadena serializada; `render_json_to(report, out)` la escribe al stream.
"""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from slopguard.core import Advisory, DependencyResult, LayerSignal, ScanReport
from slopguard.core.models import LlmAssessment
from slopguard.core.normalize import sanitize_for_output


def _advisory_to_dict(advisory: Advisory) -> dict[str, object]:
    """Serializa un Advisory con claves fijas en orden determinista (§2.4, H2-T14).

    Todos los strings se sanean: el id y la url se construyen en la fuente pero se
    sanean de nuevo aqui como defensa en profundidad (R7.4, saneo en la salida).
    """
    return {
        "id": sanitize_for_output(advisory.id),
        "kind": sanitize_for_output(advisory.kind),
        "url": sanitize_for_output(advisory.url),
        "source": sanitize_for_output(advisory.source),
    }


def _llm_assessment_to_dict(assessment: LlmAssessment) -> dict[str, object]:
    """Serializa un LlmAssessment con claves fijas en orden determinista (H3-T18).

    `clasificacion` es un StrEnum: se usa .value para que el JSON sea estable.
    El resto de strings externos (patron, rationale, modelo, prompt_version) se
    sanean como defensa en profundidad (R6.5/R7.4), aunque ya vienen truncados
    del evaluador.
    """
    return {
        "clasificacion": assessment.clasificacion.value,
        "confianza": assessment.confianza,
        "patron": sanitize_for_output(assessment.patron),
        "rationale": sanitize_for_output(assessment.rationale),
        "modelo": sanitize_for_output(assessment.modelo),
        "prompt_version": sanitize_for_output(assessment.prompt_version),
    }


def _signal_to_dict(signal: LayerSignal) -> dict[str, object]:
    """Serializa una LayerSignal con claves fijas en orden determinista."""
    return {
        "layer": signal.layer.value,
        "code": signal.code.value,
        "weight": signal.weight,
        "is_soft": signal.is_soft,
        "is_llm_channel": signal.is_llm_channel,
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
        # Clave estable (§2.4, schema 1.1): siempre presente, [] si sin malicia.
        "advisories": [_advisory_to_dict(a) for a in result.advisories],
        # Clave estable (H3-T18, schema 1.2): null si sin evaluacion LLM.
        "llm_assessment": (
            _llm_assessment_to_dict(result.llm_assessment)
            if result.llm_assessment is not None
            else None
        ),
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
            "llm_unavailable": summary.llm_unavailable,
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
