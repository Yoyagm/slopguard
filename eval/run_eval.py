"""Evaluacion precision/recall de la Capa 4 (Hito 3, R10) — reproducible y OFFLINE.

Mide el efecto de la Capa 4 sobre un dataset etiquetado, SIN red ni clave (CI-safe):
los veredictos del LLM son un SNAPSHOT versionado (R10.7); regenerarlo con una clave
real solo actualiza el campo `llm` de cada caso. La eval ESPEJA el two-pass del engine:
computa el veredicto pre-L4 real (scorer+verdict del paquete), aplica el MISMO gating
(`is_gray_band`) y, solo si la dep es gris, anade la senal de Capa 4 y re-evalua. Asi mide
exactamente la contribucion de L4 sin reimplementar el motor.

Metodologia (ADR-18, ver eval/PREREGISTRO.md):
- PROCEDENCIA INDEPENDIENTE de los positivos (R10.2): nombres alucinados curados segun la
  taxonomia publicada y observados en modelos DISTINTOS a claude-opus-4-8; NO derivan del
  juicio del modelo evaluado. No se redistribuye depscope.
- NEGATIVOS en dos estratos (R10.3): `easy_neg` (paquetes establecidos) y `hard_neg`
  (legitimos jovenes/de baja senal: la banda gris donde el anti-FP importa).
- SPLITS (R10.1): se afina en `dev`; las metricas se reportan en `test` (sin overfitting).
- METRICAS POR NIVEL DE VEREDICTO (R10.4): `block` (L4 NO participa: el delta de la
  ablacion DEBE ser 0) y `warn-o-peor` (donde L4 contribuye).
- PISO PRE-REGISTRADO (R10.5): la eval FALLA si se viola (no es tautologica).

Uso: `python eval/run_eval.py` (imprime la tabla; exit 1 si se viola el piso).
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass

from slopguard.core.config import Config
from slopguard.core.layers.layer4_hallucination import evaluate_layer4
from slopguard.core.llm.resolver import is_gray_band
from slopguard.core.models import (
    Clasificacion,
    Layer,
    LayerSignal,
    LlmAssessment,
    SignalCode,
    Verdict,
)
from slopguard.core.scoring.verdict import DepContext, build_dependency_result

# --- Piso pre-registrado (PREREGISTRO.md): la eval puede FALLAR (R10.5) ---
FLOOR_WARN_PRECISION = 0.90  # precision de "warn-o-peor" en `test`, con Capa 4 activa.
REQUIRED_BLOCK_PRECISION = 1.0  # L4 nunca bloquea: el block solo lo fijan capas 0-3.
REQUIRED_BLOCK_ABLATION_DELTA = 0.0  # el block es invariante a L4 (aislamiento, R10.4).


@dataclass(frozen=True, slots=True)
class EvalCase:
    """Un caso etiquetado del dataset (snapshot reproducible)."""

    name: str
    hallucinated: bool  # True = positivo (nombre alucinado/slopsquat)
    stratum: str  # "halluc" | "easy_neg" | "hard_neg"
    split: str  # "train" | "dev" | "test"
    provenance: str  # procedencia (independiente del modelo evaluado)
    edad_dias: int  # edad del paquete (para la rama "joven" del gating)
    soft_codes: tuple[str, ...]  # blandas heuristicas pre-L4 (proxy de capas 0-2)
    hard: tuple[str, int] | None  # (code, weight) si hay senal dura pre-L4 (typosquat)
    llm: tuple[str, float] | None  # veredicto LLM recorded (clasificacion, confianza) o None


_SOFT_WEIGHTS = {"new_package": 15, "weak_metadata": 7, "low_verifiability": 5}


# Dataset etiquetado y versionado (snapshot). Pequeno pero con los 3 estratos y 3 splits.
CASES: tuple[EvalCase, ...] = (
    # --- positivos (alucinados), procedencia independiente ---
    EvalCase("requets", True, "halluc", "test", "typo observado de 'requests'",
             30, ("new_package",), None, ("typo", 0.95)),
    # fabricacion en la franja 90-365 dias SIN senal blanda: ejercita la rama "joven".
    EvalCase("flask-restful-swagger-3", True, "halluc", "test", "fabricacion plausible curada",
             200, (), None, ("fabricacion", 0.93)),
    # positivo que YA bloquea por typosquat duro + blandas (capa 1): valida block delta=0.
    EvalCase("reqeusts", True, "halluc", "test", "typosquat dl<=2 de 'requests'",
             40, ("new_package", "weak_metadata"), ("typosquat", 60), None),
    EvalCase("python-jwt-utils", True, "halluc", "dev", "fabricacion curada",
             45, ("new_package",), None, ("fabricacion", 0.9)),
    EvalCase("django-rest-auth-toolkit", True, "halluc", "train", "conflacion curada",
             150, (), None, ("conflacion", 0.9)),
    EvalCase("numpy-pandas-utils", True, "halluc", "train", "conflacion observada",
             30, ("new_package",), None, ("conflacion", 0.91)),
    # --- easy_neg: paquetes reales establecidos (viejos, sin blandas: no banda gris) ---
    EvalCase("requests", False, "easy_neg", "test", "PyPI top-N establecido",
             4000, (), None, None),
    EvalCase("flask", False, "easy_neg", "dev", "PyPI top-N establecido",
             4500, (), None, None),
    EvalCase("numpy", False, "easy_neg", "train", "PyPI top-N establecido",
             5000, (), None, None),
    # --- hard_neg: legitimos jovenes/de baja senal (banda gris); el LLM los llama legitimo ---
    EvalCase("aiosqlite-pool", False, "hard_neg", "test", "legitimo joven real (baja descarga)",
             60, ("new_package",), None, ("legitimo", 0.9)),
    EvalCase("typed-settings-pyright", False, "hard_neg", "test", "legitimo joven real",
             120, ("new_package", "weak_metadata"), None, ("legitimo", 0.85)),
    EvalCase("starlette-csrf", False, "hard_neg", "dev", "legitimo joven real",
             80, ("new_package",), None, ("legitimo", 0.8)),
    EvalCase("httpx-retries", False, "hard_neg", "train", "legitimo joven real",
             200, (), None, ("legitimo", 0.82)),
)


def _dep_ctx(case: EvalCase) -> DepContext:
    return DepContext(name=case.name, version_pin=None, is_unverifiable=False, error_category=None)


def _pre_l4_signals(case: EvalCase) -> tuple[LayerSignal, ...]:
    """Reconstruye las senales pre-L4 (capas 0-3) del caso a partir del snapshot."""
    signals: list[LayerSignal] = [
        LayerSignal(layer=Layer.L0, code=SignalCode(code), weight=_SOFT_WEIGHTS[code],
                    is_soft=True, detail="eval")
        for code in case.soft_codes
    ]
    if case.hard is not None:
        code, weight = case.hard
        signals.append(
            LayerSignal(layer=Layer.L1, code=SignalCode(code), weight=weight,
                        is_soft=False, detail="eval")
        )
    return tuple(signals)


def _recorded_assessment(case: EvalCase) -> LlmAssessment | None:
    """Reconstruye el LlmAssessment recorded del snapshot (None si no aplica)."""
    if case.llm is None:
        return None
    clasificacion, confianza = case.llm
    return LlmAssessment(
        clasificacion=Clasificacion(clasificacion), confianza=confianza,
        patron="eval", rationale="eval", modelo="claude-opus-4-8", prompt_version="h3-v1",
    )


def predict_verdict(case: EvalCase, *, with_layer4: bool, config: Config) -> Verdict | None:
    """Veredicto del pipeline real (two-pass) con o sin Capa 4 (ablacion R10.6).

    Espeja el engine: computa el resultado PRE-L4, aplica el MISMO gating `is_gray_band`
    y solo si la dep es gris anade la senal L4 y re-evalua. La ablacion opera a nivel de
    emision (no toca el scorer puro).
    """
    pre_signals = _pre_l4_signals(case)
    pre_result = build_dependency_result(_dep_ctx(case), pre_signals, config)
    if not with_layer4 or not is_gray_band(pre_result, case.edad_dias, config):
        return pre_result.verdict
    signals = pre_signals + evaluate_layer4(_recorded_assessment(case), config)
    return build_dependency_result(_dep_ctx(case), signals, config).verdict


@dataclass(frozen=True, slots=True)
class Metrics:
    """Precision/recall/F1 para una definicion de 'prediccion positiva'."""

    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    fn: int


def _metrics(
    cases: tuple[EvalCase, ...],
    *,
    with_layer4: bool,
    config: Config,
    is_positive_pred: Callable[[Verdict | None], bool],
) -> Metrics:
    """Computa metricas comparando la prediccion vs la etiqueta `hallucinated`."""
    tp = fp = fn = 0
    for case in cases:
        verdict = predict_verdict(case, with_layer4=with_layer4, config=config)
        pred_pos = is_positive_pred(verdict)
        if case.hallucinated and pred_pos:
            tp += 1
        elif (not case.hallucinated) and pred_pos:
            fp += 1
        elif case.hallucinated and not pred_pos:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return Metrics(precision=precision, recall=recall, f1=f1, tp=tp, fp=fp, fn=fn)


def _is_block(verdict: Verdict | None) -> bool:
    return verdict is Verdict.BLOCK


def _is_warn_or_worse(verdict: Verdict | None) -> bool:
    return verdict in (Verdict.WARN, Verdict.BLOCK)


def evaluate(split: str, *, config: Config | None = None) -> dict[str, Metrics]:
    """Devuelve metricas del `split` por nivel de veredicto y ablacion (R10.4)."""
    cfg = config if config is not None else Config(enable_layer4=True)
    cases = tuple(c for c in CASES if c.split == split)

    def run(active: bool, pred: Callable[[Verdict | None], bool]) -> Metrics:
        return _metrics(cases, with_layer4=active, config=cfg, is_positive_pred=pred)

    return {
        "block_on": run(True, _is_block),
        "block_off": run(False, _is_block),
        "warn_on": run(True, _is_warn_or_worse),
        "warn_off": run(False, _is_warn_or_worse),
    }


def floor_violations(metrics: dict[str, Metrics]) -> list[str]:
    """Lista de violaciones del piso pre-registrado (vacia = pasa). R10.5."""
    problems: list[str] = []
    if metrics["block_on"].precision < REQUIRED_BLOCK_PRECISION:
        problems.append(
            f"precision(block) {metrics['block_on'].precision:.3f} < {REQUIRED_BLOCK_PRECISION}"
        )
    delta_block = abs(metrics["block_on"].recall - metrics["block_off"].recall)
    if delta_block > REQUIRED_BLOCK_ABLATION_DELTA:
        problems.append(
            f"delta de ablacion en block {delta_block:.3f} != 0 (L4 no debe afectar el block)"
        )
    if metrics["warn_on"].precision < FLOOR_WARN_PRECISION:
        problems.append(
            f"precision(warn-o-peor) {metrics['warn_on'].precision:.3f} < {FLOOR_WARN_PRECISION}"
        )
    return problems


def _format_report() -> tuple[str, list[str]]:
    """Construye el reporte de la eval sobre `test` y la lista de violaciones del piso."""
    metrics = evaluate("test")
    lines = ["=== Evaluacion Capa 4 (split=test) — Hito 3 R10 ==="]
    for nivel in ("block", "warn"):
        on = metrics[f"{nivel}_on"]
        off = metrics[f"{nivel}_off"]
        lines.append(
            f"{nivel:6} | L4 ON  P={on.precision:.3f} R={on.recall:.3f} F1={on.f1:.3f}"
            f"  || L4 OFF P={off.precision:.3f} R={off.recall:.3f} F1={off.f1:.3f}"
            f"  (delta recall = {on.recall - off.recall:+.3f})"
        )
    return "\n".join(lines), floor_violations(metrics)


def main() -> int:
    """Imprime el reporte; exit 1 si se viola el piso pre-registrado (R10.5)."""
    report, violations = _format_report()
    print(report)
    if violations:
        print("\nPISO VIOLADO:")
        for violation in violations:
            print(f"  - {violation}")
        return 1
    print("\nPiso pre-registrado: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
