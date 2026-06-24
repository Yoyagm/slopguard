"""Tests de la evaluacion precision/recall de la Capa 4 (Hito 3, T25, R10.5).

Anclan el piso pre-registrado sobre el split `test` y verifican que el chequeo del piso
NO es tautologico (puede fallar con metricas malas). Importan el harness de `eval/`.
"""

from __future__ import annotations

import sys
from pathlib import Path

_EVAL_DIR = Path(__file__).resolve().parent.parent / "eval"
if str(_EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(_EVAL_DIR))

import run_eval  # noqa: E402 (path injimport tras ajustar sys.path)


def test_block_aislado_de_layer4() -> None:
    """R10.4: la Capa 4 nunca afecta el `block` (delta de ablacion = 0; precision = 1.0)."""
    m = run_eval.evaluate("test")
    assert m["block_on"].precision == run_eval.REQUIRED_BLOCK_PRECISION
    assert m["block_on"].recall == m["block_off"].recall  # delta 0: aislamiento


def test_warn_precision_sobre_el_piso() -> None:
    """R10.5: la precision de warn-o-peor (con L4) supera el piso pre-registrado."""
    m = run_eval.evaluate("test")
    assert m["warn_on"].precision >= run_eval.FLOOR_WARN_PRECISION


def test_layer4_aumenta_recall() -> None:
    """Criterio de valor: la Capa 4 detecta lo que las capas deterministas no marcan."""
    m = run_eval.evaluate("test")
    assert m["warn_on"].recall > m["warn_off"].recall


def test_rama_joven_detecta_fabricacion() -> None:
    """La rama 'joven' del gating (90-365 dias sin blanda) permite detectar la fabricacion.

    'flask-restful-swagger-3' (edad 200, sin senal blanda) solo entra a la Capa 4 por la
    rama joven; sin L4 quedaria en allow (FN). Valida el fix del review de la Ola 3.
    """
    config = run_eval.Config(enable_layer4=True)
    case = next(c for c in run_eval.CASES if c.name == "flask-restful-swagger-3")
    con = run_eval.predict_verdict(case, with_layer4=True, config=config)
    sin = run_eval.predict_verdict(case, with_layer4=False, config=config)
    assert con is run_eval.Verdict.WARN
    assert sin is run_eval.Verdict.ALLOW


def test_piso_pasa_en_el_dataset() -> None:
    """El dataset versionado satisface el piso (sin violaciones)."""
    assert run_eval.floor_violations(run_eval.evaluate("test")) == []


def test_el_chequeo_del_piso_puede_fallar() -> None:
    """R10.5: el chequeo NO es tautologico — con metricas malas reporta violaciones."""
    malo = {
        "block_on": run_eval.Metrics(0.5, 1.0, 0.66, 1, 1, 0),  # precision block < 1.0
        "block_off": run_eval.Metrics(1.0, 0.0, 0.0, 0, 0, 1),  # delta recall != 0
        "warn_on": run_eval.Metrics(0.4, 1.0, 0.57, 2, 3, 0),  # precision warn < piso
        "warn_off": run_eval.Metrics(1.0, 0.0, 0.0, 0, 0, 2),
    }
    violations = run_eval.floor_violations(malo)
    assert len(violations) >= 3
