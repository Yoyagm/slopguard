"""Pruebas de modelos de dominio y errores (T08, R5/§3.6/NFR-Det.1)."""

from __future__ import annotations

import dataclasses

import pytest

from slopguard.core.errors import (
    DatasetIntegrityError,
    InvalidConfigError,
    ManifestParseError,
    NetworkUnverifiableError,
    SlopGuardError,
)
from slopguard.core.models import (
    Dependency,
    DependencyResult,
    ErrorCategory,
    Layer,
    LayerSignal,
    ScanReport,
    ScanSummary,
    SignalCode,
    Status,
    Verdict,
)


def test_dependency_es_inmutable() -> None:
    dep = Dependency(name="requests", version_pin=None, raw="requests", origin="r.txt")
    with pytest.raises(dataclasses.FrozenInstanceError):
        dep.name = "otro"  # type: ignore[misc]


def test_scanreport_resultados_son_tupla() -> None:
    """Inmutabilidad de verdad: las colecciones del resultado son tuple, no list."""
    summary = ScanSummary(total=0, allow=0, warn=0, block=0, unverifiable=0, exit_code=0)
    report = ScanReport(
        schema_version="1.0",
        tool_version="0.1.0",
        ecosystem="pypi",
        summary=summary,
        results=(),
        error_category=None,
    )
    assert isinstance(report.results, tuple)


def test_layersignal_default_sin_objetivo() -> None:
    signal = LayerSignal(
        layer=Layer.L0,
        code=SignalCode.NEW_PACKAGE,
        weight=15,
        is_soft=True,
        detail="nuevo",
    )
    assert signal.suspected_target is None


def test_dependencyresult_unverifiable_sin_score() -> None:
    result = DependencyResult(
        name="x",
        version_pin=None,
        status=Status.UNVERIFIABLE,
        verdict=None,
        score=None,
        signals=(),
        suspected_target=None,
        error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
    )
    assert result.score is None
    assert result.verdict is None


def test_enums_valores_estables() -> None:
    """El JSON depende de estos valores: no deben cambiar silenciosamente."""
    assert Verdict.BLOCK.value == "block"
    assert Status.UNVERIFIABLE.value == "unverifiable"
    assert int(Layer.L2) == 2
    assert SignalCode.TYPOSQUAT.value == "typosquat"


@pytest.mark.parametrize(
    ("exc", "categoria"),
    [
        (ManifestParseError("x"), ErrorCategory.MANIFEST_PARSE),
        (InvalidConfigError("x"), ErrorCategory.INVALID_CONFIG),
        (DatasetIntegrityError("x"), ErrorCategory.DATASET_INTEGRITY),
        (NetworkUnverifiableError("x"), ErrorCategory.NETWORK_UNVERIFIABLE),
    ],
)
def test_errores_mapean_a_su_categoria(exc: SlopGuardError, categoria: ErrorCategory) -> None:
    assert exc.error_category is categoria
    assert isinstance(exc, SlopGuardError)
