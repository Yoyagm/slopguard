"""Suite de scoring/verdict (T32, R5.1-R5.8, R7.1-R7.6, ADR-01).

Dos estilos de prueba:
  (A) TABLA exhaustiva — combinaciones de señales de ADR-01, umbrales exactos,
      override 404, unverifiable, prioridad Capa 0, aggregate_exit_code con/sin strict.
  (B) PROPIEDAD — anti-FP R5.6 y determinismo bajo permutacion R5.7.

Sin I/O, sin red, sin reloj. Funciones puras.
"""

from __future__ import annotations

import itertools
from typing import ClassVar

import pytest

from slopguard.core.config import Config
from slopguard.core.models import (
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
from slopguard.core.scoring.scorer import SOFT_CAP, compute_score
from slopguard.core.scoring.verdict import (
    DepContext,
    aggregate_exit_code,
    augment_with_dataset_note,
    build_dependency_result,
    score_to_verdict,
)

# ---------------------------------------------------------------------------
# Constantes de ADR-01 (pesos exactos de la tabla de diseño)
# ---------------------------------------------------------------------------
_W_TYPOSQUAT_DL1 = 60
_W_TYPOSQUAT_DL2 = 40
_W_TYPOSQUAT_JW_STRONG = 30  # jw >= 0.95
_W_TYPOSQUAT_JW_WEAK = 25  # 0.92 <= jw < 0.95
_W_NAME_UNTRUSTED = 30
_W_NEW_PACKAGE = 15
_W_WEAK_METADATA = 7
_W_LOW_VERIFIABILITY = 5

_DEFAULT_CFG = Config()


# ---------------------------------------------------------------------------
# Helpers de construccion de señales
# ---------------------------------------------------------------------------

def _sig_typosquat(weight: int, target: str = "requests") -> LayerSignal:
    return LayerSignal(
        layer=Layer.L1,
        code=SignalCode.TYPOSQUAT,
        weight=weight,
        is_soft=False,
        detail=f"Typosquat de '{target}'.",
        suspected_target=target,
    )


def _sig_name_untrusted() -> LayerSignal:
    return LayerSignal(
        layer=Layer.L1,
        code=SignalCode.NAME_UNTRUSTED,
        weight=_W_NAME_UNTRUSTED,
        is_soft=False,
        detail="Nombre demasiado largo.",
        suspected_target=None,
    )


def _sig_new_package() -> LayerSignal:
    return LayerSignal(
        layer=Layer.L0,
        code=SignalCode.NEW_PACKAGE,
        weight=_W_NEW_PACKAGE,
        is_soft=True,
        detail="Publicado hace 4 dias.",
        suspected_target=None,
    )


def _sig_weak_metadata(weight: int = _W_WEAK_METADATA) -> LayerSignal:
    return LayerSignal(
        layer=Layer.L2,
        code=SignalCode.WEAK_METADATA,
        weight=weight,
        is_soft=True,
        detail="Faltan metadatos.",
        suspected_target=None,
    )


def _sig_low_verif(weight: int = _W_LOW_VERIFIABILITY) -> LayerSignal:
    return LayerSignal(
        layer=Layer.L2,
        code=SignalCode.LOW_VERIFIABILITY,
        weight=weight,
        is_soft=True,
        detail="Sin repositorio.",
        suspected_target=None,
    )


def _sig_nonexistent() -> LayerSignal:
    return LayerSignal(
        layer=Layer.L0,
        code=SignalCode.NONEXISTENT,
        weight=0,
        is_soft=False,
        detail="No existe en PyPI.",
        suspected_target=None,
    )


def _ctx(name: str = "pkg", *, is_unverifiable: bool = False) -> DepContext:
    cat = ErrorCategory.NETWORK_UNVERIFIABLE if is_unverifiable else None
    return DepContext(
        name=name,
        version_pin=None,
        is_unverifiable=is_unverifiable,
        error_category=cat,
    )


def _make_report(
    results: tuple[DependencyResult, ...],
    *,
    error_category: ErrorCategory | None = None,
) -> ScanReport:
    allow = sum(1 for r in results if r.verdict is Verdict.ALLOW)
    warn = sum(1 for r in results if r.verdict is Verdict.WARN)
    block = sum(1 for r in results if r.verdict is Verdict.BLOCK)
    unverifiable = sum(1 for r in results if r.status is Status.UNVERIFIABLE)
    return ScanReport(
        schema_version="1.0",
        tool_version="0.1.0",
        ecosystem="pypi",
        summary=ScanSummary(
            total=len(results),
            allow=allow,
            warn=warn,
            block=block,
            unverifiable=unverifiable,
            exit_code=0,
        ),
        results=results,
        error_category=error_category,
    )


# ===========================================================================
# PARTE A — TABLA EXHAUSTIVA
# ===========================================================================


class TestComputeScorePesosExactos:
    """Verifica los pesos exactos de ADR-01 en el scorer puro."""

    def test_sin_senales_score_cero(self) -> None:
        assert compute_score(()) == 0

    def test_typosquat_dl1_solo(self) -> None:
        assert compute_score((_sig_typosquat(_W_TYPOSQUAT_DL1),)) == 60

    def test_typosquat_dl2_solo(self) -> None:
        assert compute_score((_sig_typosquat(_W_TYPOSQUAT_DL2),)) == 40

    def test_typosquat_jw_strong_solo(self) -> None:
        assert compute_score((_sig_typosquat(_W_TYPOSQUAT_JW_STRONG),)) == 30

    def test_typosquat_jw_weak_solo(self) -> None:
        assert compute_score((_sig_typosquat(_W_TYPOSQUAT_JW_WEAK),)) == 25

    def test_name_untrusted_solo(self) -> None:
        assert compute_score((_sig_name_untrusted(),)) == 30

    def test_new_package_solo(self) -> None:
        """Blanda sola: nunca supera SOFT_CAP=25 ni llega a umbral_warn=50."""
        assert compute_score((_sig_new_package(),)) == 15

    def test_weak_metadata_solo(self) -> None:
        assert compute_score((_sig_weak_metadata(),)) == 7

    def test_low_verif_solo(self) -> None:
        assert compute_score((_sig_low_verif(),)) == 5

    def test_l2_maximo_0_5_7_10(self) -> None:
        """Aporte L2 pertenece al conjunto {0, 5, 7, 10} segun ADR-01."""
        assert compute_score(()) == 0
        assert compute_score((_sig_low_verif(),)) == 5
        assert compute_score((_sig_weak_metadata(),)) == 7
        # Ambas blandas L2: 7+5=12 > SOFT_CAP=25? No, 12 < 25 -> score=12.
        # Pero la capa 2 ya aplica el cap c2_max_contrib=10 antes de llegar aqui.
        # El scorer simplemente suma las blandas y acota a SOFT_CAP=25.
        # Si L2 ya emitio pesos ajustados (cap=10), la suma aqui es 10.
        assert compute_score((_sig_weak_metadata(5), _sig_low_verif(5))) == 10

    def test_blandas_maximo_sin_dura(self) -> None:
        """max(blandas) = NEW_PACKAGE(15) + L2(10) = 25 = SOFT_CAP."""
        signals = (
            _sig_new_package(),
            _sig_weak_metadata(5),
            _sig_low_verif(5),
        )
        assert compute_score(signals) == SOFT_CAP

    def test_dura_dl1_mas_blandas_maximas(self) -> None:
        """dl=1(60) + blandas_max(25) = 85; pero >= umbral_block=80 -> BLOCK."""
        signals = (
            _sig_typosquat(_W_TYPOSQUAT_DL1),
            _sig_new_package(),
            _sig_weak_metadata(5),
            _sig_low_verif(5),
        )
        assert compute_score(signals) == 85

    def test_dura_dl2_mas_blandas_maximas(self) -> None:
        """dl=2(40) + blandas_max(25) = 65; < umbral_block=80 -> WARN."""
        signals = (
            _sig_typosquat(_W_TYPOSQUAT_DL2),
            _sig_new_package(),
            _sig_weak_metadata(5),
            _sig_low_verif(5),
        )
        assert compute_score(signals) == 65

    def test_dura_jw_strong_mas_blandas(self) -> None:
        """jw_strong(30) + blandas_max(25) = 55."""
        signals = (
            _sig_typosquat(_W_TYPOSQUAT_JW_STRONG),
            _sig_new_package(),
            _sig_weak_metadata(5),
            _sig_low_verif(5),
        )
        assert compute_score(signals) == 55

    def test_dura_jw_weak_mas_blandas(self) -> None:
        """jw_weak(25) + blandas_max(25) = 50 -> exactamente umbral_warn -> WARN."""
        signals = (
            _sig_typosquat(_W_TYPOSQUAT_JW_WEAK),
            _sig_new_package(),
            _sig_weak_metadata(5),
            _sig_low_verif(5),
        )
        assert compute_score(signals) == 50

    def test_name_untrusted_mas_blandas(self) -> None:
        """NAME_UNTRUSTED(30) + blandas_max(25) = 55."""
        signals = (
            _sig_name_untrusted(),
            _sig_new_package(),
            _sig_weak_metadata(5),
            _sig_low_verif(5),
        )
        assert compute_score(signals) == 55

    def test_soft_cap_acota_en_25(self) -> None:
        """Tres blandas con suma > 25 se acotan a 25."""
        signals = (
            _sig_new_package(),       # 15
            _sig_weak_metadata(7),    # 7
            _sig_low_verif(5),        # 5  -> total=27 > 25 -> acotado a 25
        )
        assert compute_score(signals) == 25

    def test_score_maximo_100(self) -> None:
        """Score nunca supera 100."""
        signals = (
            _sig_typosquat(100),      # dura inflada artificialmente
            _sig_new_package(),
        )
        assert compute_score(signals) == 100

    def test_nonexistent_ignorado_en_scorer(self) -> None:
        """NONEXISTENT tiene peso=0 y no contribuye al score numerico."""
        signals = (_sig_nonexistent(),)
        assert compute_score(signals) == 0

    def test_nonexistent_mas_blandas_no_cambia_score(self) -> None:
        """NONEXISTENT no eleva el score numerico aunque lleguen blandas."""
        signals = (_sig_nonexistent(), _sig_new_package())
        assert compute_score(signals) == 15

    def test_dura_mayor_gana_defensa_en_profundidad(self) -> None:
        """Si llegan dos duras (defensa en profundidad), toma la mayor."""
        sig_a = _sig_typosquat(_W_TYPOSQUAT_DL1)   # 60
        sig_b = _sig_name_untrusted()               # 30
        assert compute_score((sig_a, sig_b)) == 60


# ---------------------------------------------------------------------------
# Tabla completa de (señales) -> (score, verdict) para todas las combos ADR-01
# ---------------------------------------------------------------------------

# (descripcion, tupla de señales, score_esperado, verdict_esperado)
_TABLA_SCORE_VERDICT: list[tuple[str, tuple[LayerSignal, ...], int, Verdict]] = [
    # --- Solo blandas (nunca warn/block con config por defecto) ---
    ("sin_senales", (), 0, Verdict.ALLOW),
    ("solo_new_package", (_sig_new_package(),), 15, Verdict.ALLOW),
    ("solo_weak_metadata", (_sig_weak_metadata(),), 7, Verdict.ALLOW),
    ("solo_low_verif", (_sig_low_verif(),), 5, Verdict.ALLOW),
    (
        "new_package_mas_weak_metadata",
        (_sig_new_package(), _sig_weak_metadata()),
        22,
        Verdict.ALLOW,
    ),
    (
        "new_package_mas_low_verif",
        (_sig_new_package(), _sig_low_verif()),
        20,
        Verdict.ALLOW,
    ),
    (
        "weak_metadata_mas_low_verif",
        (_sig_weak_metadata(), _sig_low_verif()),
        12,
        Verdict.ALLOW,
    ),
    (
        "blandas_maximo_25",
        (_sig_new_package(), _sig_weak_metadata(5), _sig_low_verif(5)),
        25,
        Verdict.ALLOW,
    ),
    # --- TYPOSQUAT dl=1 ---
    ("typosquat_dl1_solo", (_sig_typosquat(60),), 60, Verdict.WARN),
    (
        "typosquat_dl1_new_package",
        (_sig_typosquat(60), _sig_new_package()),
        75,
        Verdict.WARN,
    ),
    (
        "typosquat_dl1_blandas_max",
        (_sig_typosquat(60), _sig_new_package(), _sig_weak_metadata(5), _sig_low_verif(5)),
        85,
        Verdict.BLOCK,
    ),
    (
        "typosquat_dl1_weak_metadata_sin_new",
        (_sig_typosquat(60), _sig_weak_metadata()),
        67,
        Verdict.WARN,
    ),
    (
        "typosquat_dl1_low_verif_sin_new",
        (_sig_typosquat(60), _sig_low_verif()),
        65,
        Verdict.WARN,
    ),
    (
        "typosquat_dl1_new_weak",
        (_sig_typosquat(60), _sig_new_package(), _sig_weak_metadata()),
        82,
        Verdict.BLOCK,
    ),
    (
        "typosquat_dl1_new_low_verif",
        (_sig_typosquat(60), _sig_new_package(), _sig_low_verif()),
        80,
        Verdict.BLOCK,
    ),
    # --- TYPOSQUAT dl=2 ---
    ("typosquat_dl2_solo", (_sig_typosquat(40),), 40, Verdict.ALLOW),
    (
        "typosquat_dl2_new_package",
        (_sig_typosquat(40), _sig_new_package()),
        55,
        Verdict.WARN,
    ),
    (
        "typosquat_dl2_blandas_max",
        (_sig_typosquat(40), _sig_new_package(), _sig_weak_metadata(5), _sig_low_verif(5)),
        65,
        Verdict.WARN,
    ),
    # --- TYPOSQUAT jw_strong ---
    ("typosquat_jw_strong_solo", (_sig_typosquat(30),), 30, Verdict.ALLOW),
    (
        "typosquat_jw_strong_blandas_max",
        (_sig_typosquat(30), _sig_new_package(), _sig_weak_metadata(5), _sig_low_verif(5)),
        55,
        Verdict.WARN,
    ),
    # --- TYPOSQUAT jw_weak ---
    ("typosquat_jw_weak_solo", (_sig_typosquat(25),), 25, Verdict.ALLOW),
    (
        "typosquat_jw_weak_blandas_max",
        (_sig_typosquat(25), _sig_new_package(), _sig_weak_metadata(5), _sig_low_verif(5)),
        50,
        Verdict.WARN,
    ),
    # --- NAME_UNTRUSTED ---
    ("name_untrusted_solo", (_sig_name_untrusted(),), 30, Verdict.ALLOW),
    (
        "name_untrusted_blandas_max",
        (_sig_name_untrusted(), _sig_new_package(), _sig_weak_metadata(5), _sig_low_verif(5)),
        55,
        Verdict.WARN,
    ),
    # --- L2 con pesos cap ajustados (ambas señales -> aporte=10) ---
    (
        "typosquat_dl1_l2_ambas_cap",
        (_sig_typosquat(60), _sig_weak_metadata(5), _sig_low_verif(5)),
        70,
        Verdict.WARN,
    ),
]


@pytest.mark.parametrize(
    "descripcion,signals,score_esperado,verdict_esperado",
    [
        (d, s, sc, v)
        for d, s, sc, v in _TABLA_SCORE_VERDICT
    ],
    ids=[d for d, _, _, _ in _TABLA_SCORE_VERDICT],
)
def test_tabla_score_y_verdict(
    descripcion: str,
    signals: tuple[LayerSignal, ...],
    score_esperado: int,
    verdict_esperado: Verdict,
) -> None:
    """Tabla exhaustiva de (señales -> score, verdict) segun ADR-01."""
    score = compute_score(signals)
    verdict = score_to_verdict(score, _DEFAULT_CFG)
    assert score == score_esperado, (
        f"[{descripcion}] score={score}, esperado={score_esperado}"
    )
    assert verdict is verdict_esperado, (
        f"[{descripcion}] verdict={verdict}, esperado={verdict_esperado}"
    )


# ---------------------------------------------------------------------------
# Umbrales exactos: 49=allow, 50=warn, 79=warn, 80=block
# ---------------------------------------------------------------------------

class TestUmbralesExactos:
    """Verifica los umbrales exactos de score_to_verdict (R5.3-5.5)."""

    def test_score_49_es_allow(self) -> None:
        assert score_to_verdict(49, _DEFAULT_CFG) is Verdict.ALLOW

    def test_score_50_es_warn(self) -> None:
        assert score_to_verdict(50, _DEFAULT_CFG) is Verdict.WARN

    def test_score_79_es_warn(self) -> None:
        assert score_to_verdict(79, _DEFAULT_CFG) is Verdict.WARN

    def test_score_80_es_block(self) -> None:
        assert score_to_verdict(80, _DEFAULT_CFG) is Verdict.BLOCK

    def test_score_0_es_allow(self) -> None:
        assert score_to_verdict(0, _DEFAULT_CFG) is Verdict.ALLOW

    def test_score_100_es_block(self) -> None:
        assert score_to_verdict(100, _DEFAULT_CFG) is Verdict.BLOCK


# ---------------------------------------------------------------------------
# Override 404 (NONEXISTENT)
# ---------------------------------------------------------------------------

class TestOverride404:
    """R5.2 + ADR-01: inexistencia -> block, score=None, independiente del umbral."""

    def test_nonexistent_da_block_score_none(self) -> None:
        signals = (_sig_nonexistent(),)
        result = build_dependency_result(_ctx(), signals, _DEFAULT_CFG)
        assert result.verdict is Verdict.BLOCK
        assert result.score is None
        assert result.status is Status.OK

    def test_nonexistent_mas_blandas_sigue_siendo_block(self) -> None:
        """Las blandas adicionales no alteran el override."""
        signals = (_sig_nonexistent(), _sig_new_package(), _sig_weak_metadata())
        result = build_dependency_result(_ctx(), signals, _DEFAULT_CFG)
        assert result.verdict is Verdict.BLOCK
        assert result.score is None

    def test_nonexistent_con_umbral_block_alto_sigue_block(self) -> None:
        """El override es independiente del valor de umbral_block (R5.2)."""
        cfg = Config(umbral_warn=10, umbral_block=90)
        signals = (_sig_nonexistent(),)
        result = build_dependency_result(_ctx(), signals, cfg)
        assert result.verdict is Verdict.BLOCK
        assert result.score is None

    def test_nonexistent_prioridad_capa0_sobre_topn(self) -> None:
        """Si hay señal NONEXISTENT (Capa 0), el block override tiene precedencia (R3.8)."""
        signals = (_sig_nonexistent(), _sig_typosquat(_W_TYPOSQUAT_DL1))
        result = build_dependency_result(_ctx(), signals, _DEFAULT_CFG)
        assert result.verdict is Verdict.BLOCK
        assert result.score is None


# ---------------------------------------------------------------------------
# Unverifiable (R5.8)
# ---------------------------------------------------------------------------

class TestUnverifiable:
    """R5.8: unverifiable -> status=UNVERIFIABLE, verdict=None, score=None, nunca allow."""

    def test_unverifiable_sin_score_ni_verdict(self) -> None:
        result = build_dependency_result(_ctx(is_unverifiable=True), (), _DEFAULT_CFG)
        assert result.status is Status.UNVERIFIABLE
        assert result.verdict is None
        assert result.score is None

    def test_unverifiable_con_senales_no_cambia(self) -> None:
        signals = (_sig_typosquat(_W_TYPOSQUAT_DL1), _sig_new_package())
        result = build_dependency_result(_ctx(is_unverifiable=True), signals, _DEFAULT_CFG)
        assert result.status is Status.UNVERIFIABLE
        assert result.verdict is None
        assert result.score is None

    def test_unverifiable_nunca_allow(self) -> None:
        """Ante unverifiable, el resultado no puede ser allow (R5.8)."""
        result = build_dependency_result(_ctx(is_unverifiable=True), (), _DEFAULT_CFG)
        assert result.verdict is not Verdict.ALLOW


# ---------------------------------------------------------------------------
# aggregate_exit_code con y sin --strict para los 4 niveles
# ---------------------------------------------------------------------------

class TestAggregateExitCode:
    """R7.1-R7.6: precedencia block(2) > operacional(3) > warn(1) > allow(0)."""

    def _dep_allow(self) -> DependencyResult:
        return DependencyResult(
            name="ok-pkg", version_pin=None, status=Status.OK,
            verdict=Verdict.ALLOW, score=0, signals=(), suspected_target=None,
            error_category=None,
        )

    def _dep_warn(self) -> DependencyResult:
        return DependencyResult(
            name="warn-pkg", version_pin=None, status=Status.OK,
            verdict=Verdict.WARN, score=60, signals=(), suspected_target=None,
            error_category=None,
        )

    def _dep_block(self) -> DependencyResult:
        return DependencyResult(
            name="block-pkg", version_pin=None, status=Status.OK,
            verdict=Verdict.BLOCK, score=None, signals=(), suspected_target=None,
            error_category=None,
        )

    def _dep_unverifiable(self) -> DependencyResult:
        return DependencyResult(
            name="unverif-pkg", version_pin=None, status=Status.UNVERIFIABLE,
            verdict=None, score=None, signals=(), suspected_target=None,
            error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
        )

    def test_todo_allow_exit_0(self) -> None:
        report = _make_report((self._dep_allow(),))
        assert aggregate_exit_code(report, strict=False) == 0

    def test_warn_sin_strict_exit_1(self) -> None:
        report = _make_report((self._dep_allow(), self._dep_warn()))
        assert aggregate_exit_code(report, strict=False) == 1

    def test_warn_con_strict_exit_2(self) -> None:
        report = _make_report((self._dep_allow(), self._dep_warn()))
        assert aggregate_exit_code(report, strict=True) == 2

    def test_block_exit_2_sin_strict(self) -> None:
        report = _make_report((self._dep_allow(), self._dep_block()))
        assert aggregate_exit_code(report, strict=False) == 2

    def test_block_exit_2_con_strict(self) -> None:
        report = _make_report((self._dep_allow(), self._dep_block()))
        assert aggregate_exit_code(report, strict=True) == 2

    def test_unverifiable_exit_3_sin_block(self) -> None:
        report = _make_report((self._dep_allow(), self._dep_unverifiable()))
        assert aggregate_exit_code(report, strict=False) == 3

    def test_unverifiable_exit_3_con_strict(self) -> None:
        report = _make_report((self._dep_allow(), self._dep_unverifiable()))
        assert aggregate_exit_code(report, strict=True) == 3

    def test_precedencia_block_sobre_unverifiable(self) -> None:
        """block(2) domina sobre unverifiable(3) — R7.5."""
        report = _make_report((self._dep_block(), self._dep_unverifiable()))
        assert aggregate_exit_code(report, strict=False) == 2

    def test_precedencia_block_sobre_warn(self) -> None:
        """block(2) domina sobre warn(1)."""
        report = _make_report((self._dep_block(), self._dep_warn()))
        assert aggregate_exit_code(report, strict=False) == 2

    def test_error_operacional_total_exit_3(self) -> None:
        """Error operacional total -> exit 3 independientemente del contenido."""
        report = _make_report(
            (self._dep_block(),),
            error_category=ErrorCategory.MANIFEST_PARSE,
        )
        assert aggregate_exit_code(report, strict=False) == 3

    def test_error_dataset_exit_3(self) -> None:
        report = _make_report((), error_category=ErrorCategory.DATASET_INTEGRITY)
        assert aggregate_exit_code(report, strict=False) == 3

    def test_error_config_exit_3(self) -> None:
        report = _make_report((), error_category=ErrorCategory.INVALID_CONFIG)
        assert aggregate_exit_code(report, strict=False) == 3

    def test_reporte_vacio_exit_0(self) -> None:
        report = _make_report(())
        assert aggregate_exit_code(report, strict=False) == 0

    def test_warn_sin_block_con_strict_es_2(self) -> None:
        """R7.6: --strict eleva warn a exit 2."""
        report = _make_report((self._dep_warn(),))
        assert aggregate_exit_code(report, strict=True) == 2

    def test_warn_sin_block_sin_strict_es_1(self) -> None:
        report = _make_report((self._dep_warn(),))
        assert aggregate_exit_code(report, strict=False) == 1


# ---------------------------------------------------------------------------
# Prioridad Capa 0 sobre top-N (R3.8)
# ---------------------------------------------------------------------------

class TestPrioridadCapa0:
    """Cuando NONEXISTENT esta presente, prevalece sobre señales L1/L2."""

    def test_nonexistent_prevalece_sobre_typosquat(self) -> None:
        signals = (_sig_nonexistent(), _sig_typosquat(_W_TYPOSQUAT_DL1))
        result = build_dependency_result(_ctx("reqursts"), signals, _DEFAULT_CFG)
        assert result.verdict is Verdict.BLOCK
        assert result.score is None

    def test_nonexistent_prevalece_sobre_blandas(self) -> None:
        signals = (_sig_nonexistent(), _sig_new_package(), _sig_weak_metadata())
        result = build_dependency_result(_ctx("ghost"), signals, _DEFAULT_CFG)
        assert result.verdict is Verdict.BLOCK
        assert result.score is None

    def test_nonexistent_sin_senales_adicionales(self) -> None:
        signals = (_sig_nonexistent(),)
        result = build_dependency_result(_ctx("ghost"), signals, _DEFAULT_CFG)
        assert result.verdict is Verdict.BLOCK
        assert result.score is None


# ---------------------------------------------------------------------------
# suspected_target determinista (R5.7 en la extraccion de target)
# ---------------------------------------------------------------------------

class TestSuspectedTargetDeterminismo:
    """Verifica seleccion determinista de suspected_target."""

    def test_typosquat_propaga_target(self) -> None:
        signals = (_sig_typosquat(_W_TYPOSQUAT_DL1, target="requests"),)
        result = build_dependency_result(_ctx(), signals, _DEFAULT_CFG)
        assert result.suspected_target == "requests"

    def test_sin_typosquat_target_es_none(self) -> None:
        signals = (_sig_new_package(), _sig_weak_metadata())
        result = build_dependency_result(_ctx(), signals, _DEFAULT_CFG)
        assert result.suspected_target is None

    def test_dos_targets_distintos_seleccion_min(self) -> None:
        """Con dos señales con targets distintos, se elige el minimo lexico (R5.7)."""
        sig_a = LayerSignal(
            layer=Layer.L1, code=SignalCode.TYPOSQUAT, weight=60, is_soft=False,
            detail="A", suspected_target="requests",
        )
        sig_b = LayerSignal(
            layer=Layer.L1, code=SignalCode.TYPOSQUAT, weight=30, is_soft=False,
            detail="B", suspected_target="flask",
        )
        result_ab = build_dependency_result(_ctx(), (sig_a, sig_b), _DEFAULT_CFG)
        result_ba = build_dependency_result(_ctx(), (sig_b, sig_a), _DEFAULT_CFG)
        assert result_ab.suspected_target == result_ba.suspected_target == "flask"


# ===========================================================================
# PARTE B — PROPIEDADES
# ===========================================================================


class TestPropiedadAntiFP:
    """R5.6 — con la config por defecto (umbral_warn=50), las señales blandas
    solas NUNCA alcanzan umbral_warn.

    SOFT_CAP=25 < umbral_warn=50, por lo que max(blandas)=25 < 50.
    """

    # Todas las señales blandas posibles con sus pesos max (antes del cap de L2)
    _BLANDAS: ClassVar[list[tuple[str, LayerSignal]]] = [
        ("new_package", _sig_new_package()),
        ("weak_metadata_7", _sig_weak_metadata(7)),
        ("weak_metadata_5", _sig_weak_metadata(5)),
        ("low_verif_5", _sig_low_verif(5)),
    ]

    def test_soft_cap_menor_que_umbral_warn_defecto(self) -> None:
        """Invariante estructural: SOFT_CAP < umbral_warn (ADR-01)."""
        assert SOFT_CAP < _DEFAULT_CFG.umbral_warn

    def test_toda_combinacion_de_blandas_no_alcanza_warn(self) -> None:
        """Para cualquier combinacion de señales blandas, score < umbral_warn."""
        blandas = [sig for _, sig in self._BLANDAS]
        for size in range(1, len(blandas) + 1):
            for combo in itertools.combinations(blandas, size):
                score = compute_score(tuple(combo))
                assert score < _DEFAULT_CFG.umbral_warn, (
                    f"Combinacion de blandas produce score={score} "
                    f">= umbral_warn={_DEFAULT_CFG.umbral_warn}: {combo}"
                )

    def test_toda_combinacion_de_blandas_da_allow(self) -> None:
        """Para cualquier combinacion de blandas, el verdict es ALLOW."""
        blandas = [sig for _, sig in self._BLANDAS]
        for size in range(0, len(blandas) + 1):
            for combo in itertools.combinations(blandas, size):
                score = compute_score(tuple(combo))
                verdict = score_to_verdict(score, _DEFAULT_CFG)
                assert verdict is Verdict.ALLOW, (
                    f"Combinacion de blandas produce verdict={verdict}: {combo}"
                )

    def test_score_maximo_de_blandas_igual_a_soft_cap(self) -> None:
        """El score maximo alcanzable con blandas es exactamente SOFT_CAP=25."""
        sigs = (
            _sig_new_package(),        # 15
            _sig_weak_metadata(5),     # 5 (cap ajustado)
            _sig_low_verif(5),         # 5 (cap ajustado)
        )
        assert compute_score(sigs) == SOFT_CAP


class TestPropiedadDeterminismo:
    """R5.7 — el score y verdict son identicos bajo cualquier permutacion
    del orden de señales y del lote de dependencias.
    """

    def test_permutaciones_de_senales_mismo_score(self) -> None:
        """Para un conjunto fijo de señales, todas sus permutaciones dan el mismo score."""
        signals = [
            _sig_typosquat(_W_TYPOSQUAT_DL1),
            _sig_new_package(),
            _sig_weak_metadata(5),
            _sig_low_verif(5),
        ]
        expected = compute_score(tuple(signals))
        for perm in itertools.permutations(signals):
            assert compute_score(tuple(perm)) == expected

    def test_permutaciones_de_senales_mismo_verdict(self) -> None:
        """Todas las permutaciones de una tupla de señales dan el mismo verdict."""
        signals = [
            _sig_typosquat(_W_TYPOSQUAT_DL2),
            _sig_new_package(),
            _sig_weak_metadata(7),
        ]
        first_score = compute_score(tuple(signals))
        expected_verdict = score_to_verdict(first_score, _DEFAULT_CFG)
        for perm in itertools.permutations(signals):
            score = compute_score(tuple(perm))
            verdict = score_to_verdict(score, _DEFAULT_CFG)
            assert score == first_score
            assert verdict is expected_verdict

    def test_permutaciones_de_senales_blandas_mismo_score(self) -> None:
        """Permutaciones de señales blandas dan el mismo score."""
        signals = [_sig_new_package(), _sig_weak_metadata(5), _sig_low_verif(5)]
        expected = compute_score(tuple(signals))
        for perm in itertools.permutations(signals):
            assert compute_score(tuple(perm)) == expected

    def test_permutaciones_nonexistent_mismo_resultado(self) -> None:
        """Con NONEXISTENT, todas las permutaciones dan block, score=None."""
        signals = [
            _sig_nonexistent(),
            _sig_typosquat(_W_TYPOSQUAT_DL1),
            _sig_new_package(),
        ]
        for perm in itertools.permutations(signals):
            result = build_dependency_result(_ctx(), tuple(perm), _DEFAULT_CFG)
            assert result.verdict is Verdict.BLOCK
            assert result.score is None

    def test_permutaciones_de_lote_mismos_resultados(self) -> None:
        """Permutaciones del lote de dependencias producen los mismos resultados
        individuales (mismo score/verdict por paquete, R5.7).
        """
        dep_a = (_ctx("reqursts"), (_sig_typosquat(60), _sig_new_package()))
        dep_b = (_ctx("flask"), (_sig_typosquat(40),))
        dep_c = (_ctx("simple"), ())

        deps = [dep_a, dep_b, dep_c]
        resultados_ref = {
            ctx.name: build_dependency_result(ctx, sigs, _DEFAULT_CFG)
            for ctx, sigs in deps
        }

        for perm in itertools.permutations(deps):
            for ctx, sigs in perm:
                result = build_dependency_result(ctx, sigs, _DEFAULT_CFG)
                ref = resultados_ref[ctx.name]
                assert result.score == ref.score
                assert result.verdict is ref.verdict

    def test_permutaciones_con_unverifiable_mismo_resultado(self) -> None:
        """Permutaciones que incluyen unverifiable son deterministas."""
        signals = [_sig_new_package(), _sig_weak_metadata(7)]
        ctx_unv = _ctx(is_unverifiable=True)
        for perm in itertools.permutations(signals):
            result = build_dependency_result(ctx_unv, tuple(perm), _DEFAULT_CFG)
            assert result.status is Status.UNVERIFIABLE
            assert result.verdict is None
            assert result.score is None

    def test_mismo_score_con_multiples_senales_identicas(self) -> None:
        """Señales repetidas del mismo tipo dan siempre el mismo score."""
        sig = _sig_new_package()
        # La suma de blandas se acota a SOFT_CAP: duplicar una señal no cambia score
        # si la suma ya alcanza o supera SOFT_CAP.
        score_1 = compute_score((sig,))
        score_2a = compute_score((sig, sig))
        score_2b = compute_score((sig, sig))
        assert score_2a == score_2b
        assert score_1 == 15   # 15 < SOFT_CAP
        assert score_2a == 25  # min(30, 25) = 25 = SOFT_CAP


# ---------------------------------------------------------------------------
# build_dependency_result: cobertura de campos del DependencyResult
# ---------------------------------------------------------------------------

class TestBuildDependencyResult:
    """Verifica que build_dependency_result ensambla correctamente el resultado."""

    def test_resultado_normal_ok(self) -> None:
        signals = (_sig_typosquat(60),)
        result = build_dependency_result(_ctx("reqursts"), signals, _DEFAULT_CFG)
        assert result.name == "reqursts"
        assert result.status is Status.OK
        assert result.verdict is Verdict.WARN
        assert result.score == 60
        assert result.version_pin is None
        assert result.error_category is None

    def test_resultado_con_version_pin(self) -> None:
        ctx = DepContext(
            name="pkg", version_pin="1.2.3", is_unverifiable=False, error_category=None
        )
        result = build_dependency_result(ctx, (), _DEFAULT_CFG)
        assert result.version_pin == "1.2.3"

    def test_resultado_allow_sin_senales(self) -> None:
        result = build_dependency_result(_ctx("safe"), (), _DEFAULT_CFG)
        assert result.verdict is Verdict.ALLOW
        assert result.score == 0
        assert result.status is Status.OK

    def test_resultado_preserva_senales(self) -> None:
        sigs = (_sig_typosquat(60), _sig_new_package())
        result = build_dependency_result(_ctx(), sigs, _DEFAULT_CFG)
        assert result.signals == sigs


# ---------------------------------------------------------------------------
# augment_with_dataset_note (R3.8)
# ---------------------------------------------------------------------------

class TestAugmentWithDatasetNote:
    """R3.8: Capa 0 con NONEXISTENT en paquete que estaba en el top-N -> nota añadida."""

    def test_nonexistent_recibe_nota(self) -> None:
        sig = _sig_nonexistent()
        augmented = augment_with_dataset_note((sig,))
        assert len(augmented) == 1
        assert "desactualizado" in augmented[0].detail.lower()

    def test_otras_senales_no_modificadas(self) -> None:
        sig_new = _sig_new_package()
        augmented = augment_with_dataset_note((sig_new,))
        assert len(augmented) == 1
        assert augmented[0].detail == sig_new.detail

    def test_tupla_mixta_solo_nonexistent_modificado(self) -> None:
        sig_none = _sig_nonexistent()
        sig_new = _sig_new_package()
        augmented = augment_with_dataset_note((sig_none, sig_new))
        assert len(augmented) == 2
        assert "desactualizado" in augmented[0].detail.lower()
        assert augmented[1].detail == sig_new.detail

    def test_tupla_vacia(self) -> None:
        assert augment_with_dataset_note(()) == ()
