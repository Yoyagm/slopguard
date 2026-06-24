"""Suite H2-T11: scoring/veredicto de la Capa 3 threat-intel (RISK-H2-4).

Fuentes de verdad:
  - design.md §3.5  (orden de 5 ramas de `build_dependency_result` + tabla exhaustiva
    de coexistencias MALICIOUS/KNOWN_HALLUCINATION/NONEXISTENT/typosquat/
    THREATINTEL_UNVERIFIABLE con su status/verdict/score/exit).
  - design-parte2.md ADR-06 (MALICIOUS override de precedencia maxima),
    ADR-07 (KNOWN_HALLUCINATION peso 85, bloquea por score, calibrable),
    ADR-10 (degradacion segura + tabla de la triada degraded_status x --strict).

Dos estilos de prueba:
  (A) TABLA EXHAUSTIVA — replica fila-a-fila la tabla de §3.5 (status/verdict/score/
      exit no-strict) y la tabla de la triada de ADR-10 (degraded_status x --strict).
  (B) PROPIEDAD anti-FP — cualquier combinacion de SOLO senales blandas +
      THREATINTEL_UNVERIFIABLE nunca alcanza umbral_warn por score (invariante R3.3
      intacta del Hito 1; SOFT_CAP sin cambios).

Frontera (finding amarillo, observacion): `core.scoring.verdict`/`scorer` NO importan
`core.threatintel.*`. Se verifica estaticamente aqui para que CI lo detecte aunque el
contrato import-linter de esa frontera aun no este materializado en pyproject.toml.

Sin I/O, sin red, sin reloj. Funciones puras y deterministas.
"""

from __future__ import annotations

import importlib
import itertools
import sys
from typing import ClassVar

import pytest

from slopguard.core import models as core_models
from slopguard.core.config import Config
from slopguard.core.models import (
    Advisory,
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
    build_dependency_result,
    score_to_verdict,
)

# ---------------------------------------------------------------------------
# Pesos exactos (ADR-01 + ADR-07). Anclados a los defaults umbral_warn=50,
# umbral_block=80: KNOWN_HALLUCINATION(85) >= umbral_block; SOFT_CAP(25) < warn.
# ---------------------------------------------------------------------------
_W_TYPOSQUAT_DL1 = 60
_W_NEW_PACKAGE = 15
_W_WEAK_METADATA = 7
_W_LOW_VERIFIABILITY = 5
_W_KNOWN_HALLUCINATION = 85

_DEFAULT_CFG = Config()

_ADVISORY = Advisory(
    id="MAL-2025-47868",
    kind="malicious",
    url="https://osv.dev/vulnerability/MAL-2025-47868",
    source="osv",
)
_ADVISORY_2 = Advisory(
    id="MAL-2025-99999",
    kind="malicious",
    url="https://osv.dev/vulnerability/MAL-2025-99999",
    source="osv",
)


# ---------------------------------------------------------------------------
# Helpers de construccion de senales (auto-contenidos: el archivo es entregable
# independiente y no depende de test_scoring.py).
# ---------------------------------------------------------------------------


def _sig_malicious(advisories: tuple[Advisory, ...] = (_ADVISORY,)) -> LayerSignal:
    """Senal L3 MALICIOUS: dura, weight=0, porta los Advisory (ADR-06, override max)."""
    return LayerSignal(
        layer=Layer.L3,
        code=SignalCode.MALICIOUS,
        weight=0,
        is_soft=False,
        detail="Reportado como malicioso por OSV (MAL-2025-47868). No instalar.",
        suspected_target=None,
        advisories=advisories,
    )


def _sig_known_hallucination() -> LayerSignal:
    """Senal L3 KNOWN_HALLUCINATION: dura, weight=85 (>= umbral_block, ADR-07)."""
    return LayerSignal(
        layer=Layer.L3,
        code=SignalCode.KNOWN_HALLUCINATION,
        weight=_W_KNOWN_HALLUCINATION,
        is_soft=False,
        detail="Nombre alucinado conocido (corpus depscope-hallucinations, 2026-06-20).",
        suspected_target=None,
    )


def _sig_ti_unverifiable() -> LayerSignal:
    """Senal L3 THREATINTEL_UNVERIFIABLE: blanda, weight=0 (ADR-10, anti-FP)."""
    return LayerSignal(
        layer=Layer.L3,
        code=SignalCode.THREATINTEL_UNVERIFIABLE,
        weight=0,
        is_soft=True,
        detail="Threat-intel no verificable: timeout en OSV.",
        suspected_target=None,
    )


def _sig_typosquat(weight: int = _W_TYPOSQUAT_DL1, target: str = "requests") -> LayerSignal:
    return LayerSignal(
        layer=Layer.L1,
        code=SignalCode.TYPOSQUAT,
        weight=weight,
        is_soft=False,
        detail=f"Typosquat de '{target}'.",
        suspected_target=target,
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


def _ctx(name: str = "pkg", *, is_unverifiable: bool = False) -> DepContext:
    cat = ErrorCategory.NETWORK_UNVERIFIABLE if is_unverifiable else None
    return DepContext(
        name=name,
        version_pin=None,
        is_unverifiable=is_unverifiable,
        error_category=cat,
    )


def _cfg_degraded(status: str) -> Config:
    """Config con threatintel_degraded_status configurado (unverifiable|warn)."""
    return Config(threatintel_degraded_status=status)


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
        schema_version="1.1",
        tool_version="0.2.0",
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


def _exit_for(
    signals: tuple[LayerSignal, ...],
    *,
    degraded: str,
    strict: bool,
    is_unverifiable: bool = False,
) -> int:
    """Atajo: build_dependency_result -> reporte de 1 dep -> aggregate_exit_code."""
    result = build_dependency_result(
        _ctx("pkg", is_unverifiable=is_unverifiable), signals, _cfg_degraded(degraded)
    )
    return aggregate_exit_code(_make_report((result,)), strict=strict)


# ===========================================================================
# FRONTERA (finding amarillo): scoring/verdict NO importan core.threatintel.*
# ===========================================================================


class TestFronteraScoringThreatintel:
    """`core.scoring.verdict`/`scorer` consumen Advisory de `core.models`, NUNCA de
    `core.threatintel.*` (design §1.3). El contrato import-linter de esta frontera no
    esta materializado en pyproject.toml (observacion); este test estatico la blinda.
    """

    _MODULOS_THREATINTEL: ClassVar[set[str]] = {
        "slopguard.core.threatintel.source",
        "slopguard.core.threatintel.osv",
        "slopguard.core.threatintel.watchlist",
        "slopguard.core.threatintel.composite",
        "slopguard.core.threatintel.resolver",
        "slopguard.core.threatintel.registry",
    }

    @pytest.mark.parametrize(
        "modulo_scoring",
        ["slopguard.core.scoring.verdict", "slopguard.core.scoring.scorer"],
    )
    def test_scoring_no_importa_threatintel(self, modulo_scoring: str) -> None:
        """Ningun simbolo de threat-intel debe estar enlazado en el namespace del modulo."""
        mod = importlib.import_module(modulo_scoring)
        for ti_name in self._MODULOS_THREATINTEL:
            ti_mod = sys.modules.get(ti_name)
            if ti_mod is None:
                continue
            assert ti_mod not in vars(mod).values(), (
                f"{modulo_scoring} importa '{ti_name}' (cruza la frontera §1.3)"
            )

    def test_advisory_es_el_de_core_models(self) -> None:
        """El Advisory que viaja en advisories[] proviene de core.models (hoja)."""
        assert Advisory is core_models.Advisory


# ===========================================================================
# PARTE A — TABLA EXHAUSTIVA §3.5 (status / verdict / score / exit no-strict)
# ===========================================================================

# Cada fila = (caso, senales, degraded_status, status, verdict, score, exit_no_strict).
# Replica fila-a-fila la "Tabla exhaustiva de casos" de design.md §3.5. El exit
# verifica el flujo completo scoring -> veredicto -> aggregate_exit_code.
_TABLA_3_5: list[
    tuple[str, tuple[LayerSignal, ...], str, Status, Verdict | None, int | None, int]
] = [
    # MALICIOUS (override de precedencia maxima, ADR-06): block, score=None, exit 2.
    (
        "malicious_solo",
        (_sig_malicious(),),
        "unverifiable", Status.OK, Verdict.BLOCK, None, 2,
    ),
    # MALICIOUS + NONEXISTENT: malicia precede al 404; ambas reportadas.
    (
        "malicious_mas_nonexistent",
        (_sig_nonexistent(), _sig_malicious()),
        "unverifiable", Status.OK, Verdict.BLOCK, None, 2,
    ),
    # MALICIOUS + TYPOSQUAT: malicia precede al score; ambas reportadas.
    (
        "malicious_mas_typosquat",
        (_sig_typosquat(), _sig_malicious()),
        "unverifiable", Status.OK, Verdict.BLOCK, None, 2,
    ),
    # MALICIOUS + THREATINTEL_UNVERIFIABLE: la malicia domina, el caido NO degrada.
    (
        "malicious_mas_ti_unverif",
        (_sig_malicious(), _sig_ti_unverifiable()),
        "unverifiable", Status.OK, Verdict.BLOCK, None, 2,
    ),
    # MALICIOUS inmune incluso con degraded=warn: nunca degrada (fail-closed).
    (
        "malicious_mas_ti_unverif_degraded_warn",
        (_sig_malicious(), _sig_ti_unverifiable()),
        "warn", Status.OK, Verdict.BLOCK, None, 2,
    ),
    # NONEXISTENT (sin MALICIOUS): override 404, block, score=None.
    (
        "nonexistent_solo",
        (_sig_nonexistent(),),
        "unverifiable", Status.OK, Verdict.BLOCK, None, 2,
    ),
    # TYPOSQUAT dl=1 (score 60: >= warn, < block): warn, exit 1.
    (
        "typosquat_dl1_warn",
        (_sig_typosquat(),),
        "unverifiable", Status.OK, Verdict.WARN, 60, 1,
    ),
    # KNOWN_HALLUCINATION (85 >= 80): block POR SCORE (no override), score=85.
    (
        "known_hallucination_block_85",
        (_sig_known_hallucination(),),
        "unverifiable", Status.OK, Verdict.BLOCK, 85, 2,
    ),
    # KNOWN_HALLUCINATION + THREATINTEL_UNVERIFIABLE: el block domina, no degrada.
    (
        "known_hallucination_mas_ti_unverif",
        (_sig_known_hallucination(), _sig_ti_unverifiable()),
        "unverifiable", Status.OK, Verdict.BLOCK, 85, 2,
    ),
    # solo THREATINTEL_UNVERIFIABLE, degraded=unverifiable (default): unverifiable, exit 3.
    (
        "solo_ti_unverif_default",
        (_sig_ti_unverifiable(),),
        "unverifiable", Status.UNVERIFIABLE, None, None, 3,
    ),
    # solo THREATINTEL_UNVERIFIABLE, degraded=warn (valvula): warn score bajo, exit 1.
    (
        "solo_ti_unverif_warn",
        (_sig_ti_unverifiable(),),
        "warn", Status.OK, Verdict.WARN, 0, 1,
    ),
    # blandas + THREATINTEL_UNVERIFIABLE, degraded=unverifiable: unverifiable, exit 3.
    (
        "blandas_mas_ti_unverif_default",
        (_sig_new_package(), _sig_ti_unverifiable()),
        "unverifiable", Status.UNVERIFIABLE, None, None, 3,
    ),
    # blandas + THREATINTEL_UNVERIFIABLE, degraded=warn: warn (score bajo no eleva), exit 1.
    (
        "blandas_mas_ti_unverif_warn",
        (_sig_new_package(), _sig_ti_unverifiable()),
        "warn", Status.OK, Verdict.WARN, 15, 1,
    ),
    # blandas solas (sin L3): allow, score <= 25 (anti-FP), exit 0.
    (
        "blandas_solas_sin_l3",
        (_sig_new_package(), _sig_weak_metadata(5), _sig_low_verif(5)),
        "unverifiable", Status.OK, Verdict.ALLOW, 25, 0,
    ),
]


@pytest.mark.parametrize(
    "caso,signals,degraded,status_esp,verdict_esp,score_esp,exit_esp",
    _TABLA_3_5,
    ids=[fila[0] for fila in _TABLA_3_5],
)
def test_tabla_exhaustiva_3_5(
    caso: str,
    signals: tuple[LayerSignal, ...],
    degraded: str,
    status_esp: Status,
    verdict_esp: Verdict | None,
    score_esp: int | None,
    exit_esp: int,
) -> None:
    """Replica la tabla §3.5: cada coexistencia ⇒ status/verdict/score/exit esperados."""
    result = build_dependency_result(_ctx("pkg"), signals, _cfg_degraded(degraded))
    assert result.status is status_esp, f"[{caso}] status={result.status}"
    assert result.verdict is verdict_esp, f"[{caso}] verdict={result.verdict}"
    assert result.score == score_esp, f"[{caso}] score={result.score}"
    exit_code = aggregate_exit_code(_make_report((result,)), strict=False)
    assert exit_code == exit_esp, f"[{caso}] exit={exit_code}"


class TestCapa0UnverifiablePrecedeATodo:
    """Rama (1) de §3.5: ctx.is_unverifiable (SOLO de Capa 0) precede a CUALQUIER
    senal L3. Threat-intel NUNCA activa is_unverifiable (design §3.5, fail-closed).
    """

    def test_capa0_unverifiable_sin_senales(self) -> None:
        """PyPI caido (Capa 0) ⇒ unverifiable, verdict=None, score=None, exit 3."""
        result = build_dependency_result(
            _ctx("ghost", is_unverifiable=True), (), _DEFAULT_CFG
        )
        assert result.status is Status.UNVERIFIABLE
        assert result.verdict is None
        assert result.score is None

    def test_capa0_unverifiable_precede_a_malicious(self) -> None:
        """is_unverifiable(L0) precede incluso a MALICIOUS: sin advisories (no se llega
        a la rama de override). El engine no pone L3 sobre deps no-FOUND (R1.5), pero la
        precedencia de la rama (1) debe sostenerse aunque lleguen senales L3."""
        signals = (_sig_malicious(), _sig_ti_unverifiable())
        result = build_dependency_result(
            _ctx("ghost", is_unverifiable=True), signals, _DEFAULT_CFG
        )
        assert result.status is Status.UNVERIFIABLE
        assert result.verdict is None
        assert result.advisories == ()

    def test_capa0_unverifiable_no_lo_activa_l3(self) -> None:
        """THREATINTEL_UNVERIFIABLE NO produce ctx.is_unverifiable (es rama 5, no rama 1):
        sin block dominante degrada por config, no por la rama de Capa 0."""
        result = build_dependency_result(
            _ctx("flaky", is_unverifiable=False),
            (_sig_ti_unverifiable(),),
            _cfg_degraded("warn"),
        )
        # Rama 5 (warn), NO rama 1: el status viene de la valvula, no de Capa 0.
        assert result.status is Status.OK
        assert result.verdict is Verdict.WARN


class TestMaliciousOverride:
    """ADR-06: MALICIOUS = override de block de precedencia MAXIMA, inmune a config."""

    def test_malicious_excluido_del_scorer(self) -> None:
        """MALICIOUS (weight=0) no contribuye al score (simetria con NONEXISTENT)."""
        assert compute_score((_sig_malicious(),)) == 0
        assert compute_score((_sig_malicious(), _sig_new_package())) == _W_NEW_PACKAGE

    def test_malicious_inmune_a_umbral_block_alto(self) -> None:
        """A diferencia de KNOWN_HALLUCINATION, el override es inmune a umbral_block."""
        cfg = Config(umbral_warn=10, umbral_block=99)
        result = build_dependency_result(_ctx("bioql"), (_sig_malicious(),), cfg)
        assert result.verdict is Verdict.BLOCK
        assert result.score is None

    def test_malicious_pobla_advisories(self) -> None:
        """build_dependency_result traslada los Advisory de la senal a DependencyResult."""
        result = build_dependency_result(_ctx("bioql"), (_sig_malicious(),), _DEFAULT_CFG)
        assert result.advisories == (_ADVISORY,)

    def test_malicious_multiples_advisories_en_orden(self) -> None:
        """Varios Advisory se concatenan en orden de aparicion (determinista)."""
        signals = (_sig_malicious((_ADVISORY, _ADVISORY_2)),)
        result = build_dependency_result(_ctx("bioql"), signals, _DEFAULT_CFG)
        assert result.advisories == (_ADVISORY, _ADVISORY_2)

    def test_malicious_reporta_todas_las_senales_coexistentes(self) -> None:
        """R3.4: con MALICIOUS+NONEXISTENT+typosquat, las 3 senales quedan en signals[]."""
        signals = (_sig_nonexistent(), _sig_typosquat(), _sig_malicious())
        result = build_dependency_result(_ctx("bioql"), signals, _DEFAULT_CFG)
        assert {s.code for s in result.signals} == {
            SignalCode.NONEXISTENT,
            SignalCode.TYPOSQUAT,
            SignalCode.MALICIOUS,
        }
        assert result.verdict is Verdict.BLOCK
        assert result.advisories == (_ADVISORY,)


class TestKnownHallucinationPorScore:
    """ADR-07: KNOWN_HALLUCINATION bloquea por SCORE (peso 85), NO por override.
    Participa en _max_hard_weight y respeta config (calibrable).
    """

    def test_known_hallucination_score_85(self) -> None:
        assert compute_score((_sig_known_hallucination(),)) == 85

    def test_known_hallucination_block_por_score_no_none(self) -> None:
        """A diferencia de MALICIOUS, el score NO es None: bloquea por umbral."""
        result = build_dependency_result(
            _ctx("reqe"), (_sig_known_hallucination(),), _DEFAULT_CFG
        )
        assert result.verdict is Verdict.BLOCK
        assert result.score == 85
        assert result.advisories == ()

    def test_known_hallucination_calibrable_a_warn(self) -> None:
        """umbral_block=90 degrada KNOWN_HALLUCINATION(85) a warn (ADR-07, calibrable)."""
        cfg = Config(umbral_warn=50, umbral_block=90)
        result = build_dependency_result(
            _ctx("reqe"), (_sig_known_hallucination(),), cfg
        )
        assert result.verdict is Verdict.WARN
        assert result.score == 85

    def test_known_hallucination_participa_en_max_hard_weight(self) -> None:
        """Con typosquat(60) coexistente, el scorer toma el maximo (85 > 60)."""
        assert compute_score((_sig_known_hallucination(), _sig_typosquat())) == 85

    def test_known_hallucination_satura_con_blandas_a_100(self) -> None:
        """85 + blandas_max(25) ⇒ min(100, 110) = 100; sigue block."""
        signals = (
            _sig_known_hallucination(),
            _sig_new_package(),
            _sig_weak_metadata(5),
            _sig_low_verif(5),
        )
        assert compute_score(signals) == 100

    def test_known_hallucination_mas_nonexistent_override_gana(self) -> None:
        """NONEXISTENT (rama 3) intercepta antes del score: block con score=None."""
        signals = (_sig_known_hallucination(), _sig_nonexistent())
        result = build_dependency_result(_ctx("reqe"), signals, _DEFAULT_CFG)
        assert result.verdict is Verdict.BLOCK
        assert result.score is None  # override 404 fija score=None, no 85.


# ===========================================================================
# PARTE A (cont.) — TABLA DE LA TRIADA ADR-10 (degraded_status x --strict)
# ===========================================================================

# (degraded_status, strict, exit_esperado) — replica la tabla de la triada de ADR-10.
# Caso fail-closed clave: unverifiable+strict NO sube a exit 2 (strict no toca
# unverifiable); el modo tolerante a OSV-flaky bajo strict es unverifiable+exit 3.
_TABLA_TRIADA: list[tuple[str, bool, int]] = [
    ("unverifiable", False, 3),
    ("unverifiable", True, 3),
    ("warn", False, 1),
    ("warn", True, 2),
]


@pytest.mark.parametrize(
    "degraded,strict,exit_esp",
    _TABLA_TRIADA,
    ids=[f"{d}-strict_{s}" for d, s, _ in _TABLA_TRIADA],
)
def test_triada_adr10_degraded_por_strict(degraded: str, strict: bool, exit_esp: int) -> None:
    """Triada ADR-10: dep limpia + OSV caido x degraded_status x --strict ⇒ exit."""
    exit_code = _exit_for((_sig_ti_unverifiable(),), degraded=degraded, strict=strict)
    assert exit_code == exit_esp, (
        f"[degraded={degraded}, strict={strict}] exit={exit_code}, esperado={exit_esp}"
    )


class TestTriadaDetalle:
    """Detalle de las 4 esquinas de la triada y su semantica fail-closed."""

    def test_unverifiable_default_nunca_eleva_a_2_bajo_strict(self) -> None:
        """unverifiable+strict sigue exit 3: strict solo toca warn, no unverifiable."""
        sin_strict = _exit_for((_sig_ti_unverifiable(),), degraded="unverifiable", strict=False)
        con_strict = _exit_for((_sig_ti_unverifiable(),), degraded="unverifiable", strict=True)
        assert sin_strict == con_strict == 3

    def test_warn_valvula_sube_a_2_bajo_strict(self) -> None:
        """warn+strict sube a exit 2 (coherente con la semantica uniforme de --strict)."""
        sin_strict = _exit_for((_sig_ti_unverifiable(),), degraded="warn", strict=False)
        con_strict = _exit_for((_sig_ti_unverifiable(),), degraded="warn", strict=True)
        assert sin_strict == 1
        assert con_strict == 2

    def test_ti_unverif_jamas_allow_en_ningun_modo(self) -> None:
        """Fail-closed (NFR-Degr.1): con OSV caido el resultado NUNCA es allow."""
        for degraded in ("unverifiable", "warn"):
            result = build_dependency_result(
                _ctx("flaky"), (_sig_ti_unverifiable(),), _cfg_degraded(degraded)
            )
            assert result.verdict is not Verdict.ALLOW
            exit_code = _exit_for((_sig_ti_unverifiable(),), degraded=degraded, strict=False)
            assert exit_code != 0


class TestWarnDominanteNoDegrada:
    """ADR-10: un block/warn determinista DOMINA sobre el threat-intel caido."""

    def test_warn_por_typosquat_domina_sobre_ti_unverif(self) -> None:
        """typosquat dl=1 (warn) + THREATINTEL_UNVERIFIABLE ⇒ warn, no unverifiable."""
        signals = (_sig_typosquat(), _sig_ti_unverifiable())
        result = build_dependency_result(_ctx("reqursts"), signals, _DEFAULT_CFG)
        assert result.status is Status.OK
        assert result.verdict is Verdict.WARN
        assert result.score == 60

    def test_block_por_known_hallucination_domina_sobre_ti_unverif(self) -> None:
        """KNOWN_HALLUCINATION (block por score) + THREATINTEL_UNVERIFIABLE ⇒ block."""
        signals = (_sig_known_hallucination(), _sig_ti_unverifiable())
        result = build_dependency_result(_ctx("reqe"), signals, _cfg_degraded("warn"))
        assert result.status is Status.OK
        assert result.verdict is Verdict.BLOCK
        assert result.score == 85


# ===========================================================================
# PARTE B — PROPIEDAD anti-FP (R3.3 / R5.6): SOLO blandas + THREATINTEL_UNVERIFIABLE
# nunca alcanzan umbral_warn por score (invariante intacta del Hito 1).
# ===========================================================================


class TestPropiedadAntiFP:
    """Cualquier combinacion de senales BLANDAS + THREATINTEL_UNVERIFIABLE (weight=0)
    queda <= SOFT_CAP < umbral_warn. SOFT_CAP no se toca (R5.6).
    """

    # Universo de senales blandas + la blanda L3 THREATINTEL_UNVERIFIABLE.
    _BLANDAS_Y_TI: ClassVar[list[LayerSignal]] = [
        _sig_new_package(),         # 15
        _sig_weak_metadata(7),      # 7
        _sig_weak_metadata(5),      # 5 (cap L2 ajustado)
        _sig_low_verif(5),          # 5
        _sig_ti_unverifiable(),     # 0 (L3 blanda, no contribuye)
    ]

    def test_soft_cap_estrictamente_menor_que_umbral_warn(self) -> None:
        """Invariante estructural anti-FP: SOFT_CAP < umbral_warn (default 50)."""
        assert SOFT_CAP < _DEFAULT_CFG.umbral_warn

    def test_toda_combinacion_blandas_y_ti_no_alcanza_warn(self) -> None:
        """PROPIEDAD: para CUALQUIER subconjunto no vacio de blandas+THREATINTEL_UNVERIFIABLE,
        score <= SOFT_CAP y score < umbral_warn (nunca cruza a warn por score).
        """
        universo = self._BLANDAS_Y_TI
        for size in range(1, len(universo) + 1):
            for combo in itertools.combinations(universo, size):
                score = compute_score(tuple(combo))
                assert score <= SOFT_CAP, (
                    f"Combinacion supera SOFT_CAP={SOFT_CAP}: score={score}, {combo}"
                )
                assert score < _DEFAULT_CFG.umbral_warn, (
                    f"Combinacion alcanza umbral_warn: score={score}, {combo}"
                )

    def test_toda_combinacion_blandas_y_ti_da_allow_o_degrada(self) -> None:
        """Por score, toda combinacion blanda da ALLOW; si incluye THREATINTEL_UNVERIFIABLE
        con degraded=unverifiable, el STATUS pasa a unverifiable (no allow), pero NUNCA por
        score: el verdict-por-umbral sigue siendo ALLOW (invariante anti-FP intacta).
        """
        universo = self._BLANDAS_Y_TI
        for size in range(1, len(universo) + 1):
            for combo in itertools.combinations(universo, size):
                score = compute_score(tuple(combo))
                assert score_to_verdict(score, _DEFAULT_CFG) is Verdict.ALLOW, (
                    f"Por score deberia ser ALLOW: score={score}, {combo}"
                )

    def test_ti_unverif_solo_score_cero(self) -> None:
        """THREATINTEL_UNVERIFIABLE sola: score 0 (no contribuye)."""
        assert compute_score((_sig_ti_unverifiable(),)) == 0

    def test_max_blandas_con_ti_igual_soft_cap(self) -> None:
        """El maximo alcanzable con blandas+THREATINTEL_UNVERIFIABLE es exactamente SOFT_CAP."""
        signals = (
            _sig_new_package(),     # 15
            _sig_weak_metadata(5),  # 5
            _sig_low_verif(5),      # 5
            _sig_ti_unverifiable(), # 0
        )
        assert compute_score(signals) == SOFT_CAP

    def test_anti_fp_se_mantiene_aunque_degraded_warn(self) -> None:
        """Con degraded=warn, la dep limpia sube a warn por DEGRADACION (status/valvula),
        NO porque el score cruce el umbral: el score permanece <= SOFT_CAP.
        """
        signals = (_sig_new_package(), _sig_weak_metadata(5), _sig_ti_unverifiable())
        score = compute_score(signals)
        assert score <= SOFT_CAP
        result = build_dependency_result(_ctx("flaky"), signals, _cfg_degraded("warn"))
        assert result.verdict is Verdict.WARN  # por valvula, no por score
        assert result.score == score  # el score se preserva, no se infla


# ===========================================================================
# PARTE B (cont.) — DETERMINISMO bajo permutacion (R5.7) en presencia de L3
# ===========================================================================


class TestDeterminismoL3:
    """R5.7/NFR-Det.1: el orden de las senales L3 no altera el veredicto."""

    def test_permutaciones_malicious_nonexistent_blandas(self) -> None:
        """MALICIOUS+NONEXISTENT+blanda: cualquier permutacion ⇒ block, score=None, mismos adv."""
        signals = [_sig_malicious(), _sig_nonexistent(), _sig_new_package()]
        for perm in itertools.permutations(signals):
            result = build_dependency_result(_ctx("bioql"), tuple(perm), _DEFAULT_CFG)
            assert result.verdict is Verdict.BLOCK
            assert result.score is None
            assert result.advisories == (_ADVISORY,)

    def test_permutaciones_known_hallucination_ti_unverif(self) -> None:
        """KNOWN_HALLUCINATION+THREATINTEL_UNVERIFIABLE: permutar ⇒ block por score 85."""
        signals = [_sig_known_hallucination(), _sig_ti_unverifiable()]
        for perm in itertools.permutations(signals):
            result = build_dependency_result(_ctx("reqe"), tuple(perm), _DEFAULT_CFG)
            assert result.verdict is Verdict.BLOCK
            assert result.score == 85

    def test_permutaciones_blandas_ti_unverif_degraded(self) -> None:
        """blandas+THREATINTEL_UNVERIFIABLE con degraded=unverifiable: permutar ⇒ unverifiable."""
        signals = [_sig_new_package(), _sig_weak_metadata(5), _sig_ti_unverifiable()]
        for perm in itertools.permutations(signals):
            result = build_dependency_result(
                _ctx("flaky"), tuple(perm), _cfg_degraded("unverifiable")
            )
            assert result.status is Status.UNVERIFIABLE
            assert result.verdict is None
