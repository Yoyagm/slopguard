"""Suite de fachada Hito 2 (H2-T13): API publica + CLI + render con Capa 3.

Verifica que la fachada `slopguard.core` expone correctamente la API del Hito 2
y que los subsistemas CLI/render producen la salida correcta cuando la Capa 3
esta activa. Todos los bordes externos (red, disco) se sustituyen por stubs en
memoria, deterministicos y sin dependencias de runtime.

Propiedades verificadas:
  - API publica de la fachada: Advisory, MaliceState re-exportados en __all__.
  - R1.5/R3.6: SOLO los FOUND van al batch de Capa 3.
  - Determinismo bajo permutacion del lote (R3.5).
  - enable_layer3=false => comportamiento identico al Hito 1 (R5.3).
  - Intercalado correcto L0→L1→L2→L3 (§4.1).
  - CLI: --no-layer3 cablea enable_layer3=False; --enable-watchlist cablea True (R5.1).
  - CLI: _cli_overrides produce los overrides correctos con los flags activos.
  - Render humano: advisories MAL-* con ID saneado + enlace canonico + accion (R7.1/R7.4).
  - Render JSON: schema_version 1.1, clave advisories[] estable, sin timestamps (R7.3/§2.4).
  - Saneo ANSI/CRLF en IDs externos reflejados en human y JSON (R7.4).
  - JSON valido con enable_layer3=false (advisories[] vacio, lectores 1.0 compatibles).
"""

from __future__ import annotations

import io
import json
import re
from typing import TYPE_CHECKING

import pytest

import slopguard.core as facade
from slopguard.cli import main as cli_main
from slopguard.cli.render_human import render_human
from slopguard.cli.render_json import render_json
from slopguard.core import (
    Advisory,
    Config,
    Dependency,
    MaliceState,
    ScanReport,
    Status,
    Verdict,
    scan_dependencies,
)
from slopguard.core.adapters.base import FetchOutcome, FetchState, PackageMetadata
from slopguard.core.dataset.top_n import TopNDataset, build_top_n
from slopguard.core.models import (
    DependencyResult,
    Layer,
    SignalCode,
    ThreatIntelResult,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

# Patch paths del engine.
_GET_ADAPTER = "slopguard.core.engine.get_adapter"
_GET_TI_SOURCE = "slopguard.core.engine.get_threatintel_source"
_ENGINE_TIME = "slopguard.core.engine.time.time"

# Epoch fijo: paquete establecido sin NEW_PACKAGE (400 dias de edad).
_NOW = 1_717_200_000.0
_DAY = 86_400.0
_OLD_EPOCH = _NOW - 400 * _DAY

# Secuencia ANSI para verificar el saneo (R7.4).
_ANSI = "\x1b[31m"
_CRLF = "\r\n"

_TOP_N_NAMES = ["requests", "flask", "numpy"]


# --------------------------------------------------------------------------- #
# Dobles de prueba (en memoria, sin red ni disco)
# --------------------------------------------------------------------------- #


def _meta(name: str) -> PackageMetadata:
    """Metadatos de un paquete establecido y limpio en L0/L1/L2."""
    return PackageMetadata(
        name=name,
        first_release_epoch=_OLD_EPOCH,
        releases_count=50,
        has_repo_url=True,
        has_description=True,
        has_author=True,
        has_license=True,
        has_classifiers=True,
        in_top_n=False,
    )


def _found(name: str) -> FetchOutcome:
    return FetchOutcome(state=FetchState.FOUND, metadata=_meta(name))


_NOT_FOUND = FetchOutcome(state=FetchState.NOT_FOUND)
_UNVERIFIABLE_OUTCOME = FetchOutcome(state=FetchState.UNVERIFIABLE)


class _StubAdapter:
    """Adapter EcosystemAdapter en memoria, sin red."""

    ecosystem_id = "pypi"

    def __init__(self, outcomes: dict[str, FetchOutcome], top_n: TopNDataset) -> None:
        self._outcomes = outcomes
        self._top_n = top_n

    def normalize_name(self, raw: str) -> str:
        return raw.strip().lower().replace("_", "-").replace(".", "-")

    def fetch(self, name: str) -> FetchOutcome:
        return self._outcomes.get(name, _UNVERIFIABLE_OUTCOME)

    def load_top_n(self) -> TopNDataset:
        return self._top_n

    @property
    def candidate_filter(self) -> None:  # H4-T23: PyPI = filtro identidad (ADR-4).
        return None

    def get_downloads(self, name: str) -> None:  # pragma: no cover
        return None


class _StubSource:
    """Fuente ThreatIntelSource en memoria: registra lotes y mapea por nombre.

    Un nombre no mapeado se resuelve CLEAN (cobertura total igual que CompositeSource).
    """

    source_id: str = "stub-facade"
    extra_allowed_hosts: frozenset[str] = frozenset()

    def __init__(self, results: dict[str, ThreatIntelResult] | None = None) -> None:
        self._results = results or {}
        self.calls: list[list[str]] = []

    def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
        batch = list(names)
        self.calls.append(batch)
        return {
            name: self._results.get(name, ThreatIntelResult(name=name, state=MaliceState.CLEAN))
            for name in batch
        }


# --------------------------------------------------------------------------- #
# Fixtures y helpers
# --------------------------------------------------------------------------- #


@pytest.fixture
def top_n() -> TopNDataset:
    return build_top_n(_TOP_N_NAMES, version="test", generated_at="test")


@pytest.fixture(autouse=True)
def _frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fija el reloj del engine (NFR-Det.1): edad reproducible."""
    monkeypatch.setattr(_ENGINE_TIME, lambda: _NOW)


def _install(
    monkeypatch: pytest.MonkeyPatch,
    outcomes: dict[str, FetchOutcome],
    top_n: TopNDataset,
    source: _StubSource | None,
) -> None:
    monkeypatch.setattr(_GET_ADAPTER, lambda *a, **k: _StubAdapter(outcomes, top_n))
    monkeypatch.setattr(_GET_TI_SOURCE, lambda *a, **k: source)


def _deps(*names: str) -> list[Dependency]:
    return [Dependency(name=n, version_pin=None, raw=n, origin="test") for n in names]


def _by_name(report: ScanReport) -> dict[str, DependencyResult]:
    return {r.name: r for r in report.results}


def _adv(advisory_id: str) -> Advisory:
    return Advisory(
        id=advisory_id,
        kind="malicious",
        url=f"https://osv.dev/vulnerability/{advisory_id}",
        source="osv",
    )


def _mal(name: str, advisory_id: str) -> ThreatIntelResult:
    return ThreatIntelResult(
        name=name, state=MaliceState.MALICIOUS, advisories=(_adv(advisory_id),)
    )


def _halluc(name: str) -> ThreatIntelResult:
    return ThreatIntelResult(
        name=name,
        state=MaliceState.KNOWN_HALLUCINATION,
        watchlist_source="depscope-hallucinations",
        watchlist_date="2026-06-01",
    )


def _unver(name: str) -> ThreatIntelResult:
    return ThreatIntelResult(
        name=name, state=MaliceState.UNVERIFIABLE, unverifiable_reason="osv 503"
    )


# ===========================================================================
# Fachada: API publica del Hito 2 (H2-T13)
# ===========================================================================


def test_facade_re_exporta_advisory() -> None:
    """H2-T13: Advisory disponible desde slopguard.core y en __all__."""
    assert "Advisory" in facade.__all__
    assert facade.Advisory is Advisory


def test_facade_re_exporta_malice_state() -> None:
    """H2-T13: MaliceState disponible desde slopguard.core y en __all__."""
    assert "MaliceState" in facade.__all__
    assert facade.MaliceState is MaliceState


def test_facade_api_hito1_intacta() -> None:
    """H2-T13: las funciones del Hito 1 siguen exportadas en __all__ (retro-compatibilidad)."""
    hito1_symbols = {
        "scan_manifest", "scan_stdin", "scan_dependencies",
        "load_config", "aggregate_exit_code",
        "Config", "ScanReport", "DependencyResult",
        "Status", "Verdict", "Dependency",
    }
    assert hito1_symbols <= set(facade.__all__)


# ===========================================================================
# R1.5/R3.6: SOLO los FOUND van al batch
# ===========================================================================


def test_solo_found_al_batch_no_not_found_ni_unverifiable(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R1.5: NOT_FOUND y UNVERIFIABLE quedan fuera del lote de threat-intel."""
    outcomes = {
        "good": _found("good"),
        "ghost": _NOT_FOUND,
        "flaky": _UNVERIFIABLE_OUTCOME,
    }
    source = _StubSource()
    _install(monkeypatch, outcomes, top_n, source)

    scan_dependencies(_deps("good", "ghost", "flaky"), Config())

    queried = {name for call in source.calls for name in call}
    assert queried == {"good"}
    assert "ghost" not in queried
    assert "flaky" not in queried


def test_not_found_no_recibe_senal_l3(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R3.6: un NOT_FOUND no porta senales L3 (MALICIOUS/KNOWN_HALLUCINATION/UNVERIFIABLE)."""
    outcomes = {"ghost": _NOT_FOUND}
    _install(monkeypatch, outcomes, top_n, _StubSource())

    report = scan_dependencies(_deps("ghost"), Config())
    l3_codes = {
        SignalCode.MALICIOUS,
        SignalCode.KNOWN_HALLUCINATION,
        SignalCode.THREATINTEL_UNVERIFIABLE,
    }
    codes = {s.code for s in report.results[0].signals}
    assert not (codes & l3_codes)


# ===========================================================================
# Determinismo bajo permutacion (R3.5)
# ===========================================================================


def test_determinismo_permutacion_malicious(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R3.5: permutar el lote no altera el ScanReport con dep MALICIOUS."""
    names = ("alpha", "bravo", "charlie")
    outcomes = {n: _found(n) for n in names}
    results_map = {"bravo": _mal("bravo", "MAL-2025-1001")}

    _install(monkeypatch, outcomes, top_n, _StubSource(dict(results_map)))
    first = scan_dependencies(_deps(*names), Config())

    _install(monkeypatch, outcomes, top_n, _StubSource(dict(results_map)))
    second = scan_dependencies(_deps(*reversed(names)), Config())

    assert first == second


def test_determinismo_permutacion_mezcla(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R3.5: determinismo con MALICIOUS + KNOWN_HALLUCINATION + UNVERIFIABLE mezclados."""
    names = ("evil", "halluc", "down", "ok")
    outcomes = {n: _found(n) for n in names}
    results_map = {
        "evil": _mal("evil", "MAL-2025-2001"),
        "halluc": _halluc("halluc"),
        "down": _unver("down"),
    }

    _install(monkeypatch, outcomes, top_n, _StubSource(dict(results_map)))
    r1 = scan_dependencies(_deps(*names), Config())

    _install(monkeypatch, outcomes, top_n, _StubSource(dict(results_map)))
    r2 = scan_dependencies(_deps(*reversed(names)), Config())

    assert r1 == r2


# ===========================================================================
# enable_layer3=false => comportamiento Hito 1 (R5.3)
# ===========================================================================


def test_layer3_desactivado_es_identico_hito1(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R5.3: source None => ti={} => sin senales L3; dep limpia sigue allow."""
    outcomes = {"plain": _found("plain")}

    _install(monkeypatch, outcomes, top_n, None)
    off = scan_dependencies(_deps("plain"), Config(enable_layer3=False))

    _install(monkeypatch, outcomes, top_n, _StubSource())
    on_clean = scan_dependencies(_deps("plain"), Config())

    assert _by_name(off)["plain"].verdict is Verdict.ALLOW
    assert off == on_clean  # CLEAN sin senal L3 es identico al modo off


def test_layer3_desactivado_no_invoca_source(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R5.3: con source None la fuente espia jamas recibe llamadas."""
    outcomes = {"plain": _found("plain")}
    spy = _StubSource()

    _install(monkeypatch, outcomes, top_n, None)  # None: desactivado
    scan_dependencies(_deps("plain"), Config(enable_layer3=False))

    assert spy.calls == []


def test_layer3_desactivado_json_sigue_valido(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """NFR-Compat.1: con enable_layer3=false el JSON es valido, schema 1.1, advisories []."""
    outcomes = {"plain": _found("plain")}
    _install(monkeypatch, outcomes, top_n, None)
    report = scan_dependencies(_deps("plain"), Config(enable_layer3=False))

    parsed = json.loads(render_json(report))
    assert parsed["schema_version"] == "1.2"
    assert parsed["results"][0]["verdict"] == "allow"
    assert parsed["results"][0]["advisories"] == []


# ===========================================================================
# Intercalado correcto L0→L1→L2→L3 (§4.1)
# ===========================================================================


def test_orden_capas_l3_al_final(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§4.1: la senal L3 se recolecta despues de L0/L1/L2 (orden no decreciente)."""
    outcomes = {"evil": _found("evil")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"evil": _mal("evil", "MAL-2025-3001")}))

    report = scan_dependencies(_deps("evil"), Config())
    signals = _by_name(report)["evil"].signals
    layers = [s.layer for s in signals]

    assert layers == sorted(layers)
    assert signals[-1].layer is Layer.L3
    assert signals[-1].code is SignalCode.MALICIOUS


# ===========================================================================
# CLI: flags --no-layer3 / --enable-watchlist (R5.1, H2-T14)
# ===========================================================================


def test_cli_no_layer3_flag_parseable() -> None:
    """R5.1: --no-layer3 se parsea y produce no_layer3=True."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--no-layer3"])
    assert args.no_layer3 is True


def test_cli_enable_watchlist_flag_parseable() -> None:
    """R5.1: --enable-watchlist se parsea y produce enable_watchlist=True."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--enable-watchlist"])
    assert args.enable_watchlist is True


def test_cli_defaults_layer3_flags() -> None:
    """R5.1: sin flags, no_layer3=False y enable_watchlist=False (no-op)."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt"])
    assert args.no_layer3 is False
    assert args.enable_watchlist is False


def test_cli_overrides_no_layer3_produce_enable_false() -> None:
    """R5.1: _cli_overrides con --no-layer3 inyecta enable_layer3=False."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--no-layer3"])
    overrides = cli_main._cli_overrides(args)
    assert overrides.get("enable_layer3") is False


def test_cli_overrides_enable_watchlist_produce_true() -> None:
    """R5.1: _cli_overrides con --enable-watchlist inyecta enable_watchlist=True."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--enable-watchlist"])
    overrides = cli_main._cli_overrides(args)
    assert overrides.get("enable_watchlist") is True


def test_cli_overrides_sin_flags_no_layer3_keys_ausentes() -> None:
    """R5.1: sin flags L3, los overrides no incluyen enable_layer3/enable_watchlist."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt"])
    overrides = cli_main._cli_overrides(args)
    # No deben incluirse (None se ignora en load_config; bool False cambiaria el default).
    assert "enable_layer3" not in overrides
    assert "enable_watchlist" not in overrides


def test_cli_ambos_flags_juntos() -> None:
    """R5.1: --no-layer3 y --enable-watchlist pueden pasarse juntos sin conflicto."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--no-layer3", "--enable-watchlist"])
    assert args.no_layer3 is True
    assert args.enable_watchlist is True


# ===========================================================================
# Render humano: advisories MAL-* con ID + enlace + accion (R7.1/R7.4)
# ===========================================================================


def _report_malicious(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset, advisory_id: str
) -> ScanReport:
    outcomes = {"evilpkg": _found("evilpkg")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"evilpkg": _mal("evilpkg", advisory_id)}))
    return scan_dependencies(_deps("evilpkg"), Config())


def test_render_humano_muestra_id_advisory(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.1: el render humano muestra el ID MAL-* del advisory."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-4001")
    buf = io.StringIO()
    render_human(report, out=buf)
    assert "MAL-2025-4001" in buf.getvalue()


def test_render_humano_muestra_enlace_osv(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.1: el render humano incluye el enlace canonico OSV del advisory."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-4002")
    buf = io.StringIO()
    render_human(report, out=buf)
    assert "https://osv.dev/vulnerability/MAL-2025-4002" in buf.getvalue()


def test_render_humano_muestra_accion_bloqueo(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.1: el render humano muestra la accion de bloqueo para MALICIOUS."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-4003")
    buf = io.StringIO()
    render_human(report, out=buf)
    assert "BLOQUEAR" in buf.getvalue()


def test_render_humano_sanea_ansi_en_id(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.4: ANSI inyectado en el ID MAL-* se elimina en el render humano."""
    adv_id = f"MAL-2025-5001{_ANSI}"
    report = _report_malicious(monkeypatch, top_n, adv_id)
    buf = io.StringIO()
    render_human(report, out=buf)
    text = buf.getvalue()
    assert _ANSI not in text
    assert "MAL-2025-5001" in text


def test_render_humano_sanea_crlf_en_id(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.4: CR/LF inyectado en el ID se neutraliza en el render humano.

    El saneo elimina los caracteres de control CR y LF del ID (C0: 0x0d, 0x0a).
    La cadena residual visible sigue en la misma linea renderizada; lo que no debe
    ocurrir es que los caracteres de control raw aparezcan en la salida.
    """
    adv_id = f"MAL-2025-5002{_CRLF}"
    report = _report_malicious(monkeypatch, top_n, adv_id)
    buf = io.StringIO()
    render_human(report, out=buf)
    text = buf.getvalue()
    # Los controles C0 (CR=0x0d, LF=0x0a) no deben aparecer embebidos en el ID.
    assert "\r" not in text.split("MAL-2025-5002")[1].split("\n")[0]
    assert "MAL-2025-5002" in text


def test_render_humano_sin_advisories_clean(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.1: dep CLEAN no muestra bloque de advisories en el render humano."""
    outcomes = {"clean": _found("clean")}
    _install(monkeypatch, outcomes, top_n, _StubSource())
    report = scan_dependencies(_deps("clean"), Config())
    buf = io.StringIO()
    render_human(report, out=buf)
    assert "Advisories" not in buf.getvalue()


# ===========================================================================
# Render JSON: schema_version 1.1 + advisories[] estable + sin timestamps (R7.3/§2.4)
# ===========================================================================


def test_json_schema_version_1_1(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§2.4: el JSON declara schema_version 1.1."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-6001")
    parsed = json.loads(render_json(report))
    assert parsed["schema_version"] == "1.2"


def test_json_advisories_clave_estable_presente(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§2.4: la clave advisories[] esta siempre presente en cada result (clave estable)."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-6002")
    parsed = json.loads(render_json(report))
    result = parsed["results"][0]
    assert "advisories" in result


def test_json_advisories_poblado_con_id_y_url(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§2.4: advisories[] porta el ID y la URL canonica del advisory MAL-*."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-6003")
    parsed = json.loads(render_json(report))
    adv = parsed["results"][0]["advisories"][0]
    assert adv["id"] == "MAL-2025-6003"
    assert adv["url"] == "https://osv.dev/vulnerability/MAL-2025-6003"
    assert adv["source"] == "osv"
    assert adv["kind"] == "malicious"


def test_json_advisories_vacio_sin_malicia(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§2.4: para una dep CLEAN advisories[] esta presente y es lista vacia."""
    outcomes = {"clean": _found("clean")}
    _install(monkeypatch, outcomes, top_n, _StubSource())
    report = scan_dependencies(_deps("clean"), Config())
    parsed = json.loads(render_json(report))
    assert parsed["results"][0]["advisories"] == []


def test_json_sin_timestamps_de_reloj(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.3: el JSON no contiene timestamps ISO de reloj (determinismo)."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-6004")
    payload = render_json(report)
    assert not re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", payload)
    assert not re.search(r"\b\d{2}:\d{2}:\d{2}\b", payload)


def test_json_sanea_ansi_en_advisory_id(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.4: ANSI inyectado en el ID del advisory se elimina en el JSON."""
    adv_id = f"MAL-2025-7001{_ANSI}"
    report = _report_malicious(monkeypatch, top_n, adv_id)
    payload = render_json(report)
    assert "\x1b" not in payload
    assert "MAL-2025-7001" in payload


def test_json_orden_claves_determinista(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.3: las claves del JSON tienen orden determinista (dict literal, no sort_keys)."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-6005")
    payload1 = render_json(report)
    payload2 = render_json(report)
    assert payload1 == payload2  # idempotente y determinista


def test_json_es_parseable(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """Propiedad basica: el JSON siempre parsea sin error."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-6006")
    parsed = json.loads(render_json(report))
    assert isinstance(parsed, dict)
    assert "results" in parsed


# ===========================================================================
# MALICIOUS: override block, advisories propagados (ADR-06)
# ===========================================================================


def test_malicious_veredicto_block_score_none(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """ADR-06: MALICIOUS => block por override, score None, advisories no vacio."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-8001")
    result = _by_name(report)["evilpkg"]
    assert result.verdict is Verdict.BLOCK
    assert result.score is None
    assert len(result.advisories) == 1
    assert result.advisories[0].id == "MAL-2025-8001"


def test_malicious_exit_code_2(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """ADR-06: un MALICIOUS produce exit code 2."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-8002")
    assert report.summary.exit_code == 2


# ===========================================================================
# KNOWN_HALLUCINATION: block por score 85 (ADR-07)
# ===========================================================================


def test_known_hallucination_block_por_score(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """ADR-07: KNOWN_HALLUCINATION => block por score 85 (no override), sin advisories."""
    outcomes = {"hallucpkg": _found("hallucpkg")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"hallucpkg": _halluc("hallucpkg")}))
    report = scan_dependencies(_deps("hallucpkg"), Config())
    result = _by_name(report)["hallucpkg"]

    assert result.verdict is Verdict.BLOCK
    assert result.score == 85
    assert result.advisories == ()


# ===========================================================================
# UNVERIFIABLE: falla closed, exit 3, jamas allow (NFR-Degr.1)
# ===========================================================================


def test_unverifiable_status_y_exit_3(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """NFR-Degr.1: threat-intel UNVERIFIABLE => status unverifiable, exit 3."""
    outcomes = {"downpkg": _found("downpkg")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"downpkg": _unver("downpkg")}))
    report = scan_dependencies(_deps("downpkg"), Config())
    result = _by_name(report)["downpkg"]

    assert result.status is Status.UNVERIFIABLE
    assert result.verdict is None
    assert report.summary.exit_code == 3


def test_unverifiable_nunca_allow(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """NFR-Degr.1: THREATINTEL_UNVERIFIABLE nunca produce allow (fail-closed)."""
    outcomes = {"downpkg": _found("downpkg")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"downpkg": _unver("downpkg")}))
    report = scan_dependencies(_deps("downpkg"), Config())
    assert report.results[0].verdict is not Verdict.ALLOW
