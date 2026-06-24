"""Suite CLI de Hito 2 (H2-T14): flags, overrides, render y schema 1.1.

Cubre los criterios faltantes identificados en los yellow warnings:
  1. (Yellow 1) Los 5 overrides de red/cache de Capa 3 anadir en _cli_overrides:
     --osv-host, --osv-ttl-horas, --osv-timeout-total, --watchlist-host,
     --watchlist-ttl-horas; incluyendo el caso sin-flags (None = no-op).
  2. (Yellow 2) Atribucion watchlist en render humano: una dep KNOWN_HALLUCINATION
     produce la linea 'Atribucion watchlist:' con mencion de la licencia (R7.2).

Ademas cubre H2-T14 completo:
  - Flags --no-layer3 / --enable-watchlist cableados (R5.1).
  - Render humano de advisories MAL-* saneados: ID + enlace + accion (R7.1/R7.4).
  - JSON schema_version 1.1 con advisories[] clave estable (§2.4).
  - Sin timestamps en el JSON (R7.3).
  - enable_layer3=false => JSON valido con advisories[] vacio (NFR-Compat.1).
  - Determinismo bajo permutacion (R3.5).
  - SOLO FOUND al batch de Capa 3 (R1.5).
  - Intercalado correcto L0->L1->L2->L3 (§4.1).

Todos los bordes externos (red, disco) se reemplazan con stubs en memoria.
"""

from __future__ import annotations

import io
import json
import re
from typing import TYPE_CHECKING

import pytest

from slopguard.cli import main as cli_main
from slopguard.cli.render_human import render_human
from slopguard.cli.render_json import render_json
from slopguard.core import (
    Advisory,
    Config,
    Dependency,
    MaliceState,
    ScanReport,
    SignalCode,
    Status,
    Verdict,
    scan_dependencies,
)
from slopguard.core.adapters.base import FetchOutcome, FetchState, PackageMetadata
from slopguard.core.dataset.top_n import TopNDataset, build_top_n
from slopguard.core.models import (
    DependencyResult,
    Layer,
    ThreatIntelResult,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

# Rutas de patch del engine.
_GET_ADAPTER = "slopguard.core.engine.get_adapter"
_GET_TI_SOURCE = "slopguard.core.engine.get_threatintel_source"
_ENGINE_TIME = "slopguard.core.engine.time.time"

# Epoch fijo: paquete establecido (400 dias de edad) => sin NEW_PACKAGE.
_NOW = 1_717_200_000.0
_DAY = 86_400.0
_OLD_EPOCH = _NOW - 400 * _DAY

# Secuencias de control para verificar saneo (R7.4).
_ANSI = "\x1b[31m"
_CRLF = "\r\n"

_TOP_N_NAMES = ["requests", "flask", "numpy"]


# --------------------------------------------------------------------------- #
# Dobles de prueba (sin red ni disco)
# --------------------------------------------------------------------------- #


def _meta(name: str) -> PackageMetadata:
    """Metadatos de un paquete establecido y completo (L0/L1/L2 sin senales propias)."""
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

    def get_downloads(self, name: str) -> None:  # pragma: no cover
        return None


class _StubSource:
    """Fuente ThreatIntelSource en memoria: registra lotes y mapea por nombre.

    Nombres no mapeados se resuelven CLEAN (cobertura total).
    """

    source_id: str = "stub-cli"
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
    """Fija el reloj del engine (NFR-Det.1): edad reproducible sin timestamp de pared."""
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
        watchlist_date="2026-06-20",
    )


def _unver(name: str) -> ThreatIntelResult:
    return ThreatIntelResult(
        name=name, state=MaliceState.UNVERIFIABLE, unverifiable_reason="osv 503"
    )


# ===========================================================================
# Yellow 1: overrides de red/cache de Capa 3 en _cli_overrides (R5.1, §3.7)
# ===========================================================================


@pytest.mark.parametrize(
    ("cli_args", "expected_key", "expected_value"),
    [
        (
            ["scan", "-", "--osv-host", "api.osv.dev"],
            "osv_host",
            "api.osv.dev",
        ),
        (
            ["scan", "-", "--osv-ttl-horas", "12"],
            "osv_ttl_cache_horas",
            12,
        ),
        (
            ["scan", "-", "--osv-timeout-total", "45.5"],
            "osv_timeout_total_por_lote_s",
            45.5,
        ),
        (
            ["scan", "-", "--watchlist-host", "depscope.dev"],
            "watchlist_host",
            "depscope.dev",
        ),
        (
            ["scan", "-", "--watchlist-ttl-horas", "48"],
            "watchlist_ttl_cache_horas",
            48,
        ),
    ],
)
def test_cli_overrides_l3_flag_produce_valor_convertido(
    cli_args: list[str],
    expected_key: str,
    expected_value: object,
) -> None:
    """R5.1/§3.7: cada flag de override L3 se parsea y fluye por _cli_overrides con
    el valor convertido al tipo correcto (str, int o float segun la definicion del flag).

    Un typo en `dest` o un error de conversion pasaria silencioso; este test lo detecta
    antes de que load_config reciba un None o un tipo incorrecto.
    """
    parser = cli_main._build_parser()
    args = parser.parse_args(cli_args)
    overrides = cli_main._cli_overrides(args)
    assert expected_key in overrides
    assert overrides[expected_key] == expected_value


def test_cli_overrides_sin_flags_l3_claves_son_none() -> None:
    """R5.1: sin pasar ninguno de los 5 flags de Capa 3, los overrides devuelven None
    para cada clave (no-op en load_config: defaults o archivo prevalecen).

    Verifica que la ausencia de flag NO inyecte un valor no-None que sobreescriba
    el archivo de config o los defaults.
    """
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "-"])
    overrides = cli_main._cli_overrides(args)

    for key in (
        "osv_host",
        "osv_ttl_cache_horas",
        "osv_timeout_total_por_lote_s",
        "watchlist_host",
        "watchlist_ttl_cache_horas",
    ):
        assert overrides[key] is None, f"Key '{key}' deberia ser None sin flag"


# ===========================================================================
# Yellow 2: atribucion watchlist en render humano (R7.2)
# ===========================================================================


def test_render_humano_muestra_atribucion_watchlist(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.2: una dep KNOWN_HALLUCINATION produce la linea 'Atribucion watchlist:'
    en el render humano con mencion de la licencia del corpus (CC-BY-NC-SA).

    Una regresion que rompa la comparacion de SignalCode en _render_watchlist_attribution
    (p.ej. 'is' vs '==' o un cambio de enum) no seria detectada sin este test.
    """
    outcomes = {"reqe": _found("reqe")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"reqe": _halluc("reqe")}))
    report = scan_dependencies(_deps("reqe"), Config())

    buf = io.StringIO()
    render_human(report, out=buf)
    text = buf.getvalue()

    assert "Atribucion watchlist:" in text
    assert "CC-BY-NC-SA" in text


def test_render_humano_atribucion_watchlist_menciona_licencia(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.2: la linea de atribucion incluye la referencia a la licencia del corpus."""
    outcomes = {"reqe": _found("reqe")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"reqe": _halluc("reqe")}))
    report = scan_dependencies(_deps("reqe"), Config())

    buf = io.StringIO()
    render_human(report, out=buf)
    text = buf.getvalue()

    assert "licencia del corpus" in text or "CC-BY-NC-SA" in text


def test_render_humano_atribucion_ausente_sin_hallucination(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.2: dep CLEAN no muestra linea de atribucion watchlist."""
    outcomes = {"clean": _found("clean")}
    _install(monkeypatch, outcomes, top_n, _StubSource())
    report = scan_dependencies(_deps("clean"), Config())

    buf = io.StringIO()
    render_human(report, out=buf)
    assert "Atribucion watchlist:" not in buf.getvalue()


# ===========================================================================
# H2-T14: Flags --no-layer3 / --enable-watchlist cableados (R5.1)
# ===========================================================================


def test_cli_no_layer3_parseable() -> None:
    """R5.1: --no-layer3 se parsea y produce no_layer3=True."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--no-layer3"])
    assert args.no_layer3 is True


def test_cli_enable_watchlist_parseable() -> None:
    """R5.1: --enable-watchlist se parsea y produce enable_watchlist=True."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt", "--enable-watchlist"])
    assert args.enable_watchlist is True


def test_cli_defaults_flags_layer3() -> None:
    """R5.1: sin flags, no_layer3=False y enable_watchlist=False."""
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
    """R5.1: sin flags L3 booleanos, enable_layer3/enable_watchlist NO aparecen en overrides."""
    parser = cli_main._build_parser()
    args = parser.parse_args(["scan", "req.txt"])
    overrides = cli_main._cli_overrides(args)
    assert "enable_layer3" not in overrides
    assert "enable_watchlist" not in overrides


# ===========================================================================
# H2-T14: Render humano de advisories MAL-* (R7.1/R7.4)
# ===========================================================================


def _report_malicious(
    monkeypatch: pytest.MonkeyPatch,
    top_n: TopNDataset,
    advisory_id: str,
) -> ScanReport:
    outcomes = {"evilpkg": _found("evilpkg")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"evilpkg": _mal("evilpkg", advisory_id)}))
    return scan_dependencies(_deps("evilpkg"), Config())


def test_render_humano_muestra_id_advisory(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.1: el render humano muestra el ID MAL-* del advisory."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-9001")
    buf = io.StringIO()
    render_human(report, out=buf)
    assert "MAL-2025-9001" in buf.getvalue()


def test_render_humano_muestra_enlace_osv(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.1: el render humano incluye el enlace canonico OSV del advisory."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-9002")
    buf = io.StringIO()
    render_human(report, out=buf)
    assert "https://osv.dev/vulnerability/MAL-2025-9002" in buf.getvalue()


def test_render_humano_muestra_accion_bloqueo(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.1: el render humano muestra la accion de bloqueo para MALICIOUS."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-9003")
    buf = io.StringIO()
    render_human(report, out=buf)
    assert "BLOQUEAR" in buf.getvalue()


def test_render_humano_sanea_ansi_en_id(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.4: secuencia ANSI inyectada en el ID MAL-* se elimina del render humano."""
    adv_id = f"MAL-2025-9004{_ANSI}"
    report = _report_malicious(monkeypatch, top_n, adv_id)
    buf = io.StringIO()
    render_human(report, out=buf)
    text = buf.getvalue()
    assert _ANSI not in text
    assert "MAL-2025-9004" in text


def test_render_humano_sanea_crlf_en_id(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.4: CR/LF inyectado en el ID se neutraliza en el render humano."""
    adv_id = f"MAL-2025-9005{_CRLF}"
    report = _report_malicious(monkeypatch, top_n, adv_id)
    buf = io.StringIO()
    render_human(report, out=buf)
    text = buf.getvalue()
    assert "MAL-2025-9005" in text
    # CR no debe aparecer embebido en la misma linea que el ID.
    assert "\r" not in text.split("MAL-2025-9005")[1].split("\n")[0]


def test_render_humano_sin_advisories_dep_clean(
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
# H2-T14: Render JSON schema_version 1.1 + advisories[] + sin timestamps (R7.3/§2.4)
# ===========================================================================


def test_json_schema_version_1_1(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§2.4: el JSON declara schema_version 1.1."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-10001")
    parsed = json.loads(render_json(report))
    assert parsed["schema_version"] == "1.2"


def test_json_advisories_clave_estable_presente(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§2.4: la clave 'advisories' esta siempre presente en cada result (clave estable)."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-10002")
    parsed = json.loads(render_json(report))
    assert "advisories" in parsed["results"][0]


def test_json_advisories_porta_id_y_url(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§2.4: advisories[] contiene el ID y la URL canonica del advisory MAL-*."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-10003")
    parsed = json.loads(render_json(report))
    adv = parsed["results"][0]["advisories"][0]
    assert adv["id"] == "MAL-2025-10003"
    assert adv["url"] == "https://osv.dev/vulnerability/MAL-2025-10003"
    assert adv["source"] == "osv"
    assert adv["kind"] == "malicious"


def test_json_advisories_vacio_para_dep_clean(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§2.4: dep CLEAN tiene advisories=[] (clave presente pero vacia)."""
    outcomes = {"clean": _found("clean")}
    _install(monkeypatch, outcomes, top_n, _StubSource())
    report = scan_dependencies(_deps("clean"), Config())
    parsed = json.loads(render_json(report))
    assert parsed["results"][0]["advisories"] == []


def test_json_sin_timestamps_de_reloj(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.3: el JSON no contiene timestamps ISO de reloj (determinismo)."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-10004")
    payload = render_json(report)
    assert not re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", payload)
    assert not re.search(r"\b\d{2}:\d{2}:\d{2}\b", payload)


def test_json_sanea_ansi_en_advisory_id(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.4: ANSI inyectado en el ID del advisory se elimina en el JSON."""
    adv_id = f"MAL-2025-10005{_ANSI}"
    report = _report_malicious(monkeypatch, top_n, adv_id)
    payload = render_json(report)
    assert "\x1b" not in payload
    assert "MAL-2025-10005" in payload


def test_json_es_parseable(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """Propiedad basica: el JSON siempre es parseable y contiene las claves obligatorias."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-10006")
    parsed = json.loads(render_json(report))
    assert isinstance(parsed, dict)
    for key in ("schema_version", "tool_version", "ecosystem", "summary", "results"):
        assert key in parsed, f"Clave '{key}' ausente del JSON"


def test_json_orden_claves_determinista(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.3: el JSON es idempotente; el mismo report siempre produce la misma cadena."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-10007")
    assert render_json(report) == render_json(report)


# ===========================================================================
# H2-T14: enable_layer3=false => JSON valido con advisories[] vacio (NFR-Compat.1)
# ===========================================================================


def test_json_enable_layer3_false_advisories_vacio(
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


def test_json_enable_layer3_false_sin_senales_l3(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R5.3: con enable_layer3=false las signals del JSON no contienen layer=3."""
    outcomes = {"plain": _found("plain")}
    _install(monkeypatch, outcomes, top_n, None)
    report = scan_dependencies(_deps("plain"), Config(enable_layer3=False))

    parsed = json.loads(render_json(report))
    for signal in parsed["results"][0]["signals"]:
        assert signal["layer"] != 3


# ===========================================================================
# H2-T14: SOLO FOUND van al batch de Capa 3 (R1.5)
# ===========================================================================


def test_solo_found_al_batch(
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


def test_not_found_no_porta_senal_l3(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R3.6: un NOT_FOUND no porta senales L3 en su DependencyResult."""
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
# H2-T14: Intercalado correcto L0->L1->L2->L3 (§4.1)
# ===========================================================================


def test_orden_capas_l3_al_final(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§4.1: la senal L3 se recolecta despues de L0/L1/L2 (orden no decreciente de Layer)."""
    outcomes = {"evil": _found("evil")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"evil": _mal("evil", "MAL-2025-11001")}))

    report = scan_dependencies(_deps("evil"), Config())
    signals = _by_name(report)["evil"].signals
    layers = [s.layer for s in signals]

    assert layers == sorted(layers)
    assert signals[-1].layer is Layer.L3
    assert signals[-1].code is SignalCode.MALICIOUS


# ===========================================================================
# H2-T14: Determinismo bajo permutacion del lote (R3.5)
# ===========================================================================


def test_determinismo_permutacion_malicious(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R3.5: permutar el lote no altera el ScanReport con dep MALICIOUS."""
    names = ("alpha", "bravo", "charlie")
    outcomes = {n: _found(n) for n in names}
    results_map = {"bravo": _mal("bravo", "MAL-2025-12001")}

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
    results_map: dict[str, ThreatIntelResult] = {
        "evil": _mal("evil", "MAL-2025-13001"),
        "halluc": _halluc("halluc"),
        "down": _unver("down"),
    }

    _install(monkeypatch, outcomes, top_n, _StubSource(dict(results_map)))
    r1 = scan_dependencies(_deps(*names), Config())

    _install(monkeypatch, outcomes, top_n, _StubSource(dict(results_map)))
    r2 = scan_dependencies(_deps(*reversed(names)), Config())

    assert r1 == r2


# ===========================================================================
# H2-T14: MALICIOUS => block + override (ADR-06)
# ===========================================================================


def test_malicious_bloquea_con_override(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """ADR-06: MALICIOUS => block por override, score None, advisories no vacio."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-14001")
    result = _by_name(report)["evilpkg"]
    assert result.verdict is Verdict.BLOCK
    assert result.score is None
    assert len(result.advisories) == 1
    assert result.advisories[0].id == "MAL-2025-14001"


def test_malicious_exit_code_2(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """ADR-06: una dep MALICIOUS produce exit code 2."""
    report = _report_malicious(monkeypatch, top_n, "MAL-2025-14002")
    assert report.summary.exit_code == 2


# ===========================================================================
# H2-T14: KNOWN_HALLUCINATION => block por score 85 (ADR-07)
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
# H2-T14: UNVERIFIABLE => fail-closed, exit 3, nunca allow (NFR-Degr.1)
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
    """NFR-Degr.1: THREATINTEL_UNVERIFIABLE nunca produce verdict allow (fail-closed)."""
    outcomes = {"downpkg": _found("downpkg")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"downpkg": _unver("downpkg")}))
    report = scan_dependencies(_deps("downpkg"), Config())
    assert report.results[0].verdict is not Verdict.ALLOW
