"""Suite de engine + CLI/render de la Capa 3 (H2-T12 / RISK-H2-3, ADR-06/07/10, §4.1).

Ejercita el FLUJO REAL del orquestador (`core.engine` via la fachada `slopguard.core`)
con la Capa 3 intercalada entre la Capa 0 (concurrente, per-dep) y el bucle por-dep, y
el render humano/JSON real (`cli.render_human`/`cli.render_json`) sobre el `ScanReport`
resultante. Todo borde externo se simula en memoria y de forma determinista:

  - Adapter: `_StubAdapter` (implementa `EcosystemAdapter`) mapea FOUND/NOT_FOUND/
    UNVERIFIABLE por nombre y expone un `TopNDataset` de fixture. Sin red.
  - Fuente de Capa 3: `_StubSource` (implementa `ThreatIntelSource`) registra los lotes
    recibidos y devuelve un `ThreatIntelResult` por nombre. Inyectada via
    `engine.get_threatintel_source` (mismo patron que `get_adapter`). Sin red ni disco.

`engine.time.time` se fija para que la edad de Capa 0 sea reproducible y para asertar
que `now_epoch` se lee UNA sola vez por corrida (NFR-Det.1), aun con el batch intercalado.

Propiedades de ENGINE verificadas (§4.1 / RISK-H2-3, criterios H2-T12):
  - R1.5/R3.6: SOLO los FOUND van al batch; NOT_FOUND/UNVERIFIABLE excluidos.
  - Invariantes de no-perdida (§4.1 tests 1-3): `keys(ti) ⊆ found`; todo FOUND tiene
    entrada; `found ∩ {NOT_FOUND, UNVERIFIABLE} = ∅`.
  - R3.5: determinismo bajo permutacion del lote (mismo ScanReport).
  - R7.5: orden de resultados sin cambios (unverifiable→block→warn→allow, luego nombre).
  - R6.5: multiples lotes (> osv_batch_max) sin perder nombres.
  - Override MALICIOUS ⇒ block + advisories (ADR-06); KNOWN_HALLUCINATION ⇒ block por
    score 85 (ADR-07); OSV caido (UNVERIFIABLE) sobre dep limpia ⇒ status unverifiable,
    exit 3, nunca falso allow (ADR-10, NFR-Degr.1).
  - Intercalado/orden de capas 0→1→2→3: la senal L3 va DESPUES de L0/L1/L2 y solo para FOUND.
  - R5.3: enable_layer3=false ⇒ source None ⇒ ti={} ⇒ comportamiento IDENTICO al Hito 1.
  - NFR-Det.1: now_epoch unico tras el batch.

Propiedades de CLI/RENDER verificadas (§2.4, §3.7, R7.3/R7.4):
  - JSON `schema_version == "1.2"` y sin timestamps de reloj (determinismo R7.3).
  - Saneo ANSI/CRLF del ID MAL-* reflejado en humano y JSON (R7.4).
  - enable_layer3=false ⇒ JSON sigue valido (lectores 1.0 ignoran lo nuevo).

Los criterios de salida que dependen de H2-T14 (NO implementado en esta rama: clave
`advisories[]` en JSON, enlace MAL- en humano, flags `--no-layer3`/`--enable-watchlist`)
quedan escritos como `xfail(strict=True)`: documentan la frontera exacta y se volveran
verdes (alertando) cuando H2-T14 cablee la salida, sin tocar aqui otro subsistema.
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
    Config,
    Dependency,
    ScanReport,
    Status,
    Verdict,
    scan_dependencies,
)
from slopguard.core.adapters.base import FetchOutcome, FetchState, PackageMetadata
from slopguard.core.dataset.top_n import TopNDataset, build_top_n
from slopguard.core.models import (
    Advisory,
    DependencyResult,
    Layer,
    MaliceState,
    SignalCode,
    ThreatIntelResult,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

_GET_ADAPTER = "slopguard.core.engine.get_adapter"
_GET_TI_SOURCE = "slopguard.core.engine.get_threatintel_source"
_ENGINE_TIME = "slopguard.core.engine.time.time"

# Epoch fijo: paquete establecido (edad holgada) ⇒ sin NEW_PACKAGE, base limpia.
_NOW = 1_717_200_000.0
_DAY = 86_400.0
_OLD_EPOCH = _NOW - 400 * _DAY

_TOP_N_NAMES = ["requests", "flask", "numpy", "pandas"]

# Secuencia de escape inyectada en un ID externo para verificar el saneo (R7.4).
_ANSI = "\x1b[31m"


# --------------------------------------------------------------------------- #
# Dobles de prueba
# --------------------------------------------------------------------------- #


def _meta(name: str) -> PackageMetadata:
    """Metadatos de un paquete establecido y completo (L2/L0 sin senales propias)."""
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
_UNVERIFIABLE = FetchOutcome(state=FetchState.UNVERIFIABLE)


class _StubAdapter:
    """Adapter `EcosystemAdapter` en memoria, sin red ni reintentos (igual a test_engine)."""

    ecosystem_id = "pypi"

    def __init__(self, outcomes: dict[str, FetchOutcome], top_n: TopNDataset) -> None:
        self._outcomes = outcomes
        self._top_n = top_n

    def normalize_name(self, raw: str) -> str:
        return raw.strip().lower().replace("_", "-").replace(".", "-")

    def fetch(self, name: str) -> FetchOutcome:
        return self._outcomes.get(name, _UNVERIFIABLE)

    def load_top_n(self) -> TopNDataset:
        return self._top_n

    def get_downloads(self, name: str) -> None:  # pragma: no cover - hook reservado
        return None


class _StubSource:
    """Fuente `ThreatIntelSource` en memoria: registra los lotes y mapea por nombre.

    `calls` acumula cada lote recibido (para asertar R1.5 y el chunking). Por defecto un
    nombre no mapeado se resuelve CLEAN. Cobertura total: una entrada por cada nombre del
    lote (igual contrato que `CompositeSource`).
    """

    source_id: str = "stub"
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
    """Fija `engine.time.time` para una edad reproducible (NFR-Det.1)."""
    monkeypatch.setattr(_ENGINE_TIME, lambda: _NOW)


def _install(
    monkeypatch: pytest.MonkeyPatch,
    outcomes: dict[str, FetchOutcome],
    top_n: TopNDataset,
    source: _StubSource | None,
) -> _StubSource | None:
    """Inyecta adapter y fuente de Capa 3 (None ⇒ enable_layer3=false simulado)."""
    monkeypatch.setattr(_GET_ADAPTER, lambda *a, **k: _StubAdapter(outcomes, top_n))
    monkeypatch.setattr(_GET_TI_SOURCE, lambda *a, **k: source)
    return source


def _deps(*names: str) -> list[Dependency]:
    return [Dependency(name=n, version_pin=None, raw=n, origin="x") for n in names]


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


def _known_hallucination(name: str) -> ThreatIntelResult:
    return ThreatIntelResult(
        name=name,
        state=MaliceState.KNOWN_HALLUCINATION,
        watchlist_source="depscope-hallucinations",
        watchlist_date="2026-06-20",
    )


def _ti_unverifiable(name: str) -> ThreatIntelResult:
    return ThreatIntelResult(
        name=name, state=MaliceState.UNVERIFIABLE, unverifiable_reason="osv 503"
    )


# ===========================================================================
# R1.5/R3.6: SOLO los FOUND van al batch de Capa 3
# ===========================================================================


def test_solo_found_van_al_batch(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R1.5/§4.1 test 3: NOT_FOUND y UNVERIFIABLE quedan FUERA del lote de threat-intel."""
    outcomes = {
        "alpha": _found("alpha"),
        "ghost": _NOT_FOUND,
        "flaky": _UNVERIFIABLE,
        "beta": _found("beta"),
    }
    source = _StubSource()
    _install(monkeypatch, outcomes, top_n, source)

    scan_dependencies(_deps("alpha", "ghost", "flaky", "beta"), Config())

    queried = {name for call in source.calls for name in call}
    assert queried == {"alpha", "beta"}  # solo los FOUND
    assert "ghost" not in queried and "flaky" not in queried


def test_keys_ti_subconjunto_de_found(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§4.1 test 1: la fuente nunca inyecta veredictos de nombres fuera del lote FOUND.

    Solo se consultan los FOUND; ningun NOT_FOUND/UNVERIFIABLE recibe senal L3 (su
    DependencyResult no debe portar `MALICIOUS`/`KNOWN_HALLUCINATION`/`THREATINTEL_*`).
    """
    outcomes = {"good": _found("good"), "ghost": _NOT_FOUND, "flaky": _UNVERIFIABLE}
    _install(monkeypatch, outcomes, top_n, _StubSource())

    report = scan_dependencies(_deps("good", "ghost", "flaky"), Config())
    by_name = _by_name(report)

    l3_codes = {
        SignalCode.MALICIOUS,
        SignalCode.KNOWN_HALLUCINATION,
        SignalCode.THREATINTEL_UNVERIFIABLE,
    }
    for name in ("ghost", "flaky"):
        codes = {s.code for s in by_name[name].signals}
        assert not (codes & l3_codes)  # ningun NOT_FOUND/UNVERIFIABLE consulto OSV


# ===========================================================================
# Invariantes de no-perdida (§4.1 tests 1-2): cobertura total de los FOUND
# ===========================================================================


def test_todo_found_tiene_senal_l3(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§4.1 test 2: toda dep FOUND recibe entrada de Capa 3 (nunca 'sin evaluar')."""
    outcomes = {n: _found(n) for n in ("a", "b", "c")}
    source = _StubSource(
        {
            "a": ThreatIntelResult(name="a", state=MaliceState.CLEAN),
            "b": _mal("b", "MAL-2025-0001"),
            "c": _ti_unverifiable("c"),
        }
    )
    _install(monkeypatch, outcomes, top_n, source)

    report = scan_dependencies(_deps("a", "b", "c"), Config())
    by_name = _by_name(report)

    # 'a' CLEAN ⇒ sin senal L3; 'b' MALICIOUS ⇒ block; 'c' UNVERIFIABLE ⇒ status unverifiable.
    assert by_name["b"].verdict is Verdict.BLOCK
    assert by_name["c"].status is Status.UNVERIFIABLE
    assert by_name["a"].verdict is Verdict.ALLOW


# ===========================================================================
# Determinismo bajo permutacion del lote (R3.5) + orden de resultados (R7.5)
# ===========================================================================


def test_determinismo_bajo_permutacion(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R3.5: permutar el lote no altera el ScanReport (orden total + batch determinista)."""
    names = ("alpha", "bravo", "charlie", "delta")
    outcomes = {n: _found(n) for n in names}
    results = {"bravo": _mal("bravo", "MAL-2025-0002")}

    _install(monkeypatch, outcomes, top_n, _StubSource(dict(results)))
    first = scan_dependencies(_deps(*names), Config())

    _install(monkeypatch, outcomes, top_n, _StubSource(dict(results)))
    second = scan_dependencies(_deps(*reversed(names)), Config())

    assert first == second


def test_orden_resultados_estable_mezcla(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.5: orden de reporte unverifiable→block→warn→allow, luego nombre, con L3 mezclada.

    Mezcla MALICIOUS (block), KNOWN_HALLUCINATION (block por score), UNVERIFIABLE (status
    unverifiable) y CLEAN (allow) en un solo escaneo intercalado: el orden del reporte es
    independiente del orden de entrada (R7.5) y consistente con el rango de estado/verdict.
    """
    outcomes = {n: _found(n) for n in ("clean1", "evil", "halluc", "down")}
    source = _StubSource(
        {
            "evil": _mal("evil", "MAL-2025-0010"),
            "halluc": _known_hallucination("halluc"),
            "down": _ti_unverifiable("down"),
            # clean1 ⇒ CLEAN por default del stub.
        }
    )
    _install(monkeypatch, outcomes, top_n, source)

    report = scan_dependencies(_deps("clean1", "evil", "halluc", "down"), Config())
    order = [r.name for r in report.results]

    # unverifiable(down) → block(evil, halluc por nombre asc) → allow(clean1).
    assert order == ["down", "evil", "halluc", "clean1"]


# ===========================================================================
# Multiples lotes (> osv_batch_max): chunking sin perder nombres (R6.5)
# ===========================================================================


def test_multiples_lotes_sin_perdida(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """> osv_batch_max FOUND ⇒ varios chunks; todos los nombres se evaluan (cobertura)."""
    names = tuple(f"pkg{i:03d}" for i in range(7))
    outcomes = {n: _found(n) for n in names}
    source = _StubSource({"pkg004": _mal("pkg004", "MAL-2025-0003")})
    _install(monkeypatch, outcomes, top_n, source)

    report = scan_dependencies(_deps(*names), Config(osv_batch_max=2))

    # 7 nombres en chunks de 2 ⇒ 4 lotes (2+2+2+1), ninguno perdido.
    assert len(source.calls) == 4
    queried = {name for call in source.calls for name in call}
    assert queried == set(names)
    assert _by_name(report)["pkg004"].verdict is Verdict.BLOCK
    assert report.summary.total == len(names)


# ===========================================================================
# Override MALICIOUS ⇒ block + advisories (ADR-06)
# ===========================================================================


def test_malicious_override_block_con_advisories(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """ADR-06/R1.2: MALICIOUS ⇒ block (score None) y advisories[] poblado, exit 2."""
    outcomes = {"evilpkg": _found("evilpkg")}
    _install(
        monkeypatch, outcomes, top_n, _StubSource({"evilpkg": _mal("evilpkg", "MAL-2025-0042")})
    )

    report = scan_dependencies(_deps("evilpkg"), Config())
    result = _by_name(report)["evilpkg"]

    assert result.verdict is Verdict.BLOCK
    assert result.score is None
    assert tuple(a.id for a in result.advisories) == ("MAL-2025-0042",)
    assert report.summary.exit_code == 2


# ===========================================================================
# KNOWN_HALLUCINATION ⇒ block por SCORE 85 (ADR-07), no por override
# ===========================================================================


def test_known_hallucination_block_por_score(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """ADR-07/R3.2: KNOWN_HALLUCINATION ⇒ senal dura weight=85 ⇒ block por score (no override).

    A diferencia de MALICIOUS, el veredicto lo fija el scorer: status OK, score=85
    (>= umbral_block=80), verdict block, exit 2; sin advisories (no es malicia OSV).
    """
    outcomes = {"reqe": _found("reqe")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"reqe": _known_hallucination("reqe")}))

    report = scan_dependencies(_deps("reqe"), Config())
    result = _by_name(report)["reqe"]

    assert result.verdict is Verdict.BLOCK
    assert result.score == 85  # block por score, no por override (score != None)
    assert result.status is Status.OK
    assert result.advisories == ()
    assert report.summary.exit_code == 2


# ===========================================================================
# OSV caido sobre dep limpia ⇒ unverifiable, exit 3, nunca falso allow (NFR-Degr.1)
# ===========================================================================


def test_osv_caido_dep_limpia_unverifiable_no_allow(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """ADR-10/NFR-Degr.1: threat-intel UNVERIFIABLE sobre dep por lo demas limpia ⇒
    status unverifiable (default), exit 3, jamas allow."""
    outcomes = {"cleanish": _found("cleanish")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"cleanish": _ti_unverifiable("cleanish")}))

    report = scan_dependencies(_deps("cleanish"), Config())
    result = _by_name(report)["cleanish"]

    assert result.status is Status.UNVERIFIABLE
    assert result.verdict is None
    assert report.summary.exit_code == 3
    # La senal blanda L3 esta presente (trazabilidad R3.4).
    codes = {s.code for s in result.signals}
    assert SignalCode.THREATINTEL_UNVERIFIABLE in codes


def test_lote_caido_completo_degrada_no_aborta(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """NFR-Degr.1: una fuente que LANZA sobre el lote degrada sus nombres a UNVERIFIABLE.

    El resolver captura la excepcion del `query_batch` (feed envenenado) y nunca produce
    un falso CLEAN ni aborta el escaneo: las deps FOUND quedan unverifiable, exit 3.
    """

    class _CrashingSource(_StubSource):
        def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
            self.calls.append(list(names))
            raise RuntimeError("feed envenenado")

    outcomes = {n: _found(n) for n in ("x", "y")}
    _install(monkeypatch, outcomes, top_n, _CrashingSource())

    report = scan_dependencies(_deps("x", "y"), Config())

    assert report.summary.exit_code == 3
    for result in report.results:
        assert result.status is Status.UNVERIFIABLE  # jamas allow/CLEAN
        assert result.verdict is None


# ===========================================================================
# Intercalado / orden de capas 0→1→2→3 (§4.1)
# ===========================================================================


def test_orden_capas_l3_despues_de_l0_l1_l2(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§4.1 paso 8: la senal L3 se recolecta DESPUES de L0/L1/L2 (orden 0→1→2→3).

    `requests` esta en el top-N y es FOUND establecido ⇒ sin senales L0/L1/L2 propias;
    una marca KNOWN_HALLUCINATION debe aparecer como la unica senal L3 y con `layer==L3`.
    Verifica que toda senal previa (si la hubiera) tenga `layer <= 3` y que la ultima sea L3.
    """
    outcomes = {"requests": _found("requests")}
    source = _StubSource({"requests": _known_hallucination("requests")})
    _install(monkeypatch, outcomes, top_n, source)

    report = scan_dependencies(_deps("requests"), Config())
    signals = _by_name(report)["requests"].signals

    layers = [s.layer for s in signals]
    assert layers == sorted(layers)  # orden no decreciente de capas (0→1→2→3)
    assert signals[-1].layer is Layer.L3  # la senal L3 cierra la recoleccion
    assert signals[-1].code is SignalCode.KNOWN_HALLUCINATION


def test_malicious_coexiste_sin_borrar_otras_senales(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """ADR-06: MALICIOUS (override block) coexiste con un paquete nuevo (senal L0 blanda).

    El paquete es FOUND pero reciente (NEW_PACKAGE, L0) y ademas MALICIOUS (L3). El override
    fija block pero NO descarta la senal L0: ambas quedan en `signals` (trazabilidad R3.4),
    con la L3 al final (orden 0→1→2→3).
    """
    recent_meta = PackageMetadata(
        name="freshevil",
        first_release_epoch=_NOW - 1 * _DAY,  # < edad_minima_dias ⇒ NEW_PACKAGE (L0 blanda)
        releases_count=1,
        has_repo_url=True,
        has_description=True,
        has_author=True,
        has_license=True,
        has_classifiers=True,
        in_top_n=False,
    )
    outcomes = {"freshevil": FetchOutcome(state=FetchState.FOUND, metadata=recent_meta)}
    _install(
        monkeypatch, outcomes, top_n, _StubSource({"freshevil": _mal("freshevil", "MAL-2025-0099")})
    )

    report = scan_dependencies(_deps("freshevil"), Config())
    result = _by_name(report)["freshevil"]
    codes = [s.code for s in result.signals]

    assert result.verdict is Verdict.BLOCK  # override MALICIOUS domina
    assert SignalCode.NEW_PACKAGE in codes  # la senal L0 no se pierde
    assert codes[-1] is SignalCode.MALICIOUS  # L3 al final del orden 0→1→2→3


# ===========================================================================
# enable_layer3=false (source None) ⇒ ti={} ⇒ comportamiento Hito 1 (R5.3)
# ===========================================================================


def test_layer3_desactivado_identico_hito1(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R5.3: con source None la Capa 3 NO emite senales; la dep limpia sigue allow.

    Compara contra una corrida con fuente que devuelve CLEAN (sin senal L3 tampoco):
    ambos reportes deben ser identicos ⇒ CLEAN no introduce ruido y None == Hito 1.
    """
    outcomes = {"plain": _found("plain")}

    _install(monkeypatch, outcomes, top_n, None)  # source None ⇒ ti={}
    off = scan_dependencies(_deps("plain"), Config())

    _install(monkeypatch, outcomes, top_n, _StubSource())  # fuente CLEAN
    clean = scan_dependencies(_deps("plain"), Config())

    result = _by_name(off)["plain"]
    assert result.verdict is Verdict.ALLOW
    assert not result.signals  # sin L0/L1/L2/L3: paquete establecido limpio
    # CLEAN tampoco emite senal L3 ⇒ identico al modo desactivado.
    assert off == clean


def test_layer3_desactivado_no_consulta_fuente(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R5.3/R8.2: source None ⇒ `resolve_threatintel` no consulta ningun lote (sin hosts)."""
    outcomes = {"plain": _found("plain")}
    source = _StubSource()
    # Aun instalando una fuente espia, el modo None debe ignorarla: se simula None directo.
    _install(monkeypatch, outcomes, top_n, None)
    scan_dependencies(_deps("plain"), Config())
    assert source.calls == []  # la fuente espia jamas se invoco


# ===========================================================================
# now_epoch unico tras el batch (NFR-Det.1)
# ===========================================================================


def test_now_epoch_unico_con_batch_intercalado(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """NFR-Det.1: el reloj se lee UNA vez por corrida pese al batch intercalado.

    La fuente stub no toca `engine.time.time`; el unico lector es `_scan` (now_epoch)."""
    calls = {"n": 0}

    def clock() -> float:
        calls["n"] += 1
        return _NOW

    monkeypatch.setattr(_ENGINE_TIME, clock)
    outcomes = {n: _found(n) for n in ("uno", "dos", "tres")}
    _install(monkeypatch, outcomes, top_n, _StubSource())

    scan_dependencies(_deps("uno", "dos", "tres"), Config())

    assert calls["n"] == 1


# ===========================================================================
# CLI / render: JSON schema 1.1 + saneo (§2.4, §3.7, R7.3/R7.4)
#
# Helpers que producen un ScanReport real con una dep MALICIOUS, para alimentar
# los renderers reales de la CLI sin red.
# ===========================================================================


def _malicious_report(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset, advisory_id: str
) -> ScanReport:
    """ScanReport real de una unica dep MALICIOUS (para los tests de render)."""
    outcomes = {"evilpkg": _found("evilpkg")}
    _install(monkeypatch, outcomes, top_n, _StubSource({"evilpkg": _mal("evilpkg", advisory_id)}))
    return scan_dependencies(_deps("evilpkg"), Config())


def test_json_schema_version_1_1(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§2.4: el JSON de salida declara `schema_version == "1.2"` (aditivo sobre 1.0)."""
    report = _malicious_report(monkeypatch, top_n, "MAL-2025-1111")
    payload = render_json(report)
    assert '"schema_version": "1.2"' in payload


def test_json_sin_timestamps_de_reloj(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.3/R6.3: el JSON es determinista, sin timestamps de reloj (fecha/hora ISO).

    Busca patrones tipo `2026-06-22T...` o `12:34:56`: ninguno debe aparecer (el reporte
    no embebe la hora de pared). Las cadenas de atribucion de fecha del corpus no entran
    aqui (dep MALICIOUS sin watchlist), aislando el determinismo del reloj.
    """
    report = _malicious_report(monkeypatch, top_n, "MAL-2025-2222")
    payload = render_json(report)
    assert not re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", payload)  # ISO datetime
    assert not re.search(r"\b\d{2}:\d{2}:\d{2}\b", payload)  # hora de reloj


def test_render_humano_sanea_id_malicioso(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.4: un ID MAL-* con ANSI inyectado se neutraliza en el render humano.

    El detail de la senal L3 porta el ID; el render lo sanea con `sanitize_for_output`,
    asi que la salida humana muestra el ID limpio y JAMAS la secuencia de escape cruda.
    """
    report = _malicious_report(monkeypatch, top_n, f"MAL-2025-3333{_ANSI}")
    buf = io.StringIO()
    render_human(report, out=buf)
    text = buf.getvalue()

    assert _ANSI not in text  # ninguna secuencia de escape cruda sobrevive
    assert "MAL-2025-3333" in text  # el ID saneado si aparece
    assert "BLOQUEAR" in text  # accion de bloqueo presente (R7.1)


def test_render_json_sanea_id_malicioso(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R7.4: el ID MAL-* con ANSI inyectado tambien se sanea en el JSON (detail de senal)."""
    report = _malicious_report(monkeypatch, top_n, f"MAL-2025-4444{_ANSI}")
    payload = render_json(report)

    assert "\x1b" not in payload  # JSON sin ESC crudo
    assert "MAL-2025-4444" in payload


def test_json_valido_con_layer3_desactivado(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """NFR-Compat.1: con source None el JSON sigue siendo valido y schema 1.1.

    Un lector 1.0 ignora `schema_version` y las claves nuevas; el reporte de una dep
    limpia sin Capa 3 serializa sin error y declara la version 1.1.
    """
    outcomes = {"plain": _found("plain")}
    _install(monkeypatch, outcomes, top_n, None)
    report = scan_dependencies(_deps("plain"), Config())

    payload = render_json(report)
    parsed = json.loads(payload)  # JSON valido (no lanza)
    assert parsed["schema_version"] == "1.2"
    assert parsed["results"][0]["verdict"] == "allow"


# ===========================================================================
# CLI/render clave advisories[] + flags Capa 3 (H2-T14 implementado)
# ===========================================================================


def test_json_clave_advisories_estable(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§2.4 (H2-T14): cada result expone la clave advisories (siempre presente, [] sin malicia)."""
    report = _malicious_report(monkeypatch, top_n, "MAL-2025-5555")
    parsed = json.loads(render_json(report))
    result = parsed["results"][0]
    assert "advisories" in result  # clave estable del schema 1.1
    assert result["advisories"][0]["id"] == "MAL-2025-5555"
    assert result["advisories"][0]["url"].endswith("MAL-2025-5555")


def test_render_humano_muestra_enlace_advisory(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """§3.7/R7.1 (H2-T14): el bloque humano de advisories MAL-* incluye el enlace canonico OSV."""
    report = _malicious_report(monkeypatch, top_n, "MAL-2025-6666")
    buf = io.StringIO()
    render_human(report, out=buf)
    assert "https://osv.dev/vulnerability/MAL-2025-6666" in buf.getvalue()


def test_cli_flags_layer3_cableados() -> None:
    """§3.7/R5.1 (H2-T14): `--no-layer3` y `--enable-watchlist` existen y se parsean sin error."""
    parser = cli_main._build_parser()  # introspeccion del parser real de la CLI
    args = parser.parse_args(["scan", "-", "--no-layer3", "--enable-watchlist"])
    assert args.no_layer3 is True
    assert args.enable_watchlist is True
