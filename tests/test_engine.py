"""Pruebas de integracion del orquestador `core.engine` y la fachada (T33).

Ejercitan el flujo COMPLETO manifiesto/stdin/lote -> parse+dedup+includes ->
fetch concurrente -> capas 0/1/2 -> scoring -> verdict -> `ScanReport` inmutable y
ordenado, SIN tocar la red. El unico borde simulado es el adapter: un
`_StubAdapter` determinista en memoria (implementa `EcosystemAdapter`) que mapea
FOUND/NOT_FOUND/UNVERIFIABLE por nombre y expone un `TopNDataset` de fixture. Las
capas, el scoring y el ensamblado son los reales (integracion del cableado, no
mocks de la logica de dominio).

`get_adapter` se monkeypatchea en el modulo `engine` para inyectar el stub sin
cambiar la API publica §3.1; `engine.time.time` se fija para que la edad (Capa 0)
sea reproducible y para verificar que `now_epoch` se inyecta UNA sola vez por
corrida (NFR-Det.1). Frontera: este test importa SOLO la fachada `slopguard.core`
para la API publica (R10.3) y `adapters.base`/`dataset.top_n` para construir el
stub; nunca toca `cli`.

EARS cubiertos: R1.6, R1.7, R2.2, R3.8, R5.2, R5.6, R5.7, R5.8, R6.4, R6.5, R7.5,
NFR-Det.1, NFR-Degr.1, §3.1, §3.6.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import slopguard.core as facade
from slopguard.core import (
    Config,
    Dependency,
    ErrorCategory,
    ScanReport,
    Status,
    Verdict,
    scan_dependencies,
    scan_manifest,
    scan_stdin,
)
from slopguard.core.adapters.base import FetchOutcome, FetchState, PackageMetadata
from slopguard.core.dataset.top_n import TopNDataset, build_top_n
from slopguard.core.errors import DatasetIntegrityError

if TYPE_CHECKING:
    from collections.abc import Iterable

# Ruta del símbolo a parchear (mypy-strict friendly, igual que test_concurrent.py).
_GET_ADAPTER = "slopguard.core.engine.get_adapter"
_ENGINE_TIME = "slopguard.core.engine.time.time"
# Factory de la fuente de Capa 3 (Hito 2). Estos tests del Hito 1 NO ejercitan
# threat-intel: se neutraliza a None (modo solo-deterministas) para que el flujo sea
# idéntico al Hito 1 (enable_layer3=false ⇒ ti={}). Los tests de intercalado L3 viven
# en `test_h2_engine.py` e inyectan su propia fuente stub.
_GET_TI_SOURCE = "slopguard.core.engine.get_threatintel_source"

# Epoch fijo (2024-06-01T00:00:00Z): edad reproducible en Capa 0 (NFR-Det.1).
_NOW = 1_717_200_000.0
_DAY = 86_400.0
_NEW_EPOCH = _NOW - 5 * _DAY  # 5 dias: por debajo de edad_minima_dias (90)
_OLD_EPOCH = _NOW - 400 * _DAY  # paquete establecido

# Dataset top-N de fixture: nombres populares para disparar Capa 1 por cercania.
_TOP_N_NAMES = ["requests", "flask", "numpy", "pandas", "urllib3", "pytest"]


# ---------------------------------------------------------------------------
# Dobles de prueba
# ---------------------------------------------------------------------------


def _meta(
    name: str,
    *,
    first_release_epoch: float | None = None,
    releases_count: int = 50,
    has_repo_url: bool = True,
    has_description: bool = True,
    has_author: bool = True,
    has_license: bool = True,
    has_classifiers: bool = True,
    in_top_n: bool = False,
) -> PackageMetadata:
    """Construye `PackageMetadata` normalizado para un FOUND de stub."""
    return PackageMetadata(
        name=name,
        first_release_epoch=first_release_epoch,
        releases_count=releases_count,
        has_repo_url=has_repo_url,
        has_description=has_description,
        has_author=has_author,
        has_license=has_license,
        has_classifiers=has_classifiers,
        in_top_n=in_top_n,
    )


def _found(name: str, **kwargs: object) -> FetchOutcome:
    return FetchOutcome(state=FetchState.FOUND, metadata=_meta(name, **kwargs))  # type: ignore[arg-type]


_NOT_FOUND = FetchOutcome(state=FetchState.NOT_FOUND)
_UNVERIFIABLE = FetchOutcome(
    state=FetchState.UNVERIFIABLE,
    error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
)


class _StubAdapter:
    """Adapter `EcosystemAdapter` en memoria, sin red ni reintentos.

    NO implementa `fetch_attempt`, asi que `fetch_many` cae a `fetch()` directo
    (sin reloj ni backoff): el escaneo es rapido y determinista. Mapea cada nombre
    NORMALIZADO a un `FetchOutcome` predefinido; los nombres ausentes del guion se
    degradan a UNVERIFIABLE (defensa, no deberia ocurrir en los tests).
    """

    ecosystem_id = "pypi"

    def __init__(self, outcomes: dict[str, FetchOutcome], top_n: TopNDataset) -> None:
        self._outcomes = outcomes
        self._top_n = top_n
        self.fetched: list[str] = []  # registro para verificar dedup/normalizacion

    def normalize_name(self, raw: str) -> str:
        return raw.strip().lower().replace("_", "-").replace(".", "-")

    def fetch(self, name: str) -> FetchOutcome:
        self.fetched.append(name)
        return self._outcomes.get(name, _UNVERIFIABLE)

    def load_top_n(self) -> TopNDataset:
        return self._top_n

    @property
    def candidate_filter(self) -> None:  # H4-T23: PyPI = filtro identidad (ADR-4).
        return None

    def get_downloads(self, name: str) -> None:  # pragma: no cover - hook reservado
        return None


class _RaisingAdapter:
    """Adapter cuyo `fetch` lanza una operacional total desde el worker (§3.6).

    Simula que `fetch_many` re-lanza un `DatasetIntegrityError` (p.ej. dataset
    corrupto detectado tarde) para verificar que el engine lo colapsa a un
    `ScanReport` con `error_category`, sin filtrar el mensaje crudo (R6.5).
    """

    ecosystem_id = "pypi"
    leaky_path = "/home/victima/.cache/slopguard/dataset.json"

    def __init__(self, top_n: TopNDataset) -> None:
        self._top_n = top_n

    def normalize_name(self, raw: str) -> str:
        return raw.strip().lower()

    def fetch(self, name: str) -> FetchOutcome:
        raise DatasetIntegrityError(f"checksum invalido en {self.leaky_path}")

    def load_top_n(self) -> TopNDataset:  # pragma: no cover - no se llega
        return self._top_n

    @property
    def candidate_filter(self) -> None:  # pragma: no cover - fetch lanza antes de Capa 1
        return None

    def get_downloads(self, name: str) -> None:  # pragma: no cover - hook reservado
        return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def top_n() -> TopNDataset:
    """Dataset top-N de fixture, ya normalizado e indexado (build_top_n real)."""
    return build_top_n(_TOP_N_NAMES, version="test", generated_at="test")


@pytest.fixture(autouse=True)
def _frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fija `engine.time.time` para que la edad de Capa 0 sea reproducible.

    Cuenta las invocaciones para asertar que `now_epoch` se lee UNA sola vez por
    corrida (NFR-Det.1): ver `test_now_epoch_se_inyecta_una_sola_vez`.
    """
    monkeypatch.setattr(_ENGINE_TIME, lambda: _NOW)


@pytest.fixture(autouse=True)
def _disable_layer3(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutraliza la Capa 3 (threat-intel) en los tests del Hito 1.

    Parchea `engine.get_threatintel_source` para devolver None: `resolve_threatintel`
    retorna `{}` sin tocar red ni caché, de modo que el flujo es IDÉNTICO al Hito 1
    (enable_layer3=false ⇒ ti={}). Sin esto, el `Config()` por defecto
    (`enable_layer3=True`) instanciaría `OsvSource` real e intentaría consultar OSV,
    rompiendo el aislamiento sin red de estas integraciones. El intercalado de Capa 3
    se prueba en `test_h2_engine.py` con una fuente stub inyectada.
    """
    monkeypatch.setattr(_GET_TI_SOURCE, lambda *a, **k: None)


def _install_stub(
    monkeypatch: pytest.MonkeyPatch,
    outcomes: dict[str, FetchOutcome],
    top_n: TopNDataset,
) -> _StubAdapter:
    """Inyecta un `_StubAdapter` via `engine.get_adapter` (sin red)."""
    stub = _StubAdapter(outcomes, top_n)
    monkeypatch.setattr(_GET_ADAPTER, lambda *a, **k: stub)
    return stub


def _write(tmp_path: Path, name: str, content: str) -> Path:
    """Escribe un manifiesto temporal y devuelve su ruta."""
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def _by_name(report: ScanReport) -> dict[str, object]:
    """Indexa los resultados del reporte por nombre para asertar por paquete."""
    return {r.name: r for r in report.results}


# ===========================================================================
# (e) Manifiesto vacio -> 0 resultados, exit 0 (R1.7)
# ===========================================================================


def test_manifiesto_vacio_cero_resultados_exit_0(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, top_n: TopNDataset
) -> None:
    """R1.7: manifiesto sin dependencias => summary todo 0 y exit 0."""
    _install_stub(monkeypatch, {}, top_n)
    path = _write(tmp_path, "requirements.txt", "# solo comentarios\n\n")

    report = scan_manifest(path, Config())

    assert report.results == ()
    assert report.summary.total == 0
    assert report.summary.exit_code == 0
    assert report.error_category is None


def test_lote_vacio_low_level_exit_0(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R1.7: `scan_dependencies([])` => reporte vacio, exit 0."""
    _install_stub(monkeypatch, {}, top_n)

    report = scan_dependencies([], Config())

    assert report.summary.total == 0
    assert report.summary.exit_code == 0


# ===========================================================================
# (a) Typosquat cercano a top-N -> block (R3.x, R5.2/R5.3, ADR-01)
# ===========================================================================


def test_typosquat_dl1_nuevo_y_debil_block(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, top_n: TopNDataset
) -> None:
    """(a) Nombre a dl=1 de 'requests' + recien publicado + metadatos debiles
    => score >= umbral_block => verdict=block, suspected_target='requests'."""
    outcomes = {
        "reqursts": _found(
            "reqursts",
            first_release_epoch=_NEW_EPOCH,
            releases_count=1,
            has_repo_url=False,
            has_description=False,
            has_author=False,
            has_license=False,
            has_classifiers=False,
        ),
    }
    _install_stub(monkeypatch, outcomes, top_n)
    path = _write(tmp_path, "requirements.txt", "reqursts==1.0.0\n")

    report = scan_manifest(path, Config())
    result = _by_name(report)["reqursts"]

    assert result.verdict is Verdict.BLOCK  # type: ignore[attr-defined]
    assert result.status is Status.OK  # type: ignore[attr-defined]
    assert result.suspected_target == "requests"  # type: ignore[attr-defined]
    assert report.summary.block == 1
    assert report.summary.exit_code == 2  # block domina (R7.5)


# ===========================================================================
# (b) Paquete nuevo legitimo -> allow (no bloquea por novedad, R5.6)
# ===========================================================================


def test_paquete_nuevo_legitimo_allow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, top_n: TopNDataset
) -> None:
    """(b) FOUND, edad < edad_minima_dias, con repo+metadatos, sin typosquat
    => solo NEW_PACKAGE (blanda, 15) < umbral_warn => allow (R5.6)."""
    outcomes = {
        "brandnewlib": _found(
            "brandnewlib",
            first_release_epoch=_NEW_EPOCH,
            releases_count=3,
        ),
    }
    _install_stub(monkeypatch, outcomes, top_n)
    path = _write(tmp_path, "requirements.txt", "brandnewlib==0.1.0\n")

    report = scan_manifest(path, Config())
    result = _by_name(report)["brandnewlib"]

    assert result.verdict is Verdict.ALLOW  # type: ignore[attr-defined]
    assert result.status is Status.OK  # type: ignore[attr-defined]
    assert result.score is not None and result.score < Config().umbral_warn  # type: ignore[attr-defined]
    assert report.summary.exit_code == 0


# ===========================================================================
# (c) 404 -> block override, score=None (R2.2, R5.2)
# ===========================================================================


def test_inexistente_404_block_override_sin_score(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, top_n: TopNDataset
) -> None:
    """(c) NOT_FOUND => override NONEXISTENT: verdict=block, score=None, status=ok."""
    outcomes = {"fantasmapkg": _NOT_FOUND}
    _install_stub(monkeypatch, outcomes, top_n)
    path = _write(tmp_path, "requirements.txt", "fantasmapkg\n")

    report = scan_manifest(path, Config())
    result = _by_name(report)["fantasmapkg"]

    assert result.verdict is Verdict.BLOCK  # type: ignore[attr-defined]
    assert result.score is None  # type: ignore[attr-defined]
    assert result.status is Status.OK  # type: ignore[attr-defined]  # verificacion SI se completo
    assert report.summary.exit_code == 2


def test_inexistente_en_top_n_anota_dataset_desactualizado(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, top_n: TopNDataset
) -> None:
    """R3.8: paquete del top-N que ahora devuelve 404 => Capa 0 prevalece (block) y
    se anota el posible desfase del dataset embebido."""
    outcomes = {"requests": _NOT_FOUND}
    _install_stub(monkeypatch, outcomes, top_n)
    path = _write(tmp_path, "requirements.txt", "requests\n")

    report = scan_manifest(path, Config())
    result = _by_name(report)["requests"]

    assert result.verdict is Verdict.BLOCK  # type: ignore[attr-defined]
    details = " ".join(s.detail for s in result.signals)  # type: ignore[attr-defined]
    assert "dataset" in details.lower()  # nota de desfase (R3.8)


# ===========================================================================
# (d) UNVERIFIABLE -> status unverifiable, nunca allow, exit incluye 3 (R5.8)
# ===========================================================================


def test_unverifiable_nunca_allow_exit_3(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, top_n: TopNDataset
) -> None:
    """(d) FetchOutcome UNVERIFIABLE => verdict=None, score=None, status=unverifiable;
    nunca allow; el exit incluye 3 (NFR-Degr.1, R5.8/R7.5)."""
    outcomes = {"flakypkg": _UNVERIFIABLE}
    _install_stub(monkeypatch, outcomes, top_n)
    path = _write(tmp_path, "requirements.txt", "flakypkg\n")

    report = scan_manifest(path, Config())
    result = _by_name(report)["flakypkg"]

    assert result.status is Status.UNVERIFIABLE  # type: ignore[attr-defined]
    assert result.verdict is None  # type: ignore[attr-defined]
    assert result.score is None  # type: ignore[attr-defined]
    assert result.error_category is ErrorCategory.NETWORK_UNVERIFIABLE  # type: ignore[attr-defined]
    assert report.summary.unverifiable == 1
    assert report.summary.exit_code == 3


def test_unverifiable_outcome_ausente_se_degrada(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """Defensa: si `fetch_many` no devolviera outcome para un nombre, el engine lo
    degrada a unverifiable (nunca allow) en vez de crashear."""
    # El stub devuelve UNVERIFIABLE por defecto para nombres ausentes del guion.
    _install_stub(monkeypatch, {}, top_n)
    dep = Dependency(name="huerfano", version_pin=None, raw="huerfano", origin="x")

    report = scan_dependencies([dep], Config())
    result = _by_name(report)["huerfano"]

    assert result.status is Status.UNVERIFIABLE  # type: ignore[attr-defined]


# ===========================================================================
# (f) ManifestParseError (include con ../) -> ScanReport sin stacktrace (§3.6)
# ===========================================================================


def test_include_escapado_error_category_sin_stacktrace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, top_n: TopNDataset
) -> None:
    """(f) Un include `-r ../escape.txt` que sale del arbol => ManifestParseError
    colapsado a ScanReport(error_category=manifest_parse), results vacios, exit 3,
    SIN stacktrace ni ruta absoluta filtrada (R1.6, §3.6, R6.5)."""
    _install_stub(monkeypatch, {}, top_n)
    # Manifiesto cuyo include escapa del arbol del proyecto (anti path-escape).
    path = _write(tmp_path, "requirements.txt", "-r ../escape.txt\n")

    report = scan_manifest(path, Config())

    assert report.error_category is ErrorCategory.MANIFEST_PARSE
    assert report.results == ()
    assert report.summary.exit_code == 3
    # R6.5: el reporte estructurado NO arrastra el mensaje crudo ni la ruta absoluta.
    assert "Traceback" not in repr(report)
    assert str(tmp_path) not in repr(report)


def test_manifiesto_inexistente_error_category(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, top_n: TopNDataset
) -> None:
    """Un archivo de manifiesto ausente => ManifestParseError => exit 3 limpio."""
    _install_stub(monkeypatch, {}, top_n)
    path = tmp_path / "no_existe.txt"

    report = scan_manifest(path, Config())

    assert report.error_category is ErrorCategory.MANIFEST_PARSE
    assert report.summary.exit_code == 3


# ===========================================================================
# Error operacional total desde un worker -> ScanReport sin filtrar mensaje (§3.6)
# ===========================================================================


def test_error_operacional_desde_worker_no_filtra_mensaje(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """Una operacional total re-lanzada por `fetch_many` (DatasetIntegrityError)
    => ScanReport con error_category=dataset_integrity, results vacios, exit 3, y el
    mensaje crudo/ruta del adapter NUNCA aparece en el reporte (R6.5, §3.6)."""
    stub = _RaisingAdapter(top_n)
    monkeypatch.setattr(_GET_ADAPTER, lambda *a, **k: stub)
    dep = Dependency(name="cualquiera", version_pin=None, raw="cualquiera", origin="x")

    report = scan_dependencies([dep], Config())

    assert report.error_category is ErrorCategory.DATASET_INTEGRITY
    assert report.results == ()
    assert report.summary.exit_code == 3
    assert _RaisingAdapter.leaky_path not in repr(report)


# ===========================================================================
# (g) Orden total (R6.4) + determinismo bajo permutacion (R5.7)
# ===========================================================================


def _mixed_outcomes() -> dict[str, FetchOutcome]:
    """Lote que produce un resultado de cada clase (unverifiable/block/warn/allow)."""
    return {
        # allow: nuevo legitimo, sin typosquat.
        "zlegitimo": _found("zlegitimo", first_release_epoch=_NEW_EPOCH, releases_count=5),
        # warn: typosquat dl=2 establecido (pandsa~pandas) => score 60.
        "pandsa": _found("pandsa", first_release_epoch=_OLD_EPOCH, releases_count=80),
        # block: 404 override.
        "ablock": _NOT_FOUND,
        # unverifiable: red no verificable.
        "munverif": _UNVERIFIABLE,
    }


def test_orden_unverifiable_block_warn_allow_y_nombre(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """(g) R6.4: orden unverifiable -> block -> warn -> allow, luego nombre asc."""
    outcomes = _mixed_outcomes()
    _install_stub(monkeypatch, outcomes, top_n)
    deps = [
        Dependency(name=n, version_pin=None, raw=n, origin="x")
        for n in ("zlegitimo", "pandsa", "ablock", "munverif")
    ]

    report = scan_dependencies(deps, Config())
    order = [r.name for r in report.results]

    assert order == ["munverif", "ablock", "pandsa", "zlegitimo"]
    assert report.summary.unverifiable == 1
    assert report.summary.block == 1
    assert report.summary.warn == 1
    assert report.summary.allow == 1
    # block domina la precedencia de exit aunque haya unverifiable (R7.5).
    assert report.summary.exit_code == 2


def test_determinismo_bajo_permutacion_del_lote(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """(g) R5.7: permutar el orden de entrada produce un ScanReport IDENTICO."""
    outcomes = _mixed_outcomes()
    names = list(outcomes.keys())

    def run(order: Iterable[str]) -> ScanReport:
        # Cada corrida reinstala un stub fresco (mismo guion) para aislar estado.
        _install_stub(monkeypatch, dict(outcomes), top_n)
        deps = [
            Dependency(name=n, version_pin=None, raw=n, origin="x") for n in order
        ]
        return scan_dependencies(deps, Config())

    baseline = run(names)
    for permuted in ([*reversed(names)], [names[2], names[0], names[3], names[1]]):
        assert run(permuted) == baseline  # frozen dataclasses => igualdad estructural


# ===========================================================================
# (h) now_epoch inyectado UNA sola vez (NFR-Det.1)
# ===========================================================================


def test_now_epoch_se_inyecta_una_sola_vez(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """(h) NFR-Det.1: el reloj se lee UNA vez por corrida y la edad es reproducible.

    Cuenta las llamadas a `engine.time.time`: debe ser exactamente 1 aunque el lote
    tenga varias dependencias (la edad de todas usa el mismo `now_epoch`)."""
    calls = {"n": 0}

    def clock() -> float:
        calls["n"] += 1
        return _NOW

    monkeypatch.setattr(_ENGINE_TIME, clock)
    outcomes = {
        "newa": _found("newa", first_release_epoch=_NEW_EPOCH, releases_count=2),
        "newb": _found("newb", first_release_epoch=_NEW_EPOCH, releases_count=2),
    }
    _install_stub(monkeypatch, outcomes, top_n)
    deps = [
        Dependency(name=n, version_pin=None, raw=n, origin="x") for n in ("newa", "newb")
    ]

    first = scan_dependencies(deps, Config())
    assert calls["n"] == 1  # una sola lectura del reloj por corrida

    # Reproducibilidad: una segunda corrida con el reloj fijo da el mismo reporte.
    calls["n"] = 0
    _install_stub(monkeypatch, dict(outcomes), top_n)
    second = scan_dependencies(deps, Config())
    assert first == second


# ===========================================================================
# scan_dependencies: normalizacion + dedup de bajo nivel (fix yellow #3)
# ===========================================================================


def test_scan_dependencies_normaliza_nombres_sin_normalizar(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """`scan_dependencies` normaliza nombres no canonicos antes de evaluar: un
    'Flask' (sin normalizar) matchea el outcome indexado por 'flask' y resuelve a
    allow en vez de degradarse silenciosamente a unverifiable."""
    outcomes = {"flask": _found("flask", releases_count=200, in_top_n=True)}
    stub = _install_stub(monkeypatch, outcomes, top_n)
    dep = Dependency(name="Flask", version_pin=None, raw="Flask", origin="x")

    report = scan_dependencies([dep], Config())

    assert report.results[0].name == "flask"  # nombre canonico en el resultado
    assert report.results[0].status is Status.OK
    assert "flask" in stub.fetched  # el adapter recibio el nombre normalizado


def test_scan_dependencies_dedup_colision_normalizada(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """Dos deps que colapsan al mismo nombre normalizado ('Flask' y 'flask')
    producen UN solo resultado: se preserva la unicidad de nombres que asume el
    orden total (R5.7) y no se emiten dos filas con el mismo nombre."""
    outcomes = {"flask": _found("flask", releases_count=200, in_top_n=True)}
    _install_stub(monkeypatch, outcomes, top_n)
    deps = [
        Dependency(name="Flask", version_pin="==1.0", raw="Flask", origin="x"),
        Dependency(name="flask", version_pin="==2.0", raw="flask", origin="y"),
    ]

    report = scan_dependencies(deps, Config())

    assert len(report.results) == 1
    assert report.results[0].name == "flask"
    # Precedencia: se conserva el primer registro (version_pin del primer 'Flask').
    assert report.results[0].version_pin == "==1.0"


# ===========================================================================
# scan_stdin: flujo pip-freeze en memoria (R1.3)
# ===========================================================================


def test_scan_stdin_flujo_freeze(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R1.3/§3.1: `scan_stdin` parsea texto pip-freeze y produce un ScanReport."""
    outcomes = {
        "requests": _found("requests", releases_count=200, in_top_n=True),
        "fantasma": _NOT_FOUND,
    }
    _install_stub(monkeypatch, outcomes, top_n)

    report = scan_stdin("requests==2.31.0\nfantasma==9.9.9\n", Config())
    by_name = _by_name(report)

    assert by_name["requests"].verdict is Verdict.ALLOW  # type: ignore[attr-defined]
    assert by_name["fantasma"].verdict is Verdict.BLOCK  # type: ignore[attr-defined]
    assert report.summary.exit_code == 2


def test_scan_stdin_excede_tamano_maximo(
    monkeypatch: pytest.MonkeyPatch, top_n: TopNDataset
) -> None:
    """R1.9: stdin que supera `max_manifest_bytes` => error_category manifest_parse."""
    _install_stub(monkeypatch, {}, top_n)
    cfg = Config(max_manifest_bytes=10)

    report = scan_stdin("a" * 100, cfg)

    assert report.error_category is ErrorCategory.MANIFEST_PARSE
    assert report.summary.exit_code == 3


# ===========================================================================
# manifest_type override (fix yellow #1) + fachada expone la API publica
# ===========================================================================


def test_manifest_type_fuerza_parser_freeze(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, top_n: TopNDataset
) -> None:
    """`manifest_type='freeze'` fuerza el parser pip-freeze sobre un archivo cuya
    extension no se autodetectaria como freeze (cablea --manifest-type, T34)."""
    outcomes = {"requests": _found("requests", releases_count=200, in_top_n=True)}
    _install_stub(monkeypatch, outcomes, top_n)
    # Nombre arbitrario (.lock) que NO se autodetecta; el override decide el parser.
    path = _write(tmp_path, "deps.lock", "requests==2.31.0\n")

    report = scan_manifest(path, Config(), manifest_type="freeze")

    assert report.results[0].name == "requests"
    assert report.error_category is None


def test_manifest_type_invalido_error_category(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, top_n: TopNDataset
) -> None:
    """Un `manifest_type` desconocido => ManifestParseError => exit 3 limpio."""
    _install_stub(monkeypatch, {}, top_n)
    path = _write(tmp_path, "requirements.txt", "requests\n")

    report = scan_manifest(path, Config(), manifest_type="inexistente")

    assert report.error_category is ErrorCategory.MANIFEST_PARSE
    assert report.summary.exit_code == 3


def test_fachada_expone_api_publica() -> None:
    """§3.1/R10.3: `import slopguard.core` expone exactamente la API publica."""
    expected = {
        "scan_manifest",
        "scan_stdin",
        "scan_dependencies",
        "load_config",
        "aggregate_exit_code",
    }
    assert expected.issubset(set(facade.__all__))
    for symbol in expected:
        assert callable(getattr(facade, symbol))
