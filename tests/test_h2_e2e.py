"""E2E de la Capa 3 (H2-T20) con servidor local que simula PyPI JSON + OSV querybatch.

Ejercita el camino REAL completo manifiesto/deps -> net -> adapter+OsvSource -> capas
0/1/2/3 -> scoring/verdict (override MALICIOUS) -> ScanReport/exit code, contra UN
servidor `http.server` local que atiende a la vez:

  - `GET  /pypi/<name>/json`   => PyPI JSON API (FOUND / 404 / 503 / hang).
  - `POST /v1/querybatch`      => OSV querybatch (MAL- => MALICIOUS / vacio => CLEAN /
                                  503 / hang), con reensamblado POSICIONAL `results[i]`.
  - `GET  /api/benchmark/hallucinations` => corpus depscope (watchlist, escenario b).

Cada request DUERME una latencia inyectada (~100 ms por defecto) para que las
mediciones de rendimiento (R6.7) sean realistas y el diferencial serial/concurrente
no sea tautologico (mismo criterio que `test_e2e.py` del Hito 1).

CONEXION DEL CAMINO REAL AL SERVIDOR LOCAL (patron de `test_e2e.py`/`test_h2_net_post.py`):
el adapter y `OsvSource`/`WatchlistSource` construyen `SecureHttpClient` fijado a https
contra `pypi.org`/`api.osv.dev`/`depscope.dev`. Para hablar con 127.0.0.1 sin TLS se
monkeypatchea, SOLO dentro de cada test:

  - `http_client.ALLOWED_HOSTS` -> {"127.0.0.1"} y `_ALLOWED_SCHEME` -> "http".
  - `http_client._is_allowed` -> permite http+127.0.0.1 (el efectivo se valida igual).
  - `http_client._reject_port_and_userinfo` -> no-op (loopback usa puerto efimero).
  - `SecureHttpClient.__init__` -> opener con `HTTPHandler` (sin TLS), reusando el
    redirect handler endurecido; acepta `extra_allowed_hosts` (lo necesita OsvSource).
  - `pypi._PYPI_API_BASE` y el `_query_url`/`_url` de las fuentes L3 -> base local.

Fuera del `with` el cliente sigue fijado a https://{pypi.org,api.osv.dev,depscope.dev}
(NFR-Seg.1/3 intactos en produccion). Como el engine construye su propio adapter y su
fuente L3 via `get_adapter`/`get_threatintel_source`, los parches viven durante TODA la
corrida del `scan_*`/`main`.

Trazabilidad EARS:
  - R1.2: FOUND + MAL- en OSV => MALICIOUS, block override, advisory con enlace canonico.
  - R1.4: FOUND + OSV vacio => CLEAN (sin senal L3); el veredicto lo fijan L0/1/2.
  - R1.5/R3.6: NOT_FOUND no consulta OSV (el servidor no recibe el nombre en el batch).
  - R1.6/NFR-Degr.1: FOUND + OSV caido (503/timeout) => THREATINTEL_UNVERIFIABLE,
    status unverifiable, exit 3, JAMAS un falso allow.
  - R2.3: FOUND + match en corpus watchlist (on) => KNOWN_HALLUCINATION, score 85 => block.
  - R3.1/R4.1: precedencia block(2) > unverifiable(3) > warn(1) > allow(0) en una mezcla.
  - R3.5/NFR-Det.1: determinismo bajo permutacion del lote (mismo ScanReport).
  - R5.3: enable_layer3=false => OSV no se consulta (servidor sin POST), salida = Hito 1.
  - R7.3: `--format json` => schema_version 1.1 + advisories[] con clave estable.
  - R6.7: 30 deps cache fria con Capa 3 <= T_ref_h2, medido por DIFERENCIAL no tautologico.
"""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
import time
import urllib.request
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

import slopguard.core.adapters.pypi as pypi_mod
import slopguard.core.net.http_client as http_mod
import slopguard.core.threatintel.osv as osv_mod
import slopguard.core.threatintel.watchlist as watchlist_mod
from slopguard import core as sg
from slopguard.cli import main as cli_main
from slopguard.core.config import Config
from slopguard.core.models import Dependency, ScanReport, SignalCode, Status, Verdict
from slopguard.core.net.http_client import SecureHttpClient

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

# --------------------------------------------------------------------------- #
# Constantes de escenario
# --------------------------------------------------------------------------- #

# Latencia por defecto inyectada por request (representativa de red domestica).
_DEFAULT_LATENCY_S = 0.100

# Numero de dependencias del caso de rendimiento R6.7 (cache fria).
_PERF_DEP_COUNT = 30

# Cota de wall-clock del caso de rendimiento (T_ref_h2 de R6.7).
_T_REF_H2_S = 12.0

# ID malicioso canonico que el OSV simulado devuelve para los nombres "marcados".
_MAL_ID = "MAL-2025-47868"
_MAL_URL = f"https://osv.dev/vulnerability/{_MAL_ID}"


# --------------------------------------------------------------------------- #
# Payloads PyPI FABRICADOS (metadatos normalizables por el adapter real)
# --------------------------------------------------------------------------- #


def _popular_payload(*, first_release_iso: str = "2010-01-01T00:00:00Z") -> dict[str, Any]:
    """Payload de un paquete POPULAR y antiguo: repo, metadatos completos, viejo.

    L2 sin senales y sin NEW_PACKAGE: score 0 => allow, salvo que la Capa 1
    dispare typosquat por el nombre o la Capa 3 lo marque malicioso/alucinado.
    """
    return {
        "info": {
            "summary": "A real, well maintained package.",
            "author": "Maintainer",
            "license": "Apache-2.0",
            "classifiers": ["Programming Language :: Python :: 3"],
            "project_urls": {"Source": "https://github.com/example/pkg"},
        },
        "releases": {
            f"{minor}.0.0": [{"upload_time_iso_8601": first_release_iso}]
            for minor in range(1, 21)  # 20 releases => releases_populares holgado
        },
    }


def _typosquat_payload(*, first_release_iso: str) -> dict[str, Any]:
    """Payload de typosquat: paquete reciente, sin repo, metadatos pobres.

    Con un nombre a DL=1 de un miembro del top-N produce score >= umbral_block
    (TYPOSQUAT 60 dura + NEW_PACKAGE 15 + WEAK_METADATA + LOW_VERIF) => block.
    """
    return {
        "info": {
            "summary": "",
            "author": "",
            "license": "",
            "classifiers": [],
            "project_urls": {},
        },
        "releases": {"0.0.1": [{"upload_time_iso_8601": first_release_iso}]},
    }


def _days_ago_iso(days: int) -> str:
    """ISO 8601 UTC de hace `days` dias (para fabricar edades de release)."""
    epoch = time.time() - days * 86_400
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


# --------------------------------------------------------------------------- #
# Servidor local DUAL: PyPI JSON (GET) + OSV querybatch (POST) + watchlist (GET)
# --------------------------------------------------------------------------- #


class _FakeBackend:
    """Guion compartido del servidor local: PyPI por nombre + OSV por nombre + corpus.

    `pypi` mapea nombre->comportamiento (dict payload | 404 | 503 | "hang").
    `osv` mapea nombre->"mal"|"clean"|"hang"|503 (default "clean": sin advisory).
    `osv_behavior` fuerza un comportamiento GLOBAL del endpoint OSV (503/"hang"),
    para simular OSV totalmente caido sin tocar el guion por-nombre.
    `corpus` es la lista de nombres alucinados del endpoint watchlist (o None=> 503).
    Registra hits para asertar dedup, cobertura y que NOT_FOUND no consulta OSV.
    """

    def __init__(
        self,
        *,
        pypi: dict[str, Any],
        osv: dict[str, str] | None = None,
        osv_behavior: str | None = None,
        corpus: list[str] | None = None,
        latency_s: float = _DEFAULT_LATENCY_S,
    ) -> None:
        self.pypi = pypi
        self.osv = osv or {}
        self.osv_behavior = osv_behavior
        self.corpus = corpus
        self.latency_s = latency_s
        self.port = 0
        self.pypi_hits: dict[str, int] = {}
        self.osv_queried: list[list[str]] = []  # nombres por cada POST a OSV
        self.watchlist_hits = 0
        self._lock = threading.Lock()

    def record_pypi(self, name: str) -> None:
        """Registra un hit a PyPI para `name` de forma thread-safe."""
        with self._lock:
            self.pypi_hits[name] = self.pypi_hits.get(name, 0) + 1

    def record_osv(self, names: list[str]) -> None:
        """Registra los nombres enviados en un POST de OSV (para R1.5 y dedup)."""
        with self._lock:
            self.osv_queried.append(names)

    def osv_names_seen(self) -> set[str]:
        """Conjunto de todos los nombres que llegaron a OSV en cualquier batch."""
        with self._lock:
            return {name for batch in self.osv_queried for name in batch}


def _make_handler(state: _FakeBackend) -> type[http.server.BaseHTTPRequestHandler]:
    """Crea el handler ligado al guion/latencia de `state` (PyPI GET + OSV/watchlist)."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:  # silencia el log del servidor
            return None

        def _send(self, code: int, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            """PyPI `/pypi/<name>/json` o watchlist `/api/benchmark/hallucinations`."""
            time.sleep(state.latency_s)
            if self.path.startswith("/api/benchmark/hallucinations"):
                self._serve_watchlist()
                return
            self._serve_pypi()

        def do_POST(self) -> None:
            """OSV `/v1/querybatch`: reensamblado posicional `results[i] <-> queries[i]`."""
            time.sleep(state.latency_s)
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b""
            if self.path != "/v1/querybatch":
                self._send(404, b'{"error":"not found"}')
                return
            self._serve_osv(raw)

        def _serve_pypi(self) -> None:
            parts = self.path.split("/")
            name = parts[2] if len(parts) > 2 else ""
            state.record_pypi(name)
            behavior = state.pypi.get(name, 404)
            if behavior == "hang":
                time.sleep(30.0)
                return
            if behavior in (404, 503):
                self._send(int(behavior), b'{"error":"x"}')
                return
            assert isinstance(behavior, dict)
            self._send(200, json.dumps(behavior).encode())

        def _serve_osv(self, raw: bytes) -> None:
            names = _osv_query_names(raw)
            state.record_osv(names)
            if state.osv_behavior == "hang":
                time.sleep(30.0)
                return
            if state.osv_behavior == "503":
                self._send(503, b'{"error":"down"}')
                return
            results = [_osv_result_for(state.osv.get(name, "clean")) for name in names]
            self._send(200, json.dumps({"results": results}).encode())

        def _serve_watchlist(self) -> None:
            state.watchlist_hits += 1
            if state.corpus is None:
                self._send(503, b'{"error":"corpus down"}')
                return
            body = {"corpus_date": "2025-06-01", "names": state.corpus}
            self._send(200, json.dumps(body).encode())

    return _Handler


def _osv_query_names(raw: bytes) -> list[str]:
    """Extrae los nombres del cuerpo del querybatch (orden posicional del body)."""
    try:
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return []
    queries = body.get("queries", []) if isinstance(body, dict) else []
    names: list[str] = []
    for query in queries:
        package = query.get("package", {}) if isinstance(query, dict) else {}
        name = package.get("name") if isinstance(package, dict) else None
        names.append(name if isinstance(name, str) else "")
    return names


def _osv_result_for(behavior: str) -> dict[str, Any]:
    """Traduce el comportamiento por-nombre a un `results[i]` del querybatch.

    "mal" => vulns con un id MAL- (=> MALICIOUS); "clean"/otro => {} (=> CLEAN).
    """
    if behavior == "mal":
        return {"vulns": [{"id": _MAL_ID, "modified": "2025-01-01T00:00:00Z"}]}
    return {}


@contextmanager
def _running_backend(state: _FakeBackend) -> Iterator[_FakeBackend]:
    """Levanta el servidor local dual; lo apaga al salir del contexto."""
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _make_handler(state))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.port = server.server_address[1]
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- #
# Conexion del camino REAL al servidor local (parches solo dentro del contexto)
# --------------------------------------------------------------------------- #


def _patched_http_init(
    self: SecureHttpClient, *, extra_allowed_hosts: frozenset[str] = frozenset()
) -> None:
    """`__init__` de SecureHttpClient con HTTPHandler (sin TLS) para 127.0.0.1.

    Acepta `extra_allowed_hosts` (lo pasa OsvSource/WatchlistSource) y reusa el
    redirect handler endurecido y los error handlers de produccion: el unico cambio
    frente al opener real es HTTP en vez de HTTPS. El `_RejectRedirectHandler` recibe
    el conjunto efectivo (base parcheada {"127.0.0.1"} | extra) igual que en produccion;
    `_validate_url` cae a la global (parcheada) por `getattr` cuando no hay `_allowed_hosts`.
    """
    effective = http_mod.ALLOWED_HOSTS | extra_allowed_hosts
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(http_mod._RejectRedirectHandler(effective))
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    self._opener = opener


def _allow_local(
    scheme: str, host: str, allowed_hosts: frozenset[str] | None = None
) -> bool:
    """Permite http+127.0.0.1 (el efectivo se ignora; solo viaja al loopback)."""
    return scheme.lower() == "http" and host == "127.0.0.1"


@contextmanager
def _local_l3_patches(port: int) -> Iterator[None]:
    """Apunta el adapter REAL y las fuentes L3 reales al servidor local.

    Restringe la allowlist a 127.0.0.1/http y reescribe las URLs de PyPI, OSV y
    watchlist al servidor local SOLO dentro de este contexto. Fuera de el, los
    clientes siguen fijados a https://{pypi.org,api.osv.dev,depscope.dev}.
    """
    pypi_base = f"http://127.0.0.1:{port}/pypi/{{name}}/json"
    osv_url = f"http://127.0.0.1:{port}/v1/querybatch"
    watch_url = f"http://127.0.0.1:{port}/api/benchmark/hallucinations"
    orig_osv_init = osv_mod.OsvSource.__init__
    orig_watch_init = watchlist_mod.WatchlistSource.__init__

    def osv_init(
        self: Any, config: Config, *, ecosystem_id: str = "pypi", use_cache: bool = True
    ) -> None:
        orig_osv_init(self, config, ecosystem_id=ecosystem_id, use_cache=use_cache)
        self._query_url = osv_url

    def watch_init(
        self: Any, config: Config, *, ecosystem_id: str = "pypi", use_cache: bool = True
    ) -> None:
        orig_watch_init(self, config, ecosystem_id=ecosystem_id, use_cache=use_cache)
        self._url = watch_url

    with (
        patch.object(http_mod, "ALLOWED_HOSTS", frozenset({"127.0.0.1"})),
        patch.object(http_mod, "_ALLOWED_SCHEME", "http"),
        patch.object(http_mod, "_is_allowed", _allow_local),
        patch.object(http_mod, "_reject_port_and_userinfo", lambda _parts: None),
        patch.object(SecureHttpClient, "__init__", _patched_http_init),
        patch.object(pypi_mod, "_PYPI_API_BASE", pypi_base),
        patch.object(osv_mod.OsvSource, "__init__", osv_init),
        patch.object(watchlist_mod.WatchlistSource, "__init__", watch_init),
    ):
        yield


def _dep(name: str) -> Dependency:
    """Construye una Dependency minima para `scan_dependencies`."""
    return Dependency(name=name, version_pin=None, raw=name, origin="e2e")


def _result_by_name(report: ScanReport, name: str) -> Any:
    """Devuelve el DependencyResult de `name`, fallando si no esta en el reporte."""
    for result in report.results:
        if result.name == name:
            return result
    raise AssertionError(f"'{name}' no esta en el reporte: {[r.name for r in report.results]}")


def _has_signal(result: Any, code: SignalCode) -> bool:
    """True si el resultado contiene una senal con el `SignalCode` dado."""
    return any(signal.code is code for signal in result.signals)


# --------------------------------------------------------------------------- #
# Fixtures: aislan la cache en disco a un HOME temporal (no contamina ~/.cache)
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _isolated_cache_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirige `Path.home()` a un tmp para aislar la cache de disco (cache fria)."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)


# =========================================================================== #
# (a) FOUND + MAL- en OSV => block override + advisory (R1.2, R3.1, R4.1, R7.1)
# =========================================================================== #


def test_e2e_found_mas_mal_es_block_override_con_advisory() -> None:
    """Un paquete que EXISTE en PyPI pero esta MAL- en OSV => block override.

    El paquete es popular/antiguo/completo (L0/1/2 lo dejarian en allow), asi que el
    block proviene EXCLUSIVAMENTE del override MALICIOUS de Capa 3 (R1.2/R3.1): score
    None y un Advisory con el enlace canonico osv.dev. Cierra el camino real
    net -> OsvSource.post_json -> parseo MAL- -> verdict override -> ScanReport.
    """
    state = _FakeBackend(
        pypi={"bioql": _popular_payload()},
        osv={"bioql": "mal"},
    )
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies([_dep("bioql")], Config(), use_cache=False)

    result = _result_by_name(report, "bioql")
    assert result.verdict is Verdict.BLOCK
    assert result.score is None  # override: el veredicto NO viene del score
    assert _has_signal(result, SignalCode.MALICIOUS)
    assert len(result.advisories) == 1
    advisory = result.advisories[0]
    assert advisory.id == _MAL_ID
    assert advisory.url == _MAL_URL  # URL reconstruida, no reflejada del feed
    assert advisory.source == "osv"
    assert sg.aggregate_exit_code(report, strict=False) == 2
    # OSV SI recibio el nombre del paquete existente (R1.1).
    assert "bioql" in state.osv_names_seen()


def test_e2e_found_limpio_en_osv_es_allow_sin_senal_l3() -> None:
    """FOUND + OSV vacio => CLEAN: sin senal L3, el veredicto lo fijan L0/1/2 (R1.4).

    El OSV simulado devuelve `{}` (sin vulns) para el nombre; la Capa 3 no emite
    senal y un paquete popular/completo queda allow. Verifica que un CLEAN real de
    red no introduce falsos positivos ni una senal espuria.
    """
    state = _FakeBackend(pypi={"requests": _popular_payload()}, osv={"requests": "clean"})
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies([_dep("requests")], Config(), use_cache=False)

    result = _result_by_name(report, "requests")
    assert result.verdict is Verdict.ALLOW
    assert not _has_signal(result, SignalCode.MALICIOUS)
    assert not _has_signal(result, SignalCode.THREATINTEL_UNVERIFIABLE)
    assert result.advisories == ()
    assert sg.aggregate_exit_code(report, strict=False) == 0


# =========================================================================== #
# (e) NOT_FOUND => no consulta OSV (R1.5/R3.6)
# =========================================================================== #


def test_e2e_not_found_no_consulta_osv() -> None:
    """Un 404 en PyPI domina con su override y NO viaja a OSV (R1.5).

    El paquete inexistente produce block por inexistencia (Capa 0); como no existe,
    su nombre nunca entra al batch OSV: el servidor no lo ve en ningun querybatch.
    """
    state = _FakeBackend(pypi={"ghost-pkg-xyz": 404}, osv={})
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies([_dep("ghost-pkg-xyz")], Config(), use_cache=False)

    result = _result_by_name(report, "ghost-pkg-xyz")
    assert result.verdict is Verdict.BLOCK  # override por inexistencia (Capa 0)
    assert "ghost-pkg-xyz" not in state.osv_names_seen()  # jamas consulto OSV (R1.5)
    assert sg.aggregate_exit_code(report, strict=False) == 2


def test_e2e_solo_found_van_al_batch_osv() -> None:
    """En una mezcla, SOLO los FOUND llegan al batch OSV (R1.5): 404 y caido excluidos."""
    state = _FakeBackend(
        pypi={
            "requests": _popular_payload(),
            "ghost": 404,
            "down": 503,
        },
        osv={"requests": "clean"},
    )
    config = Config(reintentos_red=0, timeout_total_por_dep_s=2.0)
    deps = [_dep("requests"), _dep("ghost"), _dep("down")]
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies(deps, config, use_cache=False)

    seen = state.osv_names_seen()
    assert "requests" in seen  # FOUND => consultado
    assert "ghost" not in seen  # NOT_FOUND => excluido (R1.5)
    assert "down" not in seen  # UNVERIFIABLE de Capa 0 => excluido (R1.5)
    assert _result_by_name(report, "requests").verdict is Verdict.ALLOW


# =========================================================================== #
# (c) FOUND limpio + OSV caido => unverifiable exit 3, NUNCA un falso allow
#     (R1.6, R4.2, NFR-Degr.1, ADR-10)
# =========================================================================== #


def test_e2e_found_con_osv_503_es_unverifiable_no_allow() -> None:
    """OSV responde 503 persistente sobre un paquete FOUND limpio => unverifiable.

    El paquete EXISTE y L0/1/2 no lo bloquean (seria allow). Como OSV cae (503 tras
    agotar reintentos), la Capa 3 degrada a THREATINTEL_UNVERIFIABLE: el status pasa
    a unverifiable (sin score) y el exit es 3, JAMAS un falso "todo bien" (NFR-Degr.1).
    """
    state = _FakeBackend(pypi={"requests": _popular_payload()}, osv_behavior="503")
    config = Config(osv_reintentos=1, osv_timeout_total_por_lote_s=3.0)
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies([_dep("requests")], config, use_cache=False)

    result = _result_by_name(report, "requests")
    assert result.status is Status.UNVERIFIABLE
    assert result.verdict is None  # degradacion segura: jamas allow
    assert result.score is None
    assert _has_signal(result, SignalCode.THREATINTEL_UNVERIFIABLE)
    assert sg.aggregate_exit_code(report, strict=False) == 3
    assert report.summary.allow == 0  # el falso "todo allow" jamas ocurre


def test_e2e_found_con_osv_timeout_es_unverifiable_no_allow() -> None:
    """OSV cuelga la respuesta (read timeout) sobre un FOUND limpio => unverifiable.

    Variante de transporte de (c): el endpoint OSV duerme mas que el read_timeout;
    tras agotar el presupuesto por lote la dep queda unverifiable, nunca allow.
    """
    state = _FakeBackend(
        pypi={"flask": _popular_payload()}, osv_behavior="hang", latency_s=0.0
    )
    config = Config(
        connect_timeout_s=0.5,
        read_timeout_s=0.5,
        osv_reintentos=1,
        osv_timeout_total_por_lote_s=2.0,
    )
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies([_dep("flask")], config, use_cache=False)

    result = _result_by_name(report, "flask")
    assert result.status is Status.UNVERIFIABLE
    assert result.verdict is None  # jamas allow ante un timeout de OSV
    assert sg.aggregate_exit_code(report, strict=False) == 3


def test_e2e_block_determinista_domina_osv_caido() -> None:
    """Un typosquat (block por score) coexiste con OSV caido: el block DOMINA (R1.6).

    Verifica que un veredicto block determinista (Capa 1) no se degrada a unverifiable
    porque OSV este caido: la dep sigue block (su capa dura ya decidio), exit 2.
    """
    state = _FakeBackend(
        pypi={"reqursts": _typosquat_payload(first_release_iso=_days_ago_iso(1))},
        osv_behavior="503",
    )
    config = Config(osv_reintentos=0, osv_timeout_total_por_lote_s=2.0)
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies([_dep("reqursts")], config, use_cache=False)

    result = _result_by_name(report, "reqursts")
    assert result.verdict is Verdict.BLOCK  # el block determinista domina al OSV caido
    assert sg.aggregate_exit_code(report, strict=False) == 2


# =========================================================================== #
# (b) FOUND + KNOWN_HALLUCINATION (watchlist on) => block por score 85 (R2.3, ADR-07)
# =========================================================================== #


def test_e2e_watchlist_match_es_known_hallucination_block() -> None:
    """Con la watchlist activa, un nombre del corpus => KNOWN_HALLUCINATION => block.

    El paquete EXISTE y esta limpio en OSV, pero figura en el corpus depscope: la Capa 3
    emite KNOWN_HALLUCINATION (dura, peso 85 >= umbral_block) => block por score (no por
    override). Verifica el camino real GET corpus -> match exacto -> senal -> verdict.
    """
    state = _FakeBackend(
        pypi={"langchain-community-ext": _popular_payload()},
        osv={"langchain-community-ext": "clean"},
        corpus=["langchain-community-ext", "otro-alucinado"],
    )
    config = Config(enable_watchlist=True)
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies(
            [_dep("langchain-community-ext")], config, use_cache=False
        )

    result = _result_by_name(report, "langchain-community-ext")
    assert result.verdict is Verdict.BLOCK
    assert _has_signal(result, SignalCode.KNOWN_HALLUCINATION)
    assert result.score is not None and result.score >= Config().umbral_block
    assert sg.aggregate_exit_code(report, strict=False) == 2


def test_e2e_watchlist_off_no_consulta_corpus() -> None:
    """Con la watchlist DESACTIVADA (default) el corpus depscope nunca se consulta (R2.1)."""
    state = _FakeBackend(
        pypi={"requests": _popular_payload()},
        osv={"requests": "clean"},
        corpus=["requests"],  # aunque el corpus contenga el nombre...
    )
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies([_dep("requests")], Config(), use_cache=False)

    assert state.watchlist_hits == 0  # depscope nunca fue contactado (R2.1)
    result = _result_by_name(report, "requests")
    assert result.verdict is Verdict.ALLOW  # sin watchlist no hay KNOWN_HALLUCINATION
    assert not _has_signal(result, SignalCode.KNOWN_HALLUCINATION)


# =========================================================================== #
# (d) enable_layer3=false => identico al Hito 1, sin tocar OSV (R5.3)
# =========================================================================== #


def test_e2e_layer3_off_no_consulta_osv_comportamiento_hito1() -> None:
    """Con `enable_layer3=false` no se consulta OSV y el resultado es el del Hito 1.

    Un paquete que estaria MAL- en OSV queda allow porque la Capa 3 esta apagada (la
    fuente es None, ti={}); el servidor OSV no recibe ningun POST. Confirma R5.3: el
    modo solo-deterministas no contacta a terceros distintos de PyPI.
    """
    state = _FakeBackend(pypi={"bioql": _popular_payload()}, osv={"bioql": "mal"})
    config = Config(enable_layer3=False)
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies([_dep("bioql")], config, use_cache=False)

    result = _result_by_name(report, "bioql")
    assert result.verdict is Verdict.ALLOW  # Capa 3 apagada: el MAL- de OSV se ignora
    assert not _has_signal(result, SignalCode.MALICIOUS)
    assert result.advisories == ()
    assert state.osv_queried == []  # NUNCA se hizo un POST a OSV (R5.3)
    assert sg.aggregate_exit_code(report, strict=False) == 0


# =========================================================================== #
# (f) Mezcla allow / block(MAL-) / block(typosquat) / unverifiable en una corrida
#     => precedencia de exit code block(2) > unverifiable(3) (R3.1, R4.1)
# =========================================================================== #


def _mixed_backend() -> _FakeBackend:
    """Backend con los cuatro destinos: limpio, MAL-, typosquat y OSV caido por-nombre.

    El OSV simulado responde por-nombre: 'requests' clean, 'bioql' mal. Para forzar un
    unverifiable de Capa 3 SIN tumbar todo OSV, 'isol-clean' usa un OSV global sano pero
    su unverifiable se obtiene por otra via (typosquat domina su rama). Aqui el
    unverifiable proviene del paquete 'down' (503 en Capa 0), distinguible del block.
    """
    return _FakeBackend(
        pypi={
            "requests": _popular_payload(),
            "bioql": _popular_payload(),
            "reqursts": _typosquat_payload(first_release_iso=_days_ago_iso(1)),
            "down": 503,
        },
        osv={"requests": "clean", "bioql": "mal", "reqursts": "clean"},
    )


def test_e2e_mezcla_allow_block_unverifiable_un_solo_scan() -> None:
    """Una corrida con allow, block(MAL- override), block(typosquat) y unverifiable.

    - 'requests' (popular, OSV clean)            => allow
    - 'bioql'    (popular, OSV MAL-)             => block override (Capa 3)
    - 'reqursts' (typosquat DL=1, nuevo+pobre)   => block por score (Capa 1/0/2)
    - 'down'     (503 persistente en PyPI)       => unverifiable (Capa 0)
    El exit agregado prioriza block (2) sobre unverifiable (3) (R4.1).
    """
    state = _mixed_backend()
    config = Config(reintentos_red=0, timeout_total_por_dep_s=2.0)
    deps = [_dep("requests"), _dep("bioql"), _dep("reqursts"), _dep("down")]
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies(deps, config, use_cache=False)

    assert _result_by_name(report, "requests").verdict is Verdict.ALLOW
    bioql = _result_by_name(report, "bioql")
    assert bioql.verdict is Verdict.BLOCK and bioql.score is None  # override MAL-
    assert _has_signal(bioql, SignalCode.MALICIOUS)
    assert _result_by_name(report, "reqursts").verdict is Verdict.BLOCK
    down = _result_by_name(report, "down")
    assert down.status is Status.UNVERIFIABLE and down.verdict is None
    assert sg.aggregate_exit_code(report, strict=False) == 2  # block precede (R4.1)
    assert report.summary.block == 2
    assert report.summary.allow == 1
    assert report.summary.unverifiable == 1


def test_e2e_unverifiable_l3_exit_3_sin_block_distinguible_de_allow() -> None:
    """Sin ningun block, deps FOUND con OSV caido elevan el exit a 3 (R4.2).

    Dos paquetes EXISTEN y L0/1/2 los dejarian en allow, pero OSV cae (503): van en el
    MISMO batch y un fallo de lote degrada AMBOS a THREATINTEL_UNVERIFIABLE (fail-closed
    del chunk, NFR-Degr.1). Sin block presente el exit es 3, distinguible de "todo allow":
    una caida de OSV nunca se reporta como falso bien.
    """
    state = _FakeBackend(
        pypi={"requests": _popular_payload(), "flask": _popular_payload()},
        osv_behavior="503",  # OSV totalmente caido => degrada el lote completo
    )
    config = Config(osv_reintentos=0, osv_timeout_total_por_lote_s=2.0)
    with _running_backend(state), _local_l3_patches(state.port):
        report = sg.scan_dependencies(
            [_dep("requests"), _dep("flask")], config, use_cache=False
        )

    assert all(r.status is Status.UNVERIFIABLE for r in report.results)
    assert all(r.verdict is None for r in report.results)
    assert all(
        _has_signal(r, SignalCode.THREATINTEL_UNVERIFIABLE) for r in report.results
    )
    assert sg.aggregate_exit_code(report, strict=False) == 3
    assert report.summary.allow == 0  # el falso "todo allow" jamas ocurre


# =========================================================================== #
# Determinismo bajo permutacion del lote con Capa 3 viva (R3.5, NFR-Det.1)
# =========================================================================== #


def test_e2e_determinismo_bajo_permutacion_con_capa3() -> None:
    """Permutar el orden de entrada produce EXACTAMENTE el mismo ScanReport (R3.5).

    Con Capa 3 activa (OSV consultado), dos corridas del mismo lote en distinto orden
    deben coincidir en orden de resultados, veredicto/score/status y summary. El batch
    OSV deduplica y el orden final es total, asi el reporte es invariante a la permutacion.
    """
    base = ["requests", "bioql", "reqursts", "down"]
    permuted = ["down", "reqursts", "requests", "bioql"]
    config = Config(reintentos_red=0, timeout_total_por_dep_s=2.0)

    with _running_backend(_mixed_backend()) as state, _local_l3_patches(state.port):
        report_a = sg.scan_dependencies([_dep(n) for n in base], config, use_cache=False)
    with _running_backend(_mixed_backend()) as state, _local_l3_patches(state.port):
        report_b = sg.scan_dependencies(
            [_dep(n) for n in permuted], config, use_cache=False
        )

    assert [r.name for r in report_a.results] == [r.name for r in report_b.results]
    assert [(r.name, r.verdict, r.score, r.status) for r in report_a.results] == [
        (r.name, r.verdict, r.score, r.status) for r in report_b.results
    ]
    assert report_a.summary == report_b.summary


# =========================================================================== #
# (g) CLI e2e: manifiesto -> `main(--format json)` -> schema 1.1 + advisories[]
#     + exit code real del proceso (R7.3, R4.1)
# =========================================================================== #


def test_e2e_cli_json_1_1_con_advisories_y_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`main` sobre un requirements.txt: JSON 1.1 con advisories[] y exit 2 por MAL-.

    Camino REAL completo desde la CLI: parse manifiesto -> engine -> net+OSV local ->
    render JSON. Verifica `schema_version == "1.2"`, el bloque `advisories[]` con clave
    estable {id,kind,url,source} y el exit code 2 del override MALICIOUS (R7.3/R4.1).
    """
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests\nbioql\n", encoding="utf-8")
    state = _FakeBackend(
        pypi={"requests": _popular_payload(), "bioql": _popular_payload()},
        osv={"requests": "clean", "bioql": "mal"},
    )
    argv = ["scan", str(manifest), "--format", "json", "--no-cache"]
    with _running_backend(state), _local_l3_patches(state.port):
        exit_code = cli_main.main(argv)

    assert exit_code == 2  # block override => exit 2 (R4.1)
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "1.2"  # R7.3
    by_name = {r["name"]: r for r in payload["results"]}
    bioql = by_name["bioql"]
    assert bioql["verdict"] == "block"
    assert bioql["score"] is None  # override: sin score
    assert bioql["advisories"] == [
        {"id": _MAL_ID, "kind": "malicious", "url": _MAL_URL, "source": "osv"}
    ]
    # Clave estable presente incluso sin malicia: 'requests' lleva advisories=[] (R7.3).
    assert by_name["requests"]["advisories"] == []


def test_e2e_cli_no_layer3_no_consulta_osv_exit_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`main --no-layer3`: el MAL- de OSV se ignora, exit 0 y OSV jamas consultado (R5.3).

    La bandera `--no-layer3` desactiva la Capa 3; un paquete que estaria MAL- queda
    allow y el servidor OSV no recibe ningun POST (modo solo-deterministas).
    """
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("bioql\n", encoding="utf-8")
    state = _FakeBackend(pypi={"bioql": _popular_payload()}, osv={"bioql": "mal"})
    argv = ["scan", str(manifest), "--format", "json", "--no-cache", "--no-layer3"]
    with _running_backend(state), _local_l3_patches(state.port):
        exit_code = cli_main.main(argv)

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "1.2"  # version sube aunque L3 este off
    assert payload["results"][0]["verdict"] == "allow"
    assert state.osv_queried == []  # ningun POST a OSV (R5.3)


# =========================================================================== #
# RENDIMIENTO R6.7 — 30 deps cache fria con Capa 3 <= T_ref_h2, por DIFERENCIAL
# =========================================================================== #


def _run_perf_scan_l3(
    names: list[str], *, latency_s: float, workers: int
) -> tuple[float, _FakeBackend]:
    """Corre `scan_dependencies` con Capa 3 activa y devuelve (wall-clock, backend).

    Cache fria (`use_cache=False`): cada paquete viaja a PyPI y todo el lote a OSV en
    un querybatch. El `_isolated_cache_home` (autouse) garantiza ausencia de cache previa.
    """
    state = _FakeBackend(
        pypi={name: _popular_payload() for name in names},
        osv={name: "clean" for name in names},
        latency_s=latency_s,
    )
    config = Config(concurrencia_max=workers, osv_timeout_total_por_lote_s=30.0)
    with _running_backend(state), _local_l3_patches(state.port):
        start = time.monotonic()
        report = sg.scan_dependencies(
            [_dep(n) for n in names], config, use_cache=False
        )
        elapsed = time.monotonic() - start
    assert len(report.results) == len(names)
    assert all(r.verdict is Verdict.ALLOW for r in report.results)
    return elapsed, state


def test_e2e_rendimiento_30_deps_capa3_cache_fria_no_tautologico() -> None:
    """R6.7: 30 deps cache fria con Capa 3 <= T_ref_h2, dominado por la latencia simulada.

    QUE MIDE (criterio explicitamente NO tautologico, como el robusto del Hito 1): el
    OVERHEAD DE ORQUESTACION con Capa 3 viva (fetch concurrente de PyPI + un querybatch
    OSV en lote + montaje de capas/scoring), NO el hardware ni la red reales. La "red" es
    un servidor local que DUERME una latencia fija INYECTADA en cada respuesta.

    DIFERENCIAL (anti-tautologia): se corre la MISMA carga con concurrencia 8 y 1. La
    Capa 3 hace UN solo querybatch (su sleep es identico en ambas corridas y se CANCELA
    en la resta); las 30 GET de PyPI las paraleliza el orquestador. El AHORRO
    (serial - concurrente) proviene EXCLUSIVAMENTE de los sleeps de PyPI paralelizados:
    si la herramienta serializara la red, el ahorro seria ~0 y la prueba fallaria. El
    diferencial es robusto en CI ruidoso (ambas corridas pagan el mismo overhead fijo +
    el mismo sleep de OSV).
    """
    latency = _DEFAULT_LATENCY_S
    workers = 8
    names = [f"h2perf{i:02d}" for i in range(_PERF_DEP_COUNT)]

    wall_concurrent, state_c = _run_perf_scan_l3(names, latency_s=latency, workers=workers)
    wall_serial, _ = _run_perf_scan_l3(names, latency_s=latency, workers=1)

    # Cada paquete se consulto exactamente una vez en PyPI (cache fria/dedup).
    assert all(hits == 1 for hits in state_c.pypi_hits.values())
    # OSV se consulto en lote: un unico querybatch cubre los 30 nombres (dedup, R6.6).
    assert len(state_c.osv_queried) == 1
    assert len(state_c.osv_queried[0]) == _PERF_DEP_COUNT

    # Cota SUPERIOR (objetivo literal R6.7): el wall concurrente <= T_ref_h2.
    assert wall_concurrent <= _T_REF_H2_S, (
        f"wall-clock {wall_concurrent:.3f}s excede T_ref_h2={_T_REF_H2_S}s"
    )

    # Cota INFERIOR por DIFERENCIAL (anti-tautologia): el serial paga N sleeps de PyPI;
    # el concurrente paga ceil(N/workers). El sleep del querybatch OSV es el mismo en
    # ambas y se cancela. Piso 0.25x del ahorro ideal de PyPI: muy por debajo del
    # estructural (~2.6 s) para tolerar la contencion de runners CI sin volverlo vacuo.
    serial_batches = -(-_PERF_DEP_COUNT // workers)  # ceil(30/8) = 4
    saved_floor = (_PERF_DEP_COUNT - serial_batches) * latency * 0.25
    latency_savings = wall_serial - wall_concurrent
    assert latency_savings >= saved_floor, (
        f"ahorro por concurrencia {latency_savings:.3f}s "
        f"(serial={wall_serial:.3f}s, concurrente={wall_concurrent:.3f}s) por debajo del "
        f"piso {saved_floor:.3f}s: la red simulada de PyPI no domina o no se paraleliza"
    )
