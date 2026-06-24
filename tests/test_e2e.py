"""Pruebas de integracion e2e con servidor PyPI SIMULADO y latencia inyectada (T38).

Estas pruebas ejercitan el camino REAL completo a traves de la fachada publica
`slopguard.core` (scan_manifest / scan_stdin / scan_dependencies), atravesando
net -> adapter -> capas 0/1/2 -> scoring -> verdict -> ScanReport, contra un
servidor HTTP local (http.server) que se comporta como la PyPI JSON API:

  - 200 con metadatos FABRICADOS para paquetes "reales" (FOUND).
  - 404 para nombres inexistentes (NOT_FOUND => override block).
  - 503 / cuerpo que tarda mas que el read_timeout => degradacion segura
    (transitorio agotado => UNVERIFIABLE, jamas un falso "todo allow").

Cada request del servidor DUERME una latencia representativa de red domestica
(~100 ms por defecto, configurable por escenario) para que las mediciones de
overhead del caso R9.8 sean realistas y NO tautologicas (ver docstring del
bloque de rendimiento).

Conexion del adapter REAL al servidor local (patron probado en test_adapter.py):
para no requerir TLS contra 127.0.0.1 se monkeypatchea la allowlist del cliente
HTTP (`core.net.http_client.ALLOWED_HOSTS` -> {"127.0.0.1"} y `_ALLOWED_SCHEME`
-> "http") y se reconstruye el `OpenerDirector` con un `HTTPHandler` (sin TLS)
reusando el redirect handler y los error handlers endurecidos de produccion. El
allowlist a 127.0.0.1 SOLO vive dentro del `with patch(...)` de cada test: fuera
de el, el cliente sigue fijado a https://pypi.org (NFR-Seg.3 intacto). Como el
engine construye su propio adapter via `get_adapter`, los parches deben estar
activos durante TODA la corrida del `scan_*` (las requests salen ahi dentro).

Trazabilidad EARS:
  - R1.1/R1.2/R1.3/R1.5: flujos completos por cada tipo de manifiesto
    (requirements.txt, pyproject.toml, pip freeze, includes -r confinados).
  - R5.2/R5.3-5.5/R5.8: override 404 => block; umbrales allow/warn/block;
    unverifiable sin score y nunca allow.
  - R5.7: determinismo bajo permutacion del orden de entrada (mismo ScanReport).
  - R7.1-7.6: exit codes y precedencia block(2) > unverifiable(3) > warn(1) > allow(0).
  - R9.8: el overhead de orquestacion (concurrencia, dedup, cache) mantiene 30
    deps con cache fria en <= T_ref bajo latencia simulada.
  - NFR-Degr.1: red agotada (timeout/5xx persistente) => unverifiable exit 3,
    NUNCA un falso "todo allow".
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
import slopguard.core.engine as engine_mod
import slopguard.core.net.http_client as http_mod
from slopguard import core as sg
from slopguard.core.config import Config
from slopguard.core.models import (
    Dependency,
    ScanReport,
    Status,
    Verdict,
)
from slopguard.core.net.http_client import SecureHttpClient

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

# --------------------------------------------------------------------------- #
# Constantes de escenario
# --------------------------------------------------------------------------- #

# Latencia por defecto inyectada por request, representativa de red domestica.
# Esta DENTRO de la ventana 80-150 ms exigida por T38/R9.8.
_DEFAULT_LATENCY_S = 0.100

# Numero de dependencias del caso de rendimiento R9.8 (cache fria).
_PERF_DEP_COUNT = 30

# Cota de wall-clock del caso de rendimiento (T_ref de R9.8).
_T_REF_S = 10.0


# --------------------------------------------------------------------------- #
# Payloads PyPI FABRICADOS (metadatos normalizables por el adapter real)
# --------------------------------------------------------------------------- #


def _popular_payload(*, first_release_iso: str = "2010-01-01T00:00:00Z") -> dict[str, Any]:
    """Payload de un paquete POPULAR y antiguo: repo, metadatos completos, viejo.

    Produce L2 sin senales (popular completo) y sin NEW_PACKAGE: score 0 => allow,
    salvo que la Capa 1 dispare typosquat por el nombre.
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
            for minor in range(1, 21)  # 20 releases => releases_populares (10) holgado
        },
    }


def _new_legit_payload(*, first_release_iso: str) -> dict[str, Any]:
    """Payload de un paquete NUEVO pero legitimo: repo + metadatos completos + reciente.

    Solo dispara NEW_PACKAGE (blanda +15). Con el cap de blandas (25 < umbral_warn=50)
    el veredicto es allow: la novedad sola NUNCA bloquea (R5.6 / ADR-01).
    """
    return {
        "info": {
            "summary": "A brand new but legitimate package.",
            "author": "New Maintainer",
            "license": "MIT",
            "classifiers": ["Programming Language :: Python :: 3"],
            "project_urls": {"Source": "https://github.com/example/new-legit"},
        },
        "releases": {
            f"{minor}.0.0": [{"upload_time_iso_8601": first_release_iso}]
            for minor in range(1, 13)  # 12 releases => no penaliza por pocas releases
        },
    }


def _typosquat_payload(*, first_release_iso: str) -> dict[str, Any]:
    """Payload de un typosquat tipico: paquete recien creado, sin repo, metadatos pobres.

    Combinado con un nombre a DL=1 de un miembro del top-N, produce:
      TYPOSQUAT dl=1 (60, dura) + NEW_PACKAGE (15) + WEAK_METADATA (5) + LOW_VERIF (5)
      => score 85 >= umbral_block (80) => BLOCK.
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


# Fechas ISO derivadas del reloj real, solo para construir payloads (no se asierta
# sobre la edad exacta, sino sobre el VEREDICTO, que es estable por construccion).
def _days_ago_iso(days: int) -> str:
    """ISO 8601 UTC de hace `days` dias (para fabricar edades de release)."""
    epoch = time.time() - days * 86_400
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


# --------------------------------------------------------------------------- #
# Servidor PyPI SIMULADO con latencia inyectada
# --------------------------------------------------------------------------- #


class _FakePyPI:
    """Guion nombre->comportamiento del servidor PyPI simulado.

    Cada entrada es uno de:
      - dict  : payload JSON servido con 200 (FOUND).
      - 404   : NOT_FOUND.
      - 503   : error de servidor transitorio (reintentable).
      - "hang": el handler no responde hasta superar el read_timeout del cliente
                (simula timeout de lectura => transporte transitorio agotado).
    Registra el numero de hits por paquete para asertar dedup/cache (R9.4).
    """

    def __init__(self, script: dict[str, Any], *, latency_s: float) -> None:
        self.script = script
        self.latency_s = latency_s
        self.hits: dict[str, int] = {}
        self.port: int = 0  # lo fija `_running_pypi` tras enlazar el socket
        self._lock = threading.Lock()

    def record(self, name: str) -> None:
        """Registra un hit al paquete `name` de forma thread-safe."""
        with self._lock:
            self.hits[name] = self.hits.get(name, 0) + 1

    def total_hits(self) -> int:
        """Suma de todos los hits registrados (para asertar concurrencia/dedup)."""
        with self._lock:
            return sum(self.hits.values())


def _make_handler(state: _FakePyPI) -> type[http.server.BaseHTTPRequestHandler]:
    """Crea una clase de handler ligada al guion/latencia de `state`."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:  # silencia el log del servidor
            return None

        def do_GET(self) -> None:
            """Atiende /pypi/<name>/json segun el guion, con latencia inyectada."""
            time.sleep(state.latency_s)  # latencia representativa de red domestica
            parts = self.path.split("/")
            name = parts[2] if len(parts) > 2 else ""
            state.record(name)
            behavior = state.script.get(name, 404)
            if behavior == "hang":
                # Duerme MAS que cualquier read_timeout de los tests => timeout de
                # lectura del cliente (transporte transitorio). El daemon thread del
                # servidor muere al cerrar el proceso de test.
                time.sleep(30.0)
                return
            if behavior == 503:
                self._send(503, b"service unavailable")
                return
            if behavior == 404:
                self._send(404, b"not found")
                return
            assert isinstance(behavior, dict)  # payload FOUND
            self._send(200, json.dumps(behavior).encode())

        def _send(self, code: int, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _Handler


@contextmanager
def _running_pypi(
    script: dict[str, Any], *, latency_s: float = _DEFAULT_LATENCY_S
) -> Iterator[_FakePyPI]:
    """Levanta el servidor PyPI simulado; lo apaga al salir del contexto."""
    state = _FakePyPI(script, latency_s=latency_s)
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
# Conexion del adapter REAL al servidor local (parche de allowlist solo en test)
# --------------------------------------------------------------------------- #


def _patched_http_init(self: SecureHttpClient) -> None:
    """`__init__` de SecureHttpClient que usa HTTPHandler (sin TLS) para 127.0.0.1.

    Reusa el redirect handler endurecido y los error handlers de produccion: el
    UNICO cambio frente al opener real es HTTP en vez de HTTPS, para hablar con el
    servidor local sin certificados. La allowlist sigue restringida (a 127.0.0.1)
    por los parches de `_local_pypi_patches`.
    """
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(http_mod._RejectRedirectHandler())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    self._opener = opener


@contextmanager
def _local_pypi_patches(port: int) -> Iterator[None]:
    """Activa los parches que apuntan el adapter REAL al servidor local.

    Restringe la allowlist a 127.0.0.1 con scheme http SOLO dentro de este
    contexto. Fuera de el, el cliente HTTP sigue fijado a https://pypi.org
    (NFR-Seg.3 no se relaja en produccion).
    """
    base = f"http://127.0.0.1:{port}/pypi/{{name}}/json"
    with (
        patch.object(http_mod, "ALLOWED_HOSTS", frozenset({"127.0.0.1"})),
        patch.object(http_mod, "_ALLOWED_SCHEME", "http"),
        # El loopback usa puerto efimero: neutraliza el rechazo de puerto explicito (A10
        # SSRF, defecto-deniega en produccion) SOLO en este contexto, igual que la allowlist.
        patch.object(http_mod, "_reject_port_and_userinfo", lambda _parts: None),
        patch.object(SecureHttpClient, "__init__", _patched_http_init),
        patch.object(pypi_mod, "_PYPI_API_BASE", base),
        # Estos e2e del Hito 1 ejercitan SOLO el servidor PyPI simulado (no OSV): se
        # neutraliza la Capa 3 (threat-intel) a None para que el flujo sea idéntico al
        # Hito 1 (enable_layer3=false ⇒ ti={}). Sin esto, el `Config()` por defecto
        # instanciaría `OsvSource`, cuyo `SecureHttpClient(extra_allowed_hosts=...)`
        # choca con el `__init__` parcheado (sin args). Los e2e de Capa 3 con servidor
        # OSV simulado son H2-T20 (otro archivo de tester).
        patch.object(engine_mod, "get_threatintel_source", lambda *a, **k: None),
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


# --------------------------------------------------------------------------- #
# Fixtures: aislan la cache en disco a un HOME temporal (no contamina ~/.cache)
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _isolated_cache_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirige `Path.home()` a un tmp para que la cache de disco quede aislada.

    El adapter construye la cache en `Path.home()/.cache/slopguard`. Aislarla evita
    que una corrida previa contamine los resultados (cache fria controlada en R9.8)
    y que estas pruebas escriban en el home real del desarrollador.
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)


# =========================================================================== #
# 1. Flujos completos por CADA tipo de manifiesto (R1.1/R1.2/R1.3/R1.5)
# =========================================================================== #


def test_e2e_requirements_txt_flujo_completo(tmp_path: Path) -> None:
    """requirements.txt real end-to-end: produce ScanReport y exit code esperados (R1.1).

    Mezcla un paquete popular (allow), un 404 (block override) y un typosquat (block):
    ejercita parse -> fetch concurrente contra el servidor local -> capas -> scoring.
    """
    script = {
        "requests": _popular_payload(),  # in top-N => allow
        "reqursts": _typosquat_payload(first_release_iso=_days_ago_iso(1)),  # DL=1 => block
        "ghost-pkg-xyz": 404,  # inexistente => block override
    }
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "# comentario\nrequests==2.31.0\nreqursts\nghost-pkg-xyz\n-e .\n", encoding="utf-8"
    )

    with _running_pypi(script) as state:
        with _local_pypi_patches(state.port):
            report = sg.scan_manifest(manifest, Config(), use_cache=False)

    assert _result_by_name(report, "requests").verdict is Verdict.ALLOW
    assert _result_by_name(report, "reqursts").verdict is Verdict.BLOCK
    assert _result_by_name(report, "ghost-pkg-xyz").verdict is Verdict.BLOCK
    # Exit precedencia: hay block => 2 (R7.5).
    assert sg.aggregate_exit_code(report, strict=False) == 2
    assert report.summary.exit_code == 2


def test_e2e_pyproject_toml_flujo_completo(tmp_path: Path) -> None:
    """pyproject.toml real end-to-end: dependencies + optional-dependencies (R1.2).

    Verifica que el orquestador extrae ambas secciones y produce el reporte/exit.
    """
    script = {
        "requests": _popular_payload(),
        "flask": _popular_payload(),
        "pytest": _popular_payload(),
    }
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "[project]\n"
        'name = "demo"\n'
        'version = "0.1.0"\n'
        'dependencies = ["requests>=2.0", "flask"]\n'
        "[project.optional-dependencies]\n"
        'dev = ["pytest>=8"]\n',
        encoding="utf-8",
    )

    with _running_pypi(script) as state:
        with _local_pypi_patches(state.port):
            report = sg.scan_manifest(manifest, Config(), use_cache=False)

    names = {r.name for r in report.results}
    assert names == {"requests", "flask", "pytest"}  # dependencies + optional (R1.2)
    assert all(r.verdict is Verdict.ALLOW for r in report.results)
    assert sg.aggregate_exit_code(report, strict=False) == 0


def test_e2e_pip_freeze_stdin_flujo_completo() -> None:
    """pip freeze por stdin end-to-end: parsea nombre==version y escanea (R1.3).

    `scan_stdin` recibe el texto en formato freeze; el flujo es identico al de un
    manifiesto en disco salvo la fuente de entrada.
    """
    script = {
        "numpy": _popular_payload(),
        "nmupy": _typosquat_payload(first_release_iso=_days_ago_iso(2)),  # DL=1 de numpy
    }
    freeze_text = "numpy==1.26.0\nnmupy==0.0.1\n"

    with _running_pypi(script) as state:
        with _local_pypi_patches(state.port):
            report = sg.scan_stdin(freeze_text, Config(), use_cache=False)

    assert _result_by_name(report, "numpy").verdict is Verdict.ALLOW
    assert _result_by_name(report, "nmupy").verdict is Verdict.BLOCK
    assert sg.aggregate_exit_code(report, strict=False) == 2


def test_e2e_includes_confinados_flujo_completo(tmp_path: Path) -> None:
    """requirements.txt con `-r` confinado end-to-end: incluye deps del archivo base (R1.5).

    El include se resuelve dentro del arbol del proyecto; sus dependencias entran
    al escaneo igual que las del archivo raiz, sin omitir ninguna en silencio.
    """
    script = {
        "requests": _popular_payload(),
        "flask": _popular_payload(),
        "urllib3": _popular_payload(),
    }
    base = tmp_path / "base.txt"
    base.write_text("urllib3\nflask\n", encoding="utf-8")
    root = tmp_path / "requirements.txt"
    root.write_text("requests\n-r base.txt\n", encoding="utf-8")

    with _running_pypi(script) as state:
        with _local_pypi_patches(state.port):
            report = sg.scan_manifest(root, Config(), use_cache=False)

    names = {r.name for r in report.results}
    assert names == {"requests", "flask", "urllib3"}  # include confinado resuelto (R1.5)
    assert all(r.verdict is Verdict.ALLOW for r in report.results)
    assert sg.aggregate_exit_code(report, strict=False) == 0


# =========================================================================== #
# 2. Escenario MIXTO allow/warn/block/unverifiable en una sola corrida
# =========================================================================== #


def test_e2e_escenario_mixto_un_solo_scan() -> None:
    """Una corrida con los cuatro veredictos: allow, warn, block, unverifiable.

    - 'requests' (popular, in top-N)      => allow
    - 'flsk'     (typosquat DL=1, antiguo) => warn  (typosquat solo: score 60)
    - 'reqursts' (typosquat DL=1, nuevo+pobre) => block (score 85)
    - 'down-pkg' (503 persistente)         => unverifiable (degradacion segura)
    El exit code agregado prioriza block (2) sobre unverifiable (3) (R7.5).
    """
    script: dict[str, Any] = {
        "requests": _popular_payload(),
        "flsk": _popular_payload(),  # antiguo + completo: solo dispara typosquat (60 => warn)
        "reqursts": _typosquat_payload(first_release_iso=_days_ago_iso(1)),  # block
        "down-pkg": 503,  # transitorio persistente => unverifiable
    }
    config = Config(reintentos_red=1, timeout_total_por_dep_s=2.0)
    deps = [_dep("requests"), _dep("flsk"), _dep("reqursts"), _dep("down-pkg")]

    with _running_pypi(script) as state:
        with _local_pypi_patches(state.port):
            report = sg.scan_dependencies(deps, config, use_cache=False)

    assert _result_by_name(report, "requests").verdict is Verdict.ALLOW
    assert _result_by_name(report, "flsk").verdict is Verdict.WARN
    assert _result_by_name(report, "reqursts").verdict is Verdict.BLOCK
    down = _result_by_name(report, "down-pkg")
    assert down.status is Status.UNVERIFIABLE
    assert down.verdict is None and down.score is None  # nunca allow (R5.8)
    # Block presente => exit 2 (precede a unverifiable 3) (R7.5).
    assert sg.aggregate_exit_code(report, strict=False) == 2
    # El summary contabiliza cada categoria.
    assert report.summary.block == 1
    assert report.summary.warn == 1
    assert report.summary.allow == 1
    assert report.summary.unverifiable == 1


# =========================================================================== #
# 3. Degradacion segura: red agotada => unverifiable, NUNCA un falso "todo allow"
# =========================================================================== #


def test_e2e_red_agotada_503_es_unverifiable_no_allow() -> None:
    """503 persistente agota reintentos => unverifiable exit 3, jamas allow (NFR-Degr.1).

    El servidor responde 503 SIEMPRE: el adapter reintenta el transitorio dentro del
    presupuesto y, al agotarlo, marca la dependencia unverifiable. El reporte NUNCA
    afirma 'todo bien' por una caida de red (degradacion conservadora).
    """
    script = {"alpha": 503, "beta": 503}
    config = Config(reintentos_red=1, timeout_total_por_dep_s=2.0)
    deps = [_dep("alpha"), _dep("beta")]

    with _running_pypi(script) as state:
        with _local_pypi_patches(state.port):
            report = sg.scan_dependencies(deps, config, use_cache=False)

    assert all(r.status is Status.UNVERIFIABLE for r in report.results)
    assert all(r.verdict is None for r in report.results)  # nunca allow/warn/block
    assert all(r.score is None for r in report.results)
    assert sg.aggregate_exit_code(report, strict=False) == 3  # unverifiable => 3
    assert report.summary.allow == 0  # el falso "todo allow" jamas ocurre
    assert report.summary.unverifiable == 2


def test_e2e_timeout_de_lectura_es_unverifiable_no_allow() -> None:
    """Un cuerpo que nunca llega (read timeout) => unverifiable, nunca allow (NFR-Degr.1).

    El handler 'hang' duerme mas que el read_timeout del cliente: simula una lectura
    colgada (transporte transitorio). Tras agotar el presupuesto la dep queda
    unverifiable; el escaneo no la confunde con un paquete sano.
    """
    script = {"slow-pkg": "hang"}
    # read_timeout corto + presupuesto corto: el intento expira rapido y se agota.
    config = Config(
        connect_timeout_s=0.5,
        read_timeout_s=0.5,
        reintentos_red=1,
        timeout_total_por_dep_s=2.0,
    )
    deps = [_dep("slow-pkg")]

    with _running_pypi(script, latency_s=0.0) as state:
        with _local_pypi_patches(state.port):
            report = sg.scan_dependencies(deps, config, use_cache=False)

    result = _result_by_name(report, "slow-pkg")
    assert result.status is Status.UNVERIFIABLE
    assert result.verdict is None  # jamas allow ante un timeout
    assert sg.aggregate_exit_code(report, strict=False) == 3


# =========================================================================== #
# 4. Typosquat => block ; paquete nuevo legitimo => allow
# =========================================================================== #


def test_e2e_typosquat_cercano_al_top_n_es_block() -> None:
    """Un nombre a DL=1 de un miembro del top-N, recien creado y pobre => block.

    Cierra el camino completo del detector: Capa 1 (typosquat dura 60) + Capa 0
    (new package 15) + Capa 2 (metadatos pobres) => score 85 >= umbral_block.
    """
    script = {"djngo": _typosquat_payload(first_release_iso=_days_ago_iso(1))}  # DL=1 de django
    deps = [_dep("djngo")]

    with _running_pypi(script) as state:
        with _local_pypi_patches(state.port):
            report = sg.scan_dependencies(deps, Config(), use_cache=False)

    result = _result_by_name(report, "djngo")
    assert result.verdict is Verdict.BLOCK
    assert result.score is not None and result.score >= Config().umbral_block
    assert result.suspected_target == "django"  # objetivo legitimo sospechado
    assert sg.aggregate_exit_code(report, strict=False) == 2


def test_e2e_paquete_nuevo_legitimo_es_allow() -> None:
    """Un paquete NUEVO pero legitimo (repo + metadatos completos, edad<min) => allow.

    La novedad sola es una senal blanda capada (25 < umbral_warn=50): nunca bloquea
    ni advierte por si misma (R5.6 / ADR-01). El nombre no se parece a ningun top-N.
    """
    script = {
        "zzqwlegitpkg": _new_legit_payload(first_release_iso=_days_ago_iso(5)),
    }
    deps = [_dep("zzqwlegitpkg")]

    with _running_pypi(script) as state:
        with _local_pypi_patches(state.port):
            report = sg.scan_dependencies(deps, Config(), use_cache=False)

    result = _result_by_name(report, "zzqwlegitpkg")
    assert result.verdict is Verdict.ALLOW
    assert result.status is Status.OK
    assert result.score is not None and result.score < Config().umbral_warn
    assert sg.aggregate_exit_code(report, strict=False) == 0


# =========================================================================== #
# 5. Determinismo bajo permutacion del orden de entrada (R5.7)
# =========================================================================== #


def test_e2e_determinismo_bajo_permutacion_del_orden() -> None:
    """Permutar el orden de entrada produce EXACTAMENTE el mismo ScanReport (R5.7).

    Dos corridas con el mismo lote en distinto orden deben coincidir en summary,
    orden de resultados (R6.4) y veredicto de cada dependencia.
    """
    script: dict[str, Any] = {
        "requests": _popular_payload(),
        "reqursts": _typosquat_payload(first_release_iso=_days_ago_iso(1)),
        "ghost-xyz": 404,
        "flask": _popular_payload(),
    }
    base_names = ["requests", "reqursts", "ghost-xyz", "flask"]
    permuted_names = ["flask", "ghost-xyz", "requests", "reqursts"]

    with _running_pypi(script) as state:
        with _local_pypi_patches(state.port):
            report_a = sg.scan_dependencies(
                [_dep(n) for n in base_names], Config(), use_cache=False
            )
            report_b = sg.scan_dependencies(
                [_dep(n) for n in permuted_names], Config(), use_cache=False
            )

    # Mismo orden de resultados (R6.4) e identico veredicto/score por dependencia.
    assert [r.name for r in report_a.results] == [r.name for r in report_b.results]
    assert [(r.name, r.verdict, r.score, r.status) for r in report_a.results] == [
        (r.name, r.verdict, r.score, r.status) for r in report_b.results
    ]
    assert report_a.summary == report_b.summary  # summary identico (incl. exit_code)


# =========================================================================== #
# 6. RENDIMIENTO R9.8 — overhead de orquestacion bajo latencia SIMULADA
# =========================================================================== #


def _run_perf_scan(script: dict[str, Any], *, latency_s: float, workers: int) -> float:
    """Corre `scan_dependencies` sobre `script` y devuelve el wall-clock en segundos.

    Usa cache fria (`use_cache=False`): cada paquete viaja a la red simulada. El
    `_isolated_cache_home` (autouse) garantiza que ninguna corrida previa cachee.
    """
    deps = [_dep(name) for name in script]
    config = Config(concurrencia_max=workers)
    with _running_pypi(script, latency_s=latency_s) as state:
        with _local_pypi_patches(state.port):
            start = time.monotonic()
            report = sg.scan_dependencies(deps, config, use_cache=False)
            elapsed = time.monotonic() - start
    assert len(report.results) == len(script)
    assert all(r.verdict is Verdict.ALLOW for r in report.results)
    assert state.total_hits() == len(script)  # 1 request por paquete (cache fria/dedup)
    return elapsed


def test_e2e_rendimiento_30_deps_cache_fria_bajo_t_ref() -> None:
    """R9.8: 30 deps con cache FRIA en <= T_ref bajo latencia simulada ~100 ms/req.

    QUE MIDE ESTA PRUEBA (criterio explicitamente NO tautologico): mide el OVERHEAD
    DE ORQUESTACION de SlopGuard (paralelismo con `concurrencia_max`, dedup, montaje
    de capas/scoring), NO el hardware ni la red reales. La "red" es un servidor
    http.server local que DUERME una latencia fija e INYECTADA (~100 ms por request)
    en cada respuesta; ese sleep DOMINA el wall-clock por diseno. La asercion no
    certifica velocidad de maquina: certifica que el orquestador acerca el wall-clock
    al PISO impuesto por la latencia + la concurrencia, en vez de serializar las 30
    requests.

    Piso teorico de latencia pura con concurrencia_max=8:
      ceil(30/8) * 0.100 s = 4 * 0.100 = 0.400 s.
    T_ref = 10 s deja amplio margen al overhead de orquestacion (objetivo R9.8).

    DOMINANCIA DE LA LATENCIA (anti-tautologia, medida POR DIFERENCIAL). Una sola
    cota `wall <= T_ref` seria tautologica: incluso un servidor SIN latencia tarda
    ~0.4 s solo por el establecimiento de conexiones TCP locales y el montaje de la
    pool, no por la latencia inyectada. Para AISLAR la contribucion de la latencia
    simulada se corre la MISMA carga con concurrencia 8 (concurrente) y con
    concurrencia 1 (serial): el serial no paraleliza la red y paga N sleeps, el
    concurrente paga ceil(N/8). El AHORRO (serial - concurrente) es puro tiempo de
    red simulada y solo puede provenir de los sleeps inyectados. Si la herramienta
    ignorase la red, ambas corridas tardarian igual y el ahorro seria ~0: la prueba
    fallaria. Este diferencial es robusto en CI ruidoso porque ambas corridas pagan
    el mismo overhead fijo, a diferencia de comparar contra una linea base sin
    latencia (que puede salir mas lenta por warmup y dar un diferencial negativo).
    """
    latency = _DEFAULT_LATENCY_S
    workers = 8
    # 30 paquetes populares (allow) con nombres que NO se parecen al top-N para que
    # el coste dominante sea la latencia de red simulada, no el scoring.
    script: dict[str, Any] = {
        f"e2eperf{i:02d}": _popular_payload() for i in range(_PERF_DEP_COUNT)
    }

    # Corrida concurrente (objetivo R9.8) y serial (concurrencia=1) sobre la MISMA
    # carga y latencia. El ahorro proviene de los sleeps REALES del servidor, que
    # ni la cobertura ni el jitter del runner inflan; ambas corridas pagan el mismo
    # overhead fijo de orquestacion+TCP, asi que el DIFERENCIAL es robusto incluso
    # en runners de CI ruidosos (no depende de una linea base que pueda salir mas
    # lenta por warmup/contencion del scheduler).
    wall_concurrent = _run_perf_scan(script, latency_s=latency, workers=workers)
    wall_serial = _run_perf_scan(script, latency_s=latency, workers=1)

    serial_batches = -(-_PERF_DEP_COUNT // workers)  # ceil(30/8) = 4

    # Cota SUPERIOR (objetivo literal R9.8): overhead de orquestacion mantiene el
    # wall-clock de la corrida concurrente <= T_ref bajo la latencia inyectada.
    assert wall_concurrent <= _T_REF_S, (
        f"wall-clock {wall_concurrent:.3f}s excede T_ref={_T_REF_S}s"
    )

    # Cota INFERIOR por DIFERENCIAL (anti-tautologia): el serial NO paraleliza la
    # red y paga N sleeps; el concurrente paga ceil(N/workers). El ahorro es puro
    # tiempo de red simulada => demuestra que el wall-clock esta dominado por la
    # latencia y que el orquestador la paraleliza. Piso 0.25x del ahorro ideal: muy
    # por debajo del ahorro estructural (~2.6 s) para tolerar la contencion de
    # runners CI de 2 cores sin volver vacua la cota (con latencia 0 el ahorro ~0).
    saved_floor = (_PERF_DEP_COUNT - serial_batches) * latency * 0.25  # (30-4)*0.1*0.25
    latency_savings = wall_serial - wall_concurrent
    assert latency_savings >= saved_floor, (
        f"ahorro por concurrencia {latency_savings:.3f}s "
        f"(serial={wall_serial:.3f}s, concurrente={wall_concurrent:.3f}s) por debajo "
        f"del piso {saved_floor:.3f}s: la red simulada no domina o no se paraleliza"
    )


def test_e2e_concurrencia_real_mas_rapida_que_serial_simulado() -> None:
    """La concurrencia recorta el wall-clock frente a la MISMA carga serial.

    Refuerza el criterio NO tautologico de R9.8 de forma ROBUSTA a la
    instrumentacion (cobertura): el serial se mide EMPIRICAMENTE con
    concurrencia_max=1 y el concurrente con concurrencia_max=8 sobre la misma
    carga y latencia. El ahorro proviene de los sleeps REALES del servidor
    simulado (que el tracing de cobertura NO infla); ambas corridas pagan el
    mismo overhead de Python, asi que el speedup se observa por DIFERENCIAL,
    sin depender de una cota absoluta de wall-clock fragil bajo carga/cobertura.

    Piso de latencia: serial = 16 * 0.100 = 1.6 s; concurrente (8) =
    ceil(16/8) * 0.100 = 0.2 s; el ahorro esperado ~1.4 s es el delta de los
    sleeps inyectados y no lo altera la instrumentacion (se cancela en la resta).
    """
    latency = _DEFAULT_LATENCY_S
    count = 16
    script: dict[str, Any] = {f"concpkg{i:02d}": _popular_payload() for i in range(count)}

    wall_serial = _run_perf_scan(script, latency_s=latency, workers=1)
    wall_concurrent = _run_perf_scan(script, latency_s=latency, workers=8)

    # El delta de latencia pura (~1.4 s) lo aporta la red simulada, no el tracing.
    # Exigimos un ahorro de 0.3 s: muy por debajo del estructural (~1.4 s) para no
    # flakear en runners CI contendidos de 2 cores (donde el dispatch de 8 hilos para
    # 16 tareas añade overhead), pero suficiente para probar la paralelizacion real.
    assert wall_serial - wall_concurrent >= 0.3, (
        f"concurrencia {wall_concurrent:.3f}s no mejora suficientemente el serial "
        f"{wall_serial:.3f}s (ahorro esperado ~1.4 s): la orquestacion no esta "
        "paralelizando la red simulada"
    )
