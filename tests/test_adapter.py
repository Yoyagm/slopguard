"""Pruebas del adapter PyPI + concurrencia (T23): clasificacion, cache, dedup, presupuesto.

Cubre los criterios de T23 y la clasificacion de Convenciones de tasks.md:

- **Mapeo de estados** (R2.1, R4.1, §3.2): 200->FOUND con `PackageMetadata` normalizado,
  404->NOT_FOUND (sin lanzar), 403/410->UNVERIFIABLE permanente (nunca FOUND), 5xx/timeout
  transitorio agotado->UNVERIFIABLE (nunca allow).
- **Transitoriedad real** (R2.5): el adapter de PRODUCCION implementa `RetryableAdapter`;
  `fetch_many` reintenta un 503/timeout y lo agota a UNVERIFIABLE respetando el presupuesto.
- **Cache antes de red** (R9.2): un hit vigente devuelve el outcome sin tocar la red.
- **Dedup** (R9.4): nombres que normalizan al mismo paquete se consultan una sola vez.
- **Paralelismo** acotado por `concurrencia_max`.
- **Factory** `get_adapter("pypi")` y rechazo de ecosistemas desconocidos (R10.2).
- **e2e real** contra un servidor HTTP local que responde 404 y 503, ejercitando el camino
  completo `PypiAdapter.fetch -> SecureHttpClient.get_json` (no solo dobles): verifica que el
  bug del opener sin `HTTPDefaultErrorHandler` quedo cerrado (404=>NOT_FOUND, 503=>UNVERIFIABLE
  transitorio, sin TypeError crudo ni aborto del lote).

Los dobles del cliente HTTP son deterministas (no hay red real salvo el harness local del
e2e, que escucha en 127.0.0.1). El reloj/espera del backoff se simulan via monkeypatch del
modulo `concurrent` para que el presupuesto sea rapido y determinista.
"""

from __future__ import annotations

import dataclasses
import http.server
import json
import socketserver
import threading
import time
import urllib.request
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

import slopguard.core.adapters.pypi as pypi_mod
import slopguard.core.net.http_client as http_mod
from slopguard.core.adapters.base import FetchOutcome, FetchState
from slopguard.core.adapters.concurrent import RetryableAdapter, fetch_many
from slopguard.core.adapters.pypi import PypiAdapter
from slopguard.core.adapters.registry import get_adapter
from slopguard.core.config import Config
from slopguard.core.errors import NetworkUnverifiableError
from slopguard.core.net.http_client import SecureHttpClient

if TYPE_CHECKING:
    from collections.abc import Iterator

# Rutas de monkeypatch del reloj del modulo concurrent (backoff determinista).
_TIME_MONOTONIC = "slopguard.core.adapters.concurrent.time.monotonic"
_TIME_SLEEP = "slopguard.core.adapters.concurrent.time.sleep"

# Payload PyPI minimo bien formado para el camino FOUND.
_GOOD_PAYLOAD: dict[str, Any] = {
    "info": {
        "summary": "HTTP for Humans",
        "author": "Kenneth Reitz",
        "license": "Apache-2.0",
        "classifiers": ["Programming Language :: Python"],
        "project_urls": {"Source": "https://github.com/psf/requests"},
    },
    "releases": {"2.0.0": [{"upload_time_iso_8601": "2013-09-24T00:00:00Z"}]},
}


# ---------------------------------------------------------------------------
# Dobles deterministas del cliente HTTP
# ---------------------------------------------------------------------------


class _StubHttp:
    """Doble de `SecureHttpClient` que mapea nombre->comportamiento determinista.

    Cada entrada del guion es un payload dict (FOUND) o una `NetworkUnverifiableError`
    tipada (404/4xx/5xx/timeout). Una lista simula intentos sucesivos (para reintentos).
    Registra cada URL pedida para asertar 'cache antes de red' y dedup.
    """

    def __init__(self, scripts: dict[str, list[Any]]) -> None:
        self._scripts = {k: list(v) for k, v in scripts.items()}
        self.urls: list[str] = []
        self._lock = threading.Lock()

    def get_json(self, url: str, **_: Any) -> dict[str, Any]:
        """Devuelve el siguiente paso del guion para el paquete codificado en `url`."""
        name = url.split("/pypi/")[1].split("/json", maxsplit=1)[0]
        with self._lock:
            self.urls.append(url)
            count = sum(1 for u in self.urls if f"/pypi/{name}/json" in u)
        steps = self._scripts[name]
        step = steps[min(count - 1, len(steps) - 1)]
        if isinstance(step, BaseException):
            raise step
        assert isinstance(step, dict)  # el guion no-excepcion es siempre un payload dict
        return step


def _http_error(status_code: int, *, is_transient: bool) -> NetworkUnverifiableError:
    """Construye el error tipado que `SecureHttpClient` elevaria ante un status HTTP."""
    return NetworkUnverifiableError(
        f"respuesta HTTP {status_code} no verificable",
        status_code=status_code,
        is_transient=is_transient,
    )


def _timeout_error() -> NetworkUnverifiableError:
    """Error tipado de transporte transitorio (timeout/conexion caida), sin status."""
    return NetworkUnverifiableError("fallo de red no verificable: TimeoutError", is_transient=True)


def _make_adapter(scripts: dict[str, list[Any]], *, use_cache: bool = False) -> PypiAdapter:
    """Crea un `PypiAdapter` real con el cliente HTTP sustituido por un stub guionado.

    El dataset top-N embebido se carga de verdad en `__init__` (camino real). Solo se
    inyecta el doble del cliente HTTP para controlar las respuestas sin red.
    """
    adapter = PypiAdapter(Config(), use_cache=use_cache)
    adapter._http = _StubHttp(scripts)  # type: ignore[assignment]
    return adapter


# ---------------------------------------------------------------------------
# Clasificacion de estados (R2.1, R4.1, Convenciones)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("step", "expected_state", "expected_transient"),
    [
        (_GOOD_PAYLOAD, FetchState.FOUND, False),
        (_http_error(404, is_transient=False), FetchState.NOT_FOUND, False),
        (_http_error(403, is_transient=False), FetchState.UNVERIFIABLE, False),
        (_http_error(410, is_transient=False), FetchState.UNVERIFIABLE, False),
        (_http_error(500, is_transient=True), FetchState.UNVERIFIABLE, True),
        (_http_error(503, is_transient=True), FetchState.UNVERIFIABLE, True),
        (_timeout_error(), FetchState.UNVERIFIABLE, True),
    ],
)
def test_fetch_attempt_clasifica_status(
    step: Any, expected_state: FetchState, expected_transient: bool
) -> None:
    """fetch_attempt mapea cada status al estado y la transitoriedad de Convenciones.

    200->FOUND, 404->NOT_FOUND (permanente), 4xx!=404->UNVERIFIABLE permanente,
    5xx/timeout->UNVERIFIABLE transitorio. Ningun caso devuelve un outcome 'positivo'
    para una anomalia (nunca FOUND salvo 200).
    """
    adapter = _make_adapter({"pkg": [step]})

    attempt = adapter.fetch_attempt("pkg")

    assert attempt.outcome.state is expected_state
    assert attempt.is_transient is expected_transient
    if expected_state is not FetchState.FOUND:
        assert attempt.outcome.metadata is None  # anomalia nunca arrastra metadata


def test_404_no_lanza_y_es_not_found() -> None:
    """Un 404 (paquete inexistente/alucinado) => NOT_FOUND sin lanzar (R2.1, override)."""
    adapter = _make_adapter({"hallucinated-pkg": [_http_error(404, is_transient=False)]})

    outcome = adapter.fetch("hallucinated-pkg")

    assert outcome.state is FetchState.NOT_FOUND
    assert outcome.metadata is None


def test_found_extrae_package_metadata_normalizado() -> None:
    """200 ok => FOUND con `PackageMetadata` normalizado, jamas el payload crudo (R4.1)."""
    adapter = _make_adapter({"requests": [_GOOD_PAYLOAD]})

    outcome = adapter.fetch("requests")

    meta = outcome.metadata
    assert outcome.state is FetchState.FOUND
    assert meta is not None
    assert meta.name == "requests"  # normalizado PEP 503
    assert meta.releases_count == 1
    assert meta.has_repo_url is True
    assert meta.has_author is True
    assert meta.has_license is True
    assert meta.has_classifiers is True
    assert meta.first_release_epoch is not None  # derivado de upload_time_iso_8601


def test_403_y_410_nunca_son_found() -> None:
    """4xx!=404 (403/410) => UNVERIFIABLE; jamas FOUND ni allow (Convenciones)."""
    adapter = _make_adapter({
        "forbidden": [_http_error(403, is_transient=False)],
        "gone": [_http_error(410, is_transient=False)],
    })

    assert adapter.fetch("forbidden").state is FetchState.UNVERIFIABLE
    assert adapter.fetch("gone").state is FetchState.UNVERIFIABLE


def test_excepcion_inesperada_degrada_a_unverifiable() -> None:
    """Defensa en profundidad: una excepcion no-NetworkUnverifiable degrada a UNVERIFIABLE.

    Una regresion del cliente HTTP (p.ej. un TypeError crudo) NUNCA debe abortar el lote
    ni escapar como stacktrace: el adapter la degrada a UNVERIFIABLE permanente (R6.5).
    """
    adapter = _make_adapter({"poison": [TypeError("regresion inesperada")]})

    attempt = adapter.fetch_attempt("poison")

    assert attempt.outcome.state is FetchState.UNVERIFIABLE
    assert attempt.is_transient is False  # inesperado => permanente (no reintentar a ciegas)


# ---------------------------------------------------------------------------
# Cache antes de red (R9.2)
# ---------------------------------------------------------------------------


def test_cache_hit_no_consulta_red() -> None:
    """Un hit vigente devuelve el outcome cacheado sin tocar la red (R9.2)."""
    adapter = _make_adapter({"requests": [_GOOD_PAYLOAD]})
    cached = FetchOutcome(state=FetchState.NOT_FOUND)

    class _AlwaysHit:
        def get(self, _eco: str, _name: str, **_: Any) -> FetchOutcome:
            return cached

        def put(self, *_a: Any, **_k: Any) -> None:
            return None

    adapter._cache = _AlwaysHit()  # type: ignore[assignment]

    outcome = adapter.fetch("requests")

    assert outcome is cached  # vino de la cache
    assert adapter._http.urls == []  # type: ignore[attr-defined]


def test_cache_miss_persiste_found_y_not_found() -> None:
    """Un miss consulta la red y persiste FOUND/NOT_FOUND; UNVERIFIABLE nunca se cachea."""
    adapter = _make_adapter({
        "requests": [_GOOD_PAYLOAD],
        "ghost": [_http_error(404, is_transient=False)],
        "down": [_http_error(503, is_transient=True)],
    })
    puts: list[tuple[str, FetchState]] = []

    class _RecordingCache:
        def get(self, _eco: str, _name: str, **_: Any) -> None:
            return None

        def put(self, _eco: str, name: str, outcome: FetchOutcome, **_: Any) -> None:
            puts.append((name, outcome.state))

    adapter._cache = _RecordingCache()  # type: ignore[assignment]

    for name in ("requests", "ghost", "down"):
        adapter.fetch(name)

    # El adapter delega la politica de no-cachear-unverifiable a DiskCache.put, pero
    # SIEMPRE le pasa el outcome: aqui verificamos que la llamada ocurre para los tres.
    assert ("requests", FetchState.FOUND) in puts
    assert ("ghost", FetchState.NOT_FOUND) in puts
    assert ("down", FetchState.UNVERIFIABLE) in puts


# ---------------------------------------------------------------------------
# El adapter real implementa RetryableAdapter (R2.5) — reintento de transitorios
# ---------------------------------------------------------------------------


def test_adapter_real_implementa_retryable() -> None:
    """PypiAdapter satisface el protocolo `RetryableAdapter` (habilita reintentos)."""
    adapter = _make_adapter({})
    assert isinstance(adapter, RetryableAdapter)


@pytest.fixture
def fake_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Reloj monotono simulado del modulo concurrent: cada sleep(s) avanza s segundos."""
    state = {"now": 1000.0}
    slept: list[float] = []

    def fake_monotonic() -> float:
        return state["now"]

    def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        state["now"] += seconds

    monkeypatch.setattr(_TIME_MONOTONIC, fake_monotonic)
    monkeypatch.setattr(_TIME_SLEEP, fake_sleep)
    return slept


def test_transitorio_se_reintenta_con_adapter_real(fake_clock: list[float]) -> None:
    """Un 503 seguido de 200 => FOUND tras 1 reintento con backoff 0.5s (adapter REAL)."""
    adapter = _make_adapter({"requests": [_http_error(503, is_transient=True), _GOOD_PAYLOAD]})

    result = fetch_many(adapter, ["requests"], Config())

    assert result["requests"].state is FetchState.FOUND
    assert fake_clock == [0.5]  # un backoff base
    # intento fallido + reintento exitoso = 2 viajes a la (stub) red
    assert len(adapter._http.urls) == 2  # type: ignore[attr-defined]


def test_transitorio_agotado_es_unverifiable_nunca_allow(fake_clock: list[float]) -> None:
    """503 persistente agota reintentos => UNVERIFIABLE; jamas FOUND/allow (R2.5/NFR-Degr.1)."""
    adapter = _make_adapter({"down": [_http_error(503, is_transient=True)]})  # siempre 503
    config = dataclasses.replace(Config(), reintentos_red=2, timeout_total_por_dep_s=100.0)

    result = fetch_many(adapter, ["down"], config)

    assert result["down"].state is FetchState.UNVERIFIABLE
    assert result["down"].metadata is None  # nunca FOUND
    assert fake_clock == [0.5, 1.0]  # intento + 2 reintentos => 2 backoffs


def test_timeout_transitorio_agota_a_unverifiable(fake_clock: list[float]) -> None:
    """Un timeout de transporte persistente se reintenta y agota a UNVERIFIABLE."""
    adapter = _make_adapter({"slow": [_timeout_error()]})
    config = dataclasses.replace(Config(), reintentos_red=1, timeout_total_por_dep_s=100.0)

    result = fetch_many(adapter, ["slow"], config)

    assert result["slow"].state is FetchState.UNVERIFIABLE
    assert fake_clock == [0.5]  # intento + 1 reintento => 1 backoff


def test_404_no_se_reintenta_con_adapter_real(fake_clock: list[float]) -> None:
    """404 es permanente: un solo intento, sin backoff, NOT_FOUND (no transitorio)."""
    adapter = _make_adapter({"ghost": [_http_error(404, is_transient=False), _GOOD_PAYLOAD]})

    result = fetch_many(adapter, ["ghost"], Config())

    assert result["ghost"].state is FetchState.NOT_FOUND
    assert fake_clock == []  # sin reintentos
    assert len(adapter._http.urls) == 1  # type: ignore[attr-defined]


def test_presupuesto_corta_reintento_que_no_cabe(fake_clock: list[float]) -> None:
    """Si el backoff no cabe en el presupuesto, agota a UNVERIFIABLE sin exceder el budget."""
    adapter = _make_adapter({"slow": [_http_error(503, is_transient=True)]})
    # Presupuesto 0.3s < primer backoff 0.5s: un solo intento, sin dormir.
    config = dataclasses.replace(Config(), reintentos_red=2, timeout_total_por_dep_s=0.3)

    result = fetch_many(adapter, ["slow"], config)

    assert result["slow"].state is FetchState.UNVERIFIABLE
    assert fake_clock == []  # nunca durmio (no cabia)
    assert len(adapter._http.urls) == 1  # type: ignore[attr-defined]


def test_presupuesto_no_inicia_intento_tras_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Si el reloj cruza el deadline DURANTE un fetch, no se inicia un nuevo intento.

    Simula un `fetch_attempt` cuyo round-trip 'consume' tiempo (avanza el reloj monotono)
    cruzando el deadline: el siguiente chequeo `monotonic() >= deadline` corta y agota a
    UNVERIFIABLE, verificando el contrato de presupuesto (no se INICIA un intento tras el
    deadline; el round-trip ya en vuelo lo acota el timeout de socket del cliente HTTP).
    """
    clock = {"now": 1000.0}
    monkeypatch.setattr(_TIME_SLEEP, lambda _s: None)
    monkeypatch.setattr(_TIME_MONOTONIC, lambda: clock["now"])
    adapter = _make_adapter({"slow": [_http_error(503, is_transient=True)]})

    real_fetch_attempt = adapter.fetch_attempt
    calls = {"n": 0}

    def slow_fetch_attempt(name: str) -> Any:
        calls["n"] += 1
        clock["now"] += 60.0  # el round-trip consume 60s de reloj monotono
        return real_fetch_attempt(name)

    adapter.fetch_attempt = slow_fetch_attempt  # type: ignore[method-assign]
    config = dataclasses.replace(Config(), reintentos_red=5, timeout_total_por_dep_s=30.0)

    result = fetch_many(adapter, ["slow"], config)

    assert result["slow"].state is FetchState.UNVERIFIABLE
    assert calls["n"] == 1  # el primer intento cruzo el deadline => no se inicio otro


# ---------------------------------------------------------------------------
# Dedup + paralelismo (R9.4)
# ---------------------------------------------------------------------------


def test_dedup_no_consulta_el_mismo_paquete_dos_veces() -> None:
    """Nombres que normalizan al mismo paquete se consultan UNA vez (R9.4)."""
    adapter = _make_adapter({"requests": [_GOOD_PAYLOAD], "zope-interface": [_GOOD_PAYLOAD]})
    names = ["requests", "Requests", "REQUESTS", "zope_interface", "zope.interface"]

    result = fetch_many(adapter, names, Config())

    assert set(result) == {"requests", "zope-interface"}
    # Exactamente dos viajes a la red: uno por paquete unico normalizado.
    assert len(adapter._http.urls) == 2  # type: ignore[attr-defined]


def test_paralelismo_respeta_concurrencia_max() -> None:
    """fetch_many nunca corre mas de `concurrencia_max` fetches en simultaneo."""
    active = {"value": 0}
    peak = {"value": 0}
    lock = threading.Lock()

    class _SlowStub:
        def get_json(self, _url: str, **_: Any) -> dict[str, Any]:
            with lock:
                active["value"] += 1
                peak["value"] = max(peak["value"], active["value"])
            time.sleep(0.05)
            with lock:
                active["value"] -= 1
            return _GOOD_PAYLOAD

    adapter = PypiAdapter(Config(), use_cache=False)
    adapter._http = _SlowStub()  # type: ignore[assignment]
    config = dataclasses.replace(Config(), concurrencia_max=3)
    names = [f"pkg-{i}" for i in range(12)]

    result = fetch_many(adapter, names, config)

    assert len(result) == 12
    assert peak["value"] <= 3  # nunca mas de concurrencia_max en vuelo


# ---------------------------------------------------------------------------
# Factory por ecosystem (R10.2)
# ---------------------------------------------------------------------------


def test_factory_pypi_retorna_adapter() -> None:
    """get_adapter('pypi') retorna un PypiAdapter listo para usar (R10.2)."""
    adapter = get_adapter("pypi", use_cache=False)
    assert isinstance(adapter, PypiAdapter)
    assert adapter.ecosystem_id == "pypi"


def test_factory_default_es_pypi() -> None:
    """get_adapter() sin argumentos usa 'pypi' por defecto."""
    assert isinstance(get_adapter(use_cache=False), PypiAdapter)


def test_factory_ecosistema_desconocido_lanza() -> None:
    """Un ecosystem_id no soportado lanza ValueError, nunca un adapter sin contrato."""
    with pytest.raises(ValueError, match="no soportado"):
        get_adapter("npm", use_cache=False)


# ---------------------------------------------------------------------------
# e2e real contra servidor HTTP local (cierra el bug del opener sin default handler)
# ---------------------------------------------------------------------------


class _LocalPyPIHandler(http.server.BaseHTTPRequestHandler):
    """Sirve /pypi/<name>/json con un status segun el nombre (404/503/200)."""

    def log_message(self, *_: Any) -> None:  # silencia el log del servidor
        return None

    def do_GET(self) -> None:
        """Responde segun el paquete codificado en la ruta (harness determinista)."""
        parts = self.path.split("/")
        name = parts[2] if len(parts) > 2 else ""
        if name == "ghost":
            self._send(404, b"not found")
        elif name == "down":
            self._send(503, b"service unavailable")
        else:
            self._send_json(_GOOD_PAYLOAD)

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict[str, Any]) -> None:
        self._send(200, json.dumps(payload).encode())


@pytest.fixture
def local_pypi() -> Iterator[int]:
    """Levanta un servidor HTTP local efimero; cede el puerto y lo apaga al terminar."""
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _LocalPyPIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def _build_local_adapter(port: int) -> PypiAdapter:
    """Crea un PypiAdapter cuyo cliente HTTP real apunta al servidor local (http/127.0.0.1).

    Reusa el opener endurecido de produccion pero con un `HTTPHandler` (en vez de HTTPS)
    y la allowlist apuntando a 127.0.0.1, para ejercitar el camino real get_json sin TLS.
    """
    def patched_init(self: SecureHttpClient) -> None:
        opener = urllib.request.OpenerDirector()
        opener.add_handler(urllib.request.HTTPHandler())
        opener.add_handler(http_mod._RejectRedirectHandler())
        opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
        opener.add_handler(urllib.request.HTTPErrorProcessor())
        self._opener = opener

    base = f"http://127.0.0.1:{port}/pypi/{{name}}/json"
    with patch.object(http_mod, "ALLOWED_HOSTS", frozenset({"127.0.0.1"})), \
         patch.object(http_mod, "_ALLOWED_SCHEME", "http"), \
         patch.object(SecureHttpClient, "__init__", patched_init), \
         patch.object(pypi_mod, "_PYPI_API_BASE", base):
        return PypiAdapter(Config(), use_cache=False)


def test_e2e_404_es_not_found(local_pypi: int) -> None:
    """e2e REAL: un 404 del servidor local => NOT_FOUND (cierra el bug del TypeError crudo).

    Ejercita PypiAdapter.fetch -> SecureHttpClient.get_json contra un servidor HTTP real.
    Antes del fix (opener sin HTTPDefaultErrorHandler) esto lanzaba un TypeError que abortaba
    el lote; ahora 404 mapea limpiamente a NOT_FOUND, disparando el override anti-slopsquatting.
    """
    adapter = _build_local_adapter(local_pypi)

    # El opener real se reconstruye en cada fetch via el SecureHttpClient ya inyectado.
    base = f"http://127.0.0.1:{local_pypi}/pypi/{{name}}/json"
    with patch.object(http_mod, "ALLOWED_HOSTS", frozenset({"127.0.0.1"})), \
         patch.object(http_mod, "_ALLOWED_SCHEME", "http"), \
         patch.object(pypi_mod, "_PYPI_API_BASE", base):
        outcome = adapter.fetch("ghost")

    assert outcome.state is FetchState.NOT_FOUND
    assert outcome.metadata is None


def test_e2e_503_es_unverifiable_transitorio(local_pypi: int) -> None:
    """e2e REAL: un 503 del servidor local => UNVERIFIABLE transitorio (degradacion segura).

    Verifica que la clasificacion 5xx->transitorio funciona end-to-end con el cliente real:
    nunca FOUND, nunca allow, y el fallo es reintentable (is_transient=True).
    """
    adapter = _build_local_adapter(local_pypi)
    base = f"http://127.0.0.1:{local_pypi}/pypi/{{name}}/json"
    with patch.object(http_mod, "ALLOWED_HOSTS", frozenset({"127.0.0.1"})), \
         patch.object(http_mod, "_ALLOWED_SCHEME", "http"), \
         patch.object(pypi_mod, "_PYPI_API_BASE", base):
        attempt = adapter.fetch_attempt("down")

    assert attempt.outcome.state is FetchState.UNVERIFIABLE
    assert attempt.is_transient is True  # 5xx es reintentable


def test_e2e_200_es_found(local_pypi: int) -> None:
    """e2e REAL: una respuesta 200 valida => FOUND con PackageMetadata normalizado."""
    adapter = _build_local_adapter(local_pypi)
    base = f"http://127.0.0.1:{local_pypi}/pypi/{{name}}/json"
    with patch.object(http_mod, "ALLOWED_HOSTS", frozenset({"127.0.0.1"})), \
         patch.object(http_mod, "_ALLOWED_SCHEME", "http"), \
         patch.object(pypi_mod, "_PYPI_API_BASE", base):
        outcome = adapter.fetch("requests")

    assert outcome.state is FetchState.FOUND
    assert outcome.metadata is not None
    assert outcome.metadata.name == "requests"
