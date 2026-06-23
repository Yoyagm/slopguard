"""Suite de `WatchlistSource` (H2-T07, R2, RISK-H2-2) con mentalidad threat-detection.

El corpus depscope es un FEED EXTERNO: entrada NO confiable. A diferencia de un fake
de transporte, esta suite ejercita el camino REAL de extremo a extremo —`WatchlistSource`
sobre un `SecureHttpClient` GENUINO que habla con un servidor HTTP local malicioso
(`http.server`)— para validar el parseo defensivo del feed sobre sockets reales:
`response.read()` en streaming, `safe_json_loads` (anti JSON-bomb), `Content-Length`
acotado, la allowlist y la cache real en disco. Solo se neutraliza, igual que el harness
de `test_h2_net_post.py`, el rechazo de `http://127.0.0.1:<puerto-efimero>` (necesidad
tecnica del loopback); el endurecimiento de produccion corre tal cual.

Defensas cubiertas (RISK-H2-2 / threat-detection):
- PARSEO DEFENSIVO sobre el transporte real: corpus truncado (`Content-Length` > cuerpo),
  JSON-bomb (profundidad > `max_json_depth`), cuerpo sobre `max_response_bytes`, no-objeto
  JSON, 4xx/5xx/redirect ⇒ watchlist UNVERIFIABLE, jamas un falso CLEAN (NFR-Degr.1).
- PARSEO TOLERANTE: lista de strings / objetos (`name`/`package`) bajo varias claves;
  estructura inesperada ⇒ UNVERIFIABLE sin crashear (R2.5).
- ANTI-ENVENENAMIENTO: cada nombre se normaliza PEP 503 y valida charset AL LEER (de red
  y de cache); un corpus envenenado (CRLF/ANSI/unicode, nombres absurdamente largos) NO
  inyecta falsos KNOWN_HALLUCINATION ni rompe; cap `_WATCHLIST_MAX_NAMES` (anti-DoS).
- FRESHNESS/TTL 24h: hit vigente evita la red; UNVERIFIABLE jamas se cachea; el validador
  de cache reaplica charset+host (una escritura manipulada no inyecta matches falsos).
- PRIVACIDAD/SSRF: `extra_allowed_hosts == {watchlist_host}`; el GET NO lleva query string
  ni dato del usuario (NFR-Priv.1); host ajeno fuera del allowlist se rechaza.
- SANEO DE SALIDA: los textos de atribucion (fecha) se neutralizan (ANSI/C0-C1/CRLF) antes
  de salir (R7.2/R7.4, NFR-Seg.4).

Criterios EARS: R2.1-R2.6, R7.2/R7.4, NFR-Priv.1, NFR-Degr.1, NFR-Seg.1/2/4.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, ClassVar

import pytest

from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config
from slopguard.core.net import http_client as hc
from slopguard.core.threatintel import watchlist as wl
from slopguard.core.threatintel.source import MaliceState, ThreatIntelResult
from slopguard.core.threatintel.watchlist import WatchlistSource

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from pathlib import Path

# Epoch fijo para TTL determinista (alineado con el conftest del Hito 1).
_NOW: float = 1_717_200_000.0

# El cap de profundidad del transporte (config default). Un corpus anidado por encima
# es una JSON-bomb que `safe_json_loads` rechaza ANTES de materializar (NFR-Seg.2).
_MAX_JSON_DEPTH: int = 50


# ===========================================================================
# Servidor HTTP local malicioso: sirve corpus por ruta (camino REAL de get_json)
# ===========================================================================


class _CorpusHandler(BaseHTTPRequestHandler):
    """Sirve corpus/anomalias segun la ruta (mentalidad pen-testing de feed externo).

    Cada instancia del servidor configura `payloads`/`status`/`raw` por ruta a traves
    de atributos de clase fijados por `_LocalCorpusServer`. Asi un mismo servidor sirve
    distintos escenarios (MAL-/no-MAL/envenenado/truncado/bomba) sin reiniciarse.
    """

    payloads: ClassVar[dict[str, Any]] = {}
    raw_bodies: ClassVar[dict[str, bytes]] = {}
    truncated: ClassVar[set[str]] = set()
    statuses: ClassVar[dict[str, int]] = {}
    redirects: ClassVar[dict[str, str]] = {}
    last_query: ClassVar[str | None] = None

    def do_GET(self) -> None:  # firma impuesta por BaseHTTPRequestHandler
        """Responde el corpus de la ruta; registra el path para el aserto de privacidad."""
        type(self).last_query = self.path
        path = self.path.split("?", 1)[0]
        if path in self.redirects:
            self._redirect(self.redirects[path])
        elif path in self.statuses:
            self._send_status(self.statuses[path])
        elif path in self.truncated:
            self._send_truncated(self.raw_bodies[path])
        elif path in self.raw_bodies:
            self._send_raw(self.raw_bodies[path])
        elif path in self.payloads:
            self._send_json(self.payloads[path])
        else:
            self._send_status(404)

    def _send_json(self, payload: Any) -> None:
        self._send_raw(json.dumps(payload).encode())

    def _send_raw(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_truncated(self, body: bytes) -> None:
        # Declara mas bytes de los que entrega: el cliente lee menos => IncompleteRead
        # (cuerpo truncado) => NetworkUnverifiableError, jamas un corpus a medias.
        self.send_response(200)
        self.send_header("Content-Length", str(len(body) + 64))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _send_status(self, code: int) -> None:
        body = b'{"error":"x"}'
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        """Silencia el log del servidor para no contaminar la salida de pytest."""


class _LocalCorpusServer:
    """Levanta `_CorpusHandler` en 127.0.0.1 (puerto efimero) en un hilo daemon."""

    def __init__(self) -> None:
        _CorpusHandler.payloads = {}
        _CorpusHandler.raw_bodies = {}
        _CorpusHandler.truncated = set()
        _CorpusHandler.statuses = {}
        _CorpusHandler.redirects = {}
        _CorpusHandler.last_query = None
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _CorpusHandler)
        # poll_interval bajo: acorta la latencia de `shutdown()` (de 0.5s default a ~5ms)
        # sin perder fidelidad de socket; con 54 tests esto baja el teardown agregado de ~26s a <1s.
        self._thread = threading.Thread(
            target=lambda: self._httpd.serve_forever(poll_interval=0.005), daemon=True
        )
        self._stopped = False

    def __enter__(self) -> _LocalCorpusServer:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        """Apaga el servidor de forma idempotente.

        Algunos tests llaman `__exit__` explicitamente (para garantizar que el 2do lote
        viene de cache, sin red); el `with` del fixture lo llama de nuevo al salir. La
        guarda `_stopped` hace inocua la segunda llamada (no doble-shutdown ni doble-join).
        """
        if self._stopped:
            return
        self._stopped = True
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def serve_json(self, path: str, payload: Any) -> None:
        _CorpusHandler.payloads[path] = payload

    def serve_raw(self, path: str, body: bytes) -> None:
        _CorpusHandler.raw_bodies[path] = body

    def serve_truncated(self, path: str, body: bytes) -> None:
        _CorpusHandler.raw_bodies[path] = body
        _CorpusHandler.truncated.add(path)

    def serve_status(self, path: str, code: int) -> None:
        _CorpusHandler.statuses[path] = code

    def serve_redirect(self, path: str, location: str) -> None:
        _CorpusHandler.redirects[path] = location

    @property
    def host(self) -> str:
        # AF_INET => server_address es (host_str, port_int); el cast acota la union de stubs.
        return str(self._httpd.server_address[0])

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])


@pytest.fixture
def corpus_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[_LocalCorpusServer]:
    """Servidor local + permisos de allowlist/puerto para http://127.0.0.1 SOLO en el test.

    El loopback usa puerto efimero (necesidad tecnica); se neutralizan `_is_allowed` y
    `_reject_port_and_userinfo` igual que el harness del Hito 1/H2-T04, sin tocar el
    endurecimiento de produccion (que sigue rechazando puerto/userinfo y todo host ajeno).
    """

    def allow_local(
        scheme: str, host: str, allowed_hosts: frozenset[str] | None = None
    ) -> bool:
        return scheme.lower() == "http" and host == "127.0.0.1"

    monkeypatch.setattr(hc, "_is_allowed", allow_local)
    monkeypatch.setattr(hc, "_reject_port_and_userinfo", lambda _parts: None)
    with _LocalCorpusServer() as server:
        yield server


def _config(server: _LocalCorpusServer, **overrides: Any) -> Config:
    """Config de watchlist apuntando al servidor local (host loopback, path por defecto).

    `watchlist_host` se fija a `127.0.0.1`: el `SecureHttpClient` lo rechazaria en
    construccion (no es FQDN), por eso `_source` parchea el predicado anti-SSRF SOLO para
    permitir el loopback durante el test, reflejando que en produccion el host es depscope.dev.
    """
    return Config(enable_watchlist=True, watchlist_host=server.host, **overrides)


def _source(
    server: _LocalCorpusServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    path: str = "/api/benchmark/hallucinations",
    use_cache: bool = True,
    config: Config | None = None,
) -> WatchlistSource:
    """Construye un `WatchlistSource` REAL contra el servidor local (sin fake de transporte).

    El `SecureHttpClient` interno es el genuino (TLS handler incluido) mas un `HTTPHandler`
    para alcanzar el loopback http; la URL apunta al puerto efimero del servidor. La cache es
    un `DiskCache` real sobre `tmp_path`. El predicado anti-SSRF del cliente se parchea para
    admitir `127.0.0.1` solo en construccion (en produccion seria depscope.dev, un FQDN valido).
    """
    monkeypatch.setattr(hc, "_is_valid_https_host", lambda host: host == server.host)
    cfg = config or _config(server, watchlist_source_path=path)
    src = WatchlistSource(cfg, use_cache=use_cache)
    src._http._opener.add_handler(urllib.request.HTTPHandler())  # alcanzar loopback http
    src._url = f"http://{server.host}:{server.port}{cfg.watchlist_source_path}"
    src._cache = DiskCache(tmp_path / "cache", 24, enabled=use_cache)
    return src


def _query(src: WatchlistSource, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
    return src.query_batch(names)


def _serve_corpus(
    server: _LocalCorpusServer, payload: Any, *, path: str = "/api/benchmark/hallucinations"
) -> None:
    server.serve_json(path, payload)


# ===========================================================================
# Construccion: extra_allowed_hosts, URL y allowlist (R2.1, ADR-09)
# ===========================================================================


class TestConstruccion:
    def test_source_id_es_watchlist(self) -> None:
        assert WatchlistSource(Config(enable_watchlist=True)).source_id == "watchlist"

    def test_extra_allowed_hosts_es_solo_watchlist_host(self) -> None:
        """R2.1/ADR-09/NFR-Seg.1: la fuente declara SOLO `{watchlist_host}` (depscope.dev)."""
        src = WatchlistSource(Config(enable_watchlist=True))
        assert src.extra_allowed_hosts == frozenset({"depscope.dev"})

    def test_url_se_construye_de_host_y_path(self) -> None:
        src = WatchlistSource(Config(enable_watchlist=True))
        assert src._url == "https://depscope.dev/api/benchmark/hallucinations"

    def test_cliente_real_no_admite_host_ajeno(self) -> None:
        """NFR-Seg.1: el `SecureHttpClient` real solo lleva la base + depscope.dev."""
        src = WatchlistSource(Config(enable_watchlist=True))
        assert src._http._allowed_hosts == frozenset({"pypi.org", "depscope.dev"})


# ===========================================================================
# Camino REAL feliz: GET corpus por socket -> match exacto (R2.3) + cobertura total
# ===========================================================================


class TestMatchExactoReal:
    def test_nombre_en_corpus_es_known_hallucination(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _serve_corpus(corpus_server, {"names": ["reqe", "djangoo"], "corpus_date": "2026-06-20"})
        src = _source(corpus_server, tmp_path, monkeypatch)
        result = _query(src, ["reqe"])["reqe"]
        assert result.state is MaliceState.KNOWN_HALLUCINATION
        assert result.watchlist_source == "depscope-hallucinations"
        assert result.watchlist_date == "2026-06-20"

    def test_nombre_fuera_de_corpus_es_clean(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _serve_corpus(corpus_server, {"names": ["reqe"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        assert _query(src, ["requests"])["requests"].state is MaliceState.CLEAN

    def test_match_es_exacto_no_fuzzy(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No hay fuzzy match en watchlist (eso es Capa 1): 'req' no matchea 'reqe' (R2.3)."""
        _serve_corpus(corpus_server, {"names": ["reqe"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        assert _query(src, ["req"])["req"].state is MaliceState.CLEAN

    def test_cobertura_total_del_lote(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """El dict devuelto tiene UNA entrada por cada nombre del lote (§3.2 punto 4)."""
        _serve_corpus(corpus_server, {"names": ["reqe", "djangoo"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        names = ["reqe", "requests", "djangoo", "flask"]
        result = _query(src, names)
        assert set(result) == set(names)
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION
        assert result["requests"].state is MaliceState.CLEAN

    def test_lote_vacio_devuelve_dict_vacio(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _serve_corpus(corpus_server, {"names": ["reqe"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        assert _query(src, []) == {}


# ===========================================================================
# Parseo TOLERANTE de la estructura del corpus, sobre el transporte real (R2.4)
# ===========================================================================


class TestParseoTolerante:
    @pytest.mark.parametrize("root_key", ["names", "packages", "hallucinations", "results"])
    def test_lista_de_strings_bajo_varias_claves(
        self,
        corpus_server: _LocalCorpusServer,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        root_key: str,
    ) -> None:
        _serve_corpus(corpus_server, {root_key: ["reqe"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        assert _query(src, ["reqe"])["reqe"].state is MaliceState.KNOWN_HALLUCINATION

    def test_lista_de_objetos_con_name(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _serve_corpus(corpus_server, {"names": [{"name": "reqe"}, {"name": "djangoo"}]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        assert _query(src, ["reqe"])["reqe"].state is MaliceState.KNOWN_HALLUCINATION

    def test_lista_de_objetos_con_package(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _serve_corpus(corpus_server, {"packages": [{"package": "reqe"}]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        assert _query(src, ["reqe"])["reqe"].state is MaliceState.KNOWN_HALLUCINATION

    def test_objetos_y_strings_mezclados_ignora_basura(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Items no reconocibles (int/null) se descartan sin invalidar el corpus (R2.4)."""
        _serve_corpus(corpus_server, {"names": ["reqe", {"name": "djangoo"}, 123, None]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        result = _query(src, ["reqe", "djangoo"])
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION
        assert result["djangoo"].state is MaliceState.KNOWN_HALLUCINATION


# ===========================================================================
# DEGRADACION SEGURA del FEED real: anomalia de transporte/estructura ⇒ UNVERIFIABLE
# (R2.5, NFR-Degr.1) — el corazon de RISK-H2-2 sobre sockets reales
# ===========================================================================


def _assert_all_unverifiable(
    result: dict[str, ThreatIntelResult], names: Sequence[str]
) -> None:
    assert set(result) == set(names)
    assert all(r.state is MaliceState.UNVERIFIABLE for r in result.values())
    assert all(r.unverifiable_reason for r in result.values())  # razon saneada presente


class TestDegradacionSeguraReal:
    @pytest.mark.parametrize(
        "payload",
        [
            {},  # sin lista reconocible
            {"otra_clave": ["reqe"]},  # clave no soportada
            {"names": "no-es-lista"},  # tipo invalido
            {"names": {"reqe": True}},  # dict en vez de lista
            {"names": 42},  # escalar
        ],
    )
    def test_estructura_inesperada_es_unverifiable(
        self,
        corpus_server: _LocalCorpusServer,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        payload: dict[str, Any],
    ) -> None:
        _serve_corpus(corpus_server, payload)
        src = _source(corpus_server, tmp_path, monkeypatch)
        _assert_all_unverifiable(_query(src, ["reqe", "flask"]), ["reqe", "flask"])

    def test_respuesta_no_objeto_json_es_unverifiable(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Un top-level que no es objeto (lista cruda) ⇒ NetworkUnverifiableError ⇒ degradado."""
        corpus_server.serve_raw("/api/benchmark/hallucinations", b'["reqe","djangoo"]')
        src = _source(corpus_server, tmp_path, monkeypatch)
        _assert_all_unverifiable(_query(src, ["reqe"]), ["reqe"])

    def test_cuerpo_truncado_es_unverifiable(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RISK-H2-2: `Content-Length` mayor que el cuerpo ⇒ lectura truncada ⇒ no CLEAN."""
        corpus_server.serve_truncated(
            "/api/benchmark/hallucinations", b'{"names":["reqe"'
        )
        src = _source(corpus_server, tmp_path, monkeypatch)
        _assert_all_unverifiable(_query(src, ["reqe"]), ["reqe"])

    def test_json_bomb_por_profundidad_es_unverifiable(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """NFR-Seg.2: anidamiento > max_json_depth se rechaza ANTES de materializar (no CLEAN)."""
        bomb = b"[" * (_MAX_JSON_DEPTH + 5) + b"]" * (_MAX_JSON_DEPTH + 5)
        corpus_server.serve_raw("/api/benchmark/hallucinations", b'{"names":' + bomb + b"}")
        src = _source(corpus_server, tmp_path, monkeypatch)
        _assert_all_unverifiable(_query(src, ["reqe"]), ["reqe"])

    def test_cuerpo_sobre_max_response_bytes_es_unverifiable(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """NFR-Seg.2: un corpus que excede `max_response_bytes` se aborta en streaming, no CLEAN."""
        cfg = _config(corpus_server, max_response_bytes=512)
        big = json.dumps({"names": ["a" * 2000]}).encode()
        corpus_server.serve_raw("/api/benchmark/hallucinations", big)
        src = _source(corpus_server, tmp_path, monkeypatch, config=cfg)
        _assert_all_unverifiable(_query(src, ["reqe"]), ["reqe"])

    @pytest.mark.parametrize("code", [404, 403, 429, 500, 503])
    def test_status_http_de_error_es_unverifiable(
        self,
        corpus_server: _LocalCorpusServer,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        code: int,
    ) -> None:
        """R2.5: cualquier respuesta >=400 (incl. 429/5xx) ⇒ corpus UNVERIFIABLE, nunca CLEAN."""
        corpus_server.serve_status("/api/benchmark/hallucinations", code)
        src = _source(corpus_server, tmp_path, monkeypatch)
        _assert_all_unverifiable(_query(src, ["reqe", "flask"]), ["reqe", "flask"])

    def test_redirect_cross_host_es_unverifiable(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """NFR-Seg.1: un 302 del feed hacia otro host se rechaza (sin seguir) ⇒ UNVERIFIABLE."""
        corpus_server.serve_redirect(
            "/api/benchmark/hallucinations", "https://evil.example/x"
        )
        src = _source(corpus_server, tmp_path, monkeypatch)
        _assert_all_unverifiable(_query(src, ["reqe"]), ["reqe"])

    def test_corpus_vacio_tras_validar_es_unverifiable(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Lista presente pero sin un solo nombre valido ⇒ UNVERIFIABLE (no CLEAN)."""
        _serve_corpus(corpus_server, {"names": [123, None, {"x": 1}]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        _assert_all_unverifiable(_query(src, ["reqe"]), ["reqe"])

    def test_lista_explicitamente_vacia_es_unverifiable(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _serve_corpus(corpus_server, {"names": []})
        src = _source(corpus_server, tmp_path, monkeypatch)
        _assert_all_unverifiable(_query(src, ["reqe"]), ["reqe"])


# ===========================================================================
# ANTI-ENVENENAMIENTO del FEED real: charset al leer + cap (threat-detection, RISK-H2-2)
# ===========================================================================


class TestAntiEnvenenamientoReal:
    @pytest.mark.parametrize(
        "poisoned",
        [
            "reqe\r\nX-Inject: y",  # CRLF (inyeccion de header/log)
            "reqe\x1b[31m",  # ANSI
            "reqe\x00",  # NUL
            "reqe@evil",  # charset fuera de [a-z0-9-]
            "REQE!",  # mayuscula+simbolo (normalize baja, ! sobrevive)
            "паке",  # unicode
        ],
    )
    def test_nombre_envenenado_no_inyecta_match(
        self,
        corpus_server: _LocalCorpusServer,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        poisoned: str,
    ) -> None:
        """Un nombre envenenado se DESCARTA al leer: no produce KNOWN_HALLUCINATION falso."""
        _serve_corpus(corpus_server, {"names": [poisoned]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        # El unico nombre se descarta ⇒ corpus vacio ⇒ UNVERIFIABLE (nunca CLEAN ni match).
        result = _query(src, ["reqe"])
        assert result["reqe"].state is not MaliceState.KNOWN_HALLUCINATION

    def test_envenenado_no_invalida_nombres_validos(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Un nombre invalido se descarta SIN invalidar el corpus entero (solo el invalido)."""
        _serve_corpus(corpus_server, {"names": ["reqe", "evil@x", "djangoo"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        result = _query(src, ["reqe", "djangoo", "evil@x"])
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION
        assert result["djangoo"].state is MaliceState.KNOWN_HALLUCINATION
        # 'evil@x' nunca entro al corpus ⇒ no matchea (CLEAN, no KNOWN_HALLUCINATION).
        assert result["evil@x"].state is MaliceState.CLEAN

    def test_nombre_absurdamente_largo_se_descarta(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nombre > nombre_max_chars se descarta al leer (no se materializa el match)."""
        largo = "a" * 200  # > nombre_max_chars (100)
        _serve_corpus(corpus_server, {"names": [largo, "reqe"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        result = _query(src, [largo, "reqe"])
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION
        assert result[largo].state is MaliceState.CLEAN  # nunca entro al corpus

    def test_normaliza_pep503_al_leer(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """'Django_Rest' (corpus) normaliza a 'django-rest' y matchea ese nombre."""
        _serve_corpus(corpus_server, {"names": ["Django_Rest"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        match = _query(src, ["django-rest"])["django-rest"]
        assert match.state is MaliceState.KNOWN_HALLUCINATION

    def test_cap_excedido_es_unverifiable(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Corpus sobre `_WATCHLIST_MAX_NAMES` ⇒ UNVERIFIABLE (anti-DoS, no se trunca)."""
        monkeypatch.setattr(wl, "_WATCHLIST_MAX_NAMES", 2)
        _serve_corpus(corpus_server, {"names": ["reqe", "djangoo", "flasky"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        _assert_all_unverifiable(_query(src, ["reqe"]), ["reqe"])


# ===========================================================================
# PRIVACIDAD (NFR-Priv.1): el GET no lleva dato del usuario; el corpus no se redistribuye
# ===========================================================================


class TestPrivacidad:
    def test_get_no_lleva_query_string_del_usuario(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """NFR-Priv.1: la peticion del corpus es un GET pelado, sin nombres en query string."""
        _serve_corpus(corpus_server, {"names": ["reqe"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        _query(src, ["secreto-del-usuario", "reqe"])
        assert _CorpusHandler.last_query == "/api/benchmark/hallucinations"
        assert "secreto-del-usuario" not in (_CorpusHandler.last_query or "")


# ===========================================================================
# FRESHNESS / TTL 24h + cache REAL en disco (R2.2/R6.2, NFR-Degr.1)
# ===========================================================================


class TestCacheYFreshness:
    def test_segundo_lote_usa_cache_sin_red(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tras un fetch real, el corpus se cachea; el 2do lote acierta aunque caiga la red."""
        _serve_corpus(corpus_server, {"names": ["reqe"], "corpus_date": "2026-06-20"})
        src = _source(corpus_server, tmp_path, monkeypatch)
        _query(src, ["reqe"])  # poblo la cache desde el servidor real
        # Apagar el servidor: si el 2do lote tocara la red, degradaria a UNVERIFIABLE.
        corpus_server.__exit__()
        result = _query(src, ["reqe", "flask"])
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION  # vino de cache
        assert result["flask"].state is MaliceState.CLEAN

    def test_unverifiable_no_se_cachea(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Un corpus caido NO se cachea: un fetch posterior reintenta y, ya OK, matchea."""
        corpus_server.serve_status("/api/benchmark/hallucinations", 503)
        src = _source(corpus_server, tmp_path, monkeypatch)
        _assert_all_unverifiable(_query(src, ["reqe"]), ["reqe"])
        # El corpus no quedo en disco: ahora el servidor responde OK y el match aparece.
        _serve_corpus(corpus_server, {"names": ["reqe"]})
        _CorpusHandler.statuses.pop("/api/benchmark/hallucinations", None)
        assert _query(src, ["reqe"])["reqe"].state is MaliceState.KNOWN_HALLUCINATION

    def test_cache_revalida_charset_al_leer(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Un blob de cache manipulado con nombres envenenados se sanea AL LEER (§2.5).

        Se escribe directamente un blob con un nombre invalido mas uno valido: al leer,
        el invalido se descarta y solo el valido matchea (no inyecta falsos positivos).
        El servidor se apaga para garantizar que el resultado vino de cache, no de red.
        """
        src = _source(corpus_server, tmp_path, monkeypatch)
        src._cache.put_blob(
            "watchlist",
            src._cache_key,
            {"source": "watchlist", "host": corpus_server.host,
             "names": ["djangoo", "evil@x"], "corpus_date": "2026-06-20"},
            now=time.time(),
        )
        corpus_server.__exit__()  # sin red: el resultado DEBE venir del blob
        result = src.query_batch(["djangoo", "evil@x"])
        assert result["djangoo"].state is MaliceState.KNOWN_HALLUCINATION
        assert result["evil@x"].state is MaliceState.CLEAN  # invalido descartado al leer

    def test_blob_de_otro_host_es_miss(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Un blob cuyo `host` no coincide con el esperado ⇒ miss ⇒ refetch (anti-manipulacion)."""
        _serve_corpus(corpus_server, {"names": ["reqe"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        src._cache.put_blob(
            "watchlist",
            src._cache_key,
            {"source": "watchlist", "host": "evil.dev", "names": ["djangoo"]},
            now=time.time(),
        )
        # El blob de host ajeno se rechaza ⇒ se va a la red ⇒ matchea 'reqe' (del servidor),
        # NO 'djangoo' (del blob manipulado): la inyeccion por cache no surte efecto.
        result = src.query_batch(["reqe", "djangoo"])
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION
        assert result["djangoo"].state is MaliceState.CLEAN

    def test_ttl_vencido_es_miss_y_refetch(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """FRESHNESS: un blob mas viejo que el TTL (24h) no se sirve; se refetch del feed."""
        _serve_corpus(corpus_server, {"names": ["reqe"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        viejo = time.time() - (25 * 3600)  # 25h > TTL 24h
        src._cache.put_blob(
            "watchlist",
            src._cache_key,
            {"source": "watchlist", "host": corpus_server.host, "names": ["djangoo"]},
            now=viejo,
        )
        # El blob vencido se ignora; el feed fresco solo conoce 'reqe'.
        result = src.query_batch(["reqe", "djangoo"])
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION
        assert result["djangoo"].state is MaliceState.CLEAN

    def test_no_cache_no_persiste(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`--no-cache` (use_cache=False) ⇒ nada se persiste en disco (R6.3)."""
        _serve_corpus(corpus_server, {"names": ["reqe"]})
        src = _source(corpus_server, tmp_path, monkeypatch, use_cache=False)
        _query(src, ["reqe"])
        cache_dir = tmp_path / "cache"
        assert not cache_dir.exists() or not list(cache_dir.glob("*.json"))


# ===========================================================================
# SANEO DE SALIDA: la fecha de atribucion se neutraliza (R7.2/R7.4, NFR-Seg.4)
# ===========================================================================


class TestSaneoAtribucion:
    def test_corpus_date_se_sanea(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ANSI/CRLF en la fecha del corpus se eliminan antes de salir (anti inyeccion)."""
        _serve_corpus(
            corpus_server, {"names": ["reqe"], "corpus_date": "2026-06-20\x1b[31m\r\n"}
        )
        src = _source(corpus_server, tmp_path, monkeypatch)
        assert _query(src, ["reqe"])["reqe"].watchlist_date == "2026-06-20"

    def test_corpus_date_acepta_date_y_generated_at(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _serve_corpus(corpus_server, {"names": ["reqe"], "generated_at": "2026-01-01"})
        src = _source(corpus_server, tmp_path, monkeypatch)
        assert _query(src, ["reqe"])["reqe"].watchlist_date == "2026-01-01"

    def test_corpus_sin_fecha_no_crashea(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _serve_corpus(corpus_server, {"names": ["reqe"]})
        src = _source(corpus_server, tmp_path, monkeypatch)
        result = _query(src, ["reqe"])["reqe"]
        assert result.state is MaliceState.KNOWN_HALLUCINATION
        assert result.watchlist_date is None


# ===========================================================================
# Round-trip de cache REAL: el corpus persistido es JSON con atribucion (§2.5, R2.6)
# ===========================================================================


class TestRoundTripCache:
    def test_corpus_persistido_es_json_con_atribucion(
        self, corpus_server: _LocalCorpusServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """El blob persistido lleva names/host/license/corpus_date y es JSON (NFR-Seg.2, R2.6)."""
        _serve_corpus(
            corpus_server, {"names": ["reqe", "djangoo"], "corpus_date": "2026-06-20"}
        )
        src = _source(corpus_server, tmp_path, monkeypatch)
        _query(src, ["reqe"])  # fuerza el fetch real + persistencia
        raw = json.loads(_blob_path(tmp_path, src._cache_key).read_bytes())
        assert raw["source"] == "watchlist"
        assert raw["host"] == corpus_server.host
        assert raw["license"] == "CC-BY-NC-SA-4.0"
        assert raw["corpus_date"] == "2026-06-20"
        assert sorted(raw["names"]) == ["djangoo", "reqe"]
        # El corpus NO se embebe en el paquete: solo cache local del usuario (CC-BY-NC-SA).
        assert _blob_path(tmp_path, src._cache_key).parent == tmp_path / "cache"


def _blob_path(tmp_path: Path, key: str) -> Path:
    digest = hashlib.sha256(f"watchlist:{key}".encode()).hexdigest()
    return tmp_path / "cache" / f"{digest}.json"
