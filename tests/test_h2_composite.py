"""Suite de `CompositeSource` y `get_threatintel_source` (H2-T08 / H2-T19-T21 parcial).

Cubre (per tasks.md H2-T08 + el finding amarillo de la tarea):

  1. PRECEDENCIA de `_merge` en todos los empates y ordenaciones:
     MALICIOUS > KNOWN_HALLUCINATION > UNVERIFIABLE > CLEAN
     incluyendo empates (primer-gana) y transitividad.

  2. AGGREGACION de `extra_allowed_hosts` con y sin watchlist:
     - Solo OSV  => {api.osv.dev}
     - OSV + watchlist => {api.osv.dev, depscope.dev}
     - enable_layer3=False => None => sin hosts

  3. COBERTURA TOTAL del dict de salida (todo nombre de entrada tiene entrada).

  4. REGISTRY (`get_threatintel_source`):
     - enable_layer3=False => None (R5.3)
     - enable_layer3=True, enable_watchlist=False => solo OsvSource en el composite
     - enable_layer3=True, enable_watchlist=True  => OsvSource + WatchlistSource

  5. COMPOSICION REAL contra stubs (fuentes falsas inyectables):
     Cada stub implementa `ThreatIntelSource` (duck typing) y devuelve un dict
     prefijado, sin red ni disco.  El composite los fan-out y fusiona.

  6. DEGRADACION / comportamiento ante fuente caida (UNVERIFIABLE desde una fuente
     pero MALICIOUS desde la otra => el positivo domina, nunca se pierde el block).

  7. PRIVACIDAD: con enable_watchlist=False, depscope.dev NO aparece en
     `extra_allowed_hosts` del composite (R2.1 / ADR-09).

  8. SERVIDOR HTTP LOCAL para los tests de composicion reales (OSV + watchlist):
     misma metodologia que `test_h2_osv.py` / `test_h2_watchlist.py`: se inyectan
     `_http` / `_query_url` / `_cache` tras la construccion de cada fuente para
     alcanzar el loopback.

No se tocan capas/scoring ni engine (fuera del alcance de esta tarea).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, ClassVar, Final

import pytest

from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config
from slopguard.core.models import Advisory
from slopguard.core.net import http_client as hc
from slopguard.core.net.http_client import SecureHttpClient
from slopguard.core.threatintel.composite import CompositeSource, _merge
from slopguard.core.threatintel.osv import OsvSource
from slopguard.core.threatintel.registry import get_threatintel_source
from slopguard.core.threatintel.source import MaliceState, ThreatIntelResult
from slopguard.core.threatintel.watchlist import WatchlistSource

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers: constructores de resultados canónicos
# ---------------------------------------------------------------------------

_ADV: Final[Advisory] = Advisory(
    id="MAL-2025-1",
    kind="malicious",
    url="https://osv.dev/vulnerability/MAL-2025-1",
    source="osv",
)


def _clean(name: str = "pkg") -> ThreatIntelResult:
    return ThreatIntelResult(name=name, state=MaliceState.CLEAN)


def _malicious(name: str = "pkg") -> ThreatIntelResult:
    return ThreatIntelResult(name=name, state=MaliceState.MALICIOUS, advisories=(_ADV,))


def _hallucination(name: str = "pkg") -> ThreatIntelResult:
    return ThreatIntelResult(
        name=name,
        state=MaliceState.KNOWN_HALLUCINATION,
        watchlist_source="depscope-hallucinations",
        watchlist_date="2026-06-20",
    )


def _unverifiable(name: str = "pkg") -> ThreatIntelResult:
    return ThreatIntelResult(
        name=name,
        state=MaliceState.UNVERIFIABLE,
        unverifiable_reason="fuente caida",
    )


def _cfg(**overrides: Any) -> Config:
    """Config base con timeouts cortos para los tests de red."""
    base: dict[str, Any] = {
        "connect_timeout_s": 2.0,
        "read_timeout_s": 2.0,
        "osv_timeout_total_por_lote_s": 2.0,
        "osv_reintentos": 1,
        "watchlist_timeout_total_s": 2.0,
    }
    base.update(overrides)
    return Config(**base)


# ---------------------------------------------------------------------------
# Stub de fuente inyectable (sin red ni disco)
# ---------------------------------------------------------------------------


class _StubSource:
    """Fuente falsa: devuelve resultados prefijados; no toca red ni disco."""

    source_id: str

    def __init__(
        self,
        source_id: str,
        results: dict[str, ThreatIntelResult],
        extra_hosts: frozenset[str] = frozenset(),
    ) -> None:
        self.source_id = source_id
        self._results = results
        self.extra_allowed_hosts: frozenset[str] = extra_hosts

    def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
        """Devuelve los resultados preconfigurados; UNVERIFIABLE para los no mapeados."""
        out: dict[str, ThreatIntelResult] = {}
        for name in names:
            out[name] = self._results.get(
                name, ThreatIntelResult(name=name, state=MaliceState.UNVERIFIABLE)
            )
        return out


# ===========================================================================
# 1. Precedencia de _merge — tabla exhaustiva (design §2.2)
# ===========================================================================


class TestMerge:
    """Verifica la tabla de precedencia MALICIOUS>KNOWN_HALLUCINATION>UNVERIFIABLE>CLEAN."""

    def test_malicious_gana_sobre_clean(self) -> None:
        assert _merge(_clean(), _malicious()).state is MaliceState.MALICIOUS

    def test_clean_no_sube_sobre_malicious(self) -> None:
        assert _merge(_malicious(), _clean()).state is MaliceState.MALICIOUS

    def test_malicious_gana_sobre_hallucination(self) -> None:
        assert _merge(_hallucination(), _malicious()).state is MaliceState.MALICIOUS

    def test_hallucination_no_sube_sobre_malicious(self) -> None:
        assert _merge(_malicious(), _hallucination()).state is MaliceState.MALICIOUS

    def test_malicious_gana_sobre_unverifiable(self) -> None:
        assert _merge(_unverifiable(), _malicious()).state is MaliceState.MALICIOUS

    def test_unverifiable_no_sube_sobre_malicious(self) -> None:
        assert _merge(_malicious(), _unverifiable()).state is MaliceState.MALICIOUS

    def test_hallucination_gana_sobre_clean(self) -> None:
        assert _merge(_clean(), _hallucination()).state is MaliceState.KNOWN_HALLUCINATION

    def test_clean_no_sube_sobre_hallucination(self) -> None:
        assert _merge(_hallucination(), _clean()).state is MaliceState.KNOWN_HALLUCINATION

    def test_hallucination_gana_sobre_unverifiable(self) -> None:
        assert _merge(_unverifiable(), _hallucination()).state is MaliceState.KNOWN_HALLUCINATION

    def test_unverifiable_no_sube_sobre_hallucination(self) -> None:
        assert _merge(_hallucination(), _unverifiable()).state is MaliceState.KNOWN_HALLUCINATION

    def test_unverifiable_gana_sobre_clean(self) -> None:
        assert _merge(_clean(), _unverifiable()).state is MaliceState.UNVERIFIABLE

    def test_clean_no_sube_sobre_unverifiable(self) -> None:
        assert _merge(_unverifiable(), _clean()).state is MaliceState.UNVERIFIABLE

    # --- Empates: primer-gana (current se conserva) ---

    def test_empate_malicious_primer_gana(self) -> None:
        # current ya es MALICIOUS => no se reemplaza con otro MALICIOUS
        current = _malicious()
        incoming = ThreatIntelResult(
            name="pkg",
            state=MaliceState.MALICIOUS,
            advisories=(
                Advisory(
                    id="MAL-9999",
                    kind="malicious",
                    url="https://osv.dev/vulnerability/MAL-9999",
                    source="osv",
                ),
            ),
        )
        merged = _merge(current, incoming)
        # La identidad del objeto resultante es 'current' (primer-gana, no el incoming)
        assert merged is current

    def test_empate_clean_primer_gana(self) -> None:
        c1 = _clean()
        c2 = _clean()
        assert _merge(c1, c2) is c1

    def test_empate_unverifiable_primer_gana(self) -> None:
        u1 = _unverifiable()
        u2 = ThreatIntelResult(
            name="pkg", state=MaliceState.UNVERIFIABLE, unverifiable_reason="otra"
        )
        assert _merge(u1, u2) is u1

    def test_empate_hallucination_primer_gana(self) -> None:
        h1 = _hallucination()
        h2 = ThreatIntelResult(
            name="pkg",
            state=MaliceState.KNOWN_HALLUCINATION,
            watchlist_date="2025-01-01",
        )
        assert _merge(h1, h2) is h1

    # --- Transitividad ---

    def test_transitividad_clean_unverifiable_malicious(self) -> None:
        # clean vs unverifiable => unverifiable; luego vs malicious => malicious
        paso1 = _merge(_clean(), _unverifiable())
        assert paso1.state is MaliceState.UNVERIFIABLE
        paso2 = _merge(paso1, _malicious())
        assert paso2.state is MaliceState.MALICIOUS

    def test_transitividad_hallucination_luego_malicious(self) -> None:
        paso1 = _merge(_clean(), _hallucination())
        paso2 = _merge(paso1, _malicious())
        assert paso2.state is MaliceState.MALICIOUS


# ===========================================================================
# 2. CompositeSource con stubs — fan-out y fusión
# ===========================================================================


class TestCompositeStubs:
    """Verifica el fan-out y la fusión del CompositeSource usando fuentes stub."""

    def test_una_fuente_osv_malicious(self) -> None:
        stub = _StubSource("osv", {"bioql": _malicious("bioql")})
        comp = CompositeSource((stub,))
        result = comp.query_batch(["bioql"])
        assert result["bioql"].state is MaliceState.MALICIOUS

    def test_dos_fuentes_osv_malicious_watchlist_clean(self) -> None:
        # OSV dice MALICIOUS, watchlist dice CLEAN => resultado es MALICIOUS
        osv_stub = _StubSource("osv", {"bioql": _malicious("bioql")})
        wl_stub = _StubSource("watchlist", {"bioql": _clean("bioql")})
        comp = CompositeSource((osv_stub, wl_stub))
        result = comp.query_batch(["bioql"])
        assert result["bioql"].state is MaliceState.MALICIOUS

    def test_dos_fuentes_osv_clean_watchlist_hallucination(self) -> None:
        # OSV dice CLEAN, watchlist dice KNOWN_HALLUCINATION => resultado es KNOWN_HALLUCINATION
        osv_stub = _StubSource("osv", {"reqe": _clean("reqe")})
        wl_stub = _StubSource("watchlist", {"reqe": _hallucination("reqe")})
        comp = CompositeSource((osv_stub, wl_stub))
        result = comp.query_batch(["reqe"])
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION

    def test_dos_fuentes_ambas_unverifiable(self) -> None:
        osv_stub = _StubSource("osv", {"x": _unverifiable("x")})
        wl_stub = _StubSource("watchlist", {"x": _unverifiable("x")})
        comp = CompositeSource((osv_stub, wl_stub))
        result = comp.query_batch(["x"])
        assert result["x"].state is MaliceState.UNVERIFIABLE

    def test_osv_unverifiable_watchlist_hallucination_positivo_domina(self) -> None:
        # OSV cae (UNVERIFIABLE), watchlist matchea => KNOWN_HALLUCINATION (positivo domina)
        # Este es el escenario de degradacion segura: la fuente viva con match positivo manda.
        osv_stub = _StubSource("osv", {"reqe": _unverifiable("reqe")})
        wl_stub = _StubSource("watchlist", {"reqe": _hallucination("reqe")})
        comp = CompositeSource((osv_stub, wl_stub))
        result = comp.query_batch(["reqe"])
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION

    def test_osv_malicious_watchlist_unverifiable_block_no_se_pierde(self) -> None:
        # OSV dice MALICIOUS, watchlist cae (UNVERIFIABLE) => MALICIOUS (block no se pierde)
        osv_stub = _StubSource("osv", {"bioql": _malicious("bioql")})
        wl_stub = _StubSource("watchlist", {"bioql": _unverifiable("bioql")})
        comp = CompositeSource((osv_stub, wl_stub))
        result = comp.query_batch(["bioql"])
        assert result["bioql"].state is MaliceState.MALICIOUS

    def test_lote_varios_nombres_cobertura_total(self) -> None:
        # Todos los nombres de entrada deben tener entrada en el resultado
        osv_stub = _StubSource("osv", {"a": _malicious("a"), "b": _clean("b")})
        comp = CompositeSource((osv_stub,))
        names = ["a", "b", "c"]
        result = comp.query_batch(names)
        assert set(result.keys()) == set(names)
        assert result["a"].state is MaliceState.MALICIOUS
        assert result["b"].state is MaliceState.CLEAN
        # "c" no está en el stub => _StubSource devuelve UNVERIFIABLE por defecto
        assert result["c"].state is MaliceState.UNVERIFIABLE

    def test_lote_vacio_devuelve_dict_vacio(self) -> None:
        stub = _StubSource("osv", {})
        comp = CompositeSource((stub,))
        assert comp.query_batch([]) == {}

    def test_mixed_escenario_completo(self) -> None:
        # Tres nombres: malicious / hallucination / clean — cada uno desde una fuente distinta
        osv_stub = _StubSource("osv", {
            "bioql": _malicious("bioql"),
            "reqe": _clean("reqe"),
            "safelib": _clean("safelib"),
        })
        wl_stub = _StubSource("watchlist", {
            "bioql": _clean("bioql"),
            "reqe": _hallucination("reqe"),
            "safelib": _clean("safelib"),
        })
        comp = CompositeSource((osv_stub, wl_stub))
        result = comp.query_batch(["bioql", "reqe", "safelib"])
        assert result["bioql"].state is MaliceState.MALICIOUS
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION
        assert result["safelib"].state is MaliceState.CLEAN


# ===========================================================================
# 3. Aggregación de extra_allowed_hosts
# ===========================================================================


class TestAllowedHosts:
    """Verifica la union de extra_allowed_hosts con/sin watchlist (ADR-09)."""

    def test_solo_osv_hosts(self) -> None:
        stub_osv = _StubSource("osv", {}, extra_hosts=frozenset({"api.osv.dev"}))
        comp = CompositeSource((stub_osv,))
        assert comp.extra_allowed_hosts == frozenset({"api.osv.dev"})

    def test_osv_y_watchlist_union_de_hosts(self) -> None:
        stub_osv = _StubSource("osv", {}, extra_hosts=frozenset({"api.osv.dev"}))
        stub_wl = _StubSource("watchlist", {}, extra_hosts=frozenset({"depscope.dev"}))
        comp = CompositeSource((stub_osv, stub_wl))
        assert comp.extra_allowed_hosts == frozenset({"api.osv.dev", "depscope.dev"})

    def test_sin_watchlist_depscope_no_aparece(self) -> None:
        stub_osv = _StubSource("osv", {}, extra_hosts=frozenset({"api.osv.dev"}))
        comp = CompositeSource((stub_osv,))
        assert "depscope.dev" not in comp.extra_allowed_hosts

    def test_source_id_es_composite(self) -> None:
        stub = _StubSource("osv", {})
        comp = CompositeSource((stub,))
        assert comp.source_id == "composite"

    def test_hosts_con_multiples_fuentes_es_union(self) -> None:
        s1 = _StubSource("a", {}, extra_hosts=frozenset({"h1.example.com"}))
        s2 = _StubSource("b", {}, extra_hosts=frozenset({"h2.example.com"}))
        s3 = _StubSource("c", {}, extra_hosts=frozenset({"h1.example.com", "h3.example.com"}))
        comp = CompositeSource((s1, s2, s3))
        assert comp.extra_allowed_hosts == frozenset(
            {"h1.example.com", "h2.example.com", "h3.example.com"}
        )


# ===========================================================================
# 4. Registry — get_threatintel_source
# ===========================================================================


class TestRegistry:
    """Verifica la lógica de habilitación del registry (R5.3, R2.1, ADR-09)."""

    def test_enable_layer3_false_devuelve_none(self) -> None:
        config = _cfg(enable_layer3=False)
        source = get_threatintel_source(config, use_cache=False)
        assert source is None

    def test_enable_layer3_true_devuelve_composite(self) -> None:
        config = _cfg(enable_layer3=True, enable_watchlist=False)
        source = get_threatintel_source(config, use_cache=False)
        assert isinstance(source, CompositeSource)

    def test_enable_layer3_true_watchlist_false_solo_osv_hosts(self) -> None:
        # Sin watchlist: depscope.dev NO está en el allowlist efectivo (R2.1)
        config = _cfg(enable_layer3=True, enable_watchlist=False)
        source = get_threatintel_source(config, use_cache=False)
        assert source is not None
        assert "depscope.dev" not in source.extra_allowed_hosts
        assert "api.osv.dev" in source.extra_allowed_hosts

    def test_enable_layer3_true_watchlist_true_incluye_depscope(self) -> None:
        # Con watchlist: depscope.dev SÍ está (R2.1)
        config = _cfg(enable_layer3=True, enable_watchlist=True)
        source = get_threatintel_source(config, use_cache=False)
        assert source is not None
        assert "depscope.dev" in source.extra_allowed_hosts
        assert "api.osv.dev" in source.extra_allowed_hosts

    def test_enable_layer3_false_sin_hosts_de_red(self) -> None:
        # None => el engine no amplía el allowlist con hosts de Capa 3 (R5.3)
        config = _cfg(enable_layer3=False)
        source = get_threatintel_source(config, use_cache=False)
        assert source is None

    def test_use_cache_false_no_crashea(self) -> None:
        # Pasar use_cache=False no debe romper la construcción
        config = _cfg(enable_layer3=True, enable_watchlist=True)
        source = get_threatintel_source(config, use_cache=False)
        assert source is not None


# ===========================================================================
# 5. Servidor HTTP local — CompositeSource REAL (OSV + watchlist)
# ===========================================================================


class _CompositeHandler(BaseHTTPRequestHandler):
    """Sirve respuestas OSV (POST) y watchlist (GET) según la ruta."""

    osv_responses: ClassVar[dict[str, Any]] = {}
    wl_responses: ClassVar[dict[str, Any]] = {}
    wl_statuses: ClassVar[dict[str, int]] = {}

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        _ = self.rfile.read(length) if length else b""
        path = self.path.split("?", 1)[0]
        payload = type(self).osv_responses.get(path)
        if payload is None:
            self._send_status(404)
        else:
            self._send_json(payload)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in type(self).wl_statuses:
            self._send_status(type(self).wl_statuses[path])
        elif path in type(self).wl_responses:
            self._send_json(type(self).wl_responses[path])
        else:
            self._send_status(404)

    def _send_json(self, payload: Any) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_status(self, code: int) -> None:
        body = b'{"error":"x"}'
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


class _CompositeServer:
    """Servidor HTTP local para tests de integración del composite."""

    def __init__(self) -> None:
        _CompositeHandler.osv_responses = {}
        _CompositeHandler.wl_responses = {}
        _CompositeHandler.wl_statuses = {}
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _CompositeHandler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self) -> _CompositeServer:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def url(self, path: str) -> str:
        host, port = self._httpd.server_address[0], self._httpd.server_address[1]
        return f"http://{host!s}:{port!s}{path}"

    def host_port(self) -> str:
        host, port = self._httpd.server_address[0], self._httpd.server_address[1]
        return f"{host!s}:{port!s}"


@pytest.fixture
def comp_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[_CompositeServer]:
    """Servidor composite local + neutralización de allowlist/puerto para loopback."""

    def allow_local(
        scheme: str, host: str, allowed_hosts: frozenset[str] | None = None
    ) -> bool:
        return scheme.lower() == "http" and host == "127.0.0.1"

    monkeypatch.setattr(hc, "_is_allowed", allow_local)
    monkeypatch.setattr(hc, "_reject_port_and_userinfo", lambda _parts: None)
    with _CompositeServer() as server:
        yield server


def _osv_resp_malicious(names: list[str]) -> dict[str, Any]:
    """Respuesta OSV querybatch con el primer nombre MALICIOUS, resto CLEAN."""
    results = []
    for i, _ in enumerate(names):
        if i == 0:
            results.append({"vulns": [{"id": "MAL-2025-47868"}]})
        else:
            results.append({})
    return {"results": results}


def _osv_resp_clean(count: int) -> dict[str, Any]:
    return {"results": [{} for _ in range(count)]}


def _wl_resp_with(names: list[str]) -> dict[str, Any]:
    return {"names": names}


def _wired_composite(
    server: _CompositeServer,
    osv_path: str,
    wl_path: str | None,
    tmp_path: Path,
    config: Config,
) -> CompositeSource:
    """Monta un CompositeSource con fuentes apuntadas al servidor local."""
    osv_source = OsvSource(config, use_cache=False)
    client_osv = SecureHttpClient(extra_allowed_hosts=frozenset({"api.osv.dev"}))
    import urllib.request as _ureq  # noqa: PLC0415

    client_osv._opener.add_handler(_ureq.HTTPHandler())
    osv_source._http = client_osv
    osv_source._query_url = server.url(osv_path)
    osv_source._cache = DiskCache(tmp_path / "osv", config.osv_ttl_cache_horas, enabled=False)

    if wl_path is None:
        return CompositeSource((osv_source,))

    wl_source = WatchlistSource(config, use_cache=False)
    client_wl = SecureHttpClient(extra_allowed_hosts=frozenset({"depscope.dev"}))
    client_wl._opener.add_handler(_ureq.HTTPHandler())
    wl_source._http = client_wl
    wl_source._url = server.url(wl_path)
    wl_source._cache = DiskCache(tmp_path / "wl", config.watchlist_ttl_cache_horas, enabled=False)

    return CompositeSource((osv_source, wl_source))


class TestCompositeReal:
    """Composición real sobre servidor HTTP local (loopback)."""

    def test_osv_malicious_sin_watchlist(
        self, comp_server: _CompositeServer, tmp_path: Path
    ) -> None:
        _CompositeHandler.osv_responses["/osv"] = {
            "results": [{"vulns": [{"id": "MAL-2025-47868"}]}]
        }
        config = _cfg(enable_layer3=True, enable_watchlist=False)
        comp = _wired_composite(comp_server, "/osv", None, tmp_path, config)
        result = comp.query_batch(["bioql"])
        assert result["bioql"].state is MaliceState.MALICIOUS
        assert result["bioql"].advisories[0].id == "MAL-2025-47868"

    def test_osv_clean_watchlist_hallucination(
        self, comp_server: _CompositeServer, tmp_path: Path
    ) -> None:
        _CompositeHandler.osv_responses["/osv2"] = {"results": [{}]}
        _CompositeHandler.wl_responses["/wl2"] = {"names": ["reqe"]}
        config = _cfg(enable_layer3=True, enable_watchlist=True)
        comp = _wired_composite(comp_server, "/osv2", "/wl2", tmp_path, config)
        result = comp.query_batch(["reqe"])
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION

    def test_osv_malicious_watchlist_hallucination_malicious_domina(
        self, comp_server: _CompositeServer, tmp_path: Path
    ) -> None:
        # Ambas fuentes señalan positivo: MALICIOUS debe dominar sobre KNOWN_HALLUCINATION
        _CompositeHandler.osv_responses["/osv3"] = {
            "results": [{"vulns": [{"id": "MAL-2025-99"}]}]
        }
        _CompositeHandler.wl_responses["/wl3"] = {"names": ["bioql"]}
        config = _cfg(enable_layer3=True, enable_watchlist=True)
        comp = _wired_composite(comp_server, "/osv3", "/wl3", tmp_path, config)
        result = comp.query_batch(["bioql"])
        assert result["bioql"].state is MaliceState.MALICIOUS

    def test_osv_caido_watchlist_hallucination_block_no_se_pierde(
        self, comp_server: _CompositeServer, tmp_path: Path
    ) -> None:
        # OSV devuelve 503 (UNVERIFIABLE); watchlist matchea => KNOWN_HALLUCINATION domina.
        _CompositeHandler.wl_statuses["/wl4-503-osv"] = 503  # route para OSV: 503
        _CompositeHandler.osv_responses["/osv4"] = None  # no encontrada => OSV UNVERIFIABLE
        _CompositeHandler.wl_responses["/wl4"] = {"names": ["reqe"]}
        config = _cfg(
            enable_layer3=True,
            enable_watchlist=True,
            osv_timeout_total_por_lote_s=0.2,
            osv_reintentos=0,
        )
        # Apuntamos OSV a una ruta que devuelve 404 => UNVERIFIABLE
        comp = _wired_composite(comp_server, "/osv4", "/wl4", tmp_path, config)
        result = comp.query_batch(["reqe"])
        # OSV 404 => UNVERIFIABLE; watchlist matchea => fusión da KNOWN_HALLUCINATION
        assert result["reqe"].state is MaliceState.KNOWN_HALLUCINATION

    def test_ambas_fuentes_clean_resultado_clean(
        self, comp_server: _CompositeServer, tmp_path: Path
    ) -> None:
        _CompositeHandler.osv_responses["/osv5"] = {"results": [{}]}
        _CompositeHandler.wl_responses["/wl5"] = {"names": ["otro-pkg"]}
        config = _cfg(enable_layer3=True, enable_watchlist=True)
        comp = _wired_composite(comp_server, "/osv5", "/wl5", tmp_path, config)
        result = comp.query_batch(["safelib"])
        # "safelib" no está en el corpus => watchlist CLEAN; OSV {} => CLEAN
        assert result["safelib"].state is MaliceState.CLEAN

    def test_lote_multi_nombre_cobertura_total_real(
        self, comp_server: _CompositeServer, tmp_path: Path
    ) -> None:
        # Tres nombres en un lote: se garantiza cobertura total (ninguno desaparece)
        _CompositeHandler.osv_responses["/osv6"] = {
            "results": [
                {"vulns": [{"id": "MAL-2025-1"}]},
                {},
                {},
            ]
        }
        config = _cfg(enable_layer3=True, enable_watchlist=False)
        comp = _wired_composite(comp_server, "/osv6", None, tmp_path, config)
        names = ["a", "b", "c"]
        result = comp.query_batch(names)
        assert set(result.keys()) == set(names)
        assert result["a"].state is MaliceState.MALICIOUS
        assert result["b"].state is MaliceState.CLEAN
        assert result["c"].state is MaliceState.CLEAN

    def test_corpus_envenenado_en_watchlist_no_inyecta_falso_match(
        self, comp_server: _CompositeServer, tmp_path: Path
    ) -> None:
        # Corpus con nombres envenenados (CRLF/ANSI): se descartan => no KNOWN_HALLUCINATION
        _CompositeHandler.osv_responses["/osv7"] = {"results": [{}]}
        _CompositeHandler.wl_responses["/wl7"] = {
            "names": ["safelib\r\nevil", "reqe\x1b[31m", "normal-valid"]
        }
        config = _cfg(enable_layer3=True, enable_watchlist=True)
        comp = _wired_composite(comp_server, "/osv7", "/wl7", tmp_path, config)
        result = comp.query_batch(["safelib"])
        # Los nombres envenenados se descartan; 'safelib' limpio => CLEAN (no KNOWN_HALLUCINATION)
        assert result["safelib"].state is MaliceState.CLEAN

    def test_corpus_watchlist_caido_no_invalida_osv_malicious(
        self, comp_server: _CompositeServer, tmp_path: Path
    ) -> None:
        # watchlist 500 => UNVERIFIABLE por watchlist; OSV da MALICIOUS => MALICIOUS domina
        _CompositeHandler.osv_responses["/osv8"] = {
            "results": [{"vulns": [{"id": "MAL-2025-8"}]}]
        }
        _CompositeHandler.wl_statuses["/wl8"] = 500
        config = _cfg(
            enable_layer3=True,
            enable_watchlist=True,
            osv_timeout_total_por_lote_s=2.0,
        )
        comp = _wired_composite(comp_server, "/osv8", "/wl8", tmp_path, config)
        result = comp.query_batch(["bioql"])
        assert result["bioql"].state is MaliceState.MALICIOUS

    def test_ambas_fuentes_caidas_es_unverifiable_nunca_clean(
        self, comp_server: _CompositeServer, tmp_path: Path
    ) -> None:
        # OSV 503 + watchlist 503 => UNVERIFIABLE; NUNCA se devuelve CLEAN (NFR-Degr.1)
        _CompositeHandler.wl_statuses["/wl9"] = 503
        config = _cfg(
            enable_layer3=True,
            enable_watchlist=True,
            osv_timeout_total_por_lote_s=0.2,
            osv_reintentos=0,
            watchlist_timeout_total_s=0.2,
        )
        comp = _wired_composite(comp_server, "/not-existing-osv9", "/wl9", tmp_path, config)
        result = comp.query_batch(["safelib"])
        # Ninguna fuente responde => UNVERIFIABLE (no CLEAN)
        assert result["safelib"].state is MaliceState.UNVERIFIABLE


# ===========================================================================
# 6. Privacidad: depscope.dev solo si watchlist activa (R2.1 / ADR-09)
# ===========================================================================


class TestPrivacidadAllowlist:
    """Verifica que depscope.dev nunca entra al allowlist sin enable_watchlist."""

    def test_sin_watchlist_depscope_no_en_allowlist_registry(self) -> None:
        config = _cfg(enable_layer3=True, enable_watchlist=False)
        source = get_threatintel_source(config, use_cache=False)
        assert source is not None
        assert "depscope.dev" not in source.extra_allowed_hosts

    def test_con_watchlist_depscope_si_en_allowlist_registry(self) -> None:
        config = _cfg(enable_layer3=True, enable_watchlist=True)
        source = get_threatintel_source(config, use_cache=False)
        assert source is not None
        assert "depscope.dev" in source.extra_allowed_hosts

    def test_enable_layer3_false_ningun_host_extra(self) -> None:
        # None => sin hosts de threat-intel en el allowlist del engine
        config = _cfg(enable_layer3=False)
        source = get_threatintel_source(config, use_cache=False)
        assert source is None  # no hay allowlist que ampliar

    def test_stub_composite_sin_watchlist_stub(self) -> None:
        # Via stubs: solo el OSV-stub => depscope no aparece
        stub_osv = _StubSource("osv", {}, extra_hosts=frozenset({"api.osv.dev"}))
        comp = CompositeSource((stub_osv,))
        assert "depscope.dev" not in comp.extra_allowed_hosts

    def test_stub_composite_con_watchlist_stub(self) -> None:
        stub_osv = _StubSource("osv", {}, extra_hosts=frozenset({"api.osv.dev"}))
        stub_wl = _StubSource("watchlist", {}, extra_hosts=frozenset({"depscope.dev"}))
        comp = CompositeSource((stub_osv, stub_wl))
        assert "depscope.dev" in comp.extra_allowed_hosts
