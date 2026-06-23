"""Suite del subsistema cache-blob (H2-T05, RISK-H2-2) + bordes de seguridad.

Foco principal: `DiskCache.get_blob`/`put_blob` (caché threat-intel genérica JSON-only,
§2.5) con énfasis en la entrada NO confiable: TTL por-llamada, schema/corrupto/state
desviado ⇒ miss, validador inyectado, perms 0700/0600, anti-traversal, no-persistencia
de UNVERIFIABLE, y las DEFENSAS ENDURECIDAS de _read_json (JSON-bomb y cota de tamaño,
camino blob Y camino tipado del Hito 1).

Secciones complementarias que tocan los archivos del subsistema:
- net-post (RISK-H2-1): servidor local malicioso (redirect cross-host osv→pypi y a host
  ajeno, host IP/localhost/puerto, 429/503/400, JSON bomb) — mentalidad pen-testing.
- config: validación host/path/degraded_status, precedencia, defaults (R5.1/R5.2).
- models-source: Advisory frozen, advisories aditivo, modelos transporte, Protocol.

Criterios EARS cubiertos: R1.7, R2.1, R5.1, R5.2, R5.3, R6.1, R6.2, R6.3, R8.1,
NFR-Seg.1/2/4, NFR-Degr.1 (degradación segura: entrada no confiable ⇒ miss, nunca crash).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import stat
import threading
import urllib.request
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from slopguard.core.cache import disk_cache as dc
from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config, load_config
from slopguard.core.errors import InvalidConfigError, NetworkUnverifiableError
from slopguard.core.models import Advisory, DependencyResult, Status, Verdict
from slopguard.core.net import http_client as hc
from slopguard.core.net.http_client import ALLOWED_HOSTS, SecureHttpClient
from slopguard.core.threatintel.source import (
    MaliceState,
    ThreatIntelResult,
    ThreatIntelSource,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

# Epoch fijo para TTL determinista (alineado con el conftest del Hito 1).
_NOW: float = 1_717_200_000.0
_OSV_TTL: int = 6 * 3600
_WATCHLIST_TTL: int = 24 * 3600


# ===========================================================================
# Helpers de cache-blob
# ===========================================================================


def _cache(tmp_path: Path, *, enabled: bool = True) -> DiskCache:
    """Cache blob; el TTL del constructor es irrelevante (los blobs usan TTL por-llamada)."""
    return DiskCache(tmp_path / "cache", 24, enabled=enabled)


def _blob_path(root: Path, namespace: str, key: str) -> Path:
    digest = hashlib.sha256(f"{namespace}:{key}".encode()).hexdigest()
    return root / f"{digest}.json"


def _write_raw_blob(root: Path, namespace: str, key: str, raw: bytes) -> Path:
    """Escribe bytes crudos en la ruta del blob (simula un archivo manipulado)."""
    root.mkdir(parents=True, exist_ok=True)
    path = _blob_path(root, namespace, key)
    path.write_bytes(raw)
    return path


def _identity(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Validador trivial: acepta el payload tal cual."""
    return payload


def _advisory(advisory_id: str = "MAL-1") -> Advisory:
    return Advisory(
        id=advisory_id,
        kind="malicious",
        url=f"https://osv.dev/vulnerability/{advisory_id}",
        source="osv",
    )


def _osv_payload(name: str = "bioql") -> dict[str, Any]:
    return {
        "source": "osv",
        "ecosystem": "pypi",
        "name": name,
        "state": "malicious",
        "advisories": [{"id": "MAL-2025-47868", "kind": "malicious", "source": "osv"}],
    }


def _get_blob(
    cache: DiskCache,
    namespace: str,
    key: str,
    *,
    ttl: int = _OSV_TTL,
    now: float = _NOW,
) -> dict[str, Any] | None:
    return cache.get_blob(namespace, key, _identity, ttl_segundos=ttl, now=now)


# ===========================================================================
# cache-blob: hit vigente sin red + sellado de control (R6.1/R6.2)
# ===========================================================================


class TestBlobHitVigente:
    def test_put_then_get_hit(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        got = _get_blob(cache, "osv", "pypi:bioql")
        assert got is not None
        assert got["name"] == "bioql"
        assert got["state"] == "malicious"

    def test_put_blob_sella_schema_y_fetched_at(self, tmp_path: Path) -> None:
        """put_blob fija `cache_schema_version` y `fetched_at`, no el caller (defensa)."""
        cache = _cache(tmp_path)
        payload = {**_osv_payload(), "cache_schema_version": "MALO", "fetched_at": 0.0}
        cache.put_blob("osv", "pypi:bioql", payload, now=_NOW)
        raw = json.loads(_blob_path(tmp_path / "cache", "osv", "pypi:bioql").read_bytes())
        assert raw["cache_schema_version"] == "ti-1"
        assert raw["fetched_at"] == _NOW

    def test_miss_cuando_no_existe(self, tmp_path: Path) -> None:
        assert _get_blob(_cache(tmp_path), "osv", "pypi:ausente") is None


# ===========================================================================
# cache-blob: TTL por-llamada (OSV 6h ≠ watchlist 24h) (R6.1/R6.2)
# ===========================================================================


class TestBlobTTL:
    def test_limite_exacto_es_hit(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        assert _get_blob(cache, "osv", "pypi:bioql", now=_NOW + _OSV_TTL) is not None

    def test_un_segundo_pasado_es_miss(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        assert _get_blob(cache, "osv", "pypi:bioql", now=_NOW + _OSV_TTL + 1) is None

    def test_ttl_independiente_por_llamada(self, tmp_path: Path) -> None:
        """Mismo blob: hit con TTL 24h, miss con TTL 6h para el mismo `now`."""
        cache = _cache(tmp_path)
        cache.put_blob("watchlist", "dep/api", {"names": ["reqe"]}, now=_NOW)
        later = _NOW + _OSV_TTL + 1
        assert _get_blob(cache, "watchlist", "dep/api", ttl=_WATCHLIST_TTL, now=later) is not None
        assert _get_blob(cache, "watchlist", "dep/api", ttl=_OSV_TTL, now=later) is None


# ===========================================================================
# cache-blob: fetched_at absurdo/inválido ⇒ miss (RISK-H2-2, guardia _blob_expired)
# Blinda las ramas defensivas que el critic señaló sin cobertura directa.
# ===========================================================================


class TestBlobFetchedAtDefensivo:
    def test_fetched_at_en_el_futuro_es_miss(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        assert _get_blob(cache, "osv", "pypi:bioql", now=_NOW - 1) is None

    def test_fetched_at_negativo_es_miss(self, tmp_path: Path) -> None:
        """`fetched_at` negativo (timestamp absurdo) ⇒ miss (rama `fetched_at < 0`)."""
        raw = json.dumps(
            {**_osv_payload(), "cache_schema_version": "ti-1", "fetched_at": -1.0}
        ).encode()
        _write_raw_blob(tmp_path / "cache", "osv", "pypi:bioql", raw)
        assert _get_blob(_cache(tmp_path), "osv", "pypi:bioql") is None

    @pytest.mark.parametrize(
        "bad_fetched_at",
        ["no-soy-numero", True, False, None, [1, 2], {"x": 1}],
    )
    def test_fetched_at_tipo_invalido_es_miss(
        self, tmp_path: Path, bad_fetched_at: object
    ) -> None:
        """`fetched_at` no numérico (string/bool/None/lista) ⇒ miss sin crashear (R6.1)."""
        raw = json.dumps(
            {**_osv_payload(), "cache_schema_version": "ti-1", "fetched_at": bad_fetched_at}
        ).encode()
        _write_raw_blob(tmp_path / "cache", "osv", "pypi:bioql", raw)
        assert _get_blob(_cache(tmp_path), "osv", "pypi:bioql") is None

    def test_fetched_at_bool_true_es_miss(self, tmp_path: Path) -> None:
        """`fetched_at: true` (bool es subclase de int) se rechaza explícitamente."""
        raw = b'{"source":"osv","name":"x","cache_schema_version":"ti-1","fetched_at":true}'
        _write_raw_blob(tmp_path / "cache", "osv", "pypi:x", raw)
        assert _get_blob(_cache(tmp_path), "osv", "pypi:x") is None


# ===========================================================================
# cache-blob: schema desviado / corrupto / no-objeto ⇒ miss (R6.1, entrada no confiable)
# ===========================================================================


class TestBlobEntradaNoConfiable:
    def test_schema_hito1_es_miss(self, tmp_path: Path) -> None:
        """Un blob con `cache_schema_version="1"` (Hito 1) ⇒ miss (separa los contratos)."""
        raw = json.dumps(
            {**_osv_payload(), "cache_schema_version": "1", "fetched_at": _NOW}
        ).encode()
        _write_raw_blob(tmp_path / "cache", "osv", "pypi:bioql", raw)
        assert _get_blob(_cache(tmp_path), "osv", "pypi:bioql") is None

    def test_json_corrupto_es_miss_sin_crashear(self, tmp_path: Path) -> None:
        _write_raw_blob(tmp_path / "cache", "osv", "pypi:bioql", b"{ no es json valido")
        assert _get_blob(_cache(tmp_path), "osv", "pypi:bioql") is None

    def test_json_no_objeto_es_miss(self, tmp_path: Path) -> None:
        _write_raw_blob(tmp_path / "cache", "osv", "pypi:bioql", b"[1, 2, 3]")
        assert _get_blob(_cache(tmp_path), "osv", "pypi:bioql") is None

    def test_validador_que_rechaza_es_miss(self, tmp_path: Path) -> None:
        """Validador inyectado que devuelve None (schema/charset/cap de la fuente) ⇒ miss."""
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        got = cache.get_blob("osv", "pypi:bioql", lambda _p: None, ttl_segundos=_OSV_TTL, now=_NOW)
        assert got is None


# ===========================================================================
# cache-blob: JSON-bomb + cota de tamaño en _read_json (RISK-H2-2, defensa endurecida)
# El validador inyectado corre DESPUÉS de materializar el árbol; safe_json_loads
# rechaza la bomba ANTES. Vector: archivo de cache manipulado (entrada no confiable).
# ===========================================================================


def _json_bomb(depth: int) -> bytes:
    """JSON con `depth` niveles de anidamiento (> _CACHE_MAX_JSON_DEPTH=50)."""
    return b'{"a":' * depth + b"1" + b"}" * depth


class TestBlobJsonBomb:
    def test_json_bomb_en_blob_es_miss_sin_crashear(self, tmp_path: Path) -> None:
        """Blob con anidamiento patológico ⇒ get_blob devuelve None sin DoS (RISK-H2-2)."""
        _write_raw_blob(tmp_path / "cache", "osv", "pypi:bioql", _json_bomb(200))
        assert _get_blob(_cache(tmp_path), "osv", "pypi:bioql") is None

    def test_json_bomb_no_invoca_validador(self, tmp_path: Path) -> None:
        """La bomba se rechaza en _read_json: el validador inyectado NUNCA se invoca."""
        _write_raw_blob(tmp_path / "cache", "osv", "pypi:bioql", _json_bomb(200))
        llamado = {"v": False}

        def _spy(payload: dict[str, Any]) -> dict[str, Any] | None:
            llamado["v"] = True
            return payload

        cache = _cache(tmp_path)
        got = cache.get_blob("osv", "pypi:bioql", _spy, ttl_segundos=_OSV_TTL, now=_NOW)
        assert got is None
        assert llamado["v"] is False  # el árbol nunca se materializó

    def test_archivo_gigante_sobre_cota_es_miss(self, tmp_path: Path) -> None:
        """Archivo > _CACHE_MAX_BYTES ⇒ miss por `os.stat` sin leerlo a memoria."""
        oversized = b'{"x":"' + b"A" * (dc._CACHE_MAX_BYTES + 1) + b'"}'
        _write_raw_blob(tmp_path / "cache", "osv", "pypi:bioql", oversized)
        assert _get_blob(_cache(tmp_path), "osv", "pypi:bioql") is None

    def test_blob_normal_bajo_cota_sigue_siendo_hit(self, tmp_path: Path) -> None:
        """Regresión: un blob legítimo de tamaño normal sigue leyéndose (no falso miss)."""
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        assert _get_blob(cache, "osv", "pypi:bioql") is not None


class TestCaminoTipadoJsonBombRegresion:
    """El mismo _read_json sirve al camino tipado del Hito 1 (`get`): regresión aditiva."""

    def test_get_tipado_con_json_bomb_es_miss(self, tmp_path: Path) -> None:
        """Un archivo de cache tipado con bomba ⇒ `get` devuelve None sin crashear."""
        root = tmp_path / "cache"
        root.mkdir()
        digest = hashlib.sha256(b"pypi:requests").hexdigest()
        (root / f"{digest}.json").write_bytes(_json_bomb(200))
        cache = DiskCache(root, 24, enabled=True)
        assert cache.get("pypi", "requests", now=_NOW) is None


# ===========================================================================
# cache-blob: UNVERIFIABLE nunca se persiste (§2.5/ADR-10, NFR-Degr.1)
# ===========================================================================


class TestBlobUnverifiableNoPersiste:
    def test_state_unverifiable_no_genera_archivo(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        payload = {**_osv_payload("flaky"), "state": "unverifiable"}
        cache.put_blob("osv", "pypi:flaky", payload, now=_NOW)
        assert not _blob_path(tmp_path / "cache", "osv", "pypi:flaky").exists()

    def test_unverifiable_minimo_no_se_persiste(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:x", {"name": "x", "state": "unverifiable"}, now=_NOW)
        assert not _blob_path(tmp_path / "cache", "osv", "pypi:x").exists()


# ===========================================================================
# cache-blob: --no-cache / enabled=False ⇒ ni lee ni escribe (R6.3)
# ===========================================================================


class TestBlobNoCache:
    def test_disabled_no_escribe(self, tmp_path: Path) -> None:
        root = tmp_path / "cache"
        DiskCache(root, 24, enabled=False).put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        assert not _blob_path(root, "osv", "pypi:bioql").exists()

    def test_disabled_no_lee_aunque_haya_archivo(self, tmp_path: Path) -> None:
        _cache(tmp_path).put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        disabled = DiskCache(tmp_path / "cache", 24, enabled=False)
        assert _get_blob(disabled, "osv", "pypi:bioql") is None


# ===========================================================================
# cache-blob: anti-traversal + separación del camino tipado + namespacing (§2.5)
# ===========================================================================


class TestBlobAntiTraversal:
    def test_traversal_en_clave_no_escapa_del_root(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:../../etc/passwd", _osv_payload("evil"), now=_NOW)
        root = tmp_path / "cache"
        archivos = [p.name for p in root.iterdir() if p.suffix == ".json"]
        assert len(archivos) == 1
        assert all(c in "0123456789abcdef" for c in archivos[0].removesuffix(".json"))

    def test_namespace_separa_del_camino_tipado(self, tmp_path: Path) -> None:
        blob_p = _blob_path(tmp_path / "cache", "osv", "pypi:bioql")
        typed_digest = hashlib.sha256(b"pypi:bioql").hexdigest()
        assert blob_p != tmp_path / "cache" / f"{typed_digest}.json"

    def test_namespaces_distintos_no_colisionan(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "k", {"who": "osv"}, now=_NOW)
        cache.put_blob("watchlist", "k", {"who": "watchlist"}, now=_NOW)
        osv = _get_blob(cache, "osv", "k")
        wl = _get_blob(cache, "watchlist", "k", ttl=_WATCHLIST_TTL)
        assert osv is not None and osv["who"] == "osv"
        assert wl is not None and wl["who"] == "watchlist"


# ===========================================================================
# cache-blob: perms 0700/0600 + JSON-only (NFR-Seg.2/6)
# ===========================================================================


class TestBlobPermsJsonOnly:
    def test_perms_dir_0700_archivo_0600(self, tmp_path: Path) -> None:
        root = tmp_path / "cache"
        DiskCache(root, 24, enabled=True).put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        assert stat.S_IMODE(os.stat(root).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(_blob_path(root, "osv", "pypi:bioql")).st_mode) == 0o600

    def test_blob_es_json_parseable(self, tmp_path: Path) -> None:
        """El blob en disco es JSON, nunca pickle/marshal (NFR-Seg.2)."""
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        raw = _blob_path(tmp_path / "cache", "osv", "pypi:bioql").read_bytes()
        assert json.loads(raw)["source"] == "osv"


# ===========================================================================
# net-post: post_json + allowlist por-instancia + SSRF (RISK-H2-1)
# Servidor local malicioso — mentalidad security-pen-testing.
# ===========================================================================


class _PostHandler(BaseHTTPRequestHandler):
    """Servidor local que sirve escenarios de POST/redirect/errores."""

    def do_POST(self) -> None:
        routes = {
            "/v1/querybatch": self._ok,
            "/redirect-pypi": lambda: self._redirect("https://pypi.org/nada"),
            "/redirect-ajeno": lambda: self._redirect("https://evil.com/exfil"),
            "/status-429": lambda: self._status(429),
            "/status-503": lambda: self._status(503),
            "/status-400": lambda: self._status(400),
            "/json-bomb": self._bomb,
        }
        routes.get(self.path, lambda: self._status(404))()

    def _ok(self) -> None:
        body = json.dumps({"results": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _status(self, code: int) -> None:
        self.send_response(code)
        self.end_headers()

    def _bomb(self) -> None:
        body = b'{"a":' * 80 + b"1" + b"}" * 80
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


class _LocalServer:
    def __init__(self) -> None:
        self._httpd = HTTPServer(("127.0.0.1", 0), _PostHandler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self) -> _LocalServer:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[0], self._httpd.server_address[1]
        return f"http://{host!s}:{port!s}"


@pytest.fixture
def post_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[_LocalServer]:
    """Servidor POST local + allowlist http://127.0.0.1 habilitada SOLO en el test.

    Parchea `_is_allowed` (para aceptar http://127.0.0.1) y `_reject_port_and_userinfo`
    (a no-op) porque el loopback usa un puerto efímero que en producción el guardia
    anti-SSRF rechazaría; ambos parches son una necesidad técnica del harness, igual que
    en el contrato del Hito 1 documentado en `_reject_port_and_userinfo`.
    """

    def allow_local(scheme: str, host: str, allowed_hosts: frozenset[str] | None = None) -> bool:
        return scheme.lower() == "http" and host == "127.0.0.1"

    monkeypatch.setattr(hc, "_is_allowed", allow_local)
    monkeypatch.setattr(hc, "_reject_port_and_userinfo", lambda _parts: None)
    with _LocalServer() as server:
        yield server


def _post_client() -> SecureHttpClient:
    """Cliente con HTTPHandler extra para alcanzar el servidor local de prueba."""
    client = SecureHttpClient()
    client._opener.add_handler(urllib.request.HTTPHandler())
    return client


def _do_post(client: SecureHttpClient, url: str, *, max_bytes: int = 1_000_000) -> object:
    return client.post_json(
        url,
        {"queries": []},
        connect_timeout_s=2.0,
        read_timeout_s=2.0,
        max_response_bytes=max_bytes,
        max_json_depth=20,
    )


class TestPostJsonBasico:
    def test_post_ok_devuelve_dict(self, post_server: _LocalServer) -> None:
        result = _do_post(_post_client(), post_server.base_url + "/v1/querybatch")
        assert isinstance(result, dict)
        assert "results" in result

    def test_post_json_bomb_rechazado(self, post_server: _LocalServer) -> None:
        with pytest.raises(NetworkUnverifiableError, match="profundidad JSON"):
            _do_post(_post_client(), post_server.base_url + "/json-bomb")


class TestPostJsonSSRF:
    """RISK-H2-1: toda redirección se rechaza (fix SSRF del redirect handler §3.3)."""

    def test_redirect_a_pypi_rechazado(self, post_server: _LocalServer) -> None:
        """api.osv.dev → pypi.org: cross-host rechazado aunque ambos en el efectivo."""
        with pytest.raises(NetworkUnverifiableError):
            _do_post(_post_client(), post_server.base_url + "/redirect-pypi")

    def test_redirect_a_host_ajeno_rechazado(self, post_server: _LocalServer) -> None:
        with pytest.raises(NetworkUnverifiableError):
            _do_post(_post_client(), post_server.base_url + "/redirect-ajeno")


class TestPostJson429Transitorio:
    """R1.7 / §3.3: 429 y 5xx ⇒ is_transient=True; 4xx≠429 ⇒ no-CLEAN."""

    def test_429_es_transitorio(self, post_server: _LocalServer) -> None:
        with pytest.raises(NetworkUnverifiableError) as info:
            _do_post(_post_client(), post_server.base_url + "/status-429")
        assert info.value.is_transient is True
        assert info.value.status_code == 429

    def test_503_es_transitorio(self, post_server: _LocalServer) -> None:
        with pytest.raises(NetworkUnverifiableError) as info:
            _do_post(_post_client(), post_server.base_url + "/status-503")
        assert info.value.is_transient is True

    def test_400_no_es_transitorio(self, post_server: _LocalServer) -> None:
        with pytest.raises(NetworkUnverifiableError) as info:
            _do_post(_post_client(), post_server.base_url + "/status-400")
        assert info.value.is_transient is False


class TestAllowlistPorInstancia:
    """ADR-09: base anclada {pypi.org}; extra_allowed_hosts amplían por instancia."""

    def test_allowed_hosts_base_es_solo_pypi(self) -> None:
        assert ALLOWED_HOSTS == frozenset({"pypi.org"})

    def test_extra_hosts_amplian_el_efectivo(self) -> None:
        client = SecureHttpClient(extra_allowed_hosts=frozenset({"api.osv.dev"}))
        assert {"pypi.org", "api.osv.dev"} <= client._allowed_hosts

    def test_sin_extra_solo_pypi(self) -> None:
        assert SecureHttpClient()._allowed_hosts == frozenset({"pypi.org"})

    def test_depscope_no_en_efectivo_sin_watchlist(self) -> None:
        """R2.1: depscope.dev no entra al allowlist si enable_watchlist=false."""
        assert "depscope.dev" not in SecureHttpClient()._allowed_hosts

    def test_host_no_allowlist_rechazado(self) -> None:
        with pytest.raises(NetworkUnverifiableError, match="allowlist"):
            SecureHttpClient().post_json(
                "https://api.osv.dev/v1/querybatch",
                {"queries": []},
                connect_timeout_s=1.0,
                read_timeout_s=1.0,
                max_response_bytes=1_000,
                max_json_depth=10,
            )

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/v1/querybatch",
            "http://localhost/v1/querybatch",
            "http://169.254.169.254/latest/meta-data",
            "https://192.168.0.1/api",
        ],
    )
    def test_url_ip_localhost_rechazada(self, url: str) -> None:
        """IP/localhost fuera de la allowlist ⇒ rechazada antes de la red (anti-SSRF)."""
        with pytest.raises(NetworkUnverifiableError, match="allowlist"):
            SecureHttpClient().post_json(
                url,
                {"queries": []},
                connect_timeout_s=1.0,
                read_timeout_s=1.0,
                max_response_bytes=1_000,
                max_json_depth=5,
            )

    def test_url_con_puerto_explicito_rechazada(self) -> None:
        """Puerto explícito ⇒ rechazado por el guardia A10 SSRF antes de la allowlist."""
        with pytest.raises(NetworkUnverifiableError, match="puerto explicito"):
            SecureHttpClient().post_json(
                "https://api.osv.dev:443/v1/querybatch",
                {"queries": []},
                connect_timeout_s=1.0,
                read_timeout_s=1.0,
                max_response_bytes=1_000,
                max_json_depth=5,
            )

    def test_url_con_userinfo_rechazada(self) -> None:
        """Userinfo (user@host) ⇒ rechazado por el guardia A10 SSRF (defecto-deniega)."""
        with pytest.raises(NetworkUnverifiableError, match="userinfo"):
            SecureHttpClient().post_json(
                "https://user:pass@api.osv.dev/v1/querybatch",
                {"queries": []},
                connect_timeout_s=1.0,
                read_timeout_s=1.0,
                max_response_bytes=1_000,
                max_json_depth=5,
            )


def _dummy_request() -> urllib.request.Request:
    return urllib.request.Request("https://pypi.org/x")


class TestRedirectHandlerEfectivo:
    """Fix SSRF §3.3: el handler valida contra el conjunto EFECTIVO inyectado."""

    def test_rechaza_osv_host_aun_en_efectivo(self) -> None:
        handler = hc._RejectRedirectHandler(frozenset({"pypi.org", "api.osv.dev"}))
        with pytest.raises(NetworkUnverifiableError):
            handler.redirect_request(
                _dummy_request(), None, 302, "Found", None,
                "https://api.osv.dev/v1/querybatch",
            )

    def test_rechaza_host_ajeno_destino_no_permitido(self) -> None:
        handler = hc._RejectRedirectHandler(frozenset({"pypi.org", "api.osv.dev"}))
        with pytest.raises(NetworkUnverifiableError, match="destino no permitido"):
            handler.redirect_request(
                _dummy_request(), None, 302, "Found", None,
                "https://evil.com/exfil",
            )


# ===========================================================================
# config: defaults / validación host/path/degraded_status / precedencia (R5.1/R5.2/R5.3)
# ===========================================================================


class TestConfigDefaults:
    def test_defaults_tabla_r5(self) -> None:
        cfg = Config()
        assert cfg.enable_layer3 is True
        assert cfg.osv_host == "api.osv.dev"
        assert cfg.osv_query_path == "/v1/querybatch"
        assert cfg.osv_batch_max == 1000
        assert cfg.osv_ttl_cache_horas == 6
        assert cfg.osv_reintentos == 2
        assert cfg.enable_watchlist is False
        assert cfg.watchlist_host == "depscope.dev"
        assert cfg.watchlist_ttl_cache_horas == 24
        assert cfg.threatintel_degraded_status == "unverifiable"


class TestConfigValidacionHost:
    @pytest.mark.parametrize(
        "bad_host",
        [
            "169.254.169.254",
            "127.0.0.1",
            "::1",
            "localhost",
            "api.osv.dev:443",
            "user@api.osv.dev",
            "api.osv.dev/v1",
            "http://api.osv.dev",
            "evil.internal",
            "192.168.0.1",
        ],
    )
    def test_osv_host_invalido_exit3(self, bad_host: str) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"osv_host": bad_host})

    @pytest.mark.parametrize(
        "bad_host", ["169.254.169.254", "localhost", "evil.com", "depscope.dev:80"]
    )
    def test_watchlist_host_invalido_exit3(self, bad_host: str) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"watchlist_host": bad_host})


class TestConfigValidacionPath:
    @pytest.mark.parametrize(
        "bad_path",
        [
            "v1/querybatch",  # no empieza por /
            "/v1/../etc/passwd",  # dot-segment (path traversal)
            "/ruta con espacios",  # espacio (charset)
            "/ruta?inyectada",  # query embebida (charset)
            "/ruta#frag",  # fragmento embebido (charset)
            "",  # vacio
        ],
    )
    def test_osv_query_path_invalido(self, bad_path: str) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"osv_query_path": bad_path})

    def test_crlf_en_path_se_sanea_no_crashea(self) -> None:
        """CRLF en el path se neutraliza por el saneo anti-inyeccion (no produce error).

        Es la defensa correcta del Hito 1: `sanitize_for_output` elimina C0/C1/CRLF en
        `_coerce` ANTES de validar el rango; el path resultante es seguro y valido.
        """
        cfg = load_config(None, {"osv_query_path": "/v1/query\nbatch"})
        assert "\n" not in cfg.osv_query_path
        assert cfg.osv_query_path == "/v1/querybatch"


class TestConfigDegradedStatus:
    @pytest.mark.parametrize("bad", ["allow", "block", "BLOCK", "unverifiable "])
    def test_valor_invalido(self, bad: str) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"threatintel_degraded_status": bad})

    @pytest.mark.parametrize("ok", ["unverifiable", "warn"])
    def test_valor_valido(self, ok: str) -> None:
        cfg = load_config(None, {"threatintel_degraded_status": ok})
        assert cfg.threatintel_degraded_status == ok


class TestConfigBoolEstricto:
    def test_int_rechazado_para_enable_layer3(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"enable_layer3": 1})

    def test_string_rechazado_para_enable_watchlist(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"enable_watchlist": "true"})

    def test_enable_layer3_false_aceptado(self) -> None:
        """R5.3: enable_layer3=false es válido (modo solo-deterministas)."""
        assert load_config(None, {"enable_layer3": False}).enable_layer3 is False


class TestConfigPrecedencia:
    def test_cli_gana_sobre_archivo(self, tmp_path: Path) -> None:
        archivo = tmp_path / ".slopguard.toml"
        archivo.write_text("osv_ttl_cache_horas = 2\n", encoding="utf-8")
        assert load_config(archivo, {"osv_ttl_cache_horas": 4}).osv_ttl_cache_horas == 4

    def test_archivo_gana_sobre_default(self, tmp_path: Path) -> None:
        archivo = tmp_path / ".slopguard.toml"
        archivo.write_text("osv_ttl_cache_horas = 2\n", encoding="utf-8")
        assert load_config(archivo, {}).osv_ttl_cache_horas == 2

    def test_default_cuando_no_hay_nada(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        cfg = load_config(None, {})
        assert cfg.osv_batch_max == 1000
        assert cfg.enable_layer3 is True


# ===========================================================================
# models-source: Advisory frozen, advisories aditivo, transporte, Protocol
# ===========================================================================


class TestAdvisory:
    def test_es_frozen(self) -> None:
        adv = _advisory()
        with pytest.raises(dataclasses.FrozenInstanceError):
            adv.id = "otro"  # type: ignore[misc]

    def test_usa_slots(self) -> None:
        assert not hasattr(_advisory(), "__dict__")


class TestDependencyResultAdvisoriesAditivo:
    def test_default_es_tupla_vacia(self) -> None:
        """NFR-Compat.1: call-site del Hito 1 sin `advisories` sigue funcionando."""
        result = DependencyResult(
            name="requests",
            version_pin=None,
            status=Status.OK,
            verdict=Verdict.ALLOW,
            score=10,
            signals=(),
            suspected_target=None,
            error_category=None,
        )
        assert result.advisories == ()
        assert isinstance(result.advisories, tuple)

    def test_se_puede_poblar(self) -> None:
        adv = _advisory()
        result = DependencyResult(
            name="bioql",
            version_pin=None,
            status=Status.OK,
            verdict=Verdict.BLOCK,
            score=None,
            signals=(),
            suspected_target=None,
            error_category=None,
            advisories=(adv,),
        )
        assert result.advisories[0].id == "MAL-1"


class TestMaliceStateYThreatIntelResult:
    def test_malice_state_valores(self) -> None:
        assert MaliceState.CLEAN.value == "clean"
        assert MaliceState.MALICIOUS.value == "malicious"
        assert MaliceState.KNOWN_HALLUCINATION.value == "known_hallucination"
        assert MaliceState.UNVERIFIABLE.value == "unverifiable"

    def test_result_frozen_slots_defaults(self) -> None:
        ti = ThreatIntelResult(name="requests", state=MaliceState.CLEAN)
        assert not hasattr(ti, "__dict__")
        assert ti.advisories == ()
        assert ti.watchlist_source is None
        assert ti.unverifiable_reason is None
        with pytest.raises(dataclasses.FrozenInstanceError):
            ti.name = "otro"  # type: ignore[misc]

    def test_unverifiable_porta_razon_saneada(self) -> None:
        ti = ThreatIntelResult(
            name="flaky", state=MaliceState.UNVERIFIABLE, unverifiable_reason="timeout en OSV"
        )
        assert ti.unverifiable_reason == "timeout en OSV"


class _ConformingSource:
    """Implementacion concreta del Protocol usada para verificar conformidad estructural."""

    source_id = "dummy"
    extra_allowed_hosts: frozenset[str] = frozenset()

    def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
        return {n: ThreatIntelResult(name=n, state=MaliceState.CLEAN) for n in names}


def _accepts_source(source: ThreatIntelSource) -> str:
    """Funcion tipada que exige un ThreatIntelSource: el check estructural lo hace mypy."""
    return source.source_id


class TestThreatIntelSourceProtocol:
    """R8.1/R8.3: el Protocol declara el contrato; la conformidad es estructural.

    `ThreatIntelSource` NO es `@runtime_checkable` (no se usa `isinstance` en runtime);
    la verificacion del contrato es estatica (mypy) + estructural (los miembros existen).
    """

    def test_protocol_declara_miembros_del_contrato(self) -> None:
        """El Protocol expone source_id, extra_allowed_hosts (anotaciones) y query_batch."""
        assert set(ThreatIntelSource.__annotations__) >= {"source_id", "extra_allowed_hosts"}
        assert hasattr(ThreatIntelSource, "query_batch")

    def test_clase_conforme_tiene_todos_los_miembros(self) -> None:
        src = _ConformingSource()
        assert src.source_id == "dummy"
        assert src.extra_allowed_hosts == frozenset()
        resultado = src.query_batch(["requests", "flask"])
        assert set(resultado) == {"requests", "flask"}
        assert all(r.state is MaliceState.CLEAN for r in resultado.values())

    def test_clase_conforme_es_aceptada_por_firma_tipada(self) -> None:
        """Una clase conforme se pasa donde se exige el Protocol (verificado por mypy)."""
        assert _accepts_source(_ConformingSource()) == "dummy"
