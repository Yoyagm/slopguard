"""Pruebas del subsistema net-post (H2-T04 / RISK-H2-1): `post_json`, allowlist por-instancia,
fix SSRF del redirect handler, rechazo de puerto/userinfo y clasificacion 429 (R1.7).

Esta suite ejercita el camino REAL del codigo NUEVO del Hito 2 sobre `SecureHttpClient`, que los
tests del Hito 1 (`test_net.py`) no cubrian: `post_json`, `extra_allowed_hosts` validado en
construccion, el predicado anti-SSRF `_is_valid_https_host`/`_is_ip_literal` (defensa en
profundidad sobre los hosts inyectados), el rechazo temprano de puerto explicito/userinfo en
`_validate_url` (A10, defecto-deniega) y la rama transitoria 429 (`_is_transient_http_status`).

Dos niveles, como en `test_net.py`:

1. **Servidor HTTP local malicioso** (`_LocalServer`, `http.server`): ejercita el camino real de
   `urllib` (sockets, `response.read()` streaming, redirect handler). Como el cliente solo admite
   https, el harness habilita `http://127.0.0.1` y neutraliza el rechazo de puerto SOLO durante el
   test (monkeypatch de `_is_allowed` y `_reject_port_and_userinfo`, igual que el harness del Hito
   1), porque el loopback usa un puerto efimero por necesidad tecnica. El endurecimiento de
   produccion (TLS, allowlist, sin redirects, rechazo de puerto/userinfo) corre tal cual.
2. **Asertos directos del predicado** `_is_valid_https_host` con vectores de pen-testing (IP v4/v6,
   `[::1]`, metadata 169.254.169.254, localhost y variantes, userinfo, puerto, path, single-label),
   que ahora SI tienen uso real: `SecureHttpClient.__init__` los invoca sobre `extra_allowed_hosts`.

Escenarios obligatorios de RISK-H2-1 cubiertos: redirect cross-host desde `api.osv.dev` hacia host
ajeno (=> 'destino no permitido') y hacia `pypi.org` (=> rechazado por politica 'ninguna redireccion
se sigue'); host IP/localhost/`host:port` rechazado al inyectarse o validar URL; clasificacion
`429 => is_transient=True` (se reintenta y, agotado el presupuesto, degrada a UNVERIFIABLE).
"""

from __future__ import annotations

import io
import json
import threading
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest

from slopguard.core.errors import NetworkUnverifiableError
from slopguard.core.net import http_client as hc
from slopguard.core.net.http_client import SecureHttpClient

if TYPE_CHECKING:
    from collections.abc import Iterator

_OSV_HOST = "api.osv.dev"
_OSV_HOSTS = frozenset({_OSV_HOST})
_OSV_URL = f"https://{_OSV_HOST}/v1/querybatch"
_BODY: dict[str, object] = {"queries": [{"package": {"ecosystem": "PyPI", "name": "bioql"}}]}


def _post(
    client: SecureHttpClient,
    url: str,
    body: dict[str, object],
    *,
    max_bytes: int = 1_000_000,
) -> dict[str, object]:
    """Invoca `post_json` con timeouts cortos y limites acotados (helper de la suite)."""
    return client.post_json(
        url,
        body,
        connect_timeout_s=2.0,
        read_timeout_s=2.0,
        max_response_bytes=max_bytes,
        max_json_depth=20,
    )


# --------------------------------------------------------------------------- #
# Predicado anti-SSRF `_is_valid_https_host` / `_is_ip_literal` (defensa activa)
#
# Antes del fix estos predicados eran CODIGO MUERTO (0% cobertura): ahora
# `SecureHttpClient.__init__` los invoca sobre cada host de `extra_allowed_hosts`
# (el cliente no confia en su llamante, ADR-09). Se prueban directamente con
# vectores de pen-testing y, mas abajo, via el constructor.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "host",
    [
        "api.osv.dev",
        "depscope.dev",
        "pypi.org",
        "sub.dominio.example.com",
    ],
)
def test_is_valid_https_host_acepta_fqdn(host: str) -> None:
    assert hc._is_valid_https_host(host) is True


@pytest.mark.parametrize(
    "host",
    [
        "",  # vacio
        "127.0.0.1",  # IPv4 loopback
        "10.0.0.1",  # IPv4 privada
        "192.168.1.1",  # IPv4 privada
        "169.254.169.254",  # metadata cloud (link-local)
        "::1",  # IPv6 loopback
        "[::1]",  # IPv6 loopback entre corchetes
        "[fe80::1]",  # IPv6 link-local entre corchetes
        "fe80::1",  # IPv6 link-local
        "localhost",  # nombre interno
        "localhost.localdomain",  # variante interna
        "ip6-localhost",  # variante interna
        "intranet",  # single-label (no-FQDN)
        "host",  # single-label
        "user@host.com",  # userinfo embebido
        "host.com:8080",  # puerto embebido
        "host.com/path",  # path embebido
        "host.com?q=1",  # query embebido
        "host.com#frag",  # fragmento embebido
        "https://host.com",  # esquema embebido
        "192.168.0.1.5",  # TLD numerico (IPv4 disfrazada)
        "bad_host.com",  # underscore fuera de LDH
        "-leading.com",  # label empieza en guion
        "trailing-.com",  # label termina en guion
    ],
)
def test_is_valid_https_host_rechaza_vector_malicioso(host: str) -> None:
    assert hc._is_valid_https_host(host) is False


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "[::1]", "[fe80::1]", "255.255.255.255"],
)
def test_is_ip_literal_detecta_ip(host: str) -> None:
    assert hc._is_ip_literal(host) is True


@pytest.mark.parametrize("host", ["api.osv.dev", "pypi.org", "no-es-ip", "", "localhost"])
def test_is_ip_literal_rechaza_no_ip(host: str) -> None:
    assert hc._is_ip_literal(host) is False


# --------------------------------------------------------------------------- #
# Construccion del cliente: `extra_allowed_hosts` valida cada host (defensa en
# profundidad). Un host inyectado IP/localhost/userinfo/puerto/path => ValueError,
# de modo que la allowlist efectiva NUNCA contiene un destino interno aunque config
# dejara de validarlo (el cliente no confia en su llamante).
# --------------------------------------------------------------------------- #


def test_constructor_admite_host_fqdn_valido() -> None:
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    # Igualdad EXACTA: base anclada {pypi.org} mas los extra, sin hosts inesperados.
    assert client._allowed_hosts == frozenset({"pypi.org"}) | _OSV_HOSTS


def test_constructor_base_anclada_sin_extra() -> None:
    # Sin extra (uso del Hito 1): la allowlist efectiva es exactamente la base {pypi.org}.
    client = SecureHttpClient()
    assert client._allowed_hosts == frozenset({"pypi.org"})


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "169.254.169.254",
        "::1",
        "localhost",
        "api.osv.dev:8080",
        "user@api.osv.dev",
        "api.osv.dev/path",
        "intranet",
    ],
)
def test_constructor_rechaza_host_inyectado_inseguro(host: str) -> None:
    with pytest.raises(ValueError, match="FQDN https"):
        SecureHttpClient(extra_allowed_hosts=frozenset({host}))


def test_constructor_rechaza_si_un_host_del_conjunto_es_inseguro() -> None:
    # Basta UN host invalido en el conjunto para rechazar toda la construccion.
    with pytest.raises(ValueError, match="FQDN https"):
        SecureHttpClient(extra_allowed_hosts=frozenset({"api.osv.dev", "169.254.169.254"}))


# --------------------------------------------------------------------------- #
# `_validate_url`: rechazo temprano de puerto explicito y userinfo (A10 SSRF).
#
# `urlsplit().hostname` descarta puerto y `user:pass@`, asi que sin el chequeo una
# URL al host de la allowlist con puerto/userinfo pasaria. Se rechaza ANTES de la
# allowlist (defecto-deniega), sin depender de que la conexion falle por transporte.
# --------------------------------------------------------------------------- #


def test_post_json_puerto_explicito_rechazado_por_validacion() -> None:
    # Host EN la allowlist efectiva pero con puerto explicito => rechazo por puerto,
    # no por allowlist ni por transporte (se valida ANTES de abrir socket).
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    with pytest.raises(NetworkUnverifiableError, match="puerto explicito"):
        _post(client, f"https://{_OSV_HOST}:1/v1/querybatch", _BODY)


def test_post_json_userinfo_rechazado_por_validacion() -> None:
    # Host EN la allowlist pero con userinfo => rechazo por userinfo (defecto-deniega).
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    with pytest.raises(NetworkUnverifiableError, match="userinfo"):
        _post(client, f"https://user:pass@{_OSV_HOST}/v1/querybatch", _BODY)


def test_post_json_userinfo_sin_password_rechazado() -> None:
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    with pytest.raises(NetworkUnverifiableError, match="userinfo"):
        _post(client, f"https://user@{_OSV_HOST}/v1/querybatch", _BODY)


def test_post_json_pypi_con_puerto_rechazado_get_tambien() -> None:
    # Regresion del hallazgo: el rechazo aplica al cliente base del Hito 1 tambien.
    client = SecureHttpClient()
    with pytest.raises(NetworkUnverifiableError, match="puerto explicito"):
        _post(client, "https://pypi.org:8080/x", _BODY)


def test_post_json_puerto_no_numerico_es_url_malformada() -> None:
    # urlsplit lanza ValueError al leer .port si no es numerico => URL malformada,
    # nunca escapa crudo (degradacion segura por-dependencia).
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    with pytest.raises(NetworkUnverifiableError, match="malformada"):
        _post(client, f"https://{_OSV_HOST}:notaport/v1/querybatch", _BODY)


# --------------------------------------------------------------------------- #
# `_validate_url`: allowlist efectiva y scheme sobre `post_json`.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "http://api.osv.dev/v1/querybatch",  # scheme no https
        "https://pypi.org.evil.com/x",  # host parecido fuera del efectivo
        "https://evil.com/v1/querybatch",  # host arbitrario
        "ftp://api.osv.dev/x",  # scheme arbitrario
    ],
)
def test_post_json_url_fuera_de_allowlist_rechazada(url: str) -> None:
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    with pytest.raises(NetworkUnverifiableError, match="allowlist"):
        _post(client, url, _BODY)


def test_post_json_depscope_bloqueado_si_no_esta_en_extra() -> None:
    # Watchlist desactivada => el cliente OSV no incluye depscope.dev en su efectivo (R2.1):
    # un POST a depscope.dev se rechaza por allowlist.
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    with pytest.raises(NetworkUnverifiableError, match="allowlist"):
        _post(client, "https://depscope.dev/api/benchmark/hallucinations", _BODY)


def test_post_json_url_ipv6_malformada_no_aborta_el_lote() -> None:
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    with pytest.raises(NetworkUnverifiableError, match="malformada"):
        _post(client, "https://[fe80::1/v1/querybatch", _BODY)


# --------------------------------------------------------------------------- #
# `_encode_json_body`: serializacion y body no serializable (R1.8/NFR-Seg.4).
# --------------------------------------------------------------------------- #


def test_encode_json_body_compacto_y_ascii() -> None:
    # ensure_ascii escapa CRLF/no-ASCII; separadores compactos (sin espacios).
    raw = hc._encode_json_body({"name": "café\r\n", "n": 1})
    assert b"\r\n" not in raw  # el CRLF viaja escapado como \r\n textual, no crudo
    assert b", " not in raw and b": " not in raw  # separadores compactos
    assert raw == b'{"name":"caf\\u00e9\\r\\n","n":1}'


def test_post_json_body_no_serializable_es_network_unverifiable() -> None:
    # Un body con un objeto no-JSON (set) se degrada, nunca escapa como TypeError crudo.
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    body: dict[str, object] = {"queries": {1, 2, 3}}  # set no es serializable a JSON
    with pytest.raises(NetworkUnverifiableError, match="no serializable"):
        _post(client, _OSV_URL, body)


def test_post_headers_no_anuncian_gzip_y_declaran_json() -> None:
    headers = hc._safe_post_headers()
    assert headers["Accept-Encoding"] == "identity"  # anti bomba de descompresion
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"


# --------------------------------------------------------------------------- #
# Clasificacion 429 como transitorio (R1.7) y 5xx; 4xx!=429 NO transitorio.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("code", [429, 500, 503, 599])
def test_is_transient_http_status_transitorio(code: int) -> None:
    assert hc._is_transient_http_status(code) is True


@pytest.mark.parametrize("code", [400, 401, 403, 404, 422, 600])
def test_is_transient_http_status_no_transitorio(code: int) -> None:
    assert hc._is_transient_http_status(code) is False


# --------------------------------------------------------------------------- #
# Servidor HTTP local malicioso: camino REAL de post_json (sockets, redirect).
# --------------------------------------------------------------------------- #


class _OsvHandler(BaseHTTPRequestHandler):
    """Sirve escenarios de POST/redirect segun la ruta (mentalidad pen-testing)."""

    def do_POST(self) -> None:  # firma impuesta por BaseHTTPRequestHandler
        path = self.path
        # Consume el cuerpo para no dejar el socket en estado inconsistente.
        length = int(self.headers.get("Content-Length", "0") or "0")
        self._body = self.rfile.read(length) if length else b""
        if path == "/v1/querybatch":
            self._send_ok()
        elif path == "/redirect-cross-host":
            self._redirect("https://evil.example/v1/querybatch")
        elif path == "/redirect-to-pypi":
            self._redirect("https://pypi.org/v1/querybatch")
        elif path == "/rate-limited":
            self._send_status(429)
        elif path == "/server-error":
            self._send_status(503)
        elif path == "/not-found":
            self._send_status(404)
        elif path == "/echo-body":
            self._echo_body()
        elif path == "/deflate-vacio":
            self._send_empty_deflate()
        else:
            self._send_status(404)

    def _send_ok(self) -> None:
        body = json.dumps({"results": [{"vulns": [{"id": "MAL-2025-1"}]}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _echo_body(self) -> None:
        # Devuelve el cuerpo recibido envuelto, para verificar que viajo serializado.
        body = json.dumps({"received": self._body.decode("utf-8")}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_empty_deflate(self) -> None:
        # Anuncia 'deflate' pero el stream descomprime a CERO bytes (stream degenerado):
        # ejercita el guard anti-stall de `_inflate_capped` y degrada por cuerpo vacio.
        body = zlib.compress(b"")
        self.send_response(200)
        self.send_header("Content-Encoding", "deflate")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _send_status(self, code: int) -> None:
        body = b'{"error": "x"}'
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        """Silencia el log del servidor para no contaminar la salida de pytest."""


class _LocalServer:
    """Levanta `_OsvHandler` en 127.0.0.1 (puerto efimero) en un hilo daemon."""

    def __init__(self) -> None:
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _OsvHandler)
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
def osv_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[_LocalServer]:
    """Servidor local + permisos de allowlist/puerto para http://127.0.0.1 SOLO en el test.

    El loopback usa puerto efimero (necesidad tecnica); se neutralizan `_is_allowed` y
    `_reject_port_and_userinfo` igual que en el harness del Hito 1, sin tocar el
    endurecimiento de produccion (que sigue rechazando puerto/userinfo y todo host ajeno).
    """

    def allow_local(
        scheme: str, host: str, allowed_hosts: frozenset[str] | None = None
    ) -> bool:
        return scheme.lower() == "http" and host == "127.0.0.1"

    monkeypatch.setattr(hc, "_is_allowed", allow_local)
    monkeypatch.setattr(hc, "_reject_port_and_userinfo", lambda _parts: None)
    with _LocalServer() as server:
        yield server


def _local_client() -> SecureHttpClient:
    """Cliente con un HTTPHandler extra para alcanzar el servidor http local de prueba."""
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    client._opener.add_handler(urllib.request.HTTPHandler())
    return client


def test_post_json_camino_feliz_real(osv_server: _LocalServer) -> None:
    # POST real: socket -> el handler responde 200 con un objeto JSON -> safe_json_loads.
    result = _post(_local_client(), osv_server.base_url + "/v1/querybatch", _BODY)
    assert result == {"results": [{"vulns": [{"id": "MAL-2025-1"}]}]}


def test_post_json_envia_cuerpo_serializado(osv_server: _LocalServer) -> None:
    # El body viaja serializado compacto: el servidor lo refleja y comprobamos el contenido.
    result = _post(_local_client(), osv_server.base_url + "/echo-body", {"name": "bioql"})
    assert result == {"received": '{"name":"bioql"}'}


def test_post_json_redirect_cross_host_rechazado(osv_server: _LocalServer) -> None:
    # RISK-H2-1: un 302 desde el host del 'extra' hacia un host ajeno => destino no permitido.
    with pytest.raises(NetworkUnverifiableError, match="destino no permitido"):
        _post(_local_client(), osv_server.base_url + "/redirect-cross-host", _BODY)


def test_post_json_redirect_a_pypi_rechazado(osv_server: _LocalServer) -> None:
    # RISK-H2-1: redirect del servidor local -> pypi.org. Bajo el harness (que habilita solo
    # http://127.0.0.1) pypi.org es cross-host => 'destino no permitido'. La rama 'inesperada'
    # (destino DENTRO del efectivo real) se verifica con el aserto directo del handler mas abajo,
    # sin parchear _is_allowed. En ambos casos NINGUNA redireccion se sigue (politica RISK-H2-1).
    with pytest.raises(NetworkUnverifiableError, match="destino no permitido"):
        _post(_local_client(), osv_server.base_url + "/redirect-to-pypi", _BODY)


def test_post_json_429_es_transitorio(osv_server: _LocalServer) -> None:
    # R1.7: un 429 real se mapea a NetworkUnverifiableError con status 429 e is_transient=True
    # (se reintentaria; tras agotar el presupuesto la fuente degrada a UNVERIFIABLE, nunca CLEAN).
    with pytest.raises(NetworkUnverifiableError) as info:
        _post(_local_client(), osv_server.base_url + "/rate-limited", _BODY)
    assert info.value.status_code == 429
    assert info.value.is_transient is True


def test_post_json_503_es_transitorio(osv_server: _LocalServer) -> None:
    with pytest.raises(NetworkUnverifiableError) as info:
        _post(_local_client(), osv_server.base_url + "/server-error", _BODY)
    assert info.value.status_code == 503
    assert info.value.is_transient is True


def test_post_json_404_no_transitorio(osv_server: _LocalServer) -> None:
    # Un 4xx != 429 es permanente: status 404, NO transitorio (no se reintenta a ciegas).
    with pytest.raises(NetworkUnverifiableError) as info:
        _post(_local_client(), osv_server.base_url + "/not-found", _BODY)
    assert info.value.status_code == 404
    assert info.value.is_transient is False


# --------------------------------------------------------------------------- #
# Redirect handler con conjunto EFECTIVO inyectado (fix SSRF §3.3): asertos
# directos sobre `_RejectRedirectHandler` construido con el extra por instancia.
# --------------------------------------------------------------------------- #


def test_redirect_handler_efectivo_destino_ajeno_rechazado() -> None:
    handler = hc._RejectRedirectHandler(frozenset({"pypi.org", _OSV_HOST}))
    with pytest.raises(NetworkUnverifiableError, match="destino no permitido"):
        handler.redirect_request(None, None, 302, "Found", None, "https://evil.example/x")  # type: ignore[arg-type]


def test_redirect_handler_efectivo_dentro_del_conjunto_es_inesperada() -> None:
    # Un destino DENTRO del efectivo (api.osv.dev) igual se rechaza: ninguna redireccion
    # se sigue; el conjunto efectivo solo cambia el MENSAJE (inesperada vs no permitido).
    handler = hc._RejectRedirectHandler(frozenset({"pypi.org", _OSV_HOST}))
    newurl = f"https://{_OSV_HOST}/otro"
    with pytest.raises(NetworkUnverifiableError, match="inesperada"):
        handler.redirect_request(None, None, 302, "Found", None, newurl)  # type: ignore[arg-type]


def test_redirect_handler_efectivo_cross_scheme_rechazado() -> None:
    handler = hc._RejectRedirectHandler(_OSV_HOSTS)
    newurl = f"http://{_OSV_HOST}/x"
    with pytest.raises(NetworkUnverifiableError, match="destino no permitido"):
        handler.redirect_request(None, None, 301, "Moved", None, newurl)  # type: ignore[arg-type]


def test_validate_url_usa_efectivo_no_global() -> None:
    # Confirma que la URL inicial se valida contra el efectivo de la instancia, no la global:
    # el host del extra es aceptado por _validate_url (no lanza) pese a no estar en ALLOWED_HOSTS.
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    parts = urlsplit(_OSV_URL)
    assert parts.hostname == _OSV_HOST
    # No debe lanzar: el host esta en el efectivo aunque NO en la base global {pypi.org}.
    client._validate_url(_OSV_URL)
    assert _OSV_HOST not in hc.ALLOWED_HOSTS  # la base global sigue anclada sin osv


# --------------------------------------------------------------------------- #
# Descompresion defensiva: guard anti-stall de `_inflate_capped` (stream que
# descomprime a CERO bytes). Un servidor que anuncia `Content-Encoding: deflate`
# pero entrega un stream degenerado (payload vacio) NO debe colgar el cliente en
# un bucle de descompresion ni materializar un falso CLEAN: el descompresor no
# produce ni consume, el loop corta por el `break` anti-stall y el cuerpo vacio
# resultante se degrada a NetworkUnverifiableError (no es un objeto JSON).
# --------------------------------------------------------------------------- #


class _FakeResponse:
    """Doble de respuesta de urllib: expone `read(n)` sobre un buffer en memoria."""

    def __init__(self, body: bytes) -> None:
        """Guarda el cuerpo crudo (ya 'comprimido') en un buffer de lectura."""
        self._stream = io.BytesIO(body)

    def read(self, size: int) -> bytes:
        """Lee hasta `size` bytes del buffer (camino streaming de `_read_capped_body`)."""
        return self._stream.read(size)


def test_read_capped_body_deflate_vacio_no_cuelga_y_devuelve_vacio() -> None:
    # Aislado: un stream deflate que descomprime a 0 bytes ejercita el `break` anti-stall
    # de `_inflate_capped`; debe retornar b"" SIN entrar en bucle (no produce ni consume).
    empty_deflate = zlib.compress(b"")
    body = hc._read_capped_body(_FakeResponse(empty_deflate), "deflate", 1_000)
    assert body == b""


def test_post_json_deflate_degenerado_es_network_unverifiable(osv_server: _LocalServer) -> None:
    # Extremo a extremo (pen-testing): el servidor anuncia deflate y sirve un stream que
    # descomprime a vacio; el cliente no cuelga y degrada el cuerpo vacio a no-verificable
    # (b"" no es un objeto JSON valido), nunca un falso CLEAN.
    with pytest.raises(NetworkUnverifiableError):
        _post(_local_client(), osv_server.base_url + "/deflate-vacio", _BODY)
