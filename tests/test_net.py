"""Pruebas del subsistema de red endurecida (T13/T14/T15, NFR-Seg.3-4, NFR-Priv.1).

Cubre `safe_json_loads` (anti JSON-bomb) y `SecureHttpClient` (TLS, allowlist,
sin redirects, streaming acotado, descompresion incremental con cota). Dos niveles:

1. **Dobles deterministas** (`_FakeResponse`): inyectan cuerpo/cabeceras directamente
   en el opener para ejercitar las cotas finas de streaming/descompresion sin tocar
   sockets ni el reloj.
2. **Servidor HTTP local malicioso** (`http.server`, clase `_LocalServer`): ejercita el
   camino REAL de `urllib` (sockets, `response.read()` streaming, redirect handler,
   descompresion incremental) contra los 5 escenarios maliciosos de ADR-03/T15:
   redireccion cross-host y cross-scheme, respuesta gigante, `Content-Length` excesivo,
   JSON profundo y gzip-bomb. Como el cliente esta fijado a `https://pypi.org`, el
   harness habilita `http://127.0.0.1` SOLO para el test (monkeypatch de `_is_allowed`)
   y registra un `HTTPHandler` temporal en el opener; asi el endurecimiento de
   produccion corre tal cual sobre bytes reales venidos de un socket.

Tambien fija como regresion los tres hallazgos de revision sobre `_read_response`/
`_validate_url`: `zlib.error` (gzip/deflate corrupto, raw-deflate), `http.client.
HTTPException` (`IncompleteRead`, `InvalidURL`) y `ValueError` de `urlsplit` (IPv6
malformado) deben degradarse SIEMPRE a `NetworkUnverifiableError`, nunca escapar
crudos (invariante de seguridad T14, degradacion por-dependencia R2.5/NFR-Degr.1).
"""

from __future__ import annotations

import gzip
import http.client
import io
import json
import ssl
import threading
import urllib.error
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

import pytest

from slopguard.core.errors import NetworkUnverifiableError
from slopguard.core.net import http_client as hc
from slopguard.core.net.http_client import SecureHttpClient
from slopguard.core.net.safe_json import safe_json_loads

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

# --------------------------------------------------------------------------- #
# Dobles de prueba (respuesta HTTP simulada)
# --------------------------------------------------------------------------- #


class _FakeResponse:
    """Doble de un objeto-respuesta de urllib: expone `headers` y `read(n)`."""

    def __init__(self, body: bytes, headers: Mapping[str, str]) -> None:
        self.headers = _Headers(headers)
        self._stream = io.BytesIO(body)

    def read(self, size: int) -> bytes:
        return self._stream.read(size)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stream.close()


class _RaisingResponse:
    """Doble cuyo `read` lanza una excepcion fija (cuerpo truncado / fallo de stream)."""

    def __init__(self, headers: Mapping[str, str], exc: BaseException) -> None:
        self.headers = _Headers(headers)
        self._exc = exc

    def read(self, _size: int) -> bytes:
        raise self._exc

    def __enter__(self) -> _RaisingResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


class _Headers:
    """Doble de `http.client.HTTPMessage`: solo el `get` insensible a mayusculas."""

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = {k.lower(): v for k, v in values.items()}

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._values.get(key.lower(), default)


def _client_with_response(
    monkeypatch: pytest.MonkeyPatch, body: bytes, headers: Mapping[str, str]
) -> SecureHttpClient:
    """Crea un cliente cuyo opener devuelve siempre una respuesta inyectada."""
    client = SecureHttpClient()

    def fake_open(_request: object, timeout: float) -> _FakeResponse:
        return _FakeResponse(body, headers)

    monkeypatch.setattr(client._opener, "open", fake_open)
    return client


def _client_with_open(
    monkeypatch: pytest.MonkeyPatch, opener: Callable[[object, float], object]
) -> SecureHttpClient:
    """Crea un cliente cuyo `opener.open` delega en `opener` (para inyectar fallos)."""
    client = SecureHttpClient()
    monkeypatch.setattr(client._opener, "open", opener)
    return client


_URL = "https://pypi.org/pypi/requests/json"


# --------------------------------------------------------------------------- #
# safe_json_loads — anti JSON-bomb (T13, NFR-Seg.4)
# --------------------------------------------------------------------------- #


def test_safe_json_parsea_objeto_plano() -> None:
    assert safe_json_loads(b'{"name": "requests", "n": 1}', max_depth=10) == {
        "name": "requests",
        "n": 1,
    }


def test_safe_json_profundidad_exacta_pasa() -> None:
    # 3 niveles de anidamiento con max_depth=3 debe pasar.
    data = b'{"a": {"b": {"c": 1}}}'
    assert safe_json_loads(data, max_depth=3) == {"a": {"b": {"c": 1}}}


def test_safe_json_profundidad_excesiva_rechaza_antes_de_materializar() -> None:
    data = b'{"a": {"b": {"c": {"d": 1}}}}'  # 4 niveles
    with pytest.raises(NetworkUnverifiableError, match="profundidad JSON"):
        safe_json_loads(data, max_depth=3)


def test_safe_json_bomba_de_arrays_rechazada() -> None:
    bomb = b"[" * 10_000 + b"]" * 10_000
    with pytest.raises(NetworkUnverifiableError, match="profundidad JSON"):
        safe_json_loads(bomb, max_depth=50)


def test_safe_json_llaves_dentro_de_string_no_cuentan() -> None:
    # Las llaves estan dentro de strings: la profundidad real es 1, no debe rechazar.
    data = b'{"k": "{{{{[[[["}'
    assert safe_json_loads(data, max_depth=2) == {"k": "{{{{[[[["}


def test_safe_json_escapes_en_string_respetados() -> None:
    # La comilla escapada no cierra la string; el `{` siguiente sigue siendo literal.
    data = b'{"k": "a\\"{{{b"}'
    assert safe_json_loads(data, max_depth=2) == {"k": 'a"{{{b'}


def test_safe_json_malformado_es_network_unverifiable() -> None:
    with pytest.raises(NetworkUnverifiableError, match="malformada"):
        safe_json_loads(b"{no es json}", max_depth=10)


def test_safe_json_max_depth_invalido() -> None:
    with pytest.raises(NetworkUnverifiableError, match="max_depth"):
        safe_json_loads(b"{}", max_depth=0)


def test_safe_json_array_anidado_en_limite() -> None:
    # Mezcla objeto+array; profundidad maxima = 4.
    data = b'{"a": [{"b": [1]}]}'
    assert safe_json_loads(data, max_depth=4) == {"a": [{"b": [1]}]}
    with pytest.raises(NetworkUnverifiableError):
        safe_json_loads(data, max_depth=3)


# --------------------------------------------------------------------------- #
# Allowlist + scheme (NFR-Seg.3) y privacidad de URL (NFR-Priv.1)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "http://pypi.org/pypi/requests/json",  # scheme no https
        "https://evil.com/pypi/requests/json",  # host fuera de allowlist
        "https://pypi.org.evil.com/x",  # host similar pero distinto
        "ftp://pypi.org/x",  # scheme arbitrario
    ],
)
def test_url_fuera_de_allowlist_rechazada(url: str) -> None:
    client = SecureHttpClient()
    with pytest.raises(NetworkUnverifiableError, match="allowlist"):
        client.get_json(
            url,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000,
            max_json_depth=10,
        )


def test_url_con_userinfo_rechazada_antes_de_allowlist() -> None:
    # Una URL con userinfo enganoso (attacker@host) se rechaza por la nueva validacion
    # A10 SSRF ANTES de consultar la allowlist (defecto-deniega temprano): el motivo del
    # rechazo es el userinfo, no el host. Sigue degradando a NetworkUnverifiableError.
    client = SecureHttpClient()
    with pytest.raises(NetworkUnverifiableError, match="userinfo"):
        client.get_json(
            "https://attacker@pypi.org.evil.com/x",
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000,
            max_json_depth=10,
        )


def test_is_allowed_case_insensitive() -> None:
    assert hc._is_allowed("HTTPS", "PyPI.org") is True
    assert hc._is_allowed("https", "files.pythonhosted.org") is False


def test_request_headers_no_anuncian_gzip() -> None:
    headers = hc._safe_request_headers()
    assert headers["Accept-Encoding"] == "identity"


# --------------------------------------------------------------------------- #
# Redirect handler — sin cross-scheme/cross-host (anti SSRF)
# --------------------------------------------------------------------------- #


def test_redirect_a_host_externo_rechazado() -> None:
    handler = hc._RejectRedirectHandler()
    with pytest.raises(NetworkUnverifiableError, match="destino no permitido"):
        handler.redirect_request(None, None, 302, "Found", None, "https://evil.com/x")  # type: ignore[arg-type]


def test_redirect_a_http_rechazado() -> None:
    handler = hc._RejectRedirectHandler()
    with pytest.raises(NetworkUnverifiableError, match="destino no permitido"):
        handler.redirect_request(None, None, 301, "Moved", None, "http://pypi.org/x")  # type: ignore[arg-type]


def test_redirect_aun_dentro_de_allowlist_se_rechaza() -> None:
    # Incluso un redirect https a pypi.org es inesperado para /json: se rechaza.
    handler = hc._RejectRedirectHandler()
    with pytest.raises(NetworkUnverifiableError, match="inesperada"):
        handler.redirect_request(None, None, 302, "Found", None, "https://pypi.org/otro")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Lectura acotada y Content-Length (NFR-Seg.4)
# --------------------------------------------------------------------------- #


def test_get_json_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"info": {"name": "requests"}}
    body = json.dumps(payload).encode()
    client = _client_with_response(monkeypatch, body, {"Content-Length": str(len(body))})
    result = client.get_json(
        _URL,
        connect_timeout_s=1.0,
        read_timeout_s=1.0,
        max_response_bytes=10_000,
        max_json_depth=10,
    )
    assert result == payload


def test_content_length_excesivo_rechazado(monkeypatch: pytest.MonkeyPatch) -> None:
    body = b'{"x": 1}'
    client = _client_with_response(monkeypatch, body, {"Content-Length": "999999999"})
    with pytest.raises(NetworkUnverifiableError, match="Content-Length excesivo"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000,
            max_json_depth=10,
        )


def test_content_length_no_numerico_rechazado(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with_response(monkeypatch, b"{}", {"Content-Length": "mucho"})
    with pytest.raises(NetworkUnverifiableError, match="no numerico"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000,
            max_json_depth=10,
        )


def test_content_length_negativo_rechazado(monkeypatch: pytest.MonkeyPatch) -> None:
    # Un Content-Length negativo es absurdo: se trata como excesivo (rechazo defensivo).
    client = _client_with_response(monkeypatch, b"{}", {"Content-Length": "-1"})
    with pytest.raises(NetworkUnverifiableError, match="Content-Length excesivo"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000,
            max_json_depth=10,
        )


def test_cuerpo_gigante_sin_content_length_aborta(monkeypatch: pytest.MonkeyPatch) -> None:
    # Sin Content-Length declarado: la cota se aplica durante la lectura streaming.
    body = b'{"data": "' + b"A" * 5_000 + b'"}'
    client = _client_with_response(monkeypatch, body, {})
    with pytest.raises(NetworkUnverifiableError, match="supera el maximo"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000,
            max_json_depth=10,
        )


def test_respuesta_no_objeto_rechazada(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with_response(monkeypatch, b"[1, 2, 3]", {})
    with pytest.raises(NetworkUnverifiableError, match="no es un objeto"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000,
            max_json_depth=10,
        )


# --------------------------------------------------------------------------- #
# Descompresion incremental con cota (gzip bomb)
# --------------------------------------------------------------------------- #


def test_gzip_legitimo_se_descomprime(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"info": {"name": "flask"}}
    raw = json.dumps(payload).encode()
    compressed = _gzip_bytes(raw)
    client = _client_with_response(monkeypatch, compressed, {"Content-Encoding": "gzip"})
    result = client.get_json(
        _URL,
        connect_timeout_s=1.0,
        read_timeout_s=1.0,
        max_response_bytes=10_000,
        max_json_depth=10,
    )
    assert result == payload


def test_gzip_bomb_abortada_antes_de_materializar(monkeypatch: pytest.MonkeyPatch) -> None:
    # 50 MB de ceros comprimidos a pocos KB: la cota de salida la detiene en streaming.
    raw = b"\x00" * (50 * 1024 * 1024)
    compressed = _gzip_bytes(raw)
    assert len(compressed) < 200_000  # confirmamos el ratio de bomba
    client = _client_with_response(monkeypatch, compressed, {"Content-Encoding": "gzip"})
    with pytest.raises(NetworkUnverifiableError, match="supera el maximo"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000_000,
            max_json_depth=10,
        )


def test_deflate_legitimo_se_descomprime(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"info": {"name": "numpy"}}
    raw = json.dumps(payload).encode()
    compressed = zlib.compress(raw)
    client = _client_with_response(monkeypatch, compressed, {"Content-Encoding": "deflate"})
    result = client.get_json(
        _URL,
        connect_timeout_s=1.0,
        read_timeout_s=1.0,
        max_response_bytes=10_000,
        max_json_depth=10,
    )
    assert result == payload


def test_content_encoding_desconocido_rechazado(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with_response(monkeypatch, b"datos", {"Content-Encoding": "br"})
    with pytest.raises(NetworkUnverifiableError, match="no soportado"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
        )


# --------------------------------------------------------------------------- #
# Regresion: flujos comprimidos corruptos => NetworkUnverifiableError (T14)
#
# `zlib.error` hereda de Exception (NO de OSError/ValueError); antes del fix
# escapaba crudo desde `_inflate_capped`/`_read_capped_body`. Un servidor (o MITM)
# que envie gzip/deflate corrupto, truncado-con-cabecera-valida o raw-deflate (no
# zlib-wrapped) debe degradar la dependencia como unverifiable, no abortar el lote.
# --------------------------------------------------------------------------- #


def test_gzip_corrupto_es_network_unverifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    # Cabecera gzip valida + datos basura: zlib lanza Error -3 al inflar.
    corrupto = _gzip_bytes(b'{"x": 1}')[:6] + b"\xff" * 64
    client = _client_with_response(monkeypatch, corrupto, {"Content-Encoding": "gzip"})
    with pytest.raises(NetworkUnverifiableError, match="no verificable"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
        )


def test_gzip_truncado_es_network_unverifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    # Stream gzip valido pero cortado a la mitad: zlib no lanza (eof=False), pero el
    # cuerpo descomprimido queda como JSON incompleto y `safe_json_loads` lo rechaza
    # como malformado => NetworkUnverifiableError. La degradacion segura se mantiene
    # tanto si el fallo lo detecta zlib como si lo detecta el parser.
    completo = _gzip_bytes(b'{"info": {"name": "' + b"x" * 2_000 + b'"}}')
    truncado = completo[: len(completo) // 2]
    client = _client_with_response(monkeypatch, truncado, {"Content-Encoding": "gzip"})
    with pytest.raises(NetworkUnverifiableError, match=r"malformada|no verificable"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
        )


def test_deflate_raw_no_zlib_wrapped_es_network_unverifiable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # HTTP 'deflate' real suele ser raw-deflate (sin cabecera zlib). El descompresor
    # del cliente espera zlib-wrapped (wbits=MAX_WBITS) => zlib.error. Debe mapearse.
    compresor = zlib.compressobj(wbits=-zlib.MAX_WBITS)  # raw, sin wrapper zlib
    raw = compresor.compress(b'{"x": 1}') + compresor.flush()
    client = _client_with_response(monkeypatch, raw, {"Content-Encoding": "deflate"})
    with pytest.raises(NetworkUnverifiableError, match="no verificable"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
        )


def test_deflate_basura_es_network_unverifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with_response(monkeypatch, b"no-soy-deflate", {"Content-Encoding": "deflate"})
    with pytest.raises(NetworkUnverifiableError, match="no verificable"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
        )


def test_zlib_error_no_expone_stacktrace_crudo(monkeypatch: pytest.MonkeyPatch) -> None:
    # El mensaje degradado no debe filtrar el detalle de zlib ('Error -3 ...').
    client = _client_with_response(monkeypatch, b"basura", {"Content-Encoding": "gzip"})
    with pytest.raises(NetworkUnverifiableError) as info:
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
        )
    assert "Error -3" not in str(info.value)
    assert "decompressing" not in str(info.value)


# --------------------------------------------------------------------------- #
# Regresion: http.client.HTTPException => NetworkUnverifiableError (T14)
#
# IncompleteRead (cuerpo truncado) e InvalidURL (puerto no numerico) heredan de
# HTTPException, NO de OSError/ValueError; antes del fix escapaban crudas.
# --------------------------------------------------------------------------- #


def test_incomplete_read_es_network_unverifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    exc = http.client.IncompleteRead(partial=b"{", expected=100)

    def opener(_request: object, timeout: float) -> _RaisingResponse:
        return _RaisingResponse({}, exc)

    client = _client_with_open(monkeypatch, opener)
    with pytest.raises(NetworkUnverifiableError, match="IncompleteRead"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
        )


def test_http_exception_generica_es_network_unverifiable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def opener(_request: object, timeout: float) -> None:
        raise http.client.InvalidURL("puerto no numerico")

    client = _client_with_open(monkeypatch, opener)
    with pytest.raises(NetworkUnverifiableError, match="no verificable"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
        )


# --------------------------------------------------------------------------- #
# Regresion: urlsplit ValueError (IPv6 malformado) => NetworkUnverifiableError
# --------------------------------------------------------------------------- #


def test_url_ipv6_malformada_no_aborta_el_lote() -> None:
    # 'https://[fe80::1/x' (literal IPv6 sin cerrar) hace que urlsplit lance ValueError
    # ANTES de _is_allowed; debe degradarse a unverifiable, no escapar como ValueError
    # crudo (que abortaria el lote). Es el hallazgo de _validate_url.
    client = SecureHttpClient()
    with pytest.raises(NetworkUnverifiableError, match="malformada"):
        client.get_json(
            "https://[fe80::1/x",
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
        )


def test_url_ipv6_con_puerto_rechazada_por_puerto() -> None:
    # 'https://[::1]:99/x' lleva puerto explicito: la nueva validacion A10 SSRF lo
    # rechaza ANTES de la allowlist (defecto-deniega). El loopback [::1] jamas debe ser
    # alcanzable; el motivo del rechazo ahora es el puerto explicito. No aborta el lote.
    client = SecureHttpClient()
    with pytest.raises(NetworkUnverifiableError, match="puerto explicito"):
        client.get_json(
            "https://[::1]:99/x",
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
        )


def test_url_ipv6_loopback_sin_puerto_rechazada_por_allowlist() -> None:
    # Sin puerto, el host loopback [::1] cae por allowlist (no esta en {pypi.org}); esto
    # confirma que el rechazo de allowlist sigue activo para IPv6 desnudo. No aborta el lote.
    client = SecureHttpClient()
    with pytest.raises(NetworkUnverifiableError, match="allowlist"):
        client.get_json(
            "https://[::1]/x",
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=10_000,
            max_json_depth=10,
        )


# --------------------------------------------------------------------------- #
# Manejo de errores de transporte
# --------------------------------------------------------------------------- #


def test_error_http_se_mapea_a_unverifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    client = SecureHttpClient()

    def raise_http(_request: object, timeout: float) -> None:
        raise urllib.error.HTTPError(_URL, 503, "Service Unavailable", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(client._opener, "open", raise_http)
    with pytest.raises(NetworkUnverifiableError, match="503"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000,
            max_json_depth=10,
        )


def test_error_url_se_mapea_a_unverifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    client = SecureHttpClient()

    def raise_url(_request: object, timeout: float) -> None:
        raise urllib.error.URLError("conexion rechazada")

    monkeypatch.setattr(client._opener, "open", raise_url)
    with pytest.raises(NetworkUnverifiableError, match="fallo de red"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000,
            max_json_depth=10,
        )


def test_os_error_se_mapea_a_unverifiable(monkeypatch: pytest.MonkeyPatch) -> None:
    # Un timeout de socket (subclase de OSError) llega como fallo de red generico.
    def opener(_request: object, timeout: float) -> None:
        raise TimeoutError("read timed out")

    client = _client_with_open(monkeypatch, opener)
    with pytest.raises(NetworkUnverifiableError, match="fallo de red"):
        client.get_json(
            _URL,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000,
            max_json_depth=10,
        )


def test_tls_context_no_desactivable() -> None:
    # El contexto TLS exige verificacion de certificado y hostname (NFR-Seg.3).
    client = SecureHttpClient()
    handlers = client._opener.handlers  # type: ignore[attr-defined]  # API runtime de urllib
    https = next(h for h in handlers if isinstance(h, urllib.request.HTTPSHandler))
    context = https._context  # type: ignore[attr-defined]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


# --------------------------------------------------------------------------- #
# Harness con servidor HTTP local malicioso (T15, ADR-03)
#
# Ejercita el camino REAL de urllib (sockets, response.read() streaming, redirect
# handler, descompresion incremental). El cliente esta fijado a https://pypi.org;
# para alcanzar el servidor local se habilita http://127.0.0.1 SOLO en el test
# (monkeypatch de `_is_allowed`, visto por _validate_url y por el redirect handler)
# y se registra un HTTPHandler temporal en el opener. NUNCA se desactiva TLS para
# pypi.org real: es un permiso local de prueba, no una opcion del producto.
# --------------------------------------------------------------------------- #


class _MaliciousHandler(BaseHTTPRequestHandler):
    """Sirve los 5 escenarios maliciosos de T15 segun la ruta solicitada."""

    def do_GET(self) -> None:
        path = self.path
        if path == "/ok":
            self._send_ok()
        elif path == "/redirect-host":
            self._redirect("https://evil.com/pypi/x/json")
        elif path == "/redirect-scheme":
            self._redirect("http://pypi.org/pypi/x/json")
        elif path == "/giant":
            self._send_giant()
        elif path == "/excessive-length":
            self._send_excessive_length()
        elif path == "/deep-json":
            self._send_deep_json()
        elif path == "/gzip-bomb":
            self._send_gzip_bomb()
        else:
            self.send_response(404)
            self.end_headers()

    def _send_ok(self) -> None:
        body = json.dumps({"info": {"name": "requests"}}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _send_giant(self) -> None:
        # Sin Content-Length: la cota se aplica durante el streaming real.
        self.send_response(200)
        self.end_headers()
        chunk = b"A" * 65_536
        for _ in range(64):  # ~4 MB, abortado mucho antes por la cota
            try:
                self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                return  # el cliente corto la conexion al exceder la cota

    def _send_excessive_length(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "999999999")
        self.end_headers()

    def _send_deep_json(self) -> None:
        body = b'{"a":' * 80 + b"1" + b"}" * 80  # 80 niveles de anidamiento
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_gzip_bomb(self) -> None:
        comp = _gzip_bytes(b"\x00" * (20 * 1024 * 1024))  # 20 MB -> pocos KB
        self.send_response(200)
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(comp)))
        self.end_headers()
        self.wfile.write(comp)

    def log_message(self, *_args: object) -> None:
        """Silencia el log del servidor para no contaminar la salida de pytest."""


class _LocalServer:
    """Levanta `_MaliciousHandler` en 127.0.0.1 en un hilo daemon; expone `base_url`."""

    def __init__(self) -> None:
        self._httpd = HTTPServer(("127.0.0.1", 0), _MaliciousHandler)
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
def local_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[_LocalServer]:
    """Servidor local + permiso de allowlist http://127.0.0.1 SOLO durante el test."""

    def allow_local(
        scheme: str, host: str, allowed_hosts: frozenset[str] | None = None
    ) -> bool:
        # Acepta el 3er parametro (allowlist EFECTIVA por-instancia, Hito 2) pero lo ignora:
        # este harness habilita http://127.0.0.1 sin importar el conjunto efectivo.
        return scheme.lower() == "http" and host == "127.0.0.1"

    def allow_local_port(_parts: object) -> None:
        # El servidor loopback usa un puerto efimero asignado por el SO: el rechazo de
        # puerto explicito (A10 SSRF, defecto-deniega en produccion) se neutraliza SOLO
        # aqui, por necesidad tecnica del harness que ejercita el camino real de urllib.
        return None

    monkeypatch.setattr(hc, "_is_allowed", allow_local)
    monkeypatch.setattr(hc, "_reject_port_and_userinfo", allow_local_port)
    with _LocalServer() as server:
        yield server


def _local_client() -> SecureHttpClient:
    """Cliente con un HTTPHandler extra para alcanzar el servidor http local de prueba."""
    client = SecureHttpClient()
    client._opener.add_handler(urllib.request.HTTPHandler())
    return client


def _get(client: SecureHttpClient, url: str, *, max_bytes: int = 1_000_000) -> object:
    """Helper de invocacion con timeouts cortos y profundidad acotada."""
    return client.get_json(
        url,
        connect_timeout_s=2.0,
        read_timeout_s=2.0,
        max_response_bytes=max_bytes,
        max_json_depth=20,
    )


def test_servidor_local_ok(local_server: _LocalServer) -> None:
    # Camino feliz real: socket -> response.read() streaming -> safe_json_loads.
    result = _get(_local_client(), local_server.base_url + "/ok")
    assert result == {"info": {"name": "requests"}}


def test_servidor_local_redirect_cross_host_rechazado(local_server: _LocalServer) -> None:
    with pytest.raises(NetworkUnverifiableError, match="destino no permitido"):
        _get(_local_client(), local_server.base_url + "/redirect-host")


def test_servidor_local_redirect_cross_scheme_rechazado(local_server: _LocalServer) -> None:
    with pytest.raises(NetworkUnverifiableError, match="destino no permitido"):
        _get(_local_client(), local_server.base_url + "/redirect-scheme")


def test_servidor_local_respuesta_gigante_abortada(local_server: _LocalServer) -> None:
    with pytest.raises(NetworkUnverifiableError, match="supera el maximo"):
        _get(_local_client(), local_server.base_url + "/giant", max_bytes=100_000)


def test_servidor_local_content_length_excesivo_rechazado(local_server: _LocalServer) -> None:
    with pytest.raises(NetworkUnverifiableError, match="Content-Length excesivo"):
        _get(_local_client(), local_server.base_url + "/excessive-length", max_bytes=1_000)


def test_servidor_local_json_profundo_rechazado(local_server: _LocalServer) -> None:
    # 80 niveles > max_json_depth=20: safe_json_loads aborta sin materializar.
    with pytest.raises(NetworkUnverifiableError, match="profundidad JSON"):
        _get(_local_client(), local_server.base_url + "/deep-json")


def test_servidor_local_gzip_bomb_abortada(local_server: _LocalServer) -> None:
    with pytest.raises(NetworkUnverifiableError, match="supera el maximo"):
        _get(_local_client(), local_server.base_url + "/gzip-bomb", max_bytes=1_000_000)


def _gzip_bytes(raw: bytes) -> bytes:
    """Comprime `raw` en formato gzip para los tests de descompresion."""
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb") as gz:
        gz.write(raw)
    return buffer.getvalue()
