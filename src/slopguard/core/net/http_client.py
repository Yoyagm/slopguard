"""Cliente HTTPS endurecido sobre `urllib` (stdlib, cero deps) — ADR-03 / NFR-Seg.3-4.

`SecureHttpClient.get_json` realiza un GET con:
- TLS verificado por `ssl.create_default_context()` (certificado y hostname),
  SIN ninguna opcion para desactivarlo.
- Allowlist estricta de host (`{pypi.org}`) y scheme `https` obligatorio, validados
  tanto en la URL inicial como en cualquier redireccion.
- `OpenerDirector` construido a mano que NO incluye el redirect handler por defecto;
  en su lugar usa uno propio que RECHAZA cualquier `Location` cross-scheme/cross-host
  (cualquier anomalia => `NetworkUnverifiableError`).
- Rechazo de `Content-Length` excesivo, lectura STREAMING acotada por
  `max_response_bytes` (aborta si excede) y descompresion incremental con cota
  (no se anuncia gzip; si llega, se descomprime con tope de salida).
- Parseo via `safe_json_loads(max_json_depth)` (anti JSON-bomb).

Ante CUALQUIER anomalia se lanza `NetworkUnverifiableError` sin exponer el payload
completo ni stacktraces crudos (NFR-Seg.3-4). La URL la construye el adapter y solo
contiene el nombre del paquete, jamas contenido del manifiesto (NFR-Priv.1).
"""

from __future__ import annotations

import http.client
import ssl
import urllib.error
import urllib.request
import zlib
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from ..errors import NetworkUnverifiableError
from .safe_json import safe_json_loads

if TYPE_CHECKING:
    from collections.abc import Iterable

# Allowlist de hosts permitidos y unico scheme aceptado (NFR-Seg.3).
ALLOWED_HOSTS: Final[frozenset[str]] = frozenset({"pypi.org"})
_ALLOWED_SCHEME: Final[str] = "https"

# Tamano de chunk de lectura/descompresion. Acota la memoria por iteracion sin
# afectar la cota dura de `max_response_bytes`.
_CHUNK_BYTES: Final[int] = 65_536

# Codificaciones de transferencia que sabemos descomprimir incrementalmente.
# NO se anuncian (Accept-Encoding: identity) para evitar bombas de descompresion;
# se manejan solo si el servidor las impone unilateralmente.
_GZIP_WBITS: Final[int] = zlib.MAX_WBITS | 16  # gzip
_DEFLATE_WBITS: Final[int] = zlib.MAX_WBITS  # zlib/deflate

# Rango de errores de servidor (5xx): transitorios y reintentables (R2.5/Convenciones).
_HTTP_SERVER_ERROR_MIN: Final[int] = 500
_HTTP_SERVER_ERROR_MAX: Final[int] = 599


def _is_allowed(scheme: str, host: str) -> bool:
    """True si el destino usa https y un host de la allowlist (case-insensitive)."""
    return scheme.lower() == _ALLOWED_SCHEME and host.lower() in ALLOWED_HOSTS


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler que solo permite redirecciones dentro de la allowlist https.

    Cualquier `Location` con scheme distinto de https o host fuera del allowlist se
    trata como anomalia => `NetworkUnverifiableError`. Reemplaza al handler por
    defecto de urllib para no seguir redirecciones cross-scheme/cross-host (SSRF).
    """

    def redirect_request(  # noqa: PLR0913 (firma impuesta por la clase base)
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        """Rechaza redirecciones fuera de la allowlist; nunca reabre cross-origin."""
        parts = urlsplit(newurl)
        if not _is_allowed(parts.scheme, parts.hostname or ""):
            raise NetworkUnverifiableError("redireccion a destino no permitido rechazada")
        raise NetworkUnverifiableError("redireccion inesperada de la fuente rechazada")


class SecureHttpClient:
    """Cliente HTTPS endurecido: allowlist, TLS verificado, sin redirects, streaming."""

    def __init__(self) -> None:
        """Construye un opener minimo con TLS verificado y redirect handler propio."""
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        https_handler = urllib.request.HTTPSHandler(context=context)
        self._opener = urllib.request.OpenerDirector()
        for handler in self._safe_handlers(https_handler):
            self._opener.add_handler(handler)

    @staticmethod
    def _safe_handlers(
        https_handler: urllib.request.HTTPSHandler,
    ) -> Iterable[urllib.request.BaseHandler]:
        """Conjunto minimo de handlers: TLS, redirect propio y procesado de errores.

        Deliberadamente NO incluye proxy ni el redirect handler por defecto de
        urllib, para no seguir redirecciones no validadas (ADR-03 / NFR-Seg.3).

        SI incluye `HTTPDefaultErrorHandler` ANTES de `HTTPErrorProcessor`: sin el,
        ante CUALQUIER respuesta >=400 el `OpenerDirector` no encuentra handler para
        el evento 'http' y `open` devuelve None, lo que hacia que `with None as ...`
        lanzara un `TypeError` crudo (abortando el lote y filtrando stacktrace). Con
        el default handler, urllib eleva `HTTPError` con `.code`, que `get_json`
        traduce a `NetworkUnverifiableError` tipada (404/4xx/5xx clasificables por el
        adapter sin romper la frontera R10.1).
        """
        return (
            https_handler,
            _RejectRedirectHandler(),
            urllib.request.HTTPDefaultErrorHandler(),
            urllib.request.HTTPErrorProcessor(),
        )

    def get_json(
        self,
        url: str,
        *,
        connect_timeout_s: float,
        read_timeout_s: float,
        max_response_bytes: int,
        max_json_depth: int,
    ) -> dict[str, object]:
        """GET HTTPS sobre un host del allowlist; devuelve el JSON parseado.

        Valida scheme/host, fuerza TLS, acota el cuerpo en streaming y parsea con
        `safe_json_loads`. Cualquier anomalia => `NetworkUnverifiableError`. El
        `timeout` de socket es `connect_timeout_s + read_timeout_s` (urllib usa un
        unico timeout por operacion de socket).
        """
        self._validate_url(url)
        # El scheme/host ya fueron restringidos a https + allowlist por `_validate_url`
        # y el opener carece de handlers para file:/ftp:/etc.; S310 es un falso positivo.
        request = urllib.request.Request(  # noqa: S310
            url, method="GET", headers=_safe_request_headers()
        )
        timeout = connect_timeout_s + read_timeout_s
        body = self._read_response(request, timeout, max_response_bytes)
        parsed = safe_json_loads(body, max_json_depth)
        if not isinstance(parsed, dict):
            raise NetworkUnverifiableError("la respuesta JSON no es un objeto")
        return parsed

    @staticmethod
    def _validate_url(url: str) -> None:
        """Rechaza scheme!=https o host fuera del allowlist (NFR-Seg.3).

        `urlsplit` puede lanzar `ValueError` ante una URL malformada (p.ej. un
        literal IPv6 sin cerrar como 'https://[fe80::1/x'). Defensa en profundidad:
        el cliente HTTP no confia en su llamante y degrada cualquier URL imparseable
        como dependencia no verificable, jamas la deja escapar como ValueError crudo
        (que abortaria el lote en vez de marcar la dep unverifiable).
        """
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            raise NetworkUnverifiableError("URL malformada rechazada") from exc
        if not _is_allowed(parts.scheme, parts.hostname or ""):
            raise NetworkUnverifiableError("URL fuera de la allowlist https rechazada")

    def _read_response(
        self,
        request: urllib.request.Request,
        timeout: float,
        max_response_bytes: int,
    ) -> bytes:
        """Abre la conexion, valida cabeceras y lee el cuerpo de forma acotada."""
        try:
            with self._opener.open(request, timeout=timeout) as response:
                _reject_excessive_content_length(response, max_response_bytes)
                encoding = response.headers.get("Content-Encoding", "")
                return _read_capped_body(response, encoding, max_response_bytes)
        except NetworkUnverifiableError:
            raise
        except urllib.error.HTTPError as exc:
            # 5xx => transitorio (reintentable); 4xx => permanente. El `status_code`
            # deja al adapter mapear 404 -> NOT_FOUND y 4xx!=404 -> UNVERIFIABLE sin
            # romper la frontera R10.1 (jamas expone el cuerpo de la respuesta).
            raise NetworkUnverifiableError(
                f"respuesta HTTP {exc.code} no verificable",
                status_code=exc.code,
                is_transient=_HTTP_SERVER_ERROR_MIN <= exc.code <= _HTTP_SERVER_ERROR_MAX,
            ) from exc
        except (
            urllib.error.URLError,
            OSError,
            ValueError,
            zlib.error,
            http.client.HTTPException,
        ) as exc:
            # Invariante de seguridad (T14/NFR-Seg.3-4): CUALQUIER anomalia de red,
            # de descompresion (zlib.error: stream corrupto/truncado/raw-deflate, que
            # hereda de Exception, NO de OSError/ValueError) o del protocolo HTTP
            # (http.client.HTTPException: IncompleteRead por cuerpo truncado, InvalidURL
            # por puerto no numerico) debe degradarse a NetworkUnverifiableError, nunca
            # escapar cruda. Es por-dependencia y no aborta el lote (degradacion segura
            # R2.5/NFR-Degr.1); jamas expone payload ni stacktrace de zlib (R6.5).
            # Un fallo de TRANSPORTE (timeout, conexion caida/reset) es transitorio y
            # reintentable; el adapter lo distingue por `is_transient`.
            raise NetworkUnverifiableError(
                f"fallo de red no verificable: {type(exc).__name__}",
                is_transient=_is_transient_transport_error(exc),
            ) from exc


def _is_transient_transport_error(exc: Exception) -> bool:
    """True si el fallo de transporte es reintentable (timeout o conexion caida).

    Transitorio: `TimeoutError` (incluye `socket.timeout`), `ConnectionError`
    (reset/refused/aborted) y un `URLError` que envuelve cualquiera de ellos. NO
    transitorio (degradacion conservadora, no se reintenta a ciegas): cuerpos
    truncados, descompresion corrupta (`zlib.error`), JSON/URL malformados
    (`ValueError`) u otras `HTTPException`, que no se resuelven reintentando.
    """
    reason = getattr(exc, "reason", None)
    candidate = reason if isinstance(reason, BaseException) else exc
    return isinstance(candidate, (TimeoutError, ConnectionError))


def _safe_request_headers() -> dict[str, str]:
    """Cabeceras de la peticion: identity para no invitar bombas de descompresion."""
    return {"Accept": "application/json", "Accept-Encoding": "identity"}


def _reject_excessive_content_length(response: object, max_response_bytes: int) -> None:
    """Si `Content-Length` declara mas que la cota, aborta antes de leer el cuerpo."""
    raw = getattr(response, "headers", None)
    declared = raw.get("Content-Length") if raw is not None else None
    if declared is None:
        return
    try:
        length = int(declared)
    except (TypeError, ValueError) as exc:
        raise NetworkUnverifiableError("Content-Length no numerico rechazado") from exc
    if length < 0 or length > max_response_bytes:
        raise NetworkUnverifiableError("Content-Length excesivo rechazado")


def _read_capped_body(response: object, encoding: str, max_response_bytes: int) -> bytes:
    """Lee el cuerpo en chunks abortando si supera la cota; descomprime si aplica.

    La cota `max_response_bytes` aplica al tamano DESCOMPRIMIDO (la salida real). La
    descompresion se hace incrementalmente con `max_length` (ver `_inflate_capped`),
    de modo que una bomba de descompresion se aborta a mitad de stream SIN llegar a
    materializar el payload expandido completo (NFR-Seg.4).
    """
    decompressor = _make_decompressor(encoding)
    out = bytearray()
    read = response.read  # type: ignore[attr-defined]
    while True:
        chunk = read(_CHUNK_BYTES)
        if not chunk:
            break
        if decompressor is None:
            _extend_capped(out, chunk, max_response_bytes)
        else:
            _inflate_capped(decompressor, chunk, out, max_response_bytes)
    if decompressor is not None:
        _extend_capped(out, decompressor.flush(), max_response_bytes)
    return bytes(out)


def _inflate_capped(
    decompressor: zlib._Decompress,
    chunk: bytes,
    out: bytearray,
    max_response_bytes: int,
) -> None:
    """Descomprime `chunk` acotando la salida por llamada con `max_length`.

    Pide a lo sumo `restante + 1` bytes por iteracion: el `+1` fuerza a `_extend_capped`
    a detectar el desbordamiento y abortar antes de materializar la bomba completa. El
    resto sin consumir queda en `unconsumed_tail` y se procesa en la siguiente vuelta.
    """
    pending = chunk
    while pending:
        allowed = max_response_bytes - len(out) + 1  # +1 para detectar el exceso
        produced = decompressor.decompress(pending, allowed)
        _extend_capped(out, produced, max_response_bytes)
        pending = decompressor.unconsumed_tail
        if not produced and not pending:
            break


def _make_decompressor(encoding: str) -> zlib._Decompress | None:
    """Crea el descompresor incremental segun `Content-Encoding`, o None si identity.

    Rechaza codificaciones desconocidas en vez de devolver bytes sin verificar.
    """
    normalized = encoding.strip().lower()
    if normalized in ("", "identity"):
        return None
    if normalized == "gzip":
        return zlib.decompressobj(_GZIP_WBITS)
    if normalized == "deflate":
        return zlib.decompressobj(_DEFLATE_WBITS)
    raise NetworkUnverifiableError(f"Content-Encoding '{normalized}' no soportado rechazado")


def _extend_capped(out: bytearray, piece: bytes, max_response_bytes: int) -> None:
    """Anade `piece` a `out` abortando si el acumulado supera `max_response_bytes`."""
    if len(out) + len(piece) > max_response_bytes:
        raise NetworkUnverifiableError("cuerpo de respuesta supera el maximo permitido")
    out.extend(piece)
