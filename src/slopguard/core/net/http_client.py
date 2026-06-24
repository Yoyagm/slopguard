"""Cliente HTTPS endurecido sobre `urllib` (stdlib, cero deps) — ADR-03 / NFR-Seg.3-4.

`SecureHttpClient.get_json`/`post_json` realizan una peticion con:
- TLS verificado por `ssl.create_default_context()` (certificado y hostname),
  SIN ninguna opcion para desactivarlo.
- Allowlist EFECTIVA de host (`ALLOWED_HOSTS` base `{pypi.org}` mas el `extra_allowed_hosts`
  por instancia, ADR-09) y scheme `https` obligatorio, validados tanto en la URL inicial
  como en cualquier redireccion. El mismo conjunto efectivo gobierna la URL inicial Y el
  redirect handler (fix SSRF §3.3): el handler ya no consulta la global, sino el conjunto
  inyectado en construccion.
- `OpenerDirector` construido a mano que NO incluye el redirect handler por defecto;
  en su lugar usa uno propio que RECHAZA cualquier `Location` cross-scheme/cross-host
  (cualquier anomalia => `NetworkUnverifiableError`).
- Rechazo de `Content-Length` excesivo, lectura STREAMING acotada por
  `max_response_bytes` (aborta si excede) y descompresion incremental con cota
  (no se anuncia gzip; si llega, se descomprime con tope de salida).
- Parseo via `safe_json_loads(max_json_depth)` (anti JSON-bomb).

Ante CUALQUIER anomalia se lanza `NetworkUnverifiableError` sin exponer el payload
completo ni stacktraces crudos (NFR-Seg.3-4). La URL la construye el adapter/fuente y
solo contiene el nombre del paquete, jamas contenido del manifiesto (NFR-Priv.1).
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.request
import zlib
from typing import TYPE_CHECKING, Final
from urllib.parse import SplitResult, urlsplit

from ..errors import NetworkUnverifiableError
from .safe_json import safe_json_loads

if TYPE_CHECKING:
    from collections.abc import Iterable

# Allowlist BASE de hosts permitidos y unico scheme aceptado (NFR-Seg.3). La base
# permanece anclada a {pypi.org} (guardia estatico ADR-09): los hosts de Capa 3
# (api.osv.dev / depscope.dev) entran solo via `extra_allowed_hosts` por instancia,
# nunca en esta constante.
ALLOWED_HOSTS: Final[frozenset[str]] = frozenset({"pypi.org"})
_ALLOWED_SCHEME: Final[str] = "https"

# Label LDH (letras/digitos/guion) de un FQDN; un host valido tiene >=2 labels y el
# TLD no es puramente numerico (eso seria una IPv4 disfrazada). Charset acotado para
# el predicado anti-SSRF `_is_valid_https_host` (§3.6).
_HOST_LABEL_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERIC_LABEL_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9]+$")
# Un FQDN valido tiene al menos dominio + TLD (2 labels): nombres de un solo label
# (intranet/`host`) se rechazan como no-FQDN (anti-SSRF a host interno, §3.6).
_MIN_FQDN_LABELS: Final[int] = 2

# Hosts internos/sensibles que NUNCA deben aceptarse como destino https (anti-SSRF a
# servicio interno; la metadata de cloud 169.254.169.254 ya cae por ser IP literal).
_FORBIDDEN_HOST_NAMES: Final[frozenset[str]] = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)

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
# Rate limit: transitorio y reintentable (R1.7). Un 429 debe reintentarse y, tras
# agotar el presupuesto, degradar a UNVERIFIABLE (nunca un falso CLEAN, §3.3).
_HTTP_RATE_LIMIT: Final[int] = 429


def _is_allowed(scheme: str, host: str, allowed_hosts: frozenset[str] | None = None) -> bool:
    """True si el destino usa https y un host de la allowlist EFECTIVA (case-insensitive).

    `allowed_hosts=None` cae a la constante base `ALLOWED_HOSTS` (lectura dinamica del
    modulo, para respetar parcheo de tests); una instancia de `SecureHttpClient` pasa su
    conjunto EFECTIVO (`ALLOWED_HOSTS | extra_allowed_hosts`) para que la URL inicial y el
    redirect handler validen contra el MISMO conjunto (fix SSRF §3.3, ADR-09).
    """
    effective = ALLOWED_HOSTS if allowed_hosts is None else allowed_hosts
    return scheme.lower() == _ALLOWED_SCHEME and host.lower() in effective


def _reject_port_and_userinfo(parts: SplitResult) -> None:
    """Rechaza puerto explicito y userinfo de una URL ya parseada (A10 SSRF, defecto-deniega).

    `urlsplit().hostname` descarta el puerto y el `user:pass@`, asi que sin este chequeo una URL
    como `https://pypi.org:1/x` o `https://user:pass@api.osv.dev/x` pasaria la allowlist por el
    host desnudo. Se rechaza ANTES de consultar `_is_allowed`. Acceder a `parts.port` puede lanzar
    `ValueError` (puerto no numerico); el caller lo captura y degrada a URL malformada.

    Es funcion modulo-nivel (no metodo) para que el harness de pruebas pueda parchearla cuando
    levanta un servidor loopback con puerto efimero (necesidad tecnica de test), igual que parchea
    `_is_allowed`; en produccion los destinos (`pypi.org`/`api.osv.dev`/`depscope.dev`) jamas llevan
    puerto ni userinfo.
    """
    if parts.port is not None:
        raise NetworkUnverifiableError("puerto explicito en la URL rechazado")
    if parts.username is not None or parts.password is not None:
        raise NetworkUnverifiableError("userinfo en la URL rechazado")


def _is_valid_https_host(host: str) -> bool:
    """True si `host` es un FQDN https seguro: ni IP, ni localhost, ni puerto/path/userinfo.

    Predicado anti-SSRF a host interno (§3.6, ADR-09). RECHAZA: cadena vacia; literal IP
    v4/v6 (incl. metadata 169.254.169.254 y loopback 127.0.0.1); `localhost` y variantes;
    userinfo (`@`), puerto (`:`), path/query/fragment (`/`,`?`,`#`) o esquema embebido
    (`//`) —cualquier separador delata que no es un host desnudo—; labels fuera de `[a-z0-9-]`;
    y no-FQDN (menos de 2 labels o TLD puramente numerico, que seria una IPv4 disfrazada).
    """
    candidate = host.strip().lower()
    if not candidate or candidate in _FORBIDDEN_HOST_NAMES:
        return False
    if any(sep in candidate for sep in ("@", ":", "/", "?", "#", " ")):
        return False
    if _is_ip_literal(candidate):
        return False
    labels = candidate.split(".")
    if len(labels) < _MIN_FQDN_LABELS or _NUMERIC_LABEL_RE.match(labels[-1]):
        return False
    return all(_HOST_LABEL_RE.match(label) for label in labels)


def _is_ip_literal(host: str) -> bool:
    """True si `host` es una direccion IP literal (v4 o v6), incluso entre corchetes."""
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler que solo valida `Location` contra la allowlist EFECTIVA https.

    Recibe en construccion el conjunto EFECTIVO de la instancia (`allowed_hosts`); si es
    `None` cae a la global (retro-compat con el opener del Hito 1 y el parcheo de tests).
    Cualquier `Location` —aun dentro de la allowlist— se RECHAZA: la politica es "no se
    sigue ninguna redireccion"; el conjunto efectivo solo distingue el mensaje de error
    (destino no permitido vs. redireccion inesperada). Reemplaza al handler por defecto
    de urllib para no seguir redirecciones cross-scheme/cross-host (SSRF, fix §3.3).
    """

    def __init__(self, allowed_hosts: frozenset[str] | None = None) -> None:
        """Guarda el conjunto EFECTIVO de la instancia (None => global, retro-compat)."""
        super().__init__()
        self._allowed_hosts = allowed_hosts

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
        if not _is_allowed(parts.scheme, parts.hostname or "", self._allowed_hosts):
            raise NetworkUnverifiableError("redireccion a destino no permitido rechazada")
        raise NetworkUnverifiableError("redireccion inesperada de la fuente rechazada")


class SecureHttpClient:
    """Cliente HTTPS endurecido: allowlist, TLS verificado, sin redirects, streaming."""

    def __init__(self, *, extra_allowed_hosts: frozenset[str] = frozenset()) -> None:
        """Construye un opener minimo con TLS verificado y redirect handler propio.

        La allowlist EFECTIVA = `ALLOWED_HOSTS` (base anclada `{pypi.org}`) | `extra_allowed_hosts`
        (los hosts que la fuente de threat-intel necesita: osv => {api.osv.dev}; watchlist =>
        {depscope.dev} solo si activa, ADR-09). El conjunto efectivo se inyecta al redirect
        handler para que URL inicial y redirecciones validen contra el MISMO conjunto (fix SSRF).

        DEFENSA EN PROFUNDIDAD (el cliente HTTP no confia en su llamante, ADR-09): cada host de
        `extra_allowed_hosts` se valida con `_is_valid_https_host` ANTES de admitirlo en la
        allowlist efectiva. Aunque `config._validate_host_field` ya valida los hosts de Capa 3
        (dominio cerrado), el cliente NO confia en que esa validacion haya corrido: un host
        inyectado que sea IP/localhost/userinfo/puerto/path/no-FQDN se rechaza aqui mismo con
        `ValueError`, de modo que la allowlist efectiva NUNCA puede contener un destino interno
        aunque un refactor de config dejara de validarlo. Es la unica fuente de verdad ACTIVA de
        este predicado en `net` (config tiene su propia copia para emitir `InvalidConfigError`).
        """
        for host in extra_allowed_hosts:
            if not _is_valid_https_host(host):
                raise ValueError(f"host inyectado no es un FQDN https valido: {host!r}")
        self._allowed_hosts: Final[frozenset[str]] = ALLOWED_HOSTS | extra_allowed_hosts
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        https_handler = urllib.request.HTTPSHandler(context=context)
        self._opener = urllib.request.OpenerDirector()
        for handler in self._safe_handlers(https_handler, self._allowed_hosts):
            self._opener.add_handler(handler)

    @staticmethod
    def _safe_handlers(
        https_handler: urllib.request.HTTPSHandler,
        allowed_hosts: frozenset[str] = ALLOWED_HOSTS,
    ) -> Iterable[urllib.request.BaseHandler]:
        """Conjunto minimo de handlers: TLS, redirect propio y procesado de errores.

        Deliberadamente NO incluye proxy ni el redirect handler por defecto de
        urllib, para no seguir redirecciones no validadas (ADR-03 / NFR-Seg.3). El
        `_RejectRedirectHandler` recibe el conjunto EFECTIVO `allowed_hosts` (fix SSRF
        §3.3): las redirecciones se validan contra la MISMA allowlist por-instancia que
        la URL inicial, no contra la global.

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
            _RejectRedirectHandler(allowed_hosts),
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
        return _parse_json_object(body, max_json_depth)

    def post_json(  # noqa: PLR0913 (firma del contrato §3.3: url+body+4 limites kw-only)
        self,
        url: str,
        body: dict[str, object],
        *,
        connect_timeout_s: float,
        read_timeout_s: float,
        max_response_bytes: int,
        max_json_depth: int,
    ) -> dict[str, object]:
        """POST HTTPS con cuerpo JSON sobre un host de la allowlist EFECTIVA; devuelve el JSON.

        Mismas defensas que `get_json`: scheme=https obligatorio, host del allowlist efectivo
        (URL inicial Y redirecciones, fix SSRF), TLS verificado no desactivable, sin redirect
        cross-scheme/host, Content-Length acotado, lectura streaming <= `max_response_bytes`,
        descompresion incremental con cota y `safe_json_loads(max_json_depth)`. El `body` se
        serializa con `json.dumps` (separadores compactos, `ensure_ascii=True` para escapar
        cualquier no-ASCII/CRLF) y se envia como bytes UTF-8. El caller debe pasar SOLO datos
        ya validados/saneados (p.ej. nombres por charset, §3.2): el cliente no inspecciona el
        contenido. Cualquier anomalia => `NetworkUnverifiableError` (con `status_code` e
        `is_transient` para clasificar 5xx/429 como transitorios, §3.3).
        """
        self._validate_url(url)
        payload = _encode_json_body(body)
        # scheme/host restringidos a https + allowlist por `_validate_url`; S310 falso positivo.
        request = urllib.request.Request(  # noqa: S310
            url, data=payload, method="POST", headers=_safe_post_headers()
        )
        timeout = connect_timeout_s + read_timeout_s
        response_body = self._read_response(request, timeout, max_response_bytes)
        return _parse_json_object(response_body, max_json_depth)

    def _validate_url(self, url: str) -> None:
        """Rechaza scheme!=https o host fuera del allowlist EFECTIVO de la instancia (NFR-Seg.3).

        Valida contra `self._allowed_hosts` (base anclada | extra por instancia, ADR-09); si la
        instancia no lo expone —p.ej. un test que parchea `__init__`— cae a la global, igual que
        el redirect handler sin conjunto inyectado (retro-compat Hito 1).

        `urlsplit` puede lanzar `ValueError` ante una URL malformada (p.ej. un literal IPv6 sin
        cerrar como 'https://[fe80::1/x'). Defensa en profundidad: el cliente HTTP no confia en su
        llamante y degrada cualquier URL imparseable como dependencia no verificable, jamas la deja
        escapar como ValueError crudo (que abortaria el lote en vez de marcar la dep unverifiable).

        A10 SSRF / defecto-deniega temprano: `urlsplit().hostname` DESCARTA el puerto y el userinfo,
        de modo que `https://pypi.org:1/x` o `https://user:pass@api.osv.dev/x` pasarian la allowlist
        por el host desnudo y el cliente intentaria conectar al puerto/host indicado (fallando solo
        de forma incidental por transporte). La politica declarada exige RECHAZAR explicitamente,
        en la capa de validacion, todo puerto explicito y todo userinfo ANTES de consultar la
        allowlist; no se delega ese rechazo a que la conexion falle.
        """
        try:
            parts = urlsplit(url)
            _reject_port_and_userinfo(parts)
        except ValueError as exc:
            raise NetworkUnverifiableError("URL malformada rechazada") from exc
        allowed = getattr(self, "_allowed_hosts", None)
        if not _is_allowed(parts.scheme, parts.hostname or "", allowed):
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
            # 5xx y 429 => transitorios (reintentables); resto de 4xx => permanente. El
            # `status_code` deja al adapter/fuente mapear 404 -> NOT_FOUND y 4xx!=404 ->
            # UNVERIFIABLE sin romper la frontera R10.1 (jamas expone el cuerpo). Un 429
            # (rate limit) se reintenta y, tras agotar el presupuesto, degrada a
            # UNVERIFIABLE, nunca CLEAN (R1.7, §3.3).
            raise NetworkUnverifiableError(
                f"respuesta HTTP {exc.code} no verificable",
                status_code=exc.code,
                is_transient=_is_transient_http_status(exc.code),
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


def _is_transient_http_status(code: int) -> bool:
    """True si un status HTTP >=400 es transitorio (reintentable): 5xx o 429 (R1.7)."""
    if code == _HTTP_RATE_LIMIT:
        return True
    return _HTTP_SERVER_ERROR_MIN <= code <= _HTTP_SERVER_ERROR_MAX


def _parse_json_object(body: bytes, max_json_depth: int) -> dict[str, object]:
    """Parsea `body` con `safe_json_loads` y exige que el top-level sea un objeto JSON.

    Reusado por `get_json` y `post_json`. Cualquier no-objeto (lista, escalar) o anomalia
    de profundidad/parseo => `NetworkUnverifiableError` (sin exponer el payload, NFR-Seg.4).
    """
    parsed = safe_json_loads(body, max_json_depth)
    if not isinstance(parsed, dict):
        raise NetworkUnverifiableError("la respuesta JSON no es un objeto")
    return parsed


def _encode_json_body(body: dict[str, object]) -> bytes:
    """Serializa `body` a bytes UTF-8 con separadores compactos y `ensure_ascii=True`.

    `ensure_ascii=True` garantiza que ningun carac. de control/CRLF/no-ASCII viaje crudo en el
    cuerpo (se escapa como \\uXXXX). El caller (la fuente) ya valido los datos por charset
    (§3.2); aqui solo se serializa de forma determinista. Un `body` no serializable (objeto no
    JSON) se degrada a `NetworkUnverifiableError`, nunca escapa como `TypeError` crudo.
    """
    try:
        return json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NetworkUnverifiableError("cuerpo JSON de la peticion no serializable") from exc


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


def _safe_post_headers() -> dict[str, str]:
    """Cabeceras del POST JSON: Content-Type explicito + identity (anti bomba)."""
    return {
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Content-Type": "application/json",
    }


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
