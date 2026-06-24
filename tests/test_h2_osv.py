"""Suite de la fuente OSV (H2-T06 / RISK-H2-1/2): parseo defensivo del feed `querybatch`,
anti-envenenamiento de IDs `MAL-*`, degradacion segura, privacidad del request y cache por-nombre.

Metodologia (feed externo NO confiable, threat-detection supply-chain T1195.001):

- **Parseo defensivo (RISK-H2-2):** toda respuesta OSV se trata como hostil. Un `len(results)!=
  len(queries)` por chunk degrada TODO el lote a UNVERIFIABLE, jamas CLEAN. Un `next_page_token`
  degrada ese nombre a UNVERIFIABLE (Hito 2 no pagina). Truncado/JSON-bomb/no-objeto => el
  transporte ya degrada a `NetworkUnverifiableError` => el lote queda UNVERIFIABLE (no CLEAN).
- **Anti-envenenamiento:** el `id` se SANEA (ANSI/C0-C1/CRLF) y se valida `^MAL-[0-9A-Za-z-]+$`
  acotado en longitud ANTES de reconstruir la URL `https://osv.dev/vulnerability/<id>`; un id
  envenenado nunca se refleja en la URL ni produce un MALICIOUS falso. IDs no-`MAL-` se ignoran.
- **Degradacion (R1.6/R1.7):** 429/5xx/timeout agotan reintentos => UNVERIFIABLE; 4xx!=429 (404,
  422) corta sin reintentar => UNVERIFIABLE. NUNCA un falso CLEAN.
- **Privacidad (NFR-Priv.1):** el body lleva SOLO `{ecosystem:"PyPI", name}` validado por charset;
  jamas version/manifiesto/ruta. Un nombre con charset invalido se EXCLUYE del POST => UNVERIFIABLE.
- **Cache (§2.5):** hit vigente evita la red; UNVERIFIABLE no se cachea; un blob con esquema/nombre/
  estado/`kind`/`source` manipulado se trata como entrada no confiable => miss => refetch.

Dos niveles, igual que `test_h2_net_post.py`:

1. **Asertos directos** de las funciones puras de parseo/validacion (rapidos, sin red): cubren la
   logica de envenenamiento y desalineamiento sin depender de sockets.
2. **Servidor HTTP local malicioso** (`_OsvServer`) que ejercita el camino REAL de `OsvSource`
   (urllib, streaming, reintentos): se inyecta `_http`/`_query_url`/`_cache` tras construir la
   fuente (patron documentado en el docstring de `OsvSource`), neutralizando el rechazo de puerto
   SOLO para el loopback (como el harness del Hito 1), sin tocar el endurecimiento de produccion.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

import pytest

from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config
from slopguard.core.net import http_client as hc
from slopguard.core.net.http_client import SecureHttpClient
from slopguard.core.threatintel import osv
from slopguard.core.threatintel.osv import OsvSource
from slopguard.core.threatintel.source import MaliceState

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_OSV_HOSTS = frozenset({"api.osv.dev"})


def _config(**overrides: Any) -> Config:
    """Config base con overrides; los timeouts cortos mantienen los tests rapidos."""
    base: dict[str, Any] = {
        "connect_timeout_s": 2.0,
        "read_timeout_s": 2.0,
        "osv_timeout_total_por_lote_s": 2.0,
        "osv_reintentos": 1,
    }
    base.update(overrides)
    return Config(**base)


# --------------------------------------------------------------------------- #
# NIVEL 1 - Asertos directos de las funciones puras (sin red).
# --------------------------------------------------------------------------- #
# Validacion de charset del nombre antes del POST (R1.8, defensa en profundidad).


@pytest.mark.parametrize("name", ["bioql", "requests", "a", "django-rest", "x0", "a-b-c", "z9"])
def test_is_valid_osv_name_acepta_pep503(name: str) -> None:
    assert osv._is_valid_osv_name(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "",  # vacio
        "Requests",  # mayuscula (no normalizado)
        "req_uests",  # underscore (no colapsado)
        "req.uests",  # punto
        "req uests",  # espacio
        "req\r\nuests",  # CRLF inyectado (sobrevive a normalize_name)
        "req\x1b[31mhack",  # ANSI embebido
        "-leading",  # empieza en guion
        "trailing-",  # termina en guion
        "café",  # no-ASCII
        "x" * 101,  # excede 100 chars
    ],
)
def test_is_valid_osv_name_rechaza_charset_no_seguro(name: str) -> None:
    assert osv._is_valid_osv_name(name) is False


# Reconstruccion del Advisory: id saneado + validado, URL reconstruida (no reflejada).


def test_advisory_from_id_mal_valido_reconstruye_url() -> None:
    advisory = osv._advisory_from_id("MAL-2025-47868")
    assert advisory is not None
    assert advisory.id == "MAL-2025-47868"
    assert advisory.kind == "malicious"
    assert advisory.source == "osv"
    # La URL se RECONSTRUYE del id validado, nunca se refleja una url del feed.
    assert advisory.url == "https://osv.dev/vulnerability/MAL-2025-47868"


def test_advisory_from_id_sanea_ansi_crlf_antes_de_validar() -> None:
    # Un id con ANSI/CRLF se SANEA primero; el residuo "MAL-1" valido reconstruye la URL
    # limpia: ningun byte de control sobrevive en `Advisory.url` (anti inyeccion de terminal).
    advisory = osv._advisory_from_id("MAL\x1b[31m-1\r\n")
    assert advisory is not None
    assert "\x1b" not in advisory.url and "\r" not in advisory.url and "\n" not in advisory.url
    assert advisory.url == "https://osv.dev/vulnerability/MAL-1"


@pytest.mark.parametrize(
    "raw_id",
    [
        "GHSA-xxxx-yyyy-zzzz",  # advisory no malicioso (R1.3)
        "CVE-2025-0001",  # CVE no es MAL-
        "PYSEC-2025-1",  # PYSEC no es MAL-
        "mal-2025-1",  # minuscula: prefijo case-sensitive
        "MAL_2025_1",  # underscore fuera del charset
        "MAL-2025/../etc",  # path traversal en el id
        "MAL-" + "x" * 200,  # id inflado por encima de la cota dura
        "",  # vacio
        "MAL-",  # sin sufijo
    ],
)
def test_advisory_from_id_descarta_no_mal_y_envenenados(raw_id: str) -> None:
    assert osv._advisory_from_id(raw_id) is None


@pytest.mark.parametrize("raw_id", [None, 123, ["MAL-1"], {"id": "MAL-1"}])
def test_advisory_from_id_no_string_es_none(raw_id: object) -> None:
    assert osv._advisory_from_id(raw_id) is None


# Reensamblado posicional de la respuesta `querybatch` (results[i] <-> names[i]).


def test_parse_batch_response_mal_es_malicious_con_advisory() -> None:
    names = ["bioql", "requests"]
    payload: dict[str, object] = {"results": [{"vulns": [{"id": "MAL-2025-47868"}]}, {}]}
    resolved = osv._parse_batch_response(payload, names)
    assert resolved["bioql"].state is MaliceState.MALICIOUS
    assert [a.id for a in resolved["bioql"].advisories] == ["MAL-2025-47868"]
    # El segundo nombre, con results[1]={} (sin vulns), es CLEAN.
    assert resolved["requests"].state is MaliceState.CLEAN


def test_parse_batch_response_no_mal_ids_ignorados_es_clean() -> None:
    names = ["pkg"]
    payload: dict[str, object] = {
        "results": [{"vulns": [{"id": "GHSA-aaaa"}, {"id": "CVE-2025-1"}]}]
    }
    resolved = osv._parse_batch_response(payload, names)
    # Solo IDs no-MAL => CLEAN (R1.3/R1.4): no se inventa malicia.
    assert resolved["pkg"].state is MaliceState.CLEAN


def test_parse_batch_response_len_mismatch_es_unverifiable_no_clean() -> None:
    # RISK-H2-2: results mas cortos que queries => TODO el chunk UNVERIFIABLE, jamas CLEAN.
    names = ["a", "b", "c"]
    payload: dict[str, object] = {"results": [{}, {}]}  # falta una entrada
    resolved = osv._parse_batch_response(payload, names)
    assert {r.state for r in resolved.values()} == {MaliceState.UNVERIFIABLE}
    assert set(resolved) == set(names)  # cobertura total: ningun nombre se pierde


def test_parse_batch_response_results_no_lista_es_unverifiable() -> None:
    # results de tipo inesperado (no lista) no se asume limpio: UNVERIFIABLE.
    resolved = osv._parse_batch_response({"results": {"a": 1}}, ["a"])
    assert resolved["a"].state is MaliceState.UNVERIFIABLE


def test_parse_batch_response_results_ausente_es_unverifiable() -> None:
    resolved = osv._parse_batch_response({}, ["a"])
    assert resolved["a"].state is MaliceState.UNVERIFIABLE


def test_parse_batch_response_next_page_token_degrada_ese_nombre() -> None:
    # Paginacion no resuelta en Hito 2: ese nombre se degrada a UNVERIFIABLE (no se asume limpio).
    names = ["a", "b"]
    payload: dict[str, object] = {"results": [{"next_page_token": "tok"}, {}]}
    resolved = osv._parse_batch_response(payload, names)
    assert resolved["a"].state is MaliceState.UNVERIFIABLE
    assert resolved["b"].state is MaliceState.CLEAN


@pytest.mark.parametrize("entry", [None, 42, "str", ["vulns"]])
def test_result_for_entry_no_dict_es_clean(entry: object) -> None:
    # Una entry no-dict (entrada hostil) se trata como sin advisories => CLEAN, sin crashear.
    assert osv._result_for_entry("pkg", entry).state is MaliceState.CLEAN


def test_extract_advisories_vulns_no_lista_es_vacio() -> None:
    assert osv._extract_advisories("no-soy-lista") == ()
    assert osv._extract_advisories(None) == ()
    # vulns con elementos no-dict se ignoran sin romper.
    assert osv._extract_advisories(["str", 1, {"id": "MAL-1"}]) == osv._extract_advisories(
        [{"id": "MAL-1"}]
    )


# --------------------------------------------------------------------------- #
# NIVEL 1 - Validacion del blob de cache (§2.5): entrada NO confiable del disco.
# --------------------------------------------------------------------------- #


def test_to_blob_no_persiste_url_solo_id_kind_source() -> None:
    # La url NO se persiste (se reconstruye al leer); el blob lleva solo campos de dominio.
    result = osv._parse_batch_response({"results": [{"vulns": [{"id": "MAL-1"}]}]}, ["pkg"])["pkg"]
    blob = osv._to_blob(result)
    assert blob == {
        "source": "osv",
        "ecosystem": "pypi",
        "name": "pkg",
        "state": "malicious",
        "advisories": [{"id": "MAL-1", "kind": "malicious", "source": "osv"}],
    }
    assert "url" not in blob["advisories"][0]  # type: ignore[index]


def _malicious_blob(name: str = "bioql") -> dict[str, object]:
    """Blob OSV `malicious` bien formado para `name` (un advisory MAL- coherente)."""
    return {
        "source": "osv",
        "ecosystem": "pypi",
        "name": name,
        "state": "malicious",
        "advisories": [{"id": "MAL-2025-1", "kind": "malicious", "source": "osv"}],
    }


def test_validate_osv_blob_malicious_reconstruye_url_desde_id() -> None:
    result = osv._validate_osv_blob(_malicious_blob(), "bioql")
    assert result is not None
    assert result.state is MaliceState.MALICIOUS
    # La url se RECONSTRUYE del id, no se confia en la del disco (que ni se persiste).
    assert result.advisories[0].url == "https://osv.dev/vulnerability/MAL-2025-1"


def test_validate_osv_blob_clean_es_clean() -> None:
    blob = {"source": "osv", "ecosystem": "pypi", "name": "ok", "state": "clean"}
    result = osv._validate_osv_blob(blob, "ok")
    assert result is not None and result.state is MaliceState.CLEAN


@pytest.mark.parametrize(
    ("mutate", "key", "value"),
    [
        ("set", "source", "evil"),  # source manipulado en el blob raiz
        ("set", "ecosystem", "npm"),  # ecosistema distinto
        ("set", "name", "otro"),  # nombre distinto del esperado (colision/manipulacion)
        ("set", "state", "unverifiable"),  # estado no cacheable en disco
        ("set", "state", "known_hallucination"),  # estado ajeno a OSV
    ],
)
def test_validate_osv_blob_rechaza_desviacion_de_esquema(
    mutate: str, key: str, value: str
) -> None:
    # Cualquier desviacion del contrato §2.5 => None (miss => refetch), nunca se confia.
    blob = _malicious_blob("bioql")
    assert mutate == "set"
    blob[key] = value
    assert osv._validate_osv_blob(blob, "bioql") is None


def test_validate_osv_blob_malicious_sin_advisory_valido_es_miss() -> None:
    # `malicious` sin ningun advisory MAL- valido es incoherente => miss.
    blob = _malicious_blob("bioql")
    blob["advisories"] = [{"id": "GHSA-x", "kind": "malicious", "source": "osv"}]
    assert osv._validate_osv_blob(blob, "bioql") is None


def test_validate_osv_blob_descarta_advisory_con_kind_source_manipulado() -> None:
    # §2.5 a la LETRA (finding amarillo): un advisory persistido cuyo `kind`/`source` no sea
    # exactamente malicious/osv se DESCARTA al leer (cuenta como ausente). Como el unico
    # advisory queda descartado, el blob `malicious` sin advisory valido => miss => refetch.
    for bad in ({"kind": "vuln"}, {"kind": "malicious", "source": "ghsa"}):
        blob = _malicious_blob("bioql")
        blob["advisories"] = [{"id": "MAL-1", "kind": "malicious", "source": "osv", **bad}]
        assert osv._validate_osv_blob(blob, "bioql") is None, f"no descarto {bad}"


def test_blob_vulns_filtra_por_kind_y_source() -> None:
    # `_blob_vulns` reduce a [{"id": ...}] SOLO las entradas con kind==malicious y source==osv.
    raw = [
        {"id": "MAL-1", "kind": "malicious", "source": "osv"},  # valido
        {"id": "MAL-2", "kind": "vuln", "source": "osv"},  # kind ajeno => descartada
        {"id": "MAL-3", "kind": "malicious", "source": "ghsa"},  # source ajeno => descartada
        "no-dict",  # estructura inesperada => ignorada sin crashear
    ]
    assert osv._blob_vulns(raw) == [{"id": "MAL-1"}]
    assert osv._blob_vulns("no-soy-lista") == []


# --------------------------------------------------------------------------- #
# NIVEL 1 - Cache por-nombre real (DiskCache en tmp): hit/miss/no-persistencia.
# --------------------------------------------------------------------------- #


def _cached_source(config: Config, tmp_path: Path, *, use_cache: bool = True) -> OsvSource:
    """OsvSource con la cache apuntada a `tmp_path` (sin red configurada todavia)."""
    source = OsvSource(config, use_cache=use_cache)
    source._cache = DiskCache(tmp_path, config.osv_ttl_cache_horas, enabled=use_cache)
    return source


def test_cache_hit_vigente_no_toca_la_red(tmp_path: Path) -> None:
    # Un blob MALICIOUS vigente en disco se resuelve SIN red: si la red se invocara, el
    # _http roto lanzaria; al no lanzarse, confirmamos que el hit corto-circuita el POST.
    config = _config()
    source = _cached_source(config, tmp_path)
    source._http = None  # type: ignore[assignment]  # si se usara la red, explotaria
    source._cache.put_blob("osv", "pypi:bioql", _malicious_blob("bioql"))
    result = source.query_batch(["bioql"])
    assert result["bioql"].state is MaliceState.MALICIOUS
    assert result["bioql"].advisories[0].id == "MAL-2025-1"


def test_cache_blob_corrupto_es_miss_no_crashea(tmp_path: Path) -> None:
    # Un blob con esquema desviado (source manipulado) => miss; sin red configurada, el nombre
    # cae a la rama de red (que aqui no existe). Verificamos que get_blob lo trata como miss.
    config = _config()
    source = _cached_source(config, tmp_path)
    # Inyecta un blob con cache_schema_version correcto pero source manipulado.
    source._cache.put_blob("osv", "pypi:bioql", {**_malicious_blob("bioql"), "source": "evil"})
    assert source._cached_result("bioql") is None


def test_cache_no_persiste_unverifiable(tmp_path: Path) -> None:
    # UNVERIFIABLE jamas se cachea (§2.5): un nombre con charset invalido nunca toca el disco.
    config = _config()
    source = _cached_source(config, tmp_path)
    source._http = None  # type: ignore[assignment]  # invalido no debe viajar a la red
    result = source.query_batch(["Bad_Name\r\n"])
    assert result["Bad_Name\r\n"].state is MaliceState.UNVERIFIABLE
    # Nada se escribio en disco para ese nombre.
    assert source._cached_result("Bad_Name\r\n") is None


# --------------------------------------------------------------------------- #
# NIVEL 2 - Servidor HTTP local malicioso: camino REAL de OsvSource (urllib).
# --------------------------------------------------------------------------- #


class _OsvHandler(BaseHTTPRequestHandler):
    """Sirve respuestas OSV por ruta (mentalidad pen-testing); registra el ultimo body."""

    last_body: bytes = b""
    hits: int = 0

    def do_POST(self) -> None:  # firma impuesta por BaseHTTPRequestHandler
        length = int(self.headers.get("Content-Length", "0") or "0")
        type(self).last_body = self.rfile.read(length) if length else b""
        type(self).hits += 1
        handler = _ROUTES.get(self.path)
        if handler is None:
            self._send_status(404)
            return
        handler(self)

    def _send_json(self, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, raw: bytes, *, declared_len: int | None = None) -> None:
        length = declared_len if declared_len is not None else len(raw)
        self.send_response(200)
        self.send_header("Content-Length", str(length))
        self.end_headers()
        self.wfile.write(raw)

    def _send_status(self, code: int) -> None:
        body = b'{"error":"x"}'
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        """Silencia el log del servidor para no contaminar la salida de pytest."""


def _route_malicious(h: _OsvHandler) -> None:
    h._send_json({"results": [{"vulns": [{"id": "MAL-2025-47868"}, {"id": "GHSA-x"}]}]})


def _route_clean(h: _OsvHandler) -> None:
    h._send_json({"results": [{}]})


def _route_poisoned_id(h: _OsvHandler) -> None:
    # Feed envenenado: id con ANSI/CRLF y un id no-MAL. El cliente sanea+valida: el ANSI
    # produce "MAL-9" limpio (reconstruido) y el no-MAL se ignora. Nunca refleja crudo.
    h._send_json({"results": [{"vulns": [{"id": "MAL\x1b[31m-9\r\n"}, {"id": "evil-$(rm)"}]}]})


def _route_mismatch(h: _OsvHandler) -> None:
    # results mas corto que queries (se pediran 2 nombres): RISK-H2-2 => lote UNVERIFIABLE.
    h._send_json({"results": [{}]})


def _route_not_list(h: _OsvHandler) -> None:
    h._send_json({"results": "no-soy-lista"})


def _route_truncated(h: _OsvHandler) -> None:
    # Declara mas bytes de los que envia: IncompleteRead => transporte degrada a no-verificable.
    h._send_raw(b'{"results": [', declared_len=4096)


def _route_429(h: _OsvHandler) -> None:
    h._send_status(429)


def _route_503(h: _OsvHandler) -> None:
    h._send_status(503)


def _route_404(h: _OsvHandler) -> None:
    h._send_status(404)


_ROUTES = {
    "/malicious": _route_malicious,
    "/clean": _route_clean,
    "/poisoned": _route_poisoned_id,
    "/mismatch": _route_mismatch,
    "/not-list": _route_not_list,
    "/truncated": _route_truncated,
    "/rate-limited": _route_429,
    "/server-error": _route_503,
    "/not-found": _route_404,
}


class _OsvServer:
    """Levanta `_OsvHandler` en 127.0.0.1 (puerto efimero) en un hilo daemon."""

    def __init__(self) -> None:
        _OsvHandler.last_body = b""
        _OsvHandler.hits = 0
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _OsvHandler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self) -> _OsvServer:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def url(self, path: str) -> str:
        host, port = self._httpd.server_address[0], self._httpd.server_address[1]
        return f"http://{host!s}:{port!s}{path}"


@pytest.fixture
def osv_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[_OsvServer]:
    """Servidor OSV local + permisos de allowlist/puerto para http://127.0.0.1 SOLO en el test.

    El loopback usa puerto efimero (necesidad tecnica); se neutralizan `_is_allowed` y
    `_reject_port_and_userinfo` como en el harness del Hito 1, sin tocar el endurecimiento de
    produccion (TLS, allowlist real, parseo defensivo, charset y reconstruccion de URL intactos).
    """

    def allow_local(
        scheme: str, host: str, allowed_hosts: frozenset[str] | None = None
    ) -> bool:
        return scheme.lower() == "http" and host == "127.0.0.1"

    monkeypatch.setattr(hc, "_is_allowed", allow_local)
    monkeypatch.setattr(hc, "_reject_port_and_userinfo", lambda _parts: None)
    with _OsvServer() as server:
        yield server


def _wired_source(
    server: _OsvServer, path: str, tmp_path: Path, config: Config, *, use_cache: bool = True
) -> OsvSource:
    """OsvSource con `_http` (HTTPHandler local), `_query_url` al servidor y `_cache` en tmp.

    Reusa el patron 'inyectable tras construccion' documentado en `OsvSource`: el endurecimiento
    de produccion (TLS/allowlist/redirect) sigue intacto en el cliente; solo se le anade el
    HTTPHandler para alcanzar el loopback http, igual que el harness de `test_h2_net_post.py`.
    """
    source = OsvSource(config, use_cache=use_cache)
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOSTS)
    client._opener.add_handler(urllib.request.HTTPHandler())
    source._http = client
    source._query_url = server.url(path)
    source._cache = DiskCache(tmp_path, config.osv_ttl_cache_horas, enabled=use_cache)
    return source


def test_query_batch_mal_real_es_malicious(osv_server: _OsvServer, tmp_path: Path) -> None:
    # Camino feliz real: socket -> 200 con un MAL- y un GHSA -> MALICIOUS con un solo advisory.
    source = _wired_source(osv_server, "/malicious", tmp_path, _config())
    result = source.query_batch(["bioql"])
    assert result["bioql"].state is MaliceState.MALICIOUS
    assert [a.id for a in result["bioql"].advisories] == ["MAL-2025-47868"]
    assert result["bioql"].advisories[0].url == "https://osv.dev/vulnerability/MAL-2025-47868"


def test_query_batch_clean_real_es_clean(osv_server: _OsvServer, tmp_path: Path) -> None:
    source = _wired_source(osv_server, "/clean", tmp_path, _config())
    result = source.query_batch(["safe"])
    assert result["safe"].state is MaliceState.CLEAN
    assert result["safe"].advisories == ()


def test_query_batch_feed_envenenado_sanea_y_no_inyecta(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    # Anti-envenenamiento extremo a extremo: el feed devuelve un id con ANSI/CRLF y un id basura.
    # El cliente sanea+valida => un unico advisory "MAL-9" con URL reconstruida limpia; el id
    # no-MAL se ignora. Ningun byte de control llega a la salida.
    source = _wired_source(osv_server, "/poisoned", tmp_path, _config())
    result = source.query_batch(["evilpkg"])
    advisories = result["evilpkg"].advisories
    assert [a.id for a in advisories] == ["MAL-9"]
    assert advisories[0].url == "https://osv.dev/vulnerability/MAL-9"
    assert all(c not in advisories[0].url for c in ("\x1b", "\r", "\n"))


def test_query_batch_len_mismatch_real_es_unverifiable(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    # RISK-H2-2 e2e: se piden 2 nombres pero el feed devuelve 1 result => lote UNVERIFIABLE.
    source = _wired_source(osv_server, "/mismatch", tmp_path, _config())
    result = source.query_batch(["a", "b"])
    assert {r.state for r in result.values()} == {MaliceState.UNVERIFIABLE}
    assert set(result) == {"a", "b"}  # cobertura total preservada


def test_query_batch_results_no_lista_real_es_unverifiable(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    source = _wired_source(osv_server, "/not-list", tmp_path, _config())
    result = source.query_batch(["a"])
    assert result["a"].state is MaliceState.UNVERIFIABLE


def test_query_batch_respuesta_truncada_es_unverifiable(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    # Respuesta truncada (Content-Length miente): el transporte degrada a no-verificable =>
    # el lote queda UNVERIFIABLE, jamas un falso CLEAN.
    source = _wired_source(osv_server, "/truncated", tmp_path, _config())
    result = source.query_batch(["a"])
    assert result["a"].state is MaliceState.UNVERIFIABLE


def test_query_batch_429_agotado_es_unverifiable_nunca_clean(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    # R1.7: 429 es transitorio => se reintenta; con presupuesto corto se agota => UNVERIFIABLE.
    # NUNCA CLEAN. El presupuesto chico evita dormir (backoff no cabe) => test rapido.
    config = _config(osv_timeout_total_por_lote_s=0.2, osv_reintentos=2)
    source = _wired_source(osv_server, "/rate-limited", tmp_path, config)
    result = source.query_batch(["a"])
    assert result["a"].state is MaliceState.UNVERIFIABLE


def test_query_batch_503_agotado_es_unverifiable(osv_server: _OsvServer, tmp_path: Path) -> None:
    config = _config(osv_timeout_total_por_lote_s=0.2, osv_reintentos=1)
    source = _wired_source(osv_server, "/server-error", tmp_path, config)
    result = source.query_batch(["a"])
    assert result["a"].state is MaliceState.UNVERIFIABLE


def test_query_batch_404_permanente_es_unverifiable_sin_reintento(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    # 4xx!=429 es permanente: corta sin reintentar => UNVERIFIABLE (no CLEAN). Se hace UNA sola
    # peticion (no reintenta), lo cual ademas confirma el corte temprano.
    config = _config(osv_reintentos=3)
    source = _wired_source(osv_server, "/not-found", tmp_path, config)
    result = source.query_batch(["a"])
    assert result["a"].state is MaliceState.UNVERIFIABLE
    assert _OsvHandler.hits == 1  # un 4xx permanente NO se reintenta


# --------------------------------------------------------------------------- #
# NIVEL 2 - Privacidad del request (NFR-Priv.1): solo {ecosystem, name}.
# --------------------------------------------------------------------------- #


def test_query_batch_body_solo_lleva_ecosystem_y_name(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    # El servidor registra el body: debe ser EXACTAMENTE {queries:[{package:{ecosystem,name}}]},
    # sin version/manifiesto/ruta (NFR-Priv.1/NFR-Seg.4).
    source = _wired_source(osv_server, "/clean", tmp_path, _config())
    source.query_batch(["bioql"])
    sent = json.loads(_OsvHandler.last_body.decode("utf-8"))
    assert sent == {"queries": [{"package": {"ecosystem": "PyPI", "name": "bioql"}}]}


def test_query_batch_nombre_invalido_no_viaja_a_la_red(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    # Un nombre con charset invalido se EXCLUYE del POST: no debe aparecer en el body, y queda
    # UNVERIFIABLE; el nombre valido del mismo lote SI viaja. Defensa en profundidad (R1.8).
    source = _wired_source(osv_server, "/clean", tmp_path, _config())
    result = source.query_batch(["good", "Bad\r\nName"])
    assert result["Bad\r\nName"].state is MaliceState.UNVERIFIABLE
    sent = json.loads(_OsvHandler.last_body.decode("utf-8"))
    sent_names = [q["package"]["name"] for q in sent["queries"]]
    assert sent_names == ["good"]  # solo el valido viajo
    assert result["good"].state is MaliceState.CLEAN


def test_query_batch_todos_invalidos_no_tocan_la_red(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    # Si TODOS los nombres son invalidos, no se emite ningun POST (lote vacio): cero hits.
    source = _wired_source(osv_server, "/clean", tmp_path, _config())
    result = source.query_batch(["Bad\r\n", "X_Y"])
    assert {r.state for r in result.values()} == {MaliceState.UNVERIFIABLE}
    assert _OsvHandler.hits == 0


# --------------------------------------------------------------------------- #
# NIVEL 2 - Cache e2e: MALICIOUS se cachea, el segundo query no toca la red.
# --------------------------------------------------------------------------- #


def test_query_batch_cachea_malicious_y_segunda_vez_no_pega_red(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    # Primera consulta: pega la red y cachea MALICIOUS. Segunda: hit de cache, cero red nueva.
    source = _wired_source(osv_server, "/malicious", tmp_path, _config())
    first = source.query_batch(["bioql"])
    assert first["bioql"].state is MaliceState.MALICIOUS
    hits_after_first = _OsvHandler.hits
    second = source.query_batch(["bioql"])
    assert second["bioql"].state is MaliceState.MALICIOUS
    assert _OsvHandler.hits == hits_after_first  # no hubo nueva peticion: salio de cache


def test_query_batch_no_cachea_unverifiable_y_reintenta_red(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    # Un lote UNVERIFIABLE (404) NO se cachea: una segunda consulta vuelve a pegar la red.
    config = _config(osv_reintentos=0)
    source = _wired_source(osv_server, "/not-found", tmp_path, config)
    source.query_batch(["a"])
    hits_after_first = _OsvHandler.hits
    source.query_batch(["a"])
    assert _OsvHandler.hits > hits_after_first  # no se cacheo: hubo nueva peticion


# --------------------------------------------------------------------------- #
# NIVEL 2 - Cobertura total e independencia de nombres en un lote real.
# --------------------------------------------------------------------------- #


def test_query_batch_cobertura_total_claves_igual_a_names(
    osv_server: _OsvServer, tmp_path: Path
) -> None:
    # Contrato §3.1: las claves del dict resultante son EXACTAMENTE el set de names, mezclando
    # un valido (va a la red) y uno invalido (queda UNVERIFIABLE sin viajar). Sin perdidas.
    source = _wired_source(osv_server, "/clean", tmp_path, _config())
    names = ["good", "Bad_Name"]
    result = source.query_batch(names)
    assert set(result) == set(names)
