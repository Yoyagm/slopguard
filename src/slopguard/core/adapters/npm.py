"""Adapter npm: nucleo de charset compartido + predicados de validez + mapeo packument.

Este modulo aloja el `NpmAdapter` (ecosystem_id "npm"). El Hito 4 lo construye por
piezas:
- H4-T01: nucleo de charset npm + predicados de validez.
- H4-T02: normalize_name.
- H4-T06: `_extract_metadata` (mapeo packument→PackageMetadata, ADR-1/§3.2).
- H4-T07: fetch, fetch_attempt, cap de streaming, URL anti-traversal.
- H4-T11: load_top_n_npm, integridad SHA-256 al arranque.

Nucleo de charset (un solo punto de endurecimiento, §3.4). Dos predicados deben
rechazar EXACTAMENTE la misma estructura peligrosa y solo diferir en el tope de
longitud (clasico foco de divergencia entre validadores):

- `_is_valid_npm_name`     (pre-fetch al registry):   <= 214 chars (limite npm).
- `_is_valid_npm_osv_name` (pre-POST al querybatch):  <= 100 chars (cota del cuerpo
  OSV, igual que `_OSV_NAME_RE` de PyPI).

Ambos comparten `_NPM_NAME_RE` (misma estructura/charset) y solo cambian el limite de
longitud, de modo que un endurecimiento futuro del charset toca UN nucleo y se aplica
a los dos canales a la vez, sin bypass por un canal si y otro no (NFR-Seg.4, §7.3).

Fail-closed (R3.3/R8.3): un nombre que cualquiera de los predicados rechace queda
UNVERIFIABLE, **nunca** CLEAN, y no viaja a la red (ni al GET del registry ni al POST
de OSV). El nombre validado ademas se url-encodea (`quote(name, safe='')`) antes de
construir la URL del registry (anti path-traversal/SSRF, §4.1, H4-T07).

Mapeo packument (H4-T06, ADR-1, §3.2): se solicita el packument completo
(`Accept: application/json`), nunca el abreviado `install-v1` (omite time/repository/
description/author/license/keywords y dejaria inertes las Capas 0/2). Toda la
entrada del packument es NO confiable: campo ausente/tipo inesperado => flag False/None,
nunca senal inventada (R4.4, fail-closed).

Frontera de arquitectura (R10.1): este modulo SI puede usar net/cache/dataset; las
capas y el scoring importan SOLO de `adapters.base`, nunca de aqui (import-linter).
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Final
from urllib.parse import quote

from ..cache.disk_cache import DiskCache
from ..config import Config
from ..dataset.top_n import NPM_JSON, NPM_SHA256, TopNDataset, load_top_n
from ..errors import NetworkUnverifiableError
from ..models import ErrorCategory
from ..net.http_client import SecureHttpClient
from .base import FetchOutcome, FetchState, PackageMetadata
from .concurrent import FetchAttempt

# Nucleo de charset npm: caracteres permitidos en UN segmento del nombre (§3.4). Solo
# minusculas/digitos y `._~-`; ningun CRLF/ANSI/C0-C1/espacio/`%`/unicode/`:`/`/` puede
# aparecer aqui, asi que la sola pertenencia a la clase ya excluye esos vectores.
_NPM_SEGMENT_CHARS: Final[str] = "a-z0-9._~-"

# Un segmento valido: 1+ chars del nucleo que NO empieza por `.` ni `_` (regla npm).
# El lookahead `(?![._])` ademas descarta los segmentos `.` y `..` (ambos empiezan por
# `.`), cerrando el traversal por segmento de ruta.
_NPM_SEGMENT_RE: Final[re.Pattern[str]] = re.compile(rf"(?![._])[{_NPM_SEGMENT_CHARS}]+")

# Nombre = segmento simple `name`  O  scoped `@<scope-seg>/<name-seg>` con EXACTAMENTE
# un `/` (y solo en la posicion del scope; `/` no pertenece al charset de segmento, asi
# que un `/` extra rompe el match). Anclado con `\A...\Z` —NO `^...$`— a proposito: en
# Python `$` tambien casa antes de un `\n` terminal, lo que dejaria pasar `"react\n"`
# (bypass CRLF). `\Z` casa solo el fin absoluto del string y cierra ese vector.
_NPM_NAME_RE: Final[re.Pattern[str]] = re.compile(
    rf"\A(@{_NPM_SEGMENT_RE.pattern}/)?{_NPM_SEGMENT_RE.pattern}\Z"
)

# Topes de longitud: unica diferencia entre los dos predicados (§3.4).
_NPM_NAME_MAX_LEN: Final[int] = 214  # limite de nombre publicable del registry npm.
_NPM_OSV_NAME_MAX_LEN: Final[int] = 100  # cota del cuerpo OSV (igual que PyPI).

# Host del registry npm: entra al allowlist del `SecureHttpClient` SOLO via este adapter
# (R4.5/NFR-Seg.1), nunca en la constante base `ALLOWED_HOSTS` de `net.http_client`.
_NPM_REGISTRY_HOST: Final[str] = "registry.npmjs.org"

# URL del packument: el nombre validado (T01) se url-encodea con `quote(name, safe='')`
# ANTES de interpolar (anti path-traversal/SSRF por path, §4.1, H4-T07). El `{name}` ya
# encodeado queda como UN solo segmento opaco (`@scope/name` -> `%40scope%2Fname`), sin
# `/` ni `..` interpretables por el registry.
_NPM_REGISTRY_BASE: Final[str] = "https://registry.npmjs.org/{name}"

# Codigo HTTP que indica inexistencia definitiva del paquete (existencia negativa).
_HTTP_NOT_FOUND: Final[int] = 404

# Outcome canonico de degradacion segura (UNVERIFIABLE por red no verificable). Cubre el
# nombre invalido (no viaja a la red), el cap excedido (>npm_max_response_bytes, ADR-2), el
# packument no-objeto y cualquier anomalia: jamas CLEAN ni metadata parcial inventada.
_UNVERIFIABLE_OUTCOME: Final[FetchOutcome] = FetchOutcome(
    state=FetchState.UNVERIFIABLE,
    error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
)
_NOT_FOUND_OUTCOME: Final[FetchOutcome] = FetchOutcome(state=FetchState.NOT_FOUND)


def _build_npm_cache(config: Config, *, enabled: bool) -> DiskCache:
    """Construye el DiskCache del adapter npm (mismo root que PyPI, namespace por ecosistema).

    El namespace lo aporta el propio `DiskCache.get/put(ecosystem_id, name)` en cada llamada
    (igual que PyPI): un blob npm de `react` y uno PyPI de `react` nunca colisionan porque la
    clave de disco hashea `ecosystem_id:name` (aislamiento de caché del adapter, NFR-Seg.3).
    """
    cache_root = Path.home() / ".cache" / "slopguard"
    return DiskCache(cache_root, config.ttl_cache_horas, enabled=enabled)


def _classify_network_error(exc: NetworkUnverifiableError) -> FetchAttempt:
    """Clasifica un `NetworkUnverifiableError` del fetch npm en un FetchAttempt (§4.1).

    - status 404 -> NOT_FOUND (existencia negativa definitiva, permanente, R4.1).
    - 5xx/429/timeout/conexion caida (`is_transient`) -> UNVERIFIABLE transitorio: `fetch_many`
      lo reintenta dentro del presupuesto (R4.1, NFR-Rend.1).
    - resto (4xx!=404, >cap de ADR-2, packument no-objeto, redirect, status None) ->
      UNVERIFIABLE permanente. El cap excedido llega aqui como `NetworkUnverifiableError` SIN
      `status_code` ni `is_transient` (lo lanza `_extend_capped` en streaming), de modo que cae
      a UNVERIFIABLE fail-safe, nunca NOT_FOUND ni metadata parcial (R4.3).
    """
    if exc.status_code == _HTTP_NOT_FOUND:
        return FetchAttempt(outcome=_NOT_FOUND_OUTCOME, is_transient=False)
    return FetchAttempt(outcome=_UNVERIFIABLE_OUTCOME, is_transient=exc.is_transient)


def _is_valid_npm_structure(name: str, *, max_len: int) -> bool:
    """True si `name` es estructuralmente valido para npm dentro de `max_len` (nucleo unico).

    Guard de longitud ANTES del match: acota el tope exacto del canal y evita medir un
    string gigante (defensa en profundidad). Vacio ⇒ False (el guard `not name` corta
    antes de tocar el regex). El resto del contrato (charset por segmento, scoped con un
    solo `/`, sin segmentos `.`/`..`, sin inicio por `.`/`_`, sin CRLF/ANSI/unicode) lo
    impone `_NPM_NAME_RE`, compartido por ambos predicados.
    """
    if not name or len(name) > max_len:
        return False
    return _NPM_NAME_RE.match(name) is not None


def _is_valid_npm_name(name: str) -> bool:
    """True si `name` es seguro para consultar el registry npm (pre-fetch, <= 214).

    Defensa en profundidad (§3.4/§4.1): `normalize_name` baja a minusculas y recorta,
    pero NO valida charset/estructura; un nombre con CRLF/ANSI/unicode, un `/` extra o
    un segmento `..` que esquivara la normalizacion sobreviviria. Solo un nombre que
    pase este predicado se url-encodea y viaja al GET del registry; cualquier otro queda
    UNVERIFIABLE (nunca CLEAN) sin tocar la red (R3.3, fail-closed).
    """
    return _is_valid_npm_structure(name, max_len=_NPM_NAME_MAX_LEN)


def _is_valid_npm_osv_name(name: str) -> bool:
    """True si `name` es seguro para el cuerpo del POST a OSV (pre-POST, <= 100).

    Mismo nucleo de charset/estructura que `_is_valid_npm_name`; solo difiere el tope de
    longitud (cota del querybatch OSV, analogo a `_is_valid_osv_name` de PyPI). Un nombre
    que no pase se excluye del POST y queda UNVERIFIABLE, nunca CLEAN, sin viajar a la red
    (R8.3, defensa en profundidad anti-reflejo).
    """
    return _is_valid_npm_structure(name, max_len=_NPM_OSV_NAME_MAX_LEN)


def _normalize_npm_name(raw: str) -> str:
    """Normaliza un nombre npm: strip+lower, preservando la estructura scoped (§3.4).

    Para nombres simples: `strip().lower()`.
    Para nombres scoped `@scope/name`: normaliza cada segmento por separado y los
    reune con `/`, preservando el `@` inicial y sin colapsar el separador de scope.
    NO aplica colapso PEP 503 de `._-` (eso es PyPI, R3.4).
    Idempotente: `normalize(normalize(x)) == normalize(x)` (R3.2).
    """
    stripped = raw.strip()
    if stripped.startswith("@") and "/" in stripped:
        # Scoped: dividir en "@scope" y "name", normalizar cada parte.
        scope_part, _, name_part = stripped.partition("/")
        return f"{scope_part.strip().lower()}/{name_part.strip().lower()}"
    return stripped.lower()


# ---------------------------------------------------------------------------
# H4-T11: carga verificada del dataset npm (ADR-3b, R5.2/R5.3)
# ---------------------------------------------------------------------------


def load_top_n_npm(
    json_path: Path | None = None,
    sha_path: Path | None = None,
) -> TopNDataset:
    """Carga el dataset top-N npm verificando integridad SHA-256 al arranque (H4-T11).

    Inyecta `_normalize_npm_name` en `build_top_n` (ADR-3b): los nombres npm con `._-`
    (p.ej. `lodash.merge`) permanecen en `members` sin colapsar a la forma PEP 503
    (`lodash-merge`). Sin esta parametrizacion, `_extract_metadata` calcularia
    `in_top_n=False` para un paquete popular con punto en su nombre, debilitando la
    senal de popularidad (falso negativo de Capa 1).

    Lanza `DatasetIntegrityError` si los archivos faltan, el JSON es invalido o el
    checksum SHA-256 no coincide (fail-closed, R5.2).
    """
    return load_top_n(
        json_path or NPM_JSON,
        sha_path or NPM_SHA256,
        normalize_fn=_normalize_npm_name,
    )


# ---------------------------------------------------------------------------
# H4-T06: mapeo packument npm -> PackageMetadata (ADR-1, §3.2, R4.2/R4.4)
# ---------------------------------------------------------------------------


def _extract_first_release_epoch(payload: dict[str, object]) -> float | None:
    """Deriva el epoch UTC de first_release via `time.created` (§3.2, R4.4).

    `time` ausente o no-dict => None. `created` ausente o invalido => None.
    Nunca inventa fecha (sin NEW_PACKAGE espurio).
    """
    time_block = payload.get("time")
    if not isinstance(time_block, dict):
        return None
    return _parse_iso_to_epoch(time_block.get("created"))


def _extract_metadata(
    payload: dict[str, object],
    name: str,
    top_n: TopNDataset,
) -> PackageMetadata:
    """Mapea un packument npm a PackageMetadata normalizado (§3.2, ADR-1, R4.2/R4.4).

    Toda la entrada es NO confiable: campo ausente/tipo inesperado => flag False/None,
    nunca senal inventada. Se usa el nombre CONSULTADO (normalizado), NO `payload["name"]`
    (que podria diferir o estar ausente). Packument completo obligatorio (ADR-1).
    """
    normalized = _normalize_npm_name(name)
    first_release_epoch = _extract_first_release_epoch(payload)
    versions = payload.get("versions")
    releases_count = len(versions) if isinstance(versions, dict) else 0
    keywords = payload.get("keywords")
    return PackageMetadata(
        name=normalized,
        first_release_epoch=first_release_epoch,
        releases_count=releases_count,
        has_repo_url=_extract_repo_url(payload.get("repository")),
        has_description=bool(_truthy_npm_str(payload.get("description"))),
        has_author=_extract_author(payload.get("author")),
        has_license=_extract_license(payload.get("license")),
        has_classifiers=isinstance(keywords, list) and len(keywords) > 0,
        in_top_n=normalized in top_n.members,
    )


def _parse_iso_to_epoch(raw: object) -> float | None:
    """Parsea una fecha ISO-8601 (str) a epoch UTC. None si ausente o invalido.

    Acepta sufijo 'Z' (UTC) y offsets '+HH:MM'. fromisoformat cubre Python 3.11+
    con el reemplazo de 'Z'. Devuelve None ante cualquier ValueError/OverflowError
    (campo ausente o malformado => no se inventa fecha, R4.4).
    """
    if not isinstance(raw, str) or not raw:
        return None
    try:
        ts = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return ts.timestamp()
    except (ValueError, OverflowError):
        return None


def _truthy_npm_str(value: object) -> str:
    """Devuelve el string si no esta vacio, de lo contrario ''.

    Mas simple que la variante de PyPI (que filtra 'UNKNOWN'): npm no tiene ese
    convenio; cualquier string no vacio se acepta como senal de presencia.
    """
    if not isinstance(value, str):
        return ""
    return value.strip()


def _extract_repo_url(repository: object) -> bool:
    """True si el campo `repository` del packument indica una URL http(s) (§3.2).

    Dos formas validas segun la especificacion npm:
    - dict con clave `url` cuyo valor es str que empieza por 'http'.
    - string directo que empieza por 'http'.
    Campo ausente/tipo inesperado/url no-http => False (fail-closed, R4.4).
    """
    if isinstance(repository, dict):
        url = repository.get("url")
        return isinstance(url, str) and url.startswith("http")
    if isinstance(repository, str):
        return repository.startswith("http")
    return False


def _extract_author(author: object) -> bool:
    """True si el packument indica un autor no vacio (§3.2).

    Dos formas validas segun la especificacion npm:
    - str no vacio (forma corta: "Author Name <email>").
    - dict con clave `name` cuyo valor es str no vacio (forma objeto).
    Campo ausente/tipo inesperado/vacio => False (fail-closed, R4.4).
    """
    if isinstance(author, str):
        return bool(author.strip())
    if isinstance(author, dict):
        name_val = author.get("name")
        return isinstance(name_val, str) and bool(name_val.strip())
    return False


def _extract_license(license_field: object) -> bool:
    """True si el packument indica una licencia (§3.2).

    Dos formas validas segun la especificacion npm:
    - str no vacio (SPDX directo: "MIT", "Apache-2.0", etc.).
    - dict con clave `type` cuyo valor es str (forma objeto SPDX legacy).
    Campo ausente/tipo inesperado/vacio => False (fail-closed, R4.4).
    """
    if isinstance(license_field, str):
        return bool(license_field.strip())
    if isinstance(license_field, dict):
        type_val = license_field.get("type")
        return isinstance(type_val, str) and bool(type_val.strip())
    return False


class NpmAdapter:
    """Adapter del ecosistema npm: normalize_name (H4-T02) + mapeo packument (H4-T06)
    + carga verificada del dataset (H4-T11) + fetch/cap/URL anti-traversal (H4-T07).

    H4-T02 implementa `normalize_name` (§3.4, R3.1/R3.2/R3.4).
    H4-T06 introduce `_extract_metadata` (§3.2, ADR-1, R4.2/R4.4).
    H4-T07 implementa `fetch`/`fetch_attempt`/`get_downloads` + cap de streaming
    (`npm_max_response_bytes`, ADR-2) + URL con `quote(name, safe='')` (§4.1).
    H4-T11 implementa `load_top_n` via `load_top_n_npm` (ADR-3b, R5.2/R5.3).

    El cliente HTTP, la caché y el dataset top-N se instancian UNA vez en `__init__`
    (ADR-02: verificacion de integridad al arranque, no por-dependencia) y se reutilizan
    en todas las llamadas. El host `registry.npmjs.org` entra al allowlist del cliente
    SOLO aqui (R4.5/NFR-Seg.1), analogo a como `OsvSource` aporta `api.osv.dev`.

    Implementa `RetryableAdapter.fetch_attempt`: `fetch_many` reintenta SOLO los fallos
    transitorios (5xx/429/timeout) sin un camino de concurrencia nuevo (NFR-Rend.1).

    Frontera de arquitectura (R10.1): este modulo SI puede usar net/cache/dataset;
    las capas y el scoring importan SOLO de `adapters.base`, nunca de aqui (import-linter).
    """

    ecosystem_id: str = "npm"

    def __init__(self, config: Config, *, use_cache: bool = True) -> None:
        """Inicializa el adapter; carga y verifica el dataset top-N npm UNA vez (ADR-02).

        El `SecureHttpClient` se construye con `extra_allowed_hosts={registry.npmjs.org}`:
        el host npm entra al allowlist EFECTIVO SOLO por esta instancia (R4.5/NFR-Seg.1),
        jamas en la constante base global. Cargar el dataset aqui centraliza la verificacion
        de integridad en un punto determinista al arranque (un dataset corrupto/ausente aborta
        con `DatasetIntegrityError`, exit 3, antes de despachar la pool), sin re-lectura ni
        rehash por-dependencia (NFR-Rend).
        """
        self._config = config
        self._http = SecureHttpClient(
            extra_allowed_hosts=frozenset({_NPM_REGISTRY_HOST})
        )
        self._cache = _build_npm_cache(config, enabled=use_cache)
        self._top_n = load_top_n_npm()

    def normalize_name(self, raw: str) -> str:
        """Normaliza un nombre npm segun las reglas del ecosistema (§3.4, R3.1/R3.2).

        Aplica strip()+lower(); para nombres scoped `@scope/name` normaliza cada
        segmento por separado preservando el `/` (sin colapsar) y el `@` inicial.
        No aplica colapso PEP 503 de `._-` (eso es PyPI, R3.4).
        Idempotente: normalize(normalize(x)) == normalize(x).
        """
        return _normalize_npm_name(raw)

    def fetch(self, name: str) -> FetchOutcome:
        """Un intento unico (cache->red) sin reintentos: el `FetchOutcome` resuelto (R4.1).

        Es la via de `EcosystemAdapter`; colapsa toda anomalia (transitoria o permanente)
        a `FetchOutcome(UNVERIFIABLE)`, nunca FOUND ni CLEAN. El motor concurrente usa
        `fetch_attempt` para reintentar transitorios; `fetch` queda como contrato base.
        """
        return self.fetch_attempt(name).outcome

    def fetch_attempt(self, name: str) -> FetchAttempt:
        """Un intento que reporta si el fallo fue transitorio (RetryableAdapter, R4.1).

        Orden estricto (fail-closed, §4.1): normalizar -> VALIDAR estructura (T01) ANTES de
        tocar cache/red -> cache antes de red -> red. Un nombre estructuralmente invalido
        (CRLF/ANSI/unicode, `/` extra, segmento `..`/`.`, inicio por `.`/`_`, >214) cae a
        UNVERIFIABLE permanente SIN viajar a la red ni consultar caché, y NUNCA produce CLEAN
        (R3.3/R4.5). FOUND/NOT_FOUND se cachean; UNVERIFIABLE no.
        """
        normalized = self.normalize_name(name)
        if not _is_valid_npm_name(normalized):
            return FetchAttempt(outcome=_UNVERIFIABLE_OUTCOME, is_transient=False)
        cached = self._cache.get(self.ecosystem_id, normalized)
        if cached is not None:
            return FetchAttempt(outcome=cached, is_transient=False)
        attempt = self._fetch_from_network(normalized)
        self._cache.put(self.ecosystem_id, normalized, attempt.outcome)
        return attempt

    def load_top_n(self) -> TopNDataset:
        """Devuelve el TopNDataset npm ya cargado y verificado en `__init__` (ADR-02).

        El dataset se carga/verifica una sola vez al construir el adapter (sin re-lectura ni
        rehash por dependencia). El checksum SHA-256 ya se valido alli (fail-closed, R5.2).
        """
        return self._top_n

    def get_downloads(self, name: str) -> None:
        """Hook reservado. Retorna None siempre (R4.4); la ausencia NO es senal de riesgo."""
        return None

    def _fetch_from_network(self, name: str) -> FetchAttempt:
        """Consulta el packument del registry npm y clasifica la respuesta (§4.1, ADR-1/ADR-2).

        El `name` ya esta normalizado Y validado (T01) por `fetch_attempt`; aqui se url-encodea
        con `quote(name, safe='')` (`@scope/name` -> `%40scope%2Fname`) ANTES de interpolar la
        URL, de modo que el path es UN segmento opaco sin `/` ni `..` interpretables (anti
        path-traversal/SSRF, §4.1). Se solicita el packument completo: `get_json` ya envia
        `Accept: application/json` (no `install-v1`, ADR-1). El cap de tamano es el propio del
        ecosistema (`npm_max_response_bytes`, ADR-2): un cuerpo que lo excede llega como
        `NetworkUnverifiableError` desde el streaming y se clasifica UNVERIFIABLE (fail-safe).

        Defensa en profundidad (R4.4/NFR-Degr.1): cualquier excepcion que NO sea
        `NetworkUnverifiableError` se degrada a UNVERIFIABLE permanente sin filtrar el mensaje,
        para que una sola dependencia envenenada nunca aborte el lote ni escape como stacktrace.
        """
        url = _NPM_REGISTRY_BASE.format(name=quote(name, safe=""))
        try:
            payload = self._http.get_json(
                url,
                connect_timeout_s=self._config.connect_timeout_s,
                read_timeout_s=self._config.read_timeout_s,
                max_response_bytes=self._config.npm_max_response_bytes,
                max_json_depth=self._config.max_json_depth,
            )
        except NetworkUnverifiableError as exc:
            return _classify_network_error(exc)
        except Exception:
            return FetchAttempt(outcome=_UNVERIFIABLE_OUTCOME, is_transient=False)
        metadata = _extract_metadata(payload, name, self._top_n)
        outcome = FetchOutcome(state=FetchState.FOUND, metadata=metadata)
        return FetchAttempt(outcome=outcome, is_transient=False)
