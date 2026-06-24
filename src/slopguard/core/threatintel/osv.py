"""Fuente threat-intel OSV: `POST /v1/querybatch` + parseo defensivo `MAL-*` + cache.

Implementa `ThreatIntelSource` (Protocol §3.1) para el feed OSV de paquetes
maliciosos. El flujo de `query_batch` para UN lote ya deduplicado de nombres
normalizados PEP 503 es:

1. Por cada nombre, intenta cache por-nombre (`DiskCache.get_blob`, ns "osv",
   TTL `osv_ttl_cache_horas`); un hit vigente evita la red (R6.2).
2. Los nombres con miss se validan por charset (`_is_valid_osv_name`): un nombre
   con charset invalido se EXCLUYE del request y queda UNVERIFIABLE, nunca CLEAN
   (R1.8, defensa en profundidad anti-reflejo, §3.2). Solo los validos viajan a OSV.
3. `_build_body` arma `{"queries":[{"package":{"ecosystem":"PyPI","name":n}}]}` con
   los nombres validos; `_retry_batch` envia el POST con backoff y presupuesto por
   lote, reintentando solo fallos transitorios (5xx/429/timeout/conexion caida).
4. La respuesta se parsea POSICIONALMENTE: `results[i] <-> queries[i]`; un
   `len(results)!=len(queries)` degrada TODO el chunk a UNVERIFIABLE, jamas CLEAN
   (RISK-H2-2). Por cada `vulns[].id` que case `^MAL-[0-9A-Za-z-]+$` se construye un
   `Advisory` con URL RECONSTRUIDA (`https://osv.dev/vulnerability/<id>`), nunca
   reflejada del feed. IDs no-`MAL-` se ignoran; sin advisories ⇒ CLEAN.
5. Solo CLEAN/MALICIOUS se cachean (`put_blob`); UNVERIFIABLE nunca (degradacion
   segura, §2.5).

TODA respuesta de OSV se trata como entrada NO confiable: se reusa `safe_json` +
streaming + limites del transporte; los IDs externos se sanean (ANSI/C0-C1/CRLF)
antes de validar el charset y construir la URL. Frontera (R8.1): esta IMPL si puede
usar `core.net`/`core.cache`; la interfaz `source.py` no.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ..cache.disk_cache import DiskCache
from ..errors import NetworkUnverifiableError
from ..models import Advisory
from ..net.http_client import SecureHttpClient
from ..normalize import sanitize_for_output
from .source import MaliceState, ThreatIntelResult

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from ..config import Config

# Identificador estable de la fuente (clave de namespace de cache y atribucion).
_SOURCE_ID: Final[str] = "osv"

# Ecosistema OSV (capitalizacion exacta de la API; constante, NUNCA reflejada del
# usuario: el cuerpo solo lleva esta constante + el nombre validado por charset).
_OSV_ECOSYSTEM: Final[str] = "PyPI"

# Namespace de cache por-nombre (clave en disco = sha256("osv:pypi:{name}")).
_CACHE_NAMESPACE: Final[str] = "osv"
_CACHE_KEY_PREFIX: Final[str] = "pypi"

# Base de la URL canonica de un advisory OSV. La URL se RECONSTRUYE con un `id` ya
# validado por `_MAL_ID_RE`; jamas se refleja una url provista por el feed (§3.2).
_ADVISORY_URL_BASE: Final[str] = "https://osv.dev/vulnerability/"

# Clase de advisory relevante en Hito 2: solo paquete malicioso confirmado.
_ADVISORY_KIND: Final[str] = "malicious"

# Charset PEP 503 normalizado acotado a 100 chars: un nombre que NO case se excluye
# del POST (defensa en profundidad: `normalize_name` no valida charset, §3.2).
_OSV_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$")

# Prefijo y charset de un id de advisory malicioso (R1.2). Solo los `MAL-*` cuentan;
# `GHSA-*`/`CVE-*`/`PYSEC-*` se ignoran (R1.3). El id se valida ANTES de construir la
# URL: un id con ANSI/CRLF/charset raro nunca se refleja en una URL (RISK-H2-2).
_MAL_ID_RE: Final[re.Pattern[str]] = re.compile(r"^MAL-[0-9A-Za-z-]+$")
# Cota dura de longitud del id (anti id inflado en una URL/cache).
_MAL_ID_MAX_LEN: Final[int] = 128

# Base del backoff exponencial del reintento por lote (§3.5: base 0.5s, igual que
# `_sleep_within_budget` del Hito 1; reusa la SEMANTICA, no el codigo per-dep).
_BACKOFF_BASE_S: Final[float] = 0.5

# Estados que SI se persisten en cache (UNVERIFIABLE queda fuera a proposito, §2.5).
_CACHEABLE_STATES: Final[frozenset[MaliceState]] = frozenset(
    {MaliceState.CLEAN, MaliceState.MALICIOUS}
)

# Razones de degradacion (saneadas, sin stacktrace ni rutas; R6.5/NFR-Seg.4).
_REASON_INVALID_NAME: Final[str] = "nombre con charset invalido, no consultado"
_REASON_BATCH_FAILED: Final[str] = "consulta OSV no verificable (red agotada o respuesta anomala)"
_REASON_LEN_MISMATCH: Final[str] = "respuesta OSV desalineada (results != queries)"
_REASON_PAGINATED: Final[str] = "respuesta OSV paginada no resuelta por completo"


def _build_cache(config: Config, *, enabled: bool) -> DiskCache:
    """Construye la `DiskCache` compartida (mismo root que el Hito 1)."""
    cache_root = Path.home() / ".cache" / "slopguard"
    return DiskCache(cache_root, config.osv_ttl_cache_horas, enabled=enabled)


class OsvSource:
    """Fuente OSV: resuelve malicia `MAL-*` por lote, con cache por-nombre y red endurecida.

    Implementa `ThreatIntelSource`. Construye su propio `SecureHttpClient` con
    `extra_allowed_hosts={config.osv_host}` (el host de OSV entra al allowlist SOLO
    via esta fuente, ADR-09) y su `DiskCache`. Es `query_batch`-puro respecto al estado:
    no muta nada compartido salvo la cache en disco (atomica). Para tests, `_http`/`_cache`
    son inyectables tras la construccion (igual patron que `PypiAdapter`).
    """

    source_id: str = _SOURCE_ID

    def __init__(self, config: Config, *, use_cache: bool = True) -> None:
        """Inicializa la fuente OSV: cliente HTTP con el host OSV en el allowlist + cache.

        El `extra_allowed_hosts` se deriva de `config.osv_host` (ya validado por
        `config._validate_ranges` contra el dominio cerrado {api.osv.dev}, R5.2). El
        cliente HTTP revalida el host (`_is_valid_https_host`) en construccion: defensa
        en profundidad si un refactor de config dejara de validarlo (ADR-09).
        """
        self._config = config
        self.extra_allowed_hosts: frozenset[str] = frozenset({config.osv_host})
        self._http = SecureHttpClient(extra_allowed_hosts=self.extra_allowed_hosts)
        self._cache = _build_cache(config, enabled=use_cache)
        self._query_url = f"https://{config.osv_host}{config.osv_query_path}"

    def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
        """Resuelve malicia OSV para un LOTE de nombres normalizados (cobertura total).

        Contrato (§3.1): devuelve un dict cuyas claves son EXACTAMENTE `set(names)`; cada
        valor es CLEAN/MALICIOUS/UNVERIFIABLE (esta fuente nunca emite KNOWN_HALLUCINATION,
        que es de watchlist). Cache por-nombre primero; los miss VALIDOS van al POST; los
        miss con charset invalido quedan UNVERIFIABLE sin viajar a la red. Un fallo de lote
        degrada los nombres consultados a UNVERIFIABLE, jamas CLEAN (NFR-Degr.1).
        """
        results: dict[str, ThreatIntelResult] = {}
        to_query: list[str] = []
        for name in names:
            cached = self._cached_result(name)
            if cached is not None:
                results[name] = cached
            elif _is_valid_osv_name(name):
                to_query.append(name)
            else:
                results[name] = _unverifiable(name, _REASON_INVALID_NAME)
        results.update(self._resolve_from_network(to_query))
        return results

    def _cached_result(self, name: str) -> ThreatIntelResult | None:
        """Devuelve el `ThreatIntelResult` cacheado vigente para `name`, o None (miss).

        El validador inyectado revalida el blob como entrada NO confiable (§2.5): schema,
        nombre esperado, estado cacheable e ids `MAL-*`; reconstruye los `Advisory` con URL
        derivada del id (no se confia en la url del disco).
        """
        return self._cache.get_blob(
            _CACHE_NAMESPACE,
            _cache_key(name),
            lambda payload: _validate_osv_blob(payload, name),
            ttl_segundos=self._config.osv_ttl_cache_horas * 3600,
        )

    def _resolve_from_network(self, names: list[str]) -> dict[str, ThreatIntelResult]:
        """Consulta OSV para los nombres con miss y cachea CLEAN/MALICIOUS (no UNVERIFIABLE).

        Un lote vacio no toca la red. Un fallo total del lote (red agotada, respuesta
        desalineada/paginada/anomala) degrada TODOS sus nombres a UNVERIFIABLE; ninguno se
        cachea. El reensamblado es posicional `results[i] <-> names[i]` (mismo orden del body).
        """
        if not names:
            return {}
        payload = self._post_batch(names)
        if payload is None:
            return {name: _unverifiable(name, _REASON_BATCH_FAILED) for name in names}
        resolved = _parse_batch_response(payload, names)
        for name, result in resolved.items():
            if result.state in _CACHEABLE_STATES:
                self._cache.put_blob(_CACHE_NAMESPACE, _cache_key(name), _to_blob(result))
        return resolved

    def _post_batch(self, names: list[str]) -> dict[str, object] | None:
        """Envia el POST del lote con presupuesto+reintentos; None si el lote no se resolvio.

        Devuelve el JSON parseado del `querybatch`, o None si se agoto el presupuesto/los
        reintentos sobre fallos transitorios o si la respuesta fue un fallo permanente
        (4xx!=429, anomalia de seguridad). El caller mapea None ⇒ UNVERIFIABLE del lote.
        """
        body = _build_body(names)
        return self._retry_batch(lambda: self._http.post_json(
            self._query_url,
            body,
            connect_timeout_s=self._config.connect_timeout_s,
            read_timeout_s=self._config.read_timeout_s,
            max_response_bytes=self._config.max_response_bytes,
            max_json_depth=self._config.max_json_depth,
        ))

    def _retry_batch(
        self, post_call: Callable[[], dict[str, object]]
    ) -> dict[str, object] | None:
        """Reintenta UN POST de chunk con backoff exponencial dentro del presupuesto por lote.

        Reusa la semantica de `_sleep_within_budget` (Hito 1) sin acoplar `concurrent.py`:
        `deadline = monotonic + osv_timeout_total_por_lote_s`, `max_attempts = osv_reintentos
        + 1`. Solo reintenta `NetworkUnverifiableError.is_transient` (5xx/429/timeout/conexion
        caida). Un fallo permanente (4xx!=429, redirect, bomba) corta sin reintentar. Agotado
        el presupuesto o los reintentos ⇒ None (el caller marca el chunk UNVERIFIABLE, nunca
        CLEAN). Determinista: el backoff usa `time.monotonic` (sin reloj de pared).
        """
        deadline = time.monotonic() + self._config.osv_timeout_total_por_lote_s
        max_attempts = self._config.osv_reintentos + 1
        attempt = 0
        while True:
            if time.monotonic() >= deadline:
                return None  # presupuesto rebasado: no se inicia un nuevo intento
            try:
                return post_call()
            except NetworkUnverifiableError as exc:
                if not exc.is_transient:
                    return None  # 4xx!=429 / anomalia permanente: no se reintenta
            attempt += 1
            if attempt >= max_attempts or not _sleep_within_budget(attempt - 1, deadline):
                return None  # reintentos agotados o sin margen de backoff ⇒ UNVERIFIABLE


def _sleep_within_budget(attempt: int, deadline: float) -> bool:
    """Espera el backoff del intento `attempt` (0.5s, 1s, 2s...) sin rebasar el deadline.

    Si la espera completa no cabe en el presupuesto restante, NO duerme y reporta False
    para cortar a UNVERIFIABLE antes que exceder el presupuesto por lote (igual criterio
    que `concurrent._sleep_within_budget`).
    """
    backoff = _BACKOFF_BASE_S * (2**attempt)
    if backoff > deadline - time.monotonic():
        return False
    time.sleep(backoff)
    return True


def _is_valid_osv_name(name: str) -> bool:
    """True si el nombre normalizado es seguro para el body del POST (charset acotado).

    Predicado propio (defensa en profundidad, §3.2): `normalize_name` colapsa separadores
    y baja a minusculas pero NO valida charset, asi que un nombre con CRLF/ANSI/unicode que
    esquivara el parser sobreviviria. Solo un nombre PEP 503 legitimo (`^[a-z0-9-]...$`,
    <=100) viaja a OSV; cualquier otro se excluye y queda UNVERIFIABLE (nunca CLEAN).
    """
    return bool(_OSV_NAME_RE.match(name))


def _build_body(names: list[str]) -> dict[str, object]:
    """Arma el cuerpo del `querybatch`: solo `{ecosystem, name}` por nombre VALIDO (R1.8).

    El `ecosystem` es la constante OSV `"PyPI"` (no reflejada del usuario) y `name` ya paso
    `_is_valid_osv_name`. NUNCA viaja version/manifiesto/ruta (NFR-Priv.1/NFR-Seg.4). El
    orden de `queries` es el de `names`, base del reensamblado posicional de la respuesta.
    """
    return {
        "queries": [
            {"package": {"ecosystem": _OSV_ECOSYSTEM, "name": name}} for name in names
        ]
    }


def _parse_batch_response(
    payload: dict[str, object], names: list[str]
) -> dict[str, ThreatIntelResult]:
    """Parsea la respuesta del `querybatch` mapeando `results[i] <-> names[i]` (posicional).

    Validacion DEFENSIVA (RISK-H2-2): si `results` no es lista o `len(results)!=len(names)`,
    TODO el chunk degrada a UNVERIFIABLE (jamas se asume CLEAN). Si esta alineado, cada
    `results[i]` se traduce a CLEAN/MALICIOUS/UNVERIFIABLE para `names[i]`. La respuesta es
    entrada NO confiable: cada acceso se tipa antes de usar.
    """
    raw_results = payload.get("results")
    if not isinstance(raw_results, list) or len(raw_results) != len(names):
        return {name: _unverifiable(name, _REASON_LEN_MISMATCH) for name in names}
    return {
        name: _result_for_entry(name, entry)
        for name, entry in zip(names, raw_results, strict=True)
    }


def _result_for_entry(name: str, entry: object) -> ThreatIntelResult:
    """Traduce un `results[i]` (entrada NO confiable) al `ThreatIntelResult` de `name`.

    - `entry` no-dict o `{}` o sin `vulns`/`vulns=[]` ⇒ CLEAN (R1.4).
    - `entry` con `next_page_token` ⇒ UNVERIFIABLE para ese nombre (Hito 2 no pagina; no se
      asume limpio un resultado parcial, §3.2 non-goal).
    - `vulns[].id` que case `^MAL-[0-9A-Za-z-]+$` ⇒ MALICIOUS + Advisory(s) (R1.2); ids
      no-`MAL-` se ignoran (R1.3); sin advisories validos ⇒ CLEAN.
    """
    if not isinstance(entry, dict):
        return _clean(name)
    if entry.get("next_page_token") is not None:
        return _unverifiable(name, _REASON_PAGINATED)
    advisories = _extract_advisories(entry.get("vulns"))
    if not advisories:
        return _clean(name)
    return ThreatIntelResult(name=name, state=MaliceState.MALICIOUS, advisories=advisories)


def _extract_advisories(vulns: object) -> tuple[Advisory, ...]:
    """Recolecta `Advisory` de `vulns[].id` que casen `MAL-*`; ignora todo lo demas.

    `vulns` es entrada NO confiable: si no es lista, se trata como vacia (⇒ CLEAN). Cada
    `id` se SANEA (ANSI/C0-C1/CRLF) y se valida por `_MAL_ID_RE` + longitud ANTES de
    construir la URL canonica; un id invalido se descarta (no se refleja en una URL).
    """
    if not isinstance(vulns, list):
        return ()
    advisories: list[Advisory] = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        advisory = _advisory_from_id(vuln.get("id"))
        if advisory is not None:
            advisories.append(advisory)
    return tuple(advisories)


def _advisory_from_id(raw_id: object) -> Advisory | None:
    """Construye un `Advisory` desde un id `MAL-*` validado, o None si no aplica/es invalido.

    El id se sanea y valida; la URL se RECONSTRUYE (`_ADVISORY_URL_BASE + id`), nunca se
    refleja una url provista por el feed. Solo ids `^MAL-[0-9A-Za-z-]+$` acotados producen
    advisory; el resto (GHSA/CVE/PYSEC, o ids envenenados) se descartan silenciosamente.
    """
    if not isinstance(raw_id, str):
        return None
    advisory_id = sanitize_for_output(raw_id)
    if len(advisory_id) > _MAL_ID_MAX_LEN or not _MAL_ID_RE.match(advisory_id):
        return None
    return Advisory(
        id=advisory_id,
        kind=_ADVISORY_KIND,
        url=f"{_ADVISORY_URL_BASE}{advisory_id}",
        source=_SOURCE_ID,
    )


def _validate_osv_blob(payload: dict[str, Any], expected_name: str) -> ThreatIntelResult | None:
    """Valida un blob de cache OSV (entrada NO confiable) y reconstruye el `ThreatIntelResult`.

    Rechaza (⇒ None ⇒ miss) cualquier desviacion (§2.5): `source!="osv"`,
    `ecosystem!="pypi"`, `name` distinto del esperado (colision de hash/manipulacion), o
    `state` no cacheable. Para `malicious`, reconstruye los `Advisory` con la MISMA logica
    de validacion de id + URL reconstruida que la red (no se confia en la url del disco); cada
    entrada persistida se revalida tambien por `kind=="malicious"` y `source=="osv"` (a la letra
    de §2.5, ver `_blob_vulns`); si no queda ningun advisory valido, el blob se rechaza
    (incoherente con `malicious`).
    """
    if payload.get("source") != _SOURCE_ID or payload.get("ecosystem") != _CACHE_KEY_PREFIX:
        return None
    if payload.get("name") != expected_name:
        return None
    state_raw = payload.get("state")
    if state_raw == MaliceState.CLEAN.value:
        return _clean(expected_name)
    if state_raw != MaliceState.MALICIOUS.value:
        return None  # unverifiable u otro estado no debe estar en disco ⇒ miss
    advisories = _extract_advisories(_blob_vulns(payload.get("advisories")))
    if not advisories:
        return None  # `malicious` sin advisory valido es incoherente ⇒ miss
    return ThreatIntelResult(
        name=expected_name, state=MaliceState.MALICIOUS, advisories=advisories
    )


def _blob_vulns(raw_advisories: object) -> list[dict[str, object]]:
    """Adapta los `advisories` del blob a la forma `[{"id": ...}]` que espera `_extract_advisories`.

    Reusa el MISMO validador de id que la respuesta de red: el blob es entrada NO confiable
    igual que el feed. Una entrada sin `id` string se descarta al revalidar (id None ⇒ no advisory).

    Alineado a la LETRA del contrato §2.5 (validador del blob OSV): ademas del `id`, cada entrada
    persistida DEBE declarar `kind=="malicious"` y `source=="osv"`. Una entrada con `kind`/`source`
    manipulado en disco se DESCARTA aqui (cuenta como advisory ausente): combinado con el rechazo
    de `_validate_osv_blob` ante `malicious` sin advisory valido, un blob con kind/source
    inconsistente degrada a miss ⇒ refetch. El impacto de seguridad de no descartarla seria nulo
    (kind/url/source se RECONSTRUYEN desde constantes en `_advisory_from_id`, jamas se reflejan del
    disco), pero el descarte cierra el gap por validacion explicita, no solo por construccion.
    """
    if not isinstance(raw_advisories, list):
        return []
    return [
        {"id": item.get("id")}
        for item in raw_advisories
        if isinstance(item, dict)
        and item.get("kind") == _ADVISORY_KIND
        and item.get("source") == _SOURCE_ID
    ]


def _to_blob(result: ThreatIntelResult) -> dict[str, object]:
    """Serializa un `ThreatIntelResult` CLEAN/MALICIOUS al payload de cache (§2.5).

    NO incluye la `url` del advisory: se RECONSTRUYE del id al leer (no se confia en una url
    persistida). `put_blob` sella `cache_schema_version`/`fetched_at`; aqui solo van los
    campos de dominio (source/ecosystem/name/state/advisories).
    """
    return {
        "source": _SOURCE_ID,
        "ecosystem": _CACHE_KEY_PREFIX,
        "name": result.name,
        "state": result.state.value,
        "advisories": [
            {"id": adv.id, "kind": adv.kind, "source": adv.source}
            for adv in result.advisories
        ],
    }


def _cache_key(name: str) -> str:
    """Clave de cache por-nombre: `"pypi:{name}"` (el namespace "osv" lo aporta `DiskCache`)."""
    return f"{_CACHE_KEY_PREFIX}:{name}"


def _clean(name: str) -> ThreatIntelResult:
    """`ThreatIntelResult` CLEAN para `name` (consultado y sin advisories `MAL-*`)."""
    return ThreatIntelResult(name=name, state=MaliceState.CLEAN)


def _unverifiable(name: str, reason: str) -> ThreatIntelResult:
    """`ThreatIntelResult` UNVERIFIABLE para `name` con un motivo ya saneado (no se cachea)."""
    return ThreatIntelResult(
        name=name, state=MaliceState.UNVERIFIABLE, unverifiable_reason=reason
    )
