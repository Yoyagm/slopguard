"""Fuente de threat-intel `WatchlistSource`: corpus depscope de alucinaciones (R2).

Implementa `ThreatIntelSource` consultando el corpus OPCIONAL de nombres de paquete
alucinados conocidos (depscope-hallucinations). El flujo de `query_batch` es:

1. Carga el corpus: hit de cache vigente (`namespace="watchlist"`, TTL 24h) ⇒ sin red;
   miss ⇒ `GET https://{watchlist_host}{watchlist_source_path}` via `SecureHttpClient.get_json`
   con `extra_allowed_hosts={watchlist_host}` (ADR-09: el host solo entra al allowlist si la
   fuente se instancia, lo que solo ocurre con `enable_watchlist=true`, R2.1).
2. Parsea el corpus de forma TOLERANTE (lista de strings, o lista de objetos con `name`/
   `package`): estructura inesperada ⇒ corpus None ⇒ todos los nombres `UNVERIFIABLE`, sin
   crashear (R2.5). Cada nombre se normaliza y valida por charset AL LEER con la regla del
   ECOSISTEMA (PyPI = PEP 503; npm = nucleo §3.4 que admite scoped `@scope/name`, ADR-8):
   descarta invalidos, anti-envenenamiento; aplica el cap `_WATCHLIST_MAX_NAMES` (anti-DoS).
3. Match EXACTO: `name in corpus` ⇒ `KNOWN_HALLUCINATION` (+ fuente y fecha, R2.3); si no ⇒ `CLEAN`.
4. Corpus ilegible/caido/sobre-cap/vacio tras validar ⇒ TODOS los nombres `UNVERIFIABLE`
   (degradacion segura, nunca un falso CLEAN — NFR-Degr.1). No invalida OSV: el `CompositeSource`
   fusiona por nombre y la porcion no verificable solo se anota (§2.2).

SEGURIDAD (RISK-H2-2): toda respuesta de depscope es entrada NO confiable. El corpus NUNCA se
embebe ni redistribuye (CC-BY-NC-SA): solo se cachea localmente (perms 0700/0600) con atribucion.
`UNVERIFIABLE` jamas se cachea. Ningun dato del usuario viaja en la peticion (NFR-Priv.1): el GET
no lleva query string. Los textos de atribucion (fuente/fecha/licencia) se sanean antes de salir.

Frontera (import-linter §1.3): este modulo es una IMPL y SI puede usar `core.net`/`core.cache`;
`source.py` (la interfaz) no. Las capas/scoring no importan este modulo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ..adapters.npm import _is_valid_npm_name, _normalize_npm_name
from ..cache.disk_cache import DiskCache
from ..errors import NetworkUnverifiableError
from ..net.http_client import SecureHttpClient
from ..normalize import normalize_name, sanitize_for_output
from .source import MaliceState, ThreatIntelResult

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from ..config import Config

# Cap duro de nombres en el corpus (anti-DoS de memoria, §2.5/RISK-H2-2): un corpus
# inflado mas alla de esto se considera sospechoso y NO se trunca silenciosamente ⇒
# watchlist UNVERIFIABLE. Un corpus legitimo de alucinaciones esta muy por debajo.
_WATCHLIST_MAX_NAMES: Final[int] = 1_000_000

# Charset de un nombre normalizado PEP 503 valido para el corpus (anti-envenenamiento):
# solo minusculas, digitos y guion. CRLF/ANSI/unicode que sobreviva a `normalize_name`
# (que no valida charset) se descarta AL LEER, antes de poder inyectar un falso match.
# `\A...\Z` (no `^...$`): en Python `$` casa antes de un `\n` terminal ⇒ bypass CRLF.
_WATCHLIST_NAME_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9-]+\Z")

# Namespace de cache del corpus (separa por construccion de la cache OSV y la del Hito 1).
_WATCHLIST_NAMESPACE: Final[str] = "watchlist"

# Prefijo de clave de cache por ecosistema (ADR-8): la clave pasa a
# `f"{cache_prefix}:{host}{path}"` (mismo patron cerrado `pypi:`/`npm:` que OSV), de modo
# que un blob de corpus de un ecosistema NO sea legible bajo la clave del otro, por
# construccion (R8.2/NFR-Seg.3). Solo se prefija; el corpus depscope sigue siendo agnostico
# de ecosistema, pero el VEREDICTO cacheado y su clave no colisionan entre ecosistemas.
_CACHE_KEY_PREFIX_PYPI: Final[str] = "pypi"
_CACHE_KEY_PREFIX_NPM: Final[str] = "npm"

# Identificadores de fuente/licencia para la atribucion (R2.6/R7.2). Constantes: jamas
# se reflejan crudos desde la respuesta de red.
_SOURCE_ID: Final[str] = "watchlist"
_CORPUS_LICENSE: Final[str] = "CC-BY-NC-SA-4.0"
_CORPUS_ATTRIBUTION: Final[str] = "depscope-hallucinations"

# Claves toleradas para extraer el nombre de un item-objeto del corpus.
_NAME_KEYS: Final[tuple[str, ...]] = ("name", "package")

# Hora a segundos (TTL del corpus = watchlist_ttl_cache_horas * 3600).
_SECONDS_PER_HOUR: Final[int] = 3600


def _is_valid_pypi_watchlist_name(name: str) -> bool:
    """True si `name` normalizado PEP 503 es charset-valido para el corpus PyPI.

    Predicado propio (anti-envenenamiento, §2.5): `normalize_name` baja a minusculas y
    colapsa separadores pero NO valida charset, asi que un nombre con CRLF/ANSI/unicode que
    lo esquivara sobreviviria. Solo un nombre `^[a-z0-9-]+$` (`\\A...\\Z`) se admite; cualquier
    otro se descarta AL LEER, antes de poder inyectar un falso `KNOWN_HALLUCINATION`.
    """
    return _WATCHLIST_NAME_RE.match(name) is not None


# Tabla CERRADA de ecosistemas soportados (ADR-8, simetria con OSV §3.7): `ecosystem_id` ->
# `(cache_prefix, normalizer, name_validator)`. El `cache_prefix` separa la cache por
# ecosistema (clave `f"{prefix}:{host}{path}"`, namespace `watchlist`); el `normalizer` y el
# `name_validator` se eligen por ecosistema (PyPI = PEP 503, charset `^[a-z0-9-]+$`; npm =
# nucleo §3.4 que admite scoped `@scope/name`). El `ecosystem_id` proviene SIEMPRE del adapter
# (registro cerrado), nunca del usuario: un id fuera de esta tabla es un error de programacion
# ⇒ `ValueError` fail-closed (jamas se refleja un id arbitrario en la clave de cache, R8.2).
_ECOSYSTEM_TABLE: Final[
    dict[str, tuple[str, Callable[[str], str], Callable[[str], bool]]]
] = {
    "pypi": (_CACHE_KEY_PREFIX_PYPI, normalize_name, _is_valid_pypi_watchlist_name),
    "npm": (_CACHE_KEY_PREFIX_NPM, _normalize_npm_name, _is_valid_npm_name),
}


@dataclass(frozen=True, slots=True)
class _Corpus:
    """Corpus de nombres alucinados ya validado: conjunto inmutable + atribucion saneada.

    Es un objeto interno (no del contrato de la fuente): encapsula el frozenset de nombres
    normalizados y la fecha del corpus para construir los `ThreatIntelResult` por nombre.
    """

    names: frozenset[str]  # nombres normalizados por ecosistema, charset validado
    date: str | None  # fecha del corpus (atribucion, saneada) o None si ausente


def _build_cache(config: Config, *, enabled: bool) -> DiskCache:
    """Construye el `DiskCache` del corpus con su TTL propio (watchlist_ttl_cache_horas)."""
    cache_root = Path.home() / ".cache" / "slopguard"
    return DiskCache(cache_root, config.watchlist_ttl_cache_horas, enabled=enabled)


class WatchlistSource:
    """Fuente threat-intel del corpus depscope: GET corpus + match exacto + cache 24h.

    Se instancia SOLO cuando `enable_watchlist=true` (lo decide el `registry`/`composite`):
    asi `depscope.dev` nunca entra al allowlist con la watchlist desactivada (R2.1, ADR-09).
    El cliente HTTP y la cache se crean una vez y se reusan en cada lote (objeto frozen-like).
    """

    source_id: str = _SOURCE_ID
    """Identificador unico de la fuente (`'watchlist'`)."""

    def __init__(
        self, config: Config, *, ecosystem_id: str = "pypi", use_cache: bool = True
    ) -> None:
        """Inicializa la fuente para `ecosystem_id`: host/path del corpus + cache namespaced.

        `extra_allowed_hosts` se fija a `{config.watchlist_host}` (validado por config como
        FQDN https del dominio cerrado depscope.dev). El `SecureHttpClient` revalida el host
        antes de admitirlo (defensa en profundidad, ADR-09): un host interno inyectado se
        rechazaria en construccion. No se persiste el corpus en memoria entre lotes: se carga
        por lote desde cache/red (la cache vigente evita la red).

        `ecosystem_id` (default `"pypi"`, cero regresion) selecciona de una tabla CERRADA
        (ADR-8) la tripleta `(cache_prefix, normalizer, name_validator)`: el `cache_prefix`
        antepone `pypi:`/`npm:` a la clave de cache (`f"{prefix}:{host}{path}"`) para que un
        blob de corpus de un ecosistema NO sea legible bajo la clave del otro (R8.2/NFR-Seg.3);
        el `normalizer`/`name_validator` se eligen por ecosistema (PyPI = PEP 503; npm = nucleo
        §3.4 que admite scoped `@scope/name`), de modo que un nombre scoped legitimo se normaliza
        y puede matchear `KNOWN_HALLUCINATION`. Un id fuera de la tabla ⇒ `ValueError` fail-closed:
        el id viene del adapter (registro cerrado), nunca del usuario, asi que un valor ajeno es
        un bug, no entrada que debamos reflejar en la clave de cache.
        """
        try:
            cache_prefix, normalizer, name_validator = _ECOSYSTEM_TABLE[ecosystem_id]
        except KeyError as exc:
            disponibles = ", ".join(sorted(_ECOSYSTEM_TABLE))
            raise ValueError(
                f"ecosystem_id no soportado por WatchlistSource: {ecosystem_id!r}; "
                f"disponibles: {disponibles}"
            ) from exc
        self._config = config
        self._ecosystem_id = ecosystem_id
        self._cache_prefix = cache_prefix
        self._normalizer = normalizer
        self._name_validator = name_validator
        self.extra_allowed_hosts: frozenset[str] = frozenset({config.watchlist_host})
        self._url = f"https://{config.watchlist_host}{config.watchlist_source_path}"
        self._cache_key = (
            f"{cache_prefix}:{config.watchlist_host}{config.watchlist_source_path}"
        )
        self._ttl_segundos = config.watchlist_ttl_cache_horas * _SECONDS_PER_HOUR
        self._http = SecureHttpClient(extra_allowed_hosts=self.extra_allowed_hosts)
        self._cache = _build_cache(config, enabled=use_cache)

    def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
        """Resuelve watchlist para un LOTE de nombres normalizados (cobertura total).

        Carga el corpus UNA vez por lote (cache→red). Corpus None (caido/ilegible/sobre-cap/
        envenenado) ⇒ TODOS los nombres `UNVERIFIABLE` (nunca CLEAN). Con corpus valido: match
        exacto ⇒ `KNOWN_HALLUCINATION`; si no ⇒ `CLEAN`. El dict devuelto tiene una entrada por
        cada nombre de `names` (cobertura total, §3.2 punto 4).
        """
        corpus = self._load_corpus()
        if corpus is None:
            return {name: self._unverifiable(name) for name in names}
        return {name: self._resolve(name, corpus) for name in names}

    def _resolve(self, name: str, corpus: _Corpus) -> ThreatIntelResult:
        """Match exacto del nombre normalizado contra el corpus (R2.3)."""
        if name in corpus.names:
            return ThreatIntelResult(
                name=name,
                state=MaliceState.KNOWN_HALLUCINATION,
                watchlist_source=_CORPUS_ATTRIBUTION,
                watchlist_date=corpus.date,
            )
        return ThreatIntelResult(name=name, state=MaliceState.CLEAN)

    def _unverifiable(self, name: str) -> ThreatIntelResult:
        """`ThreatIntelResult` de degradacion segura para watchlist (motivo saneado)."""
        return ThreatIntelResult(
            name=name,
            state=MaliceState.UNVERIFIABLE,
            unverifiable_reason="corpus de watchlist no verificable",
        )

    def _load_corpus(self) -> _Corpus | None:
        """Devuelve el corpus validado: cache vigente o refetch de red. None si no verificable.

        Cache hit ⇒ sin red (las validaciones de charset/cap se reaplican AL LEER en el
        validador inyectado). Miss ⇒ GET + parseo; si el corpus se carga OK se cachea (jamas
        se cachea UNVERIFIABLE). Cualquier anomalia ⇒ None ⇒ el caller degrada el lote.
        """
        cached = self._cache.get_blob(
            _WATCHLIST_NAMESPACE,
            self._cache_key,
            self._validate_blob,
            ttl_segundos=self._ttl_segundos,
        )
        if cached is not None:
            return cached
        return self._fetch_corpus()

    def _fetch_corpus(self) -> _Corpus | None:
        """GET del corpus, parseo tolerante y persistencia en cache si es valido.

        Un fallo de red (`NetworkUnverifiableError`: timeout, 4xx/5xx, redirect, bomba, JSON
        malformado) ⇒ None, sin propagar la excepcion ni filtrar stacktrace (degradacion segura
        por-fuente, R2.5/NFR-Degr.1). Un payload con estructura inesperada/sobre-cap/vacio tras
        validar ⇒ None. Solo se cachea un corpus efectivamente cargado.
        """
        try:
            raw = self._http.get_json(
                self._url,
                connect_timeout_s=self._config.connect_timeout_s,
                read_timeout_s=self._config.watchlist_timeout_total_s,
                max_response_bytes=self._config.max_response_bytes,
                max_json_depth=self._config.max_json_depth,
            )
        except NetworkUnverifiableError:
            return None  # corpus caido/anomalo ⇒ todos UNVERIFIABLE (no invalida OSV)
        corpus = self._parse_corpus(raw)
        if corpus is not None:
            self._persist(corpus)
        return corpus

    def _persist(self, corpus: _Corpus) -> None:
        """Cachea el corpus validado como conjunto de nombres + atribucion (§2.5).

        Solo caché local (nunca embebido/redistribuido, CC-BY-NC-SA). `put_blob` sella
        `cache_schema_version`/`fetched_at` y respeta `--no-cache`. Ordena los nombres para
        un payload determinista.
        """
        payload: dict[str, Any] = {
            "source": _SOURCE_ID,
            "host": self._config.watchlist_host,
            "license": _CORPUS_LICENSE,
            "corpus_date": corpus.date,
            "names": sorted(corpus.names),
        }
        self._cache.put_blob(_WATCHLIST_NAMESPACE, self._cache_key, payload)

    def _parse_corpus(self, raw: dict[str, Any]) -> _Corpus | None:
        """Parsea la respuesta de red como entrada NO confiable. None si no reconocible.

        Tolera: corpus directo (`{"names":[...]}` / `{"packages":[...]}`) y el objeto-raiz
        como contenedor. Extrae los items, valida charset+cap y construye el `_Corpus`. La
        fecha de atribucion se sanea (ANSI/CRLF) antes de guardarse.
        """
        items = _extract_items(raw)
        if items is None:
            return None
        return self._build_corpus(items, _extract_corpus_date(raw))

    def _validate_blob(self, payload: dict[str, Any]) -> _Corpus | None:
        """Valida un blob de cache como entrada NO confiable y reconstruye el corpus.

        Reaplica TODA la verificacion al LEER (no solo al escribir, §2.5): `source`/`host`
        esperados, charset+cap de cada nombre. Cualquier desviacion ⇒ None ⇒ miss ⇒ refetch.
        Mitiga una escritura de cache manipulada (falsos KNOWN_HALLUCINATION o retiro de nombres).
        """
        if payload.get("source") != _SOURCE_ID:
            return None
        if payload.get("host") != self._config.watchlist_host:
            return None
        names = payload.get("names")
        if not isinstance(names, list):
            return None
        return self._build_corpus(names, _extract_corpus_date(payload))

    def _build_corpus(self, items: list[Any], date: str | None) -> _Corpus | None:
        """Normaliza+valida los items y arma el `_Corpus`. None si sobre-cap o queda vacio.

        Cap ANTES de iterar (anti-DoS): un corpus inflado ⇒ None sin materializar el set.
        Charset por nombre AL LEER: invalidos se descartan (no invalidan el corpus). Un corpus
        que queda vacio tras validar ⇒ None (degradacion conservadora: indistinguible de un
        envenenamiento por retiro, nunca un falso "todo limpio").
        """
        if len(items) > _WATCHLIST_MAX_NAMES:
            return None  # corpus inflado/sospechoso ⇒ UNVERIFIABLE, no se trunca
        valid: set[str] = set()
        for item in items:
            name = self._validated_name(item)
            if name is not None:
                valid.add(name)
        if not valid:
            return None  # nada valido ⇒ no se reporta CLEAN para nadie (NFR-Degr.1)
        return _Corpus(names=frozenset(valid), date=date)

    def _validated_name(self, item: Any) -> str | None:
        """Extrae y valida UN nombre del corpus: normaliza + charset + longitud por ecosistema.

        Tolera item-string y item-objeto (`{"name"|"package": ...}`). Normaliza con la regla
        del ecosistema (`self._normalizer`: PyPI = PEP 503; npm = §3.4, preserva scoped) y valida
        con su charset (`self._name_validator`: PyPI = `^[a-z0-9-]+$`; npm = nucleo §3.4 que admite
        `@scope/name`). Descarta (None) si el tipo no es reconocible, el nombre supera
        `nombre_max_chars` o no pasa el charset del ecosistema (anti-envenenamiento: CRLF/ANSI/
        unicode que sobreviva a la normalizacion no inyecta un falso `KNOWN_HALLUCINATION`).
        """
        raw = _raw_name(item)
        if raw is None:
            return None
        normalized = self._normalizer(raw)
        if len(normalized) > self._config.nombre_max_chars:
            return None  # nombre absurdamente largo ⇒ descartado (no se mide distancia)
        return normalized if self._name_validator(normalized) else None


def _extract_items(raw: dict[str, Any]) -> list[Any] | None:
    """Extrae la lista de items del corpus de un objeto-raiz tolerante. None si no hay lista.

    Tolera las claves `names`/`packages`/`hallucinations`/`results`; toma la PRIMERA que sea
    una lista. Si ninguna lo es ⇒ None (estructura no reconocida ⇒ watchlist UNVERIFIABLE).
    """
    for key in ("names", "packages", "hallucinations", "results"):
        value = raw.get(key)
        if isinstance(value, list):
            return value
    return None


def _raw_name(item: Any) -> str | None:
    """Obtiene el nombre crudo de un item-string o item-objeto. None si no es reconocible."""
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for key in _NAME_KEYS:
            value = item.get(key)
            if isinstance(value, str):
                return value
    return None


def _extract_corpus_date(raw: dict[str, Any]) -> str | None:
    """Extrae y SANEA la fecha del corpus para atribucion (R2.6/R7.2). None si ausente/invalida.

    Acepta `corpus_date`/`date`/`generated_at` como string; se sanea (ANSI/C0-C1/CRLF) antes de
    devolverse para que nunca arrastre secuencias de control a la salida. Un valor no-string o
    vacio tras sanear ⇒ None (la atribucion es opcional; su ausencia no invalida el corpus).
    """
    for key in ("corpus_date", "date", "generated_at"):
        value = raw.get(key)
        if isinstance(value, str):
            sanitized = sanitize_for_output(value).strip()
            if sanitized:
                return sanitized
    return None
