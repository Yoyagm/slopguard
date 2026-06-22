"""Adapter PyPI: caché → red → PackageMetadata normalizado (R2.1, R4.1, R9.1-R9.7).

Implementa `EcosystemAdapter` y el protocolo opcional `RetryableAdapter` (T22) para
el ecosistema PyPI. El flujo de `fetch_attempt` (un intento) es:
1. Consulta `DiskCache`; si hay hit vigente, lo retorna sin red (intento definitivo).
2. Si miss, llama a `SecureHttpClient.get_json` hacia `https://pypi.org/pypi/{name}/json`.
3. Clasifica la respuesta segun las Convenciones de tasks.md:
   - 200 ok       → FOUND con PackageMetadata normalizado (nunca payload crudo)
   - 404          → NOT_FOUND (existencia negativa definitiva; permanente, R2.1)
   - 4xx ≠ 404    → UNVERIFIABLE permanente (anomalia, nunca FOUND, Convenciones)
   - 5xx/timeout/conexion caida → UNVERIFIABLE TRANSITORIO (reintentable, R2.5)
   - otra anomalia de red (redirect/bomba/depth) → UNVERIFIABLE permanente
4. Persiste FOUND/NOT_FOUND en caché; UNVERIFIABLE nunca se cachea (§2.6).

La distincion transitorio/permanente se obtiene de `NetworkUnverifiableError`
(`status_code`/`is_transient`), que `SecureHttpClient` rellena. Esto permite que
`fetch_many` reintente SOLO los fallos transitorios (R2.5) con el adapter real,
sin que las capas/scoring vean nunca la excepcion (frontera R10.1).

El dataset top-N se carga UNA vez en `__init__` (ADR-02): la verificacion de
checksum ocurre al arranque (un fallo => DatasetIntegrityError, exit 3 operacional),
no por-dependencia ni en cada FOUND. La instancia es frozen+slots: thread-safe para
compartir entre los workers de la pool sin re-lectura ni rehash.

Frontera de arquitectura (R10.1): este modulo SÍ importa net/cache/dataset.
Las capas y el scoring importan SOLO de `adapters.base`, no de aquí (import-linter).
"""

from __future__ import annotations

import datetime
from pathlib import Path

from ..cache.disk_cache import DiskCache
from ..config import Config
from ..dataset.top_n import TopNDataset, load_top_n
from ..errors import NetworkUnverifiableError
from ..models import ErrorCategory
from ..net.http_client import SecureHttpClient
from ..normalize import normalize_name
from .base import FetchOutcome, FetchState, PackageMetadata
from .concurrent import FetchAttempt

# URL base de la API JSON de PyPI (NFR-Priv.1: solo el nombre del paquete).
_PYPI_API_BASE = "https://pypi.org/pypi/{name}/json"

# Codigo HTTP que indica inexistencia definitiva del paquete.
_HTTP_NOT_FOUND = 404

# Outcome canonico de degradacion segura (UNVERIFIABLE por red no verificable).
_UNVERIFIABLE_OUTCOME = FetchOutcome(
    state=FetchState.UNVERIFIABLE,
    error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
)
_NOT_FOUND_OUTCOME = FetchOutcome(state=FetchState.NOT_FOUND)


def _build_cache(config: Config, *, enabled: bool) -> DiskCache:
    """Construye la instancia de DiskCache segun la config."""
    cache_root = Path.home() / ".cache" / "slopguard"
    return DiskCache(cache_root, config.ttl_cache_horas, enabled=enabled)


class PypiAdapter:
    """Adapter del ecosistema PyPI: normalize, fetch (cache+red), load_top_n.

    Se construye con una `Config` y un flag `use_cache`. El cliente HTTP, la cache
    y el dataset top-N se instancian una vez y se reutilizan en todas las llamadas.
    Implementa `RetryableAdapter.fetch_attempt` para habilitar reintentos seguros
    de fallos transitorios en `fetch_many` (R2.5).
    """

    ecosystem_id: str = "pypi"

    def __init__(self, config: Config, *, use_cache: bool = True) -> None:
        """Inicializa el adapter; carga y verifica el dataset top-N UNA vez (ADR-02).

        Cargar el top-N aqui centraliza la verificacion de integridad en un unico
        punto determinista al arranque: un dataset corrupto/ausente aborta con
        `DatasetIntegrityError` (exit 3 operacional) antes de despachar la pool, en
        vez de fallar por-dependencia de forma no determinista segun el timing de
        los workers. `load_top_n` re-lee y rehashea el .json; hacerlo una sola vez
        evita N lecturas+rehash redundantes por corrida (NFR-Rend).
        """
        self._config = config
        self._http = SecureHttpClient()
        self._cache = _build_cache(config, enabled=use_cache)
        self._top_n = load_top_n()

    def normalize_name(self, raw: str) -> str:
        """Normaliza un nombre de paquete segun PEP 503 (reusa core/normalize)."""
        return normalize_name(raw)

    def fetch(self, name: str) -> FetchOutcome:
        """Un intento unico (cache→red) sin reintentos: el `FetchOutcome` resuelto.

        Es la via de `EcosystemAdapter`; colapsa cualquier anomalia transitoria o
        permanente a UNVERIFIABLE (nunca FOUND, nunca allow). El motor concurrente
        usa `fetch_attempt` para reintentar transitorios; `fetch` queda como contrato
        base y para llamadas directas sin presupuesto.
        """
        return self.fetch_attempt(name).outcome

    def fetch_attempt(self, name: str) -> FetchAttempt:
        """Un intento que ademas reporta si el fallo fue transitorio (RetryableAdapter).

        Cache antes de red (R9.2): un hit vigente es siempre definitivo (no transitorio).
        Un miss consulta la red y clasifica 404→NOT_FOUND, 4xx≠404→UNVERIFIABLE,
        5xx/timeout→UNVERIFIABLE transitorio. FOUND/NOT_FOUND se cachean; UNVERIFIABLE no.
        """
        normalized = self.normalize_name(name)
        cached = self._cache.get(self.ecosystem_id, normalized)
        if cached is not None:
            return FetchAttempt(outcome=cached, is_transient=False)
        attempt = self._fetch_from_network(normalized)
        self._cache.put(self.ecosystem_id, normalized, attempt.outcome)
        return attempt

    def load_top_n(self) -> TopNDataset:
        """Devuelve el dataset top-N ya cargado y verificado en `__init__` (ADR-02)."""
        return self._top_n

    def get_downloads(self, name: str) -> None:
        """Hook reservado. Retorna None siempre (R4.4); no es senal de riesgo."""
        return None

    def _fetch_from_network(self, name: str) -> FetchAttempt:
        """Llama a la API de PyPI y clasifica la respuesta en un FetchAttempt.

        Defensa en profundidad (NFR-Degr.1/R6.5): cualquier excepcion inesperada que
        NO sea `NetworkUnverifiableError` (p.ej. una regresion en el cliente HTTP) se
        degrada a UNVERIFIABLE permanente sin filtrar el mensaje, para que una sola
        dependencia envenenada nunca aborte el lote ni escape como stacktrace. Las
        operacionales totales (DatasetIntegrityError) no se capturan aqui: el dataset
        ya se verifico en `__init__`, antes de cualquier fetch.
        """
        url = _PYPI_API_BASE.format(name=name)
        try:
            payload = self._http.get_json(
                url,
                connect_timeout_s=self._config.connect_timeout_s,
                read_timeout_s=self._config.read_timeout_s,
                max_response_bytes=self._config.max_response_bytes,
                max_json_depth=self._config.max_json_depth,
            )
        except NetworkUnverifiableError as exc:
            return _classify_network_error(exc)
        except Exception:
            # Defensa en profundidad: cualquier anomalia inesperada degrada a
            # UNVERIFIABLE permanente sin filtrar el mensaje (no aborta el lote, R6.5).
            return FetchAttempt(outcome=_UNVERIFIABLE_OUTCOME, is_transient=False)
        outcome = _build_found_outcome(payload, name, self._top_n)
        return FetchAttempt(outcome=outcome, is_transient=False)


def _classify_network_error(exc: NetworkUnverifiableError) -> FetchAttempt:
    """Clasifica un `NetworkUnverifiableError` en un FetchAttempt (Convenciones).

    - status 404 → NOT_FOUND (existencia negativa definitiva, permanente).
    - status 4xx≠404 → UNVERIFIABLE permanente (anomalia; nunca FOUND).
    - 5xx/timeout/conexion caida (`is_transient`) → UNVERIFIABLE transitorio (R2.5).
    - resto (redirect/bomba/depth, status None) → UNVERIFIABLE permanente.
    """
    if exc.status_code == _HTTP_NOT_FOUND:
        return FetchAttempt(outcome=_NOT_FOUND_OUTCOME, is_transient=False)
    return FetchAttempt(outcome=_UNVERIFIABLE_OUTCOME, is_transient=exc.is_transient)


def _build_found_outcome(
    payload: dict[str, object], name: str, top_n: TopNDataset
) -> FetchOutcome:
    """Construye FetchOutcome(FOUND) derivando PackageMetadata del JSON de PyPI.

    Usa el `top_n` ya cargado/verificado en `__init__` (sin re-lectura ni rehash por
    dependencia, ADR-02/NFR-Rend) para determinar `in_top_n`.
    """
    metadata = _extract_metadata(payload, name, top_n)
    return FetchOutcome(state=FetchState.FOUND, metadata=metadata)


def _extract_metadata(
    payload: dict[str, object],
    name: str,
    top_n: TopNDataset,
) -> PackageMetadata:
    """Extrae y normaliza PackageMetadata del payload JSON de PyPI (R4.1).

    Nunca devuelve el payload crudo; solo los campos del modelo normalizado.
    """
    normalized = normalize_name(name)
    info = payload.get("info") or {}
    if not isinstance(info, dict):
        info = {}

    releases = payload.get("releases") or {}
    if not isinstance(releases, dict):
        releases = {}

    first_release_epoch = _extract_first_release_epoch(releases)
    releases_count = len(releases)
    has_repo_url = _has_repo_url(info)
    has_description = bool(_truthy_str(info.get("summary")) or _truthy_str(info.get("description")))
    has_author = bool(_truthy_str(info.get("author")) or _truthy_str(info.get("author_email")))
    has_license = bool(_truthy_str(info.get("license")))
    classifiers = info.get("classifiers")
    has_classifiers = isinstance(classifiers, list) and len(classifiers) > 0
    in_top_n = normalized in top_n.members

    return PackageMetadata(
        name=normalized,
        first_release_epoch=first_release_epoch,
        releases_count=releases_count,
        has_repo_url=has_repo_url,
        has_description=has_description,
        has_author=has_author,
        has_license=has_license,
        has_classifiers=has_classifiers,
        in_top_n=in_top_n,
    )


def _extract_first_release_epoch(releases: dict[str, object]) -> float | None:
    """Deriva el epoch UTC de la primera release publicada del campo `releases`.

    Itera sobre todas las versiones y sus upload_time_iso_8601; retorna el minimo
    o None si no hay ninguna fecha parseable.
    """
    earliest: float | None = None
    for version_files in releases.values():
        if not isinstance(version_files, list):
            continue
        for file_info in version_files:
            if not isinstance(file_info, dict):
                continue
            epoch = _parse_upload_time(file_info.get("upload_time_iso_8601"))
            if epoch is not None and (earliest is None or epoch < earliest):
                earliest = epoch
    return earliest


def _parse_upload_time(raw: object) -> float | None:
    """Parsea un upload_time_iso_8601 de PyPI a epoch UTC. None si invalido."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        # PyPI usa ISO 8601 con 'T'; fromisoformat lo maneja en Python 3.11+.
        ts = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return ts.timestamp()
    except (ValueError, OverflowError):
        return None


def _has_repo_url(info: dict[str, object]) -> bool:
    """True si el paquete tiene una URL de repositorio en project_urls o home_page."""
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        repo_keys = {"Source", "Repository", "Source Code", "Code", "Homepage"}
        for key, url in project_urls.items():
            if key in repo_keys and isinstance(url, str) and url.startswith("http"):
                return True
    home_page = info.get("home_page")
    if isinstance(home_page, str) and home_page.startswith("http"):
        return True
    return False


def _truthy_str(value: object) -> str:
    """Devuelve el string si no esta vacio ni es 'UNKNOWN', de lo contrario ''."""
    if not isinstance(value, str):
        return ""
    stripped = value.strip()
    if not stripped or stripped.upper() in {"UNKNOWN", "NONE", "N/A"}:
        return ""
    return stripped
