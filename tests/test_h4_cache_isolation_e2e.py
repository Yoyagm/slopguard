"""H4-T37: aislamiento end-to-end de TODAS las caches entre ecosistemas (NFR-Seg.3, §7.2 pto 4).

Cierra el invariante de aislamiento *de forma compuesta y sobre disco real*: una corrida
npm y una corrida PyPI del **mismo nombre** (`react`/`lodash`, que existen en ambos
ecosistemas) NO comparten blob en NINGUNA de las cuatro caches —OSV, L4, watchlist y la
del adapter— aunque compartan el MISMO `DiskCache` (mismo root en disco).

A diferencia de los tests por-fuente (`test_h4_osv_npm.py`, `test_layer4_npm.py`,
`test_h4_watchlist_npm.py`), que verifican una sola fuente con la cache deshabilitada, aqui
se persiste de verdad en un `tmp_path` compartido y se comprueban las **DOS lineas de
defensa** que exige §7.2 pto 4, para que un bug en una sola de ellas no pase desapercibido:

  (a) **Por construccion (clave/namespace):** las claves/namespaces difieren (prefijos
      `npm:`/`pypi:` en OSV/watchlist/L4; namespace `npm`/`pypi` en el adapter). Un blob
      escrito por un ecosistema queda en un archivo distinto del otro ⇒ la lectura ajena
      es un MISS (refetch), nunca un HIT cruzado.

  (b) **Por validador (segunda capa):** aunque un blob del ecosistema ajeno se forzara bajo
      la clave del ecosistema correcto (clave malformada por un bug), `_validate_osv_blob`
      (OSV) y `_validate_blob` (L4) lo RECHAZAN (⇒ None ⇒ miss) por el campo `ecosystem`.
      Asi el aislamiento sobrevive a un bug que malforme la clave.

Comportamiento observable, no detalles internos: se ejercita la API publica de cache
(`get_blob`/`put_blob`, `get`/`put`) y los validadores reales de cada fuente. Sin red.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from slopguard.core.adapters.base import FetchOutcome, FetchState, PackageMetadata
from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config
from slopguard.core.llm.resolver import _cache_key as l4_cache_key
from slopguard.core.llm.resolver import _to_blob as l4_to_blob
from slopguard.core.llm.resolver import _validate_blob as l4_validate_blob
from slopguard.core.models import (
    Clasificacion,
    HallucinationContext,
    LlmAssessment,
)
from slopguard.core.threatintel.osv import OsvSource, _parse_batch_response
from slopguard.core.threatintel.source import MaliceState, ThreatIntelResult
from slopguard.core.threatintel.watchlist import WatchlistSource

if TYPE_CHECKING:
    from pathlib import Path

_NOW_EPOCH = 1_700_000_000.0

# Nombres que existen en AMBOS ecosistemas: el caso exacto que el aislamiento debe separar.
_SHARED_NAMES = ("react", "lodash")


# --------------------------------------------------------------------------- #
# Constructores deterministas.
# --------------------------------------------------------------------------- #


def _config() -> Config:
    return Config(
        connect_timeout_s=2.0,
        read_timeout_s=2.0,
        osv_timeout_total_por_lote_s=2.0,
        osv_reintentos=1,
    )


def _osv_clean(name: str) -> ThreatIntelResult:
    """`ThreatIntelResult` CLEAN reusando el parser real (sin red): la unica via publica."""
    return _parse_batch_response({"results": [{"vulns": []}]}, [name])[name]


def _assessment() -> LlmAssessment:
    return LlmAssessment(
        clasificacion=Clasificacion.FABRICACION,
        confianza=1.0,
        patron="p",
        rationale="r",
        modelo="claude-opus-4-8",
        prompt_version="h4-v1",
    )


def _context() -> HallucinationContext:
    return HallucinationContext(
        existe=True,
        edad_dias=10,
        typo_vecino=None,
        typo_distancia=None,
        tiene_repo=False,
        tiene_metadata=False,
        senales_blandas=(),
    )


def _found_outcome(name: str) -> FetchOutcome:
    return FetchOutcome(
        state=FetchState.FOUND,
        metadata=PackageMetadata(
            name=name,
            first_release_epoch=_NOW_EPOCH - 86400,
            releases_count=1,
            has_repo_url=False,
            has_description=False,
            has_author=False,
            has_license=False,
            has_classifiers=False,
            in_top_n=False,
        ),
    )


def _shared_cache(tmp_path: Path) -> DiskCache:
    """Un UNICO `DiskCache` sobre disco real, compartido por npm y PyPI (mismo root)."""
    return DiskCache(tmp_path, _config().osv_ttl_cache_horas, enabled=True)


def _osv_source(config: Config, cache: DiskCache, ecosystem_id: str) -> OsvSource:
    """`OsvSource` del ecosistema con su `_cache` apuntando al root compartido (sin red)."""
    source = OsvSource(config, ecosystem_id=ecosystem_id, use_cache=True)
    source._cache = cache  # inyeccion de cache compartida (mismo patron que los tests H2)
    return source


def _watchlist_source(
    config: Config, cache: DiskCache, ecosystem_id: str
) -> WatchlistSource:
    source = WatchlistSource(config, ecosystem_id=ecosystem_id, use_cache=True)
    source._cache = cache
    return source


# --------------------------------------------------------------------------- #
# OSV — aislamiento end-to-end sobre disco compartido (clave Y validador).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", _SHARED_NAMES)
def test_osv_blob_npm_no_es_legible_en_una_corrida_pypi(
    tmp_path: Path, name: str
) -> None:
    # (a) Por construccion: npm persiste su blob CLEAN; PyPI lee del MISMO root y NO lo ve.
    config = _config()
    cache = _shared_cache(tmp_path)
    npm = _osv_source(config, cache, "npm")
    pypi = _osv_source(config, cache, "pypi")

    key_npm = npm._cache_key(name)
    cache.put_blob("osv", key_npm, npm._to_blob(_osv_clean(name)), now=_NOW_EPOCH)

    # La clave de PyPI difiere (prefijo distinto) ⇒ el blob npm no esta bajo la clave PyPI.
    assert npm._cache_key(name) != pypi._cache_key(name)
    miss_pypi = cache.get_blob(
        "osv", pypi._cache_key(name),
        lambda payload: pypi._validate_osv_blob(payload, name),
        ttl_segundos=config.osv_ttl_cache_horas * 3600, now=_NOW_EPOCH,
    )
    assert miss_pypi is None  # PyPI no hereda el veredicto npm
    # Sanidad: el propio npm SI relee su blob (la persistencia funciona, no es un falso miss).
    hit_npm = cache.get_blob(
        "osv", key_npm,
        lambda payload: npm._validate_osv_blob(payload, name),
        ttl_segundos=config.osv_ttl_cache_horas * 3600, now=_NOW_EPOCH,
    )
    assert hit_npm is not None and hit_npm.state is MaliceState.CLEAN


@pytest.mark.parametrize("name", _SHARED_NAMES)
def test_osv_validador_atrapa_un_blob_npm_forzado_bajo_la_clave_pypi(
    tmp_path: Path, name: str
) -> None:
    # (b) Por validador: aun si un bug escribiera el blob npm BAJO la clave PyPI (clave
    # malformada), `_validate_osv_blob` lo rechaza por el campo `ecosystem` ⇒ miss ⇒ refetch.
    config = _config()
    cache = _shared_cache(tmp_path)
    npm = _osv_source(config, cache, "npm")
    pypi = _osv_source(config, cache, "pypi")

    blob_npm = npm._to_blob(_osv_clean(name))
    assert blob_npm["ecosystem"] == "npm"  # el blob lleva su ecosistema sellado
    cache.put_blob("osv", pypi._cache_key(name), blob_npm, now=_NOW_EPOCH)

    leido_como_pypi = cache.get_blob(
        "osv", pypi._cache_key(name),
        lambda payload: pypi._validate_osv_blob(payload, name),
        ttl_segundos=config.osv_ttl_cache_horas * 3600, now=_NOW_EPOCH,
    )
    assert leido_como_pypi is None  # el validador rechaza el ecosistema ajeno


# --------------------------------------------------------------------------- #
# Capa 4 (LLM) — aislamiento end-to-end sobre disco compartido (clave Y validador).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", _SHARED_NAMES)
def test_l4_blob_npm_no_es_legible_en_una_corrida_pypi(
    tmp_path: Path, name: str
) -> None:
    # (a) Por construccion: la clave L4 antepone el ecosistema; npm y PyPI no colisionan.
    config = Config()
    cache = DiskCache(tmp_path, config.llm_ttl_cache_horas, enabled=True)
    context = _context()

    key_npm = l4_cache_key(name, context, config, "npm")
    key_pypi = l4_cache_key(name, context, config, "pypi")
    assert key_npm != key_pypi
    assert key_npm.split("|")[0] == "npm"

    cache.put_blob(
        "llm", key_npm, l4_to_blob(_assessment(), "npm"),
        schema_version="llm-1", now=_NOW_EPOCH,
    )
    miss_pypi = cache.get_blob(
        "llm", key_pypi, lambda payload: l4_validate_blob(payload, "pypi"),
        ttl_segundos=config.llm_ttl_cache_horas * 3600,
        schema_version="llm-1", now=_NOW_EPOCH,
    )
    assert miss_pypi is None
    hit_npm = cache.get_blob(
        "llm", key_npm, lambda payload: l4_validate_blob(payload, "npm"),
        ttl_segundos=config.llm_ttl_cache_horas * 3600,
        schema_version="llm-1", now=_NOW_EPOCH,
    )
    assert hit_npm is not None and hit_npm.clasificacion is Clasificacion.FABRICACION


@pytest.mark.parametrize("name", _SHARED_NAMES)
def test_l4_validador_atrapa_un_blob_pypi_forzado_bajo_la_clave_npm(
    tmp_path: Path, name: str
) -> None:
    # (b) Por validador: un blob L4 sellado `ecosystem=="pypi"` persistido BAJO la clave npm
    # (clave malformada por un bug) se RECHAZA al leer como npm ⇒ miss (NFR-Seg.3, §7.2 pto 4).
    config = Config()
    cache = DiskCache(tmp_path, config.llm_ttl_cache_horas, enabled=True)
    context = _context()
    key_npm = l4_cache_key(name, context, config, "npm")

    cache.put_blob(
        "llm", key_npm, l4_to_blob(_assessment(), "pypi"),
        schema_version="llm-1", now=_NOW_EPOCH,
    )
    leido_como_npm = cache.get_blob(
        "llm", key_npm, lambda payload: l4_validate_blob(payload, "npm"),
        ttl_segundos=config.llm_ttl_cache_horas * 3600,
        schema_version="llm-1", now=_NOW_EPOCH,
    )
    assert leido_como_npm is None


# --------------------------------------------------------------------------- #
# Watchlist — aislamiento end-to-end (clave prefijada por ecosistema, ADR-8).
# --------------------------------------------------------------------------- #


def test_watchlist_npm_y_pypi_no_comparten_blob_de_corpus(tmp_path: Path) -> None:
    # La clave de corpus difiere por prefijo de ecosistema: un blob de corpus escrito por npm
    # no es legible como el corpus PyPI (mismo host/path), y viceversa, sobre el MISMO root.
    config = Config(connect_timeout_s=2.0, read_timeout_s=2.0)
    cache = DiskCache(tmp_path, config.watchlist_ttl_cache_horas, enabled=True)
    npm = _watchlist_source(config, cache, "npm")
    pypi = _watchlist_source(config, cache, "pypi")

    assert npm._cache_key.startswith("npm:")
    assert pypi._cache_key.startswith("pypi:")
    assert npm._cache_key != pypi._cache_key

    corpus_blob = {
        "source": "watchlist",
        "host": config.watchlist_host,
        "license": "CC-BY-NC-SA-4.0",
        "corpus_date": "2024-01-01",
        "names": ["lodahs"],
    }
    cache.put_blob(
        "watchlist", npm._cache_key, dict(corpus_blob), now=_NOW_EPOCH
    )

    # PyPI lee del MISMO root con SU clave (prefijo pypi:) ⇒ no encuentra el corpus npm.
    miss_pypi = cache.get_blob(
        "watchlist", pypi._cache_key, pypi._validate_blob,
        ttl_segundos=config.watchlist_ttl_cache_horas * 3600, now=_NOW_EPOCH,
    )
    assert miss_pypi is None
    # npm SI relee su propio corpus (la persistencia es real, no un falso miss).
    hit_npm = cache.get_blob(
        "watchlist", npm._cache_key, npm._validate_blob,
        ttl_segundos=config.watchlist_ttl_cache_horas * 3600, now=_NOW_EPOCH,
    )
    assert hit_npm is not None
    assert "lodahs" in hit_npm.names


# --------------------------------------------------------------------------- #
# Adapter — aislamiento de la cache tipada por namespace de ecosistema.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", _SHARED_NAMES)
def test_adapter_cache_npm_no_es_legible_en_una_corrida_pypi(
    tmp_path: Path, name: str
) -> None:
    # La cache tipada del adapter (get/put) hashea `f"{ecosystem_id}:{name}"`: un FOUND
    # de npm para `react` no es legible como el `react` de PyPI (archivos de disco distintos).
    config = Config()
    cache = DiskCache(tmp_path, config.ttl_cache_horas, enabled=True)

    cache.put("npm", name, _found_outcome(name), now=_NOW_EPOCH)

    # PyPI consulta el MISMO root con su propio namespace ⇒ miss (no hereda metadata npm).
    assert cache.get("pypi", name, now=_NOW_EPOCH) is None
    # npm SI relee su FOUND (persistencia real).
    hit_npm = cache.get("npm", name, now=_NOW_EPOCH)
    assert hit_npm is not None and hit_npm.state is FetchState.FOUND


@pytest.mark.parametrize("name", _SHARED_NAMES)
def test_adapter_cache_pypi_no_es_legible_en_una_corrida_npm(
    tmp_path: Path, name: str
) -> None:
    # Simetria inversa: un FOUND PyPI no se sirve a una consulta npm del mismo nombre.
    config = Config()
    cache = DiskCache(tmp_path, config.ttl_cache_horas, enabled=True)

    cache.put("pypi", name, _found_outcome(name), now=_NOW_EPOCH)

    assert cache.get("npm", name, now=_NOW_EPOCH) is None
    assert cache.get("pypi", name, now=_NOW_EPOCH) is not None


# --------------------------------------------------------------------------- #
# Sintesis end-to-end: las CUATRO cachas a la vez sobre un unico root compartido.
# --------------------------------------------------------------------------- #


def test_ninguna_de_las_cuatro_caches_cruza_entre_ecosistemas(tmp_path: Path) -> None:
    # Una corrida npm escribe en OSV + L4 + watchlist + adapter sobre un UNICO root; una
    # corrida PyPI del mismo nombre NO hereda NINGUNO de los cuatro veredictos cacheados.
    name = "react"
    config = Config(connect_timeout_s=2.0, read_timeout_s=2.0)
    osv_cache = DiskCache(tmp_path, config.osv_ttl_cache_horas, enabled=True)
    l4_cache = DiskCache(tmp_path, config.llm_ttl_cache_horas, enabled=True)
    wl_cache = DiskCache(tmp_path, config.watchlist_ttl_cache_horas, enabled=True)
    adapter_cache = DiskCache(tmp_path, config.ttl_cache_horas, enabled=True)
    context = _context()

    # --- npm persiste sus cuatro blobs ---
    npm_osv = _osv_source(config, osv_cache, "npm")
    osv_cache.put_blob(
        "osv", npm_osv._cache_key(name), npm_osv._to_blob(_osv_clean(name)), now=_NOW_EPOCH
    )
    l4_cache.put_blob(
        "llm", l4_cache_key(name, context, config, "npm"),
        l4_to_blob(_assessment(), "npm"), schema_version="llm-1", now=_NOW_EPOCH,
    )
    npm_wl = _watchlist_source(config, wl_cache, "npm")
    wl_cache.put_blob(
        "watchlist", npm_wl._cache_key,
        {
            "source": "watchlist", "host": config.watchlist_host,
            "license": "CC-BY-NC-SA-4.0", "corpus_date": "2024-01-01", "names": [name],
        },
        now=_NOW_EPOCH,
    )
    adapter_cache.put("npm", name, _found_outcome(name), now=_NOW_EPOCH)

    # --- PyPI lee del MISMO root: las cuatro lecturas son miss (sin cruce) ---
    pypi_osv = _osv_source(config, osv_cache, "pypi")
    assert osv_cache.get_blob(
        "osv", pypi_osv._cache_key(name),
        lambda payload: pypi_osv._validate_osv_blob(payload, name),
        ttl_segundos=config.osv_ttl_cache_horas * 3600, now=_NOW_EPOCH,
    ) is None
    assert l4_cache.get_blob(
        "llm", l4_cache_key(name, context, config, "pypi"),
        lambda payload: l4_validate_blob(payload, "pypi"),
        ttl_segundos=config.llm_ttl_cache_horas * 3600,
        schema_version="llm-1", now=_NOW_EPOCH,
    ) is None
    pypi_wl = _watchlist_source(config, wl_cache, "pypi")
    assert wl_cache.get_blob(
        "watchlist", pypi_wl._cache_key, pypi_wl._validate_blob,
        ttl_segundos=config.watchlist_ttl_cache_horas * 3600, now=_NOW_EPOCH,
    ) is None
    assert adapter_cache.get("pypi", name, now=_NOW_EPOCH) is None
