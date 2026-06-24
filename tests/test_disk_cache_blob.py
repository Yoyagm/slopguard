"""Pruebas de la cache blob generica (H2-T05, RISK-H2-2, §2.5).

Cubre `get_blob`/`put_blob`: hit vigente sin red, clave namespaced anti-traversal,
TTL por-llamada, esquema desviado/corrupto/`state=unverifiable` ⇒ miss, validador
inyectado que rechaza ⇒ miss, `--no-cache`/`enabled=False` ⇒ no lee/escribe, JSON-only,
perms 0700/0600, no persistencia de UNVERIFIABLE, separacion del camino tipado del Hito 1.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from slopguard.core.cache.disk_cache import DiskCache

# Epoch fijo para TTL determinista (alineado con conftest del Hito 1).
_NOW: float = 1_717_200_000.0
_OSV_TTL = 6 * 3600
_WATCHLIST_TTL = 24 * 3600


def _cache(tmp_path: Path, *, enabled: bool = True) -> DiskCache:
    """Cache blob con TTL del constructor irrelevante (los blobs usan TTL por-llamada)."""
    return DiskCache(tmp_path / "cache", 24, enabled=enabled)


def _blob_path(root: Path, namespace: str, key: str) -> Path:
    digest = hashlib.sha256(f"{namespace}:{key}".encode()).hexdigest()
    return root / f"{digest}.json"


def _read_raw(root: Path, namespace: str, key: str) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(_blob_path(root, namespace, key).read_bytes())
    return parsed


def _identity_validator(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Validador trivial: acepta el payload tal cual (devuelve None solo si lo rechaza)."""
    return payload


def _osv_payload(name: str = "bioql") -> dict[str, Any]:
    return {
        "source": "osv",
        "ecosystem": "pypi",
        "name": name,
        "state": "malicious",
        "advisories": [{"id": "MAL-2025-47868", "kind": "malicious", "source": "osv"}],
    }


# --- Hit vigente sin red + sellado de control -----------------------------------


def test_put_then_get_blob_hit_vigente(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
    got = cache.get_blob(
        "osv", "pypi:bioql", _identity_validator, ttl_segundos=_OSV_TTL, now=_NOW
    )
    assert got is not None
    assert got["name"] == "bioql"
    assert got["state"] == "malicious"


def test_put_blob_sella_schema_y_fetched_at(tmp_path: Path) -> None:
    """put_blob fija `cache_schema_version="ti-1"` y `fetched_at`, no el caller."""
    cache = _cache(tmp_path)
    cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
    raw = _read_raw(tmp_path / "cache", "osv", "pypi:bioql")
    assert raw["cache_schema_version"] == "ti-1"
    assert raw["fetched_at"] == _NOW


def test_put_blob_sobrescribe_control_del_caller(tmp_path: Path) -> None:
    """Aunque el caller inyecte control falso, put_blob lo sobreescribe (defensa)."""
    cache = _cache(tmp_path)
    payload = {**_osv_payload(), "cache_schema_version": "MALO", "fetched_at": 0.0}
    cache.put_blob("osv", "pypi:bioql", payload, now=_NOW)
    raw = _read_raw(tmp_path / "cache", "osv", "pypi:bioql")
    assert raw["cache_schema_version"] == "ti-1"
    assert raw["fetched_at"] == _NOW


def test_get_blob_miss_cuando_no_existe(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    got = cache.get_blob(
        "osv", "pypi:ausente", _identity_validator, ttl_segundos=_OSV_TTL, now=_NOW
    )
    assert got is None


# --- enabled=False / --no-cache ⇒ ni lee ni escribe -----------------------------


def test_disabled_no_escribe_blob(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    cache = DiskCache(root, 24, enabled=False)
    cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
    assert not _blob_path(root, "osv", "pypi:bioql").exists()


def test_disabled_no_lee_blob_aunque_haya_archivo(tmp_path: Path) -> None:
    enabled = _cache(tmp_path)
    enabled.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
    disabled = DiskCache(tmp_path / "cache", 24, enabled=False)
    got = disabled.get_blob(
        "osv", "pypi:bioql", _identity_validator, ttl_segundos=_OSV_TTL, now=_NOW
    )
    assert got is None


# --- TTL por-llamada (OSV 6h ≠ watchlist 24h) -----------------------------------


def test_ttl_blob_al_limite_exacto_es_hit(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
    got = cache.get_blob(
        "osv",
        "pypi:bioql",
        _identity_validator,
        ttl_segundos=_OSV_TTL,
        now=_NOW + _OSV_TTL,
    )
    assert got is not None


def test_ttl_blob_un_segundo_pasado_es_miss(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
    got = cache.get_blob(
        "osv",
        "pypi:bioql",
        _identity_validator,
        ttl_segundos=_OSV_TTL,
        now=_NOW + _OSV_TTL + 1,
    )
    assert got is None


def test_ttl_independiente_por_llamada(tmp_path: Path) -> None:
    """El mismo blob es hit con TTL 24h y miss con TTL 6h para el mismo `now`."""
    cache = _cache(tmp_path)
    cache.put_blob("watchlist", "depscope.dev/api", {"names": ["reqe"]}, now=_NOW)
    later = _NOW + _OSV_TTL + 1
    assert (
        cache.get_blob(
            "watchlist", "depscope.dev/api", _identity_validator,
            ttl_segundos=_WATCHLIST_TTL, now=later,
        )
        is not None
    )
    assert (
        cache.get_blob(
            "watchlist", "depscope.dev/api", _identity_validator,
            ttl_segundos=_OSV_TTL, now=later,
        )
        is None
    )


def test_fetched_at_en_el_futuro_es_miss(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
    got = cache.get_blob(
        "osv", "pypi:bioql", _identity_validator, ttl_segundos=_OSV_TTL, now=_NOW - 1
    )
    assert got is None


# --- Entrada NO confiable: esquema/corrupto/control ⇒ miss ----------------------


def test_schema_desviado_es_miss(tmp_path: Path) -> None:
    """Un blob con `cache_schema_version` distinto de "ti-1" ⇒ miss (separa del Hito 1)."""
    cache = _cache(tmp_path)
    path = _blob_path(tmp_path / "cache", "osv", "pypi:bioql")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        json.dumps({**_osv_payload(), "cache_schema_version": "1", "fetched_at": _NOW})
        .encode()
    )
    got = cache.get_blob(
        "osv", "pypi:bioql", _identity_validator, ttl_segundos=_OSV_TTL, now=_NOW
    )
    assert got is None


def test_json_corrupto_blob_es_miss_sin_crashear(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    path = _blob_path(tmp_path / "cache", "osv", "pypi:bioql")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"{ no es json valido")
    got = cache.get_blob(
        "osv", "pypi:bioql", _identity_validator, ttl_segundos=_OSV_TTL, now=_NOW
    )
    assert got is None


def test_json_no_objeto_blob_es_miss(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    path = _blob_path(tmp_path / "cache", "osv", "pypi:bioql")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"[1, 2, 3]")
    got = cache.get_blob(
        "osv", "pypi:bioql", _identity_validator, ttl_segundos=_OSV_TTL, now=_NOW
    )
    assert got is None


def test_validador_que_rechaza_es_miss(tmp_path: Path) -> None:
    """Si el validador inyectado devuelve None (schema/charset/cap de la fuente) ⇒ miss."""
    cache = _cache(tmp_path)
    cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)

    def _reject(_payload: dict[str, Any]) -> dict[str, Any] | None:
        return None

    got = cache.get_blob(
        "osv", "pypi:bioql", _reject, ttl_segundos=_OSV_TTL, now=_NOW
    )
    assert got is None


# --- UNVERIFIABLE nunca se cachea (degradacion segura) --------------------------


def test_unverifiable_no_se_persiste(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    payload = {**_osv_payload("flaky"), "state": "unverifiable"}
    cache.put_blob("osv", "pypi:flaky", payload, now=_NOW)
    assert not _blob_path(tmp_path / "cache", "osv", "pypi:flaky").exists()


def test_unverifiable_aunque_haya_advisories_no_se_persiste(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put_blob("osv", "pypi:x", {"name": "x", "state": "unverifiable"}, now=_NOW)
    assert not _blob_path(tmp_path / "cache", "osv", "pypi:x").exists()


# --- Anti path traversal + separacion del camino tipado del Hito 1 --------------


def test_clave_namespaced_anti_traversal(tmp_path: Path) -> None:
    """Una key con `../` no escapa del root: el nombre en disco es solo el hexdigest."""
    cache = _cache(tmp_path)
    cache.put_blob("osv", "pypi:../../etc/passwd", _osv_payload("evil"), now=_NOW)
    root = tmp_path / "cache"
    archivos = [p.name for p in root.iterdir() if p.suffix == ".json"]
    assert len(archivos) == 1
    assert all(c in "0123456789abcdef" for c in archivos[0].removesuffix(".json"))


def test_namespace_separa_del_camino_tipado(tmp_path: Path) -> None:
    """`osv:pypi:bioql` (blob) y `pypi:bioql` (tipado) producen archivos distintos."""
    blob_path = _blob_path(tmp_path / "cache", "osv", "pypi:bioql")
    typed_digest = hashlib.sha256(b"pypi:bioql").hexdigest()
    typed_path = tmp_path / "cache" / f"{typed_digest}.json"
    assert blob_path != typed_path


def test_namespaces_distintos_no_colisionan(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put_blob("osv", "k", {"who": "osv"}, now=_NOW)
    cache.put_blob("watchlist", "k", {"who": "watchlist"}, now=_NOW)
    osv = cache.get_blob(
        "osv", "k", _identity_validator, ttl_segundos=_OSV_TTL, now=_NOW
    )
    wl = cache.get_blob(
        "watchlist", "k", _identity_validator, ttl_segundos=_WATCHLIST_TTL, now=_NOW
    )
    assert osv is not None and osv["who"] == "osv"
    assert wl is not None and wl["who"] == "watchlist"


# --- Perms 0700/0600 + escritura atomica JSON-only ------------------------------


def test_blob_perms_dir_0700_archivo_0600(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    cache = DiskCache(root, 24, enabled=True)
    cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
    assert stat.S_IMODE(os.stat(root).st_mode) == 0o700
    path = _blob_path(root, "osv", "pypi:bioql")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_blob_es_json_no_pickle(tmp_path: Path) -> None:
    """El blob en disco es JSON parseable, nunca un binario pickle/marshal."""
    cache = _cache(tmp_path)
    cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
    raw = _blob_path(tmp_path / "cache", "osv", "pypi:bioql").read_bytes()
    assert json.loads(raw)["source"] == "osv"  # parsea como JSON sin excepcion
