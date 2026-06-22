"""Pruebas de la cache en disco segura (T16/T17, R9.1-R9.7, NFR-Seg.6).

Cubre: hit/miss/TTL al limite, corrupcion/esquema viejo ⇒ miss sin crashear,
carrera de escritura concurrente, perms 0700/0600, --no-cache, no persistencia de
unverifiable y anti path traversal por hash de clave.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from slopguard.core.adapters.base import (
    FetchOutcome,
    FetchState,
    PackageMetadata,
)
from slopguard.core.cache.disk_cache import DiskCache

# Epoch fijo para TTL determinista (2024-06-01T00:00:00Z), alineado con conftest.
_NOW: float = 1_717_200_000.0
_TTL_HORAS = 24
_TTL_SEGUNDOS = _TTL_HORAS * 3600


def _metadata(name: str = "requests") -> PackageMetadata:
    """Construye un metadato normalizado FOUND tipico."""
    return PackageMetadata(
        name=name,
        first_release_epoch=1_297_500_000.0,
        releases_count=148,
        has_repo_url=True,
        has_description=True,
        has_author=True,
        has_license=True,
        has_classifiers=True,
        in_top_n=True,
    )


def _found(name: str = "requests") -> FetchOutcome:
    return FetchOutcome(state=FetchState.FOUND, metadata=_metadata(name))


def _cache(tmp_path: Path, *, enabled: bool = True) -> DiskCache:
    return DiskCache(tmp_path / "cache", _TTL_HORAS, enabled=enabled)


def _cache_path(root: Path, ecosystem: str, name: str) -> Path:
    digest = hashlib.sha256(f"{ecosystem}:{name}".encode()).hexdigest()
    return root / f"{digest}.json"


# --- R9.1/R9.2: hit vigente devuelve el outcome sin red --------------------------


def test_put_then_get_hit_vigente(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put("pypi", "requests", _found(), now=_NOW)
    result = cache.get("pypi", "requests", now=_NOW + 10)
    assert result == _found()


def test_get_not_found_se_cachea_con_metadata_null(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put("pypi", "fake-pkg", FetchOutcome(state=FetchState.NOT_FOUND), now=_NOW)
    result = cache.get("pypi", "fake-pkg", now=_NOW)
    assert result == FetchOutcome(state=FetchState.NOT_FOUND)
    assert result is not None and result.metadata is None


def test_get_miss_cuando_no_existe_archivo(tmp_path: Path) -> None:
    assert _cache(tmp_path).get("pypi", "nunca-cacheado", now=_NOW) is None


# --- R9.3: --no-cache / enabled=False ⇒ ni lee ni escribe ------------------------


def test_disabled_no_escribe(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    cache = DiskCache(root, _TTL_HORAS, enabled=False)
    cache.put("pypi", "requests", _found())
    assert not root.exists()  # no creo el directorio ni el archivo


def test_disabled_no_lee_aunque_haya_archivo(tmp_path: Path) -> None:
    enabled = _cache(tmp_path)
    enabled.put("pypi", "requests", _found())
    disabled = DiskCache(tmp_path / "cache", _TTL_HORAS, enabled=False)
    assert disabled.get("pypi", "requests", now=_NOW) is None


# --- R9.5: TTL al limite, expirado y corrupto ⇒ miss sin crashear ---------------


def test_ttl_al_limite_exacto_es_hit(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    path = _write_raw(tmp_path, "pypi", "requests", _entry(fetched_at=_NOW))
    assert path.exists()
    # now justo en el borde del TTL: (now - fetched_at) == ttl ⇒ NO expirado.
    assert cache.get("pypi", "requests", now=_NOW + _TTL_SEGUNDOS) is not None


def test_ttl_un_segundo_pasado_el_limite_es_miss(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    _write_raw(tmp_path, "pypi", "requests", _entry(fetched_at=_NOW))
    assert cache.get("pypi", "requests", now=_NOW + _TTL_SEGUNDOS + 1) is None


def test_fetched_at_en_el_futuro_es_miss(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    _write_raw(tmp_path, "pypi", "requests", _entry(fetched_at=_NOW + 10_000))
    assert cache.get("pypi", "requests", now=_NOW) is None


def test_json_corrupto_es_miss_sin_crashear(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    path = _cache_path(tmp_path / "cache", "pypi", "requests")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"{ esto no es json valido ")
    assert cache.get("pypi", "requests", now=_NOW) is None


def test_json_no_es_objeto_es_miss(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    path = _cache_path(tmp_path / "cache", "pypi", "requests")
    path.parent.mkdir(parents=True)
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert cache.get("pypi", "requests", now=_NOW) is None


def test_esquema_viejo_es_miss(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    entry = _entry(fetched_at=_NOW)
    entry["cache_schema_version"] = "0"
    _write_raw(tmp_path, "pypi", "requests", entry)
    assert cache.get("pypi", "requests", now=_NOW) is None


@pytest.mark.parametrize(
    "mutacion",
    [
        {"fetched_at": "ayer"},
        {"fetched_at": True},
        {"state": "weird"},
        {"state": "unverifiable"},  # nunca debe estar en disco ⇒ miss
        {"metadata": None},  # FOUND sin metadata ⇒ incoherente
        {"ecosystem": "npm"},  # ecosystem distinto ⇒ defensa anti-colision
        {"name": "otro"},
    ],
)
def test_entradas_invalidas_son_miss(tmp_path: Path, mutacion: dict[str, Any]) -> None:
    cache = _cache(tmp_path)
    entry = _entry(fetched_at=_NOW)
    entry.update(mutacion)
    _write_raw(tmp_path, "pypi", "requests", entry)
    assert cache.get("pypi", "requests", now=_NOW) is None


@pytest.mark.parametrize(
    "campo,valor",
    [
        ("releases_count", -1),
        ("releases_count", "muchos"),
        ("releases_count", True),
        ("first_release_epoch", "fecha"),
        ("first_release_epoch", -5),
        ("has_repo_url", "si"),
        ("has_author", 1),
        ("name", "otro-nombre"),
    ],
)
def test_metadata_con_tipos_invalidos_es_miss(
    tmp_path: Path, campo: str, valor: Any
) -> None:
    cache = _cache(tmp_path)
    entry = _entry(fetched_at=_NOW)
    assert isinstance(entry["metadata"], dict)
    entry["metadata"][campo] = valor
    _write_raw(tmp_path, "pypi", "requests", entry)
    assert cache.get("pypi", "requests", now=_NOW) is None


def test_first_release_null_es_valido(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    entry = _entry(fetched_at=_NOW)
    assert isinstance(entry["metadata"], dict)
    entry["metadata"]["first_release_epoch"] = None
    _write_raw(tmp_path, "pypi", "requests", entry)
    result = cache.get("pypi", "requests", now=_NOW)
    assert result is not None
    assert result.metadata is not None
    assert result.metadata.first_release_epoch is None


# --- §2.6: unverifiable NO se persiste -----------------------------------------


def test_unverifiable_no_se_persiste(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put("pypi", "flaky", FetchOutcome(state=FetchState.UNVERIFIABLE))
    path = _cache_path(tmp_path / "cache", "pypi", "flaky")
    assert not path.exists()
    assert cache.get("pypi", "flaky", now=_NOW) is None


# --- R9.7: perms 0700 dir / 0600 archivo ---------------------------------------


def test_permisos_dir_0700_y_archivo_0600(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    cache = DiskCache(root, _TTL_HORAS, enabled=True)
    cache.put("pypi", "requests", _found())
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    path = _cache_path(root, "pypi", "requests")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_dir_preexistente_laxo_se_reendurece_a_0700(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    root.mkdir(mode=0o755)
    cache = DiskCache(root, _TTL_HORAS, enabled=True)
    cache.put("pypi", "requests", _found())
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


# --- R9.6: escritura atomica y concurrencia ------------------------------------


def test_escritura_concurrente_no_corrompe_ni_deja_temporales(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    cache = DiskCache(root, _TTL_HORAS, enabled=True)

    def _put(index: int) -> None:
        # Misma clave: todos compiten por el mismo archivo final (peor caso de carrera).
        cache.put("pypi", "requests", _found(), now=_NOW)
        cache.get("pypi", "requests", now=_NOW)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(_put, range(200)))

    result = cache.get("pypi", "requests", now=_NOW)
    assert result == _found()  # entrada final integra, nunca a medias
    temporales = list(root.glob("*.tmp"))
    assert temporales == []  # ningun temporal huerfano


def test_escritura_atomica_no_deja_archivo_a_medias_ante_fallo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "cache"
    cache = DiskCache(root, _TTL_HORAS, enabled=True)
    cache.put("pypi", "requests", _found(), now=_NOW)  # entrada buena previa

    # Simulo un fallo de E/S en el rename: la entrada previa debe sobrevivir intacta.
    def _boom(src: Any, dst: Any) -> None:
        raise OSError("disco lleno")

    monkeypatch.setattr(os, "replace", _boom)
    cache.put("pypi", "requests", _found("otro"), now=_NOW)  # no debe crashear

    monkeypatch.undo()
    result = cache.get("pypi", "requests", now=_NOW)
    assert result == _found()  # sigue la entrada original, no corrupta
    assert list(root.glob("*.tmp")) == []  # temporal limpiado tras el fallo


# --- Anti path traversal por hash de clave -------------------------------------


@pytest.mark.parametrize(
    "name",
    ["../../etc/passwd", "a/b/c", "..", "name\x00ofile", "con espacios"],
)
def test_clave_maliciosa_no_escapa_del_root(tmp_path: Path, name: str) -> None:
    root = tmp_path / "cache"
    cache = DiskCache(root, _TTL_HORAS, enabled=True)
    cache.put("pypi", name, FetchOutcome(state=FetchState.NOT_FOUND))
    # Todo archivo creado vive dentro de root y su nombre es solo hex + .json.
    archivos = [p for p in root.iterdir() if p.is_file()]
    assert archivos, "se esperaba al menos una entrada"
    for archivo in archivos:
        assert archivo.parent == root
        assert archivo.suffix == ".json"
        assert all(ch in "0123456789abcdef" for ch in archivo.stem)


# --- Helpers de fixtures crudas -------------------------------------------------


def _entry(*, fetched_at: float) -> dict[str, Any]:
    """Entrada de cache valida y completa (espejo del formato §2.6)."""
    return {
        "cache_schema_version": "1",
        "ecosystem": "pypi",
        "name": "requests",
        "fetched_at": fetched_at,
        "state": "found",
        "metadata": {
            "name": "requests",
            "first_release_epoch": 1_297_500_000.0,
            "releases_count": 148,
            "has_repo_url": True,
            "has_description": True,
            "has_author": True,
            "has_license": True,
            "has_classifiers": True,
            "in_top_n": True,
        },
    }


def _write_raw(tmp_path: Path, ecosystem: str, name: str, entry: dict[str, Any]) -> Path:
    """Escribe una entrada cruda directamente en el path de cache (bypass de put)."""
    path = _cache_path(tmp_path / "cache", ecosystem, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entry), encoding="utf-8")
    return path
