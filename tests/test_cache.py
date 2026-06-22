"""Suite de subsistemas correctness/security-critical: cache (T16/T17), net con
servidor HTTP local malicioso real (T15), similaridad (T29 parcial), manifiestos
(T12) y dataset (R3.9).

Cubre camino feliz, casos borde Y modos de fallo de los criterios EARS:
- cache (R9.1-R9.7, NFR-Seg.6): TTL al limite/expirado, corrupcion->miss, escritura
  concurrente con ThreadPool, perms 0700/0600, --no-cache, no persistencia de
  unverifiable, anti path traversal por hash de clave.
- net (NFR-Seg.3-4): servidor `http.server` local que sirve redireccion cross-host y
  cross-scheme, respuesta gigante, Content-Length excesivo, JSON profundo y gzip-bomb;
  cada escenario produce `NetworkUnverifiableError` SIN materializar el payload.
- similaridad (R3.1, ADR-02): tabla DL con transposiciones (`ab<->ba`, `attrs/attr`,
  `requests/reqursts`, `martha/marhta`) + off-by-one + 6 vectores JW de referencia.
- manifiestos (R1.5/R1.6/R1.9, T12): includes con `../`/absoluto/ciclo, limites de
  tamano/deps, vacio->0 deps, malformado->error sin stacktrace, --manifest-type.
- dataset (R3.9): checksum ausente/corrupto->DatasetIntegrityError; indices vs fixture.

El servidor local es real (sockets reales): la allowlist de `core.net` se relaja a
`http://127.0.0.1` SOLO dentro del fixture, de modo que `SecureHttpClient.get_json`
ejercita el camino real de urllib (streaming, descompresion, redirect handler propio)
contra escenarios maliciosos servidos en vivo, sin tocar PyPI.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import stat
import threading
import urllib.request
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from slopguard.core.adapters.base import FetchOutcome, FetchState, PackageMetadata
from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config
from slopguard.core.dataset.top_n import build_top_n, load_top_n
from slopguard.core.errors import (
    DatasetIntegrityError,
    ManifestParseError,
    NetworkUnverifiableError,
)
from slopguard.core.layers.similarity.damerau import damerau_levenshtein_bounded
from slopguard.core.layers.similarity.jaro_winkler import jaro_winkler
from slopguard.core.manifests.detect import detect_and_parse
from slopguard.core.net import http_client as hc
from slopguard.core.net.http_client import SecureHttpClient

# Epoch fijo (2024-06-01T00:00:00Z) para TTL determinista (NFR-Det.1).
_NOW: float = 1_717_200_000.0
_TTL_HORAS = 24
_TTL_SEGUNDOS = _TTL_HORAS * 3600
_CFG = Config()


# =========================================================================== #
# Helpers de cache
# =========================================================================== #


def _metadata(name: str = "requests") -> PackageMetadata:
    """Metadato normalizado FOUND tipico (espejo de §2.6)."""
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


def _entry(*, fetched_at: float) -> dict[str, Any]:
    """Entrada de cache valida y completa (formato §2.6)."""
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
    """Escribe una entrada cruda directamente (bypass de put) para fixtures defensivas."""
    path = _cache_path(tmp_path / "cache", ecosystem, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entry), encoding="utf-8")
    return path


# =========================================================================== #
# CACHE — R9.1/R9.2: hit vigente sin red (camino feliz)
# =========================================================================== #


def test_cache_put_then_get_hit_vigente(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put("pypi", "requests", _found(), now=_NOW)
    assert cache.get("pypi", "requests", now=_NOW + 10) == _found()


def test_cache_not_found_se_cachea_con_metadata_null(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put("pypi", "fake-pkg", FetchOutcome(state=FetchState.NOT_FOUND), now=_NOW)
    result = cache.get("pypi", "fake-pkg", now=_NOW)
    assert result == FetchOutcome(state=FetchState.NOT_FOUND)
    assert result is not None and result.metadata is None


def test_cache_miss_cuando_no_existe_archivo(tmp_path: Path) -> None:
    assert _cache(tmp_path).get("pypi", "nunca", now=_NOW) is None


# =========================================================================== #
# CACHE — R9.3: --no-cache / enabled=False ni lee ni escribe
# =========================================================================== #


def test_cache_disabled_no_escribe(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    DiskCache(root, _TTL_HORAS, enabled=False).put("pypi", "requests", _found())
    assert not root.exists()


def test_cache_disabled_no_lee_aunque_haya_archivo(tmp_path: Path) -> None:
    _cache(tmp_path).put("pypi", "requests", _found(), now=_NOW)
    disabled = DiskCache(tmp_path / "cache", _TTL_HORAS, enabled=False)
    assert disabled.get("pypi", "requests", now=_NOW) is None


# =========================================================================== #
# CACHE — R9.5: TTL al limite, expirado, futuro y corrupto -> miss
# =========================================================================== #


def test_cache_ttl_al_limite_exacto_es_hit(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    _write_raw(tmp_path, "pypi", "requests", _entry(fetched_at=_NOW))
    # (now - fetched_at) == ttl: el borde NO expira.
    assert cache.get("pypi", "requests", now=_NOW + _TTL_SEGUNDOS) is not None


def test_cache_ttl_un_segundo_pasado_es_miss(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    _write_raw(tmp_path, "pypi", "requests", _entry(fetched_at=_NOW))
    assert cache.get("pypi", "requests", now=_NOW + _TTL_SEGUNDOS + 1) is None


def test_cache_fetched_at_futuro_es_miss(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    _write_raw(tmp_path, "pypi", "requests", _entry(fetched_at=_NOW + 10_000))
    assert cache.get("pypi", "requests", now=_NOW) is None


def test_cache_json_corrupto_es_miss_sin_crashear(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    path = _cache_path(tmp_path / "cache", "pypi", "requests")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"{ esto no es json valido ")
    assert cache.get("pypi", "requests", now=_NOW) is None


def test_cache_json_no_objeto_es_miss(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    path = _cache_path(tmp_path / "cache", "pypi", "requests")
    path.parent.mkdir(parents=True)
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert cache.get("pypi", "requests", now=_NOW) is None


def test_cache_esquema_viejo_es_miss(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    entry = _entry(fetched_at=_NOW)
    entry["cache_schema_version"] = "0"
    _write_raw(tmp_path, "pypi", "requests", entry)
    assert cache.get("pypi", "requests", now=_NOW) is None


@pytest.mark.parametrize(
    "mutacion",
    [
        {"fetched_at": "ayer"},
        {"fetched_at": True},  # bool no es timestamp valido
        {"state": "weird"},
        {"state": "unverifiable"},  # nunca debe estar en disco
        {"metadata": None},  # FOUND sin metadata es incoherente
        {"ecosystem": "npm"},  # defensa anti-colision de hash
        {"name": "otro"},
    ],
)
def test_cache_entradas_invalidas_son_miss(
    tmp_path: Path, mutacion: dict[str, Any]
) -> None:
    cache = _cache(tmp_path)
    entry = _entry(fetched_at=_NOW)
    entry.update(mutacion)
    _write_raw(tmp_path, "pypi", "requests", entry)
    assert cache.get("pypi", "requests", now=_NOW) is None


@pytest.mark.parametrize(
    ("campo", "valor"),
    [
        ("releases_count", -1),
        ("releases_count", "muchos"),
        ("releases_count", True),  # bool no es int valido
        ("first_release_epoch", "fecha"),
        ("first_release_epoch", -5),
        ("has_repo_url", "si"),
        ("has_author", 1),  # int no es bool estricto
        ("name", "otro-nombre"),
    ],
)
def test_cache_metadata_tipos_invalidos_es_miss(
    tmp_path: Path, campo: str, valor: Any
) -> None:
    cache = _cache(tmp_path)
    entry = _entry(fetched_at=_NOW)
    assert isinstance(entry["metadata"], dict)
    entry["metadata"][campo] = valor
    _write_raw(tmp_path, "pypi", "requests", entry)
    assert cache.get("pypi", "requests", now=_NOW) is None


def test_cache_first_release_null_es_valido(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    entry = _entry(fetched_at=_NOW)
    assert isinstance(entry["metadata"], dict)
    entry["metadata"]["first_release_epoch"] = None
    _write_raw(tmp_path, "pypi", "requests", entry)
    result = cache.get("pypi", "requests", now=_NOW)
    assert result is not None and result.metadata is not None
    assert result.metadata.first_release_epoch is None


# =========================================================================== #
# CACHE — §2.6: unverifiable NO se persiste
# =========================================================================== #


def test_cache_unverifiable_no_se_persiste(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.put("pypi", "flaky", FetchOutcome(state=FetchState.UNVERIFIABLE))
    assert not _cache_path(tmp_path / "cache", "pypi", "flaky").exists()
    assert cache.get("pypi", "flaky", now=_NOW) is None


# =========================================================================== #
# CACHE — R9.7: perms 0700 dir / 0600 archivo
# =========================================================================== #


def test_cache_permisos_0700_y_0600(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    DiskCache(root, _TTL_HORAS, enabled=True).put("pypi", "requests", _found())
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    path = _cache_path(root, "pypi", "requests")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_cache_dir_preexistente_laxo_se_reendurece(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    root.mkdir(mode=0o755)
    DiskCache(root, _TTL_HORAS, enabled=True).put("pypi", "requests", _found())
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


# =========================================================================== #
# CACHE — R9.6: escritura atomica + concurrencia con ThreadPool
# =========================================================================== #


def test_cache_escritura_concurrente_misma_clave(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    cache = DiskCache(root, _TTL_HORAS, enabled=True)

    def _put(_index: int) -> None:
        # Peor caso de carrera: todos compiten por el mismo archivo final.
        cache.put("pypi", "requests", _found(), now=_NOW)
        cache.get("pypi", "requests", now=_NOW)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(_put, range(200)))

    assert cache.get("pypi", "requests", now=_NOW) == _found()
    assert list(root.glob("*.tmp")) == []  # ningun temporal huerfano


def test_cache_escritura_concurrente_claves_distintas(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    cache = DiskCache(root, _TTL_HORAS, enabled=True)
    nombres = [f"pkg-{i}" for i in range(120)]

    def _put(name: str) -> None:
        cache.put("pypi", name, _found(name), now=_NOW)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(_put, nombres))

    for name in nombres:
        assert cache.get("pypi", name, now=_NOW) == _found(name)
    assert list(root.glob("*.tmp")) == []


def test_cache_fallo_en_rename_no_deja_a_medias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "cache"
    cache = DiskCache(root, _TTL_HORAS, enabled=True)
    cache.put("pypi", "requests", _found(), now=_NOW)  # entrada buena previa

    def _boom(src: Any, dst: Any) -> None:
        raise OSError("disco lleno")

    monkeypatch.setattr(os, "replace", _boom)
    cache.put("pypi", "requests", _found("otro"), now=_NOW)  # no debe crashear
    monkeypatch.undo()

    assert cache.get("pypi", "requests", now=_NOW) == _found()  # original intacta
    assert list(root.glob("*.tmp")) == []  # temporal limpiado tras el fallo


# =========================================================================== #
# CACHE — anti path traversal por hash de clave
# =========================================================================== #


@pytest.mark.parametrize(
    "name",
    ["../../etc/passwd", "a/b/c", "..", "name\x00ofile", "con espacios", "."],
)
def test_cache_clave_maliciosa_no_escapa_del_root(tmp_path: Path, name: str) -> None:
    root = tmp_path / "cache"
    cache = DiskCache(root, _TTL_HORAS, enabled=True)
    cache.put("pypi", name, FetchOutcome(state=FetchState.NOT_FOUND))
    archivos = [p for p in root.iterdir() if p.is_file()]
    assert archivos, "se esperaba al menos una entrada"
    for archivo in archivos:
        assert archivo.parent == root
        assert archivo.suffix == ".json"
        assert all(ch in "0123456789abcdef" for ch in archivo.stem)


# =========================================================================== #
# NET — servidor HTTP local malicioso real (http.server) — T15
# =========================================================================== #


class _QuietServer(ThreadingHTTPServer):
    """Servidor de pruebas que silencia los errores por cierre abrupto del cliente.

    En los escenarios maliciosos (cuerpo gigante, gzip-bomb) el cliente aborta la
    lectura a mitad y cierra el socket: el `BrokenPipeError`/`ConnectionResetError`
    resultante es ESPERADO y no debe ensuciar la salida de pytest.
    """

    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Ignora los errores de socket esperados al cortar el cliente."""


class _MaliciousHandler(BaseHTTPRequestHandler):
    """Handler cuyo comportamiento por path emula respuestas maliciosas.

    Cada ruta dispara un escenario adversarial distinto. El servidor es real (urllib
    abre un socket de verdad), de modo que se ejercita el camino completo de lectura
    streaming/descompresion/redirect handler de `SecureHttpClient`.
    """

    server_version = "MaliciousTest/0.0"

    def log_message(self, *_args: Any) -> None:
        """Silencia el logging del servidor para no ensuciar la salida de pytest."""

    def do_GET(self) -> None:
        """Despacha el escenario malicioso segun el path solicitado (nombre de la API)."""
        handlers = {
            "/ok": self._serve_ok,
            "/giant": self._serve_giant,
            "/badlen": self._serve_excessive_content_length,
            "/deep": self._serve_deep_json,
            "/bomb": self._serve_gzip_bomb,
            "/redirect-host": self._serve_redirect_external_host,
            "/redirect-scheme": self._serve_redirect_other_scheme,
        }
        handler = handlers.get(self.path, self._serve_not_found)
        handler()

    def _serve_ok(self) -> None:
        body = json.dumps({"info": {"name": "requests"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_giant(self) -> None:
        # 4 MB sin Content-Length: la cota se aplica durante la lectura streaming.
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"data": "' + b"A" * (4 * 1024 * 1024) + b'"}')

    def _serve_excessive_content_length(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "999999999")
        self.end_headers()
        self.wfile.write(b'{"x": 1}')

    def _serve_deep_json(self) -> None:
        body = b"[" * 2_000 + b"]" * 2_000  # anidamiento patologico
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_gzip_bomb(self) -> None:
        raw = b"\x00" * (40 * 1024 * 1024)  # 40 MB -> pocos KB comprimidos
        compressed = _gzip_bytes(raw)
        self.send_response(200)
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(compressed)))
        self.end_headers()
        self.wfile.write(compressed)

    def _serve_redirect_external_host(self) -> None:
        self.send_response(302)
        self.send_header("Location", "https://evil.example.com/pypi/requests/json")
        self.end_headers()

    def _serve_redirect_other_scheme(self) -> None:
        self.send_response(302)
        self.send_header("Location", "file:///etc/passwd")
        self.end_headers()

    def _serve_not_found(self) -> None:
        self.send_response(404)
        self.end_headers()


def _patch_http_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Anade un `HTTPHandler` al opener del cliente para el servidor http local.

    El cliente productivo solo registra `HTTPSHandler` (PyPI es https). Para
    ejercitar el camino REAL de streaming/redireccion contra un servidor local de
    pruebas (http), se inyecta el handler plano conservando el redirect handler propio
    y el resto del endurecimiento. Solo afecta a los tests, no al codigo productivo.
    """
    original = SecureHttpClient._safe_handlers

    def _with_http(
        https_handler: urllib.request.HTTPSHandler,
    ) -> tuple[urllib.request.BaseHandler, ...]:
        return (urllib.request.HTTPHandler(), *original(https_handler))

    monkeypatch.setattr(SecureHttpClient, "_safe_handlers", staticmethod(_with_http))


@pytest.fixture
def malicious_server(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[str]:
    """Levanta el servidor malicioso local y relaja la allowlist a http://127.0.0.1.

    La relajacion es SOLO para este fixture: permite que `get_json` y el redirect
    handler reales ejerciten el servidor local sin tocar PyPI. El host externo del
    redirect sigue fuera de la allowlist, asi que el rechazo es genuino.
    """
    server = _QuietServer(("127.0.0.1", 0), _MaliciousHandler)
    port = server.server_address[1]  # puerto efimero asignado por el SO
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(hc, "_ALLOWED_SCHEME", "http")
    monkeypatch.setattr(hc, "ALLOWED_HOSTS", frozenset({"127.0.0.1"}))
    _patch_http_handler(monkeypatch)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get_json(base: str, path: str, *, max_bytes: int, max_depth: int = 50) -> Any:
    """Atajo: GET contra el servidor local con timeouts cortos."""
    return SecureHttpClient().get_json(
        base + path,
        connect_timeout_s=5.0,
        read_timeout_s=5.0,
        max_response_bytes=max_bytes,
        max_json_depth=max_depth,
    )


def test_net_servidor_local_ok(malicious_server: str) -> None:
    result = _get_json(malicious_server, "/ok", max_bytes=10_000)
    assert result == {"info": {"name": "requests"}}


def test_net_respuesta_gigante_aborta_sin_materializar(malicious_server: str) -> None:
    with pytest.raises(NetworkUnverifiableError, match="supera el maximo"):
        _get_json(malicious_server, "/giant", max_bytes=100_000)


def test_net_content_length_excesivo_rechazado(malicious_server: str) -> None:
    with pytest.raises(NetworkUnverifiableError, match="Content-Length excesivo"):
        _get_json(malicious_server, "/badlen", max_bytes=1_000)


def test_net_json_profundo_rechazado(malicious_server: str) -> None:
    with pytest.raises(NetworkUnverifiableError, match="profundidad JSON"):
        _get_json(malicious_server, "/deep", max_bytes=1_000_000, max_depth=50)


def test_net_gzip_bomb_abortada(malicious_server: str) -> None:
    with pytest.raises(NetworkUnverifiableError, match="supera el maximo"):
        _get_json(malicious_server, "/bomb", max_bytes=1_000_000)


def test_net_redireccion_cross_host_rechazada(malicious_server: str) -> None:
    with pytest.raises(NetworkUnverifiableError):
        _get_json(malicious_server, "/redirect-host", max_bytes=10_000)


def test_net_redireccion_cross_scheme_rechazada(malicious_server: str) -> None:
    with pytest.raises(NetworkUnverifiableError):
        _get_json(malicious_server, "/redirect-scheme", max_bytes=10_000)


def test_net_allowlist_real_rechaza_host_externo() -> None:
    # Sin relajar la allowlist: cualquier host != pypi.org se rechaza antes de conectar.
    with pytest.raises(NetworkUnverifiableError, match="allowlist"):
        SecureHttpClient().get_json(
            "http://127.0.0.1/x",
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            max_response_bytes=1_000,
            max_json_depth=10,
        )


def _gzip_bytes(raw: bytes) -> bytes:
    """Comprime `raw` en formato gzip (para el escenario gzip-bomb)."""
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb") as gz:
        gz.write(raw)
    return buffer.getvalue()


# =========================================================================== #
# SIMILARIDAD — DL con transposiciones + off-by-one (T29 parcial)
# =========================================================================== #

_DL_MAX = 2  # default dl_max (tabla R8.4).


@pytest.mark.parametrize(
    ("a", "b", "esperado"),
    [
        # Transposiciones (dl=1) — el corazon de la correctitud OSA (ADR-02).
        ("ab", "ba", 1),
        ("requests", "reqursts", 1),  # transposicion 'ue'->'eu'
        ("martha", "marhta", 1),  # transposicion 'th'->'ht'
        ("abcd", "abdc", 1),  # transposicion al final
        # Operaciones simples (dl=1).
        ("attrs", "attr", 1),  # eliminacion
        ("attrs", "attr5", 1),  # sustitucion final
        ("kitten", "kittenx", 1),  # insercion
        # Identidad.
        ("requests", "requests", 0),
        ("", "", 0),
        # Distancia 2 dentro de banda.
        ("abcde", "abxye", 2),  # dos sustituciones contiguas
    ],
)
def test_dl_distancia_exacta(a: str, b: str, esperado: int) -> None:
    assert damerau_levenshtein_bounded(a, b, _DL_MAX) == esperado


def test_dl_transposicion_no_es_off_by_one() -> None:
    # Una transposicion pura es dl=1, jamas 2 (off-by-one clasico de OSA).
    assert damerau_levenshtein_bounded("ba", "ab", _DL_MAX) == 1
    assert damerau_levenshtein_bounded("marhta", "martha", _DL_MAX) == 1


def test_dl_simetria() -> None:
    for a, b in [("requests", "reqursts"), ("attrs", "attr"), ("ab", "ba")]:
        assert damerau_levenshtein_bounded(a, b, _DL_MAX) == damerau_levenshtein_bounded(
            b, a, _DL_MAX
        )


def test_dl_satura_por_diferencia_de_longitud() -> None:
    # |len(a)-len(b)| = 3 > dl_max=2 -> satura sin computar.
    assert damerau_levenshtein_bounded("abc", "abcdef", _DL_MAX) == _DL_MAX + 1


def test_dl_satura_por_corte_de_fila() -> None:
    assert damerau_levenshtein_bounded("abcde", "vwxyz", _DL_MAX) == _DL_MAX + 1


def test_dl_distancia_exacta_con_limite_mayor() -> None:
    assert damerau_levenshtein_bounded("abcde", "vwxyz", 5) == 5


def test_dl_no_doble_edicion_osa() -> None:
    # OSA no permite editar dos veces la misma subcadena: 'ca'->'abc' es 3.
    assert damerau_levenshtein_bounded("ca", "abc", 5) == 3


# =========================================================================== #
# SIMILARIDAD — 6 vectores Jaro-Winkler de referencia (T29 parcial)
# =========================================================================== #

# NOTA: el enunciado T25 cita jw("requests","reqursts")~0.967 y
# jw("requests","requesocks")~0.937, pero esos valores son IMPOSIBLES con la formula
# canonica de Jaro-Winkler (p=0.1, prefijo<=4) que el propio enunciado describe: para
# strings de longitud 8 no existe (matches, transposiciones) entero que de jaro=0.9444.
# La implementacion canonica correcta (verificada vs jellyfish/Apache Commons Text) da
# 0.950 y 0.915. Se afirman los valores REALES de la implementacion; los otros 4 son
# consistentes y se cumplen exactamente.
@pytest.mark.parametrize(
    ("a", "b", "esperado"),
    [
        ("requests", "reqursts", 0.950),  # enunciado citaba 0.967 (imposible)
        ("requests", "requesocks", 0.915),  # enunciado citaba 0.937 (imposible)
        ("dwayne", "duane", 0.840),  # vector del enunciado, correcto
        ("martha", "marhta", 0.961),  # vector del enunciado, correcto
        ("abc", "xyz", 0.0),  # sin coincidencia
        ("requests", "requests", 1.0),  # identidad
    ],
)
def test_jw_vectores_de_referencia(a: str, b: str, esperado: float) -> None:
    assert jaro_winkler(a, b) == pytest.approx(esperado, abs=0.001)


def test_jw_rango_y_determinismo() -> None:
    for a, b in [("requests", "reqursts"), ("dwayne", "duane"), ("abc", "xyz")]:
        valor = jaro_winkler(a, b)
        assert 0.0 <= valor <= 1.0
        assert jaro_winkler(a, b) == valor  # determinista


def test_jw_boost_de_prefijo_aplicado() -> None:
    # Comparten prefijo "mar" (3): JW > Jaro base. Verifica el boost de Winkler.
    assert jaro_winkler("martha", "marhta") > 0.94


# =========================================================================== #
# MANIFIESTOS — includes con ../ y ciclo, limites, vacio, malformado (T12)
# =========================================================================== #


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_manifest_include_relativo_confinado_ok(tmp_path: Path) -> None:
    _write(tmp_path, "base.txt", "flask==2.3.0\n")
    main = _write(tmp_path, "requirements.txt", "-r base.txt\nrequests==2.31.0\n")
    deps = detect_and_parse(main, _CFG)
    nombres = {d.name for d in deps}
    assert nombres == {"flask", "requests"}


def test_manifest_include_absoluto_rechazado(tmp_path: Path) -> None:
    main = _write(tmp_path, "requirements.txt", "-r /etc/passwd\n")
    with pytest.raises(ManifestParseError, match="absoluta"):
        detect_and_parse(main, _CFG)


def test_manifest_include_escape_dotdot_rechazado(tmp_path: Path) -> None:
    sub = tmp_path / "proj"
    sub.mkdir()
    # El secreto esta FUERA del arbol del proyecto (project_root = sub).
    _write(tmp_path, "secret.txt", "evil==1.0\n")
    main = _write(sub, "requirements.txt", "-r ../secret.txt\n")
    with pytest.raises(ManifestParseError, match="escapa"):
        detect_and_parse(main, _CFG)


def test_manifest_include_inexistente_rechazado(tmp_path: Path) -> None:
    main = _write(tmp_path, "requirements.txt", "-r noexiste.txt\n")
    with pytest.raises(ManifestParseError, match="no encontrado"):
        detect_and_parse(main, _CFG)


def test_manifest_include_ciclo_rechazado(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "-r b.txt\n")
    _write(tmp_path, "b.txt", "-r requirements.txt\n")
    main = tmp_path / "requirements.txt"
    with pytest.raises(ManifestParseError, match="ciclo"):
        detect_and_parse(main, _CFG)


def test_manifest_include_profundidad_excedida(tmp_path: Path) -> None:
    cfg = Config(max_include_depth=2)
    # Cadena requirements -> b -> c -> d: la profundidad 2 se supera antes de llegar a d.
    _write(tmp_path, "requirements.txt", "-r b.txt\n")
    _write(tmp_path, "b.txt", "-r c.txt\n")
    _write(tmp_path, "c.txt", "-r d.txt\n")
    _write(tmp_path, "d.txt", "x==1.0\n")
    main = tmp_path / "requirements.txt"
    with pytest.raises(ManifestParseError, match="profundidad"):
        detect_and_parse(main, cfg)


def test_manifest_vacio_es_cero_deps(tmp_path: Path) -> None:
    main = _write(tmp_path, "requirements.txt", "")
    assert detect_and_parse(main, _CFG) == ()


def test_manifest_solo_comentarios_es_cero_deps(tmp_path: Path) -> None:
    main = _write(tmp_path, "requirements.txt", "# nada\n\n  \n")
    assert detect_and_parse(main, _CFG) == ()


def test_manifest_excede_max_deps(tmp_path: Path) -> None:
    cfg = Config(max_deps=3)
    contenido = "".join(f"pkg{i}==1.0\n" for i in range(10))
    main = _write(tmp_path, "requirements.txt", contenido)
    with pytest.raises(ManifestParseError, match="maximo de 3"):
        detect_and_parse(main, cfg)


def test_manifest_excede_max_bytes(tmp_path: Path) -> None:
    cfg = Config(max_manifest_bytes=10)
    main = _write(tmp_path, "requirements.txt", "requests==2.31.0\nflask==2.0.0\n")
    with pytest.raises(ManifestParseError, match="tamano maximo"):
        detect_and_parse(main, cfg)


def test_manifest_malformado_error_con_nombre_sin_stacktrace(tmp_path: Path) -> None:
    main = _write(tmp_path, "requirements.txt", "@@@ invalido !!\n")
    with pytest.raises(ManifestParseError) as exc:
        detect_and_parse(main, _CFG)
    mensaje = str(exc.value)
    assert "requirements.txt" in mensaje
    assert "Traceback" not in mensaje  # sin stacktrace crudo (R1.8/R6.5)
    assert str(tmp_path) not in mensaje  # sin ruta absoluta del sistema (R6.5)


def test_manifest_pyproject_malformado_con_nombre(tmp_path: Path) -> None:
    main = _write(tmp_path, "pyproject.toml", "[project\nbroken")
    with pytest.raises(ManifestParseError, match=r"pyproject\.toml"):
        detect_and_parse(main, _CFG)


def test_manifest_type_fuerza_parser_freeze(tmp_path: Path) -> None:
    # Archivo .txt cuyo contenido es formato freeze, forzado por --manifest-type.
    main = _write(tmp_path, "deps.txt", "requests==2.31.0\nflask==2.0.0\n")
    deps = detect_and_parse(main, _CFG, manifest_type="freeze")
    assert {d.name for d in deps} == {"requests", "flask"}


def test_manifest_type_fuerza_parser_pyproject(tmp_path: Path) -> None:
    contenido = '[project]\ndependencies = ["requests==2.31.0"]\n'
    main = _write(tmp_path, "config.txt", contenido)
    deps = detect_and_parse(main, _CFG, manifest_type="pyproject")
    assert {d.name for d in deps} == {"requests"}


def test_manifest_type_invalido_rechazado(tmp_path: Path) -> None:
    main = _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    with pytest.raises(ManifestParseError, match="desconocido"):
        detect_and_parse(main, _CFG, manifest_type="npm")


def test_manifest_dedup_por_nombre_normalizado(tmp_path: Path) -> None:
    # My_Package y my-package normalizan al mismo PEP 503: una sola dep.
    main = _write(tmp_path, "requirements.txt", "My_Package==1.0\nmy-package==2.0\n")
    deps = detect_and_parse(main, _CFG)
    assert len(deps) == 1
    assert deps[0].name == "my-package"


# =========================================================================== #
# DATASET — checksum ausente/corrupto -> DatasetIntegrityError; indices
# =========================================================================== #


def _make_artifact(names: list[str], tmp_path: Path) -> tuple[Path, Path]:
    """Crea un par .json/.sha256 valido en `tmp_path`."""
    artifact = {
        "schema": "slopguard-top-n-v1",
        "version": "1.0.0",
        "generated_at": "2026-06-22",
        "provenance": "test",
        "count": len(names),
        "names": names,
    }
    raw = json.dumps(
        artifact, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    json_path = tmp_path / "top_n.json"
    sha_path = tmp_path / "top_n.sha256"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())
    return json_path, sha_path


def test_dataset_carga_valida_construye_indices(tmp_path: Path) -> None:
    names = ["requests", "flask", "django", "flask-login", "numpy"]
    json_path, sha_path = _make_artifact(names, tmp_path)
    dataset = load_top_n(json_path, sha_path)
    assert dataset.members == frozenset(names)
    assert "flask" in dataset.by_length[5] and "numpy" in dataset.by_length[5]
    assert "requests" in dataset.by_length[8]
    assert "requests" in dataset.by_first_char["r"]
    assert "flask" in dataset.by_first_char["f"]
    assert "flask-login" in dataset.by_first_char["f"]


def test_dataset_checksum_corrupto_es_error(tmp_path: Path) -> None:
    json_path, sha_path = _make_artifact(["requests"], tmp_path)
    sha_path.write_text("0" * 64)  # checksum que no coincide
    with pytest.raises(DatasetIntegrityError, match="checksum"):
        load_top_n(json_path, sha_path)


def test_dataset_json_manipulado_falla_checksum(tmp_path: Path) -> None:
    json_path, sha_path = _make_artifact(["requests"], tmp_path)
    # Manipular el .json sin actualizar el .sha256 => integridad rota.
    json_path.write_bytes(json_path.read_bytes() + b" ")
    with pytest.raises(DatasetIntegrityError, match="checksum"):
        load_top_n(json_path, sha_path)


def test_dataset_json_ausente_es_error(tmp_path: Path) -> None:
    _json_path, sha_path = _make_artifact(["requests"], tmp_path)
    with pytest.raises(DatasetIntegrityError, match="no encontrado"):
        load_top_n(tmp_path / "no_existe.json", sha_path)


def test_dataset_sha_ausente_es_error(tmp_path: Path) -> None:
    json_path, _sha_path = _make_artifact(["requests"], tmp_path)
    with pytest.raises(DatasetIntegrityError, match="no encontrado"):
        load_top_n(json_path, tmp_path / "no_existe.sha256")


def test_dataset_json_malformado_es_error(tmp_path: Path) -> None:
    json_path = tmp_path / "top_n.json"
    sha_path = tmp_path / "top_n.sha256"
    raw = b"{no es json"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())  # checksum valido del basura
    with pytest.raises(DatasetIntegrityError, match="malformado"):
        load_top_n(json_path, sha_path)


def test_dataset_names_ausente_es_error(tmp_path: Path) -> None:
    artifact = {"version": "1.0", "generated_at": "2026"}
    raw = json.dumps(artifact).encode()
    json_path = tmp_path / "top_n.json"
    sha_path = tmp_path / "top_n.sha256"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())
    with pytest.raises(DatasetIntegrityError, match="names"):
        load_top_n(json_path, sha_path)


def test_dataset_build_normaliza_y_dedup() -> None:
    # Nombres sin normalizar deben colapsar (PEP 503) e indexarse en forma canonica.
    dataset = build_top_n(
        ["Flask", "flask", "My_Pkg"], version="1", generated_at="2026"
    )
    assert dataset.members == frozenset({"flask", "my-pkg"})
    assert "flask" in dataset.by_first_char["f"]


def test_dataset_embebido_carga_y_verifica_integridad() -> None:
    # El artefacto embebido real debe cargar con checksum valido (R3.9, NFR-Seg.7).
    dataset = load_top_n()
    assert len(dataset.members) > 0
    assert dataset.version != "" and dataset.generated_at != ""
