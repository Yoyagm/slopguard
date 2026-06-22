"""Cache en disco segura (R9.1-R9.7, NFR-Seg.6, ADR-05): JSON-only, atomica, validada.

Decisiones de seguridad clave:
- Filename = `sha256(f"{ecosystem}:{name}").hexdigest()+".json"`: el hexdigest solo
  contiene `[0-9a-f]`, por lo que el path traversal queda eliminado por construccion
  (jamas hay `/` ni `..` en la clave).
- Serializacion EXCLUSIVAMENTE JSON; nunca pickle/marshal (NFR-Seg.2). Toda entrada
  leida del disco se trata como entrada NO confiable y se valida (esquema/tipos/rangos):
  cualquier fallo se degrada a MISS sin crashear (R9.5).
- Escritura ATOMICA: archivo temporal en el mismo directorio + `os.replace` (rename
  atomico). Un lector concurrente ve el archivo viejo o el nuevo completo, nunca a
  medias (R9.6). Dir 0700, archivo 0600 (R9.7).
- `UNVERIFIABLE` NO se persiste (no cachear fallos transitorios, §2.6).
- `enabled=False` (`--no-cache`) ⇒ ni lee ni escribe (R9.3).

Cero dependencias de runtime: solo stdlib.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from ..adapters.base import FetchOutcome, FetchState, PackageMetadata

# Version del esquema de la entrada en disco. Un valor distinto ⇒ miss (esquema viejo).
_CACHE_SCHEMA_VERSION = "1"

# Estados que SI se persisten. UNVERIFIABLE queda fuera a proposito (§2.6).
_CACHEABLE_STATES = frozenset({FetchState.FOUND, FetchState.NOT_FOUND})

# Permisos restrictivos (R9.7): el directorio 0700 y cada archivo 0600.
_DIR_MODE = 0o700
_FILE_MODE = 0o600

# Campos booleanos del metadato normalizado (validacion de tipos al leer).
_METADATA_BOOL_FIELDS = (
    "has_repo_url",
    "has_description",
    "has_author",
    "has_license",
    "has_classifiers",
    "in_top_n",
)


class DiskCache:
    """Cache clave-valor en disco, segura y validada. Una entrada JSON por paquete."""

    def __init__(self, root: Path, ttl_horas: int, *, enabled: bool) -> None:
        """Configura la cache. `enabled=False` la convierte en no-op total (R9.3)."""
        self._root = Path(root)
        self._ttl_segundos = ttl_horas * 3600
        self._enabled = enabled

    def get(
        self, ecosystem: str, name: str, *, now: float | None = None
    ) -> FetchOutcome | None:
        """Devuelve el `FetchOutcome` cacheado vigente, o None si es miss.

        Miss = deshabilitada, ausente, expirada, corrupta o de esquema invalido. Nunca
        lanza por una entrada corrupta: la trata como miss y deja que el caller refetchee
        (R9.5). `now` es inyectable para TTL determinista en tests (NFR-Det.1).
        """
        if not self._enabled:
            return None
        path = self._path_for(ecosystem, name)
        payload = self._read_json(path)
        if payload is None:
            return None
        reference_now = time.time() if now is None else now
        return self._deserialize(payload, ecosystem, name, reference_now)

    def put(
        self, ecosystem: str, name: str, outcome: FetchOutcome, *, now: float | None = None
    ) -> None:
        """Persiste FOUND/NOT_FOUND de forma atomica con perms restrictivos.

        No-op si la cache esta deshabilitada (R9.3) o si el estado es UNVERIFIABLE
        (no se cachean fallos transitorios, §2.6). `now` es inyectable para que el
        `fetched_at` grabado sea determinista en tests (NFR-Det.1).
        """
        if not self._enabled:
            return
        if outcome.state not in _CACHEABLE_STATES:
            return
        fetched_at = time.time() if now is None else now
        payload = self._serialize(ecosystem, name, outcome, fetched_at)
        self._atomic_write(self._path_for(ecosystem, name), payload)

    def _path_for(self, ecosystem: str, name: str) -> Path:
        """Ruta del archivo de cache: hash sha256 ⇒ sin path traversal posible."""
        key = f"{ecosystem}:{name}".encode()
        digest = hashlib.sha256(key).hexdigest()
        return self._root / f"{digest}.json"

    def _read_json(self, path: Path) -> dict[str, Any] | None:
        """Lee y parsea el JSON del archivo. None si ausente, ilegible o no es objeto."""
        try:
            raw = path.read_bytes()
        except OSError:
            return None  # ausente o ilegible ⇒ miss, sin crashear
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return None  # corrupto ⇒ miss (JSON-only, nunca eval/pickle)
        return payload if isinstance(payload, dict) else None

    def _deserialize(
        self, payload: dict[str, Any], ecosystem: str, name: str, now: float
    ) -> FetchOutcome | None:
        """Valida la entrada como NO confiable y reconstruye el `FetchOutcome`.

        Cualquier desviacion de esquema/tipos/rangos o TTL vencido ⇒ None (miss).
        """
        if payload.get("cache_schema_version") != _CACHE_SCHEMA_VERSION:
            return None
        if payload.get("ecosystem") != ecosystem or payload.get("name") != name:
            return None  # colision de hash o archivo manipulado ⇒ miss defensivo
        if self._is_expired(payload.get("fetched_at"), now):
            return None
        return self._build_outcome(payload.get("state"), payload.get("metadata"), name)

    def _is_expired(self, fetched_at: Any, now: float) -> bool:
        """True si falta el timestamp, es invalido, esta en el futuro o vencio el TTL."""
        if isinstance(fetched_at, bool) or not isinstance(fetched_at, (int, float)):
            return True
        if fetched_at < 0 or fetched_at > now:
            return True  # timestamp absurdo (futuro/negativo) ⇒ tratar como invalido
        return (now - fetched_at) > self._ttl_segundos

    def _build_outcome(
        self, state_raw: Any, metadata_raw: Any, name: str
    ) -> FetchOutcome | None:
        """Reconstruye el outcome validando la coherencia state↔metadata."""
        try:
            state = FetchState(state_raw)
        except ValueError:
            return None
        if state not in _CACHEABLE_STATES:
            return None  # UNVERIFIABLE u otro estado no debe estar en disco ⇒ miss
        if state is FetchState.NOT_FOUND:
            return None if metadata_raw is not None else FetchOutcome(state=state)
        metadata = self._build_metadata(metadata_raw, name)
        return None if metadata is None else FetchOutcome(state=state, metadata=metadata)

    def _build_metadata(self, raw: Any, name: str) -> PackageMetadata | None:
        """Valida tipos/rangos de los metadatos. None si algo es invalido."""
        if not isinstance(raw, dict) or raw.get("name") != name:
            return None
        releases = raw.get("releases_count")
        if isinstance(releases, bool) or not isinstance(releases, int) or releases < 0:
            return None
        ok, first_release = self._parse_first_release(raw.get("first_release_epoch"))
        if not ok:
            return None
        bools = self._parse_bools(raw)
        if bools is None:
            return None
        return PackageMetadata(
            name=name,
            first_release_epoch=first_release,
            releases_count=releases,
            **bools,
        )

    def _parse_first_release(self, value: Any) -> tuple[bool, float | None]:
        """(ok, valor): None es valido (sin release); numero >=0 valido; resto ⇒ ok=False."""
        if value is None:
            return True, None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False, None
        return (True, float(value)) if value >= 0 else (False, None)

    def _parse_bools(self, raw: dict[str, Any]) -> dict[str, bool] | None:
        """Extrae los flags booleanos exigiendo tipo bool estricto. None si falta/invalido."""
        result: dict[str, bool] = {}
        for field in _METADATA_BOOL_FIELDS:
            value = raw.get(field)
            if not isinstance(value, bool):
                return None
            result[field] = value
        return result

    def _serialize(
        self, ecosystem: str, name: str, outcome: FetchOutcome, fetched_at: float
    ) -> dict[str, Any]:
        """Construye el dict serializable (§2.6). `not_found` ⇒ metadata=null."""
        metadata = outcome.metadata
        return {
            "cache_schema_version": _CACHE_SCHEMA_VERSION,
            "ecosystem": ecosystem,
            "name": name,
            "fetched_at": fetched_at,
            "state": outcome.state.value,
            "metadata": None if metadata is None else _metadata_to_dict(metadata),
        }

    def _atomic_write(self, path: Path, payload: dict[str, Any]) -> None:
        """Escribe atomicamente: temp en el mismo dir + os.replace, perms 0700/0600.

        Si algo falla a mitad, el temporal se elimina y el archivo final queda intacto
        (nunca a medias). Tolera fallos de E/S sin crashear el escaneo.
        """
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        try:
            self._ensure_dir()
            self._write_temp_then_replace(path, data)
        except OSError:
            return  # la cache es best-effort: un fallo de escritura no rompe el escaneo

    def _ensure_dir(self) -> None:
        """Crea el directorio raiz con 0700 y reafirma los permisos si ya existia."""
        os.makedirs(self._root, mode=_DIR_MODE, exist_ok=True)
        os.chmod(self._root, _DIR_MODE)  # reafirma 0700 aunque el dir preexistiera

    def _write_temp_then_replace(self, path: Path, data: bytes) -> None:
        """Vuelca a un temporal con perms 0600 y lo renombra atomicamente sobre `path`."""
        fd, tmp_name = tempfile.mkstemp(dir=self._root, suffix=".tmp")
        tmp_path = Path(tmp_name)
        try:
            os.fchmod(fd, _FILE_MODE)  # 0600 ANTES de escribir el contenido
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)  # rename atomico: lector ve viejo o nuevo
        except OSError:
            tmp_path.unlink(missing_ok=True)  # no dejar temporales huerfanos
            raise


def _metadata_to_dict(metadata: PackageMetadata) -> dict[str, Any]:
    """Serializa `PackageMetadata` a un dict JSON-able con las claves de §2.6."""
    return {
        "name": metadata.name,
        "first_release_epoch": metadata.first_release_epoch,
        "releases_count": metadata.releases_count,
        "has_repo_url": metadata.has_repo_url,
        "has_description": metadata.has_description,
        "has_author": metadata.has_author,
        "has_license": metadata.has_license,
        "has_classifiers": metadata.has_classifiers,
        "in_top_n": metadata.in_top_n,
    }
