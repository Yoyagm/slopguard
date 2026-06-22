"""Dataset top-N de PyPI: estructura inmutable con indices precomputados.

`TopNDataset` acota el coste de Capa 1 (ADR-02): `by_length` habilita la banda de
Damerau-Levenshtein (solo candidatos con longitud en `[L-dl_max, L+dl_max]`) y
`by_first_char` el prefiltro de Jaro-Winkler.

`load_top_n` carga el artefacto embebido verificando su checksum SHA-256 contra el
archivo `.sha256` adjunto. Si falta algun archivo, el JSON no es parseable, o el
checksum no coincide, lanza `DatasetIntegrityError` (R3.9, NFR-Seg.7).

Contrato de `build_top_n`: normaliza los nombres via `normalize_name` (PEP 503) antes
de deduplicar y construir los indices. Esto garantiza el invariante incluso si una
futura regeneracion del artefacto (T19) introdujera nombres sin normalizar, evitando
que un miembro no normalizado nunca matchee en Capa 1 de forma silenciosa (ADR-02,
opcion A defensiva).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from ..errors import DatasetIntegrityError
from ..normalize import normalize_name


@dataclass(frozen=True, slots=True)
class TopNDataset:
    """Top-N normalizado + indices precomputados (todo inmutable)."""

    members: frozenset[str]
    by_length: Mapping[int, tuple[str, ...]]
    by_first_char: Mapping[str, tuple[str, ...]]
    version: str
    generated_at: str


_DEFAULT_JSON = Path(__file__).parent / "pypi_top_10k.json"
_DEFAULT_SHA256 = Path(__file__).parent / "pypi_top_10k.sha256"


def load_top_n(
    json_path: Path | None = None,
    sha_path: Path | None = None,
) -> TopNDataset:
    """Carga el dataset top-N desde disco y verifica su integridad SHA-256.

    Si `json_path` o `sha_path` son None, usa los artefactos embebidos junto
    a este modulo. Lanza `DatasetIntegrityError` si:
    - alguno de los archivos falta o no puede leerse,
    - el JSON no es parseable o le faltan campos obligatorios,
    - el digest SHA-256 del `.json` en disco no coincide con el valor del `.sha256`.
    """
    resolved_json = json_path or _DEFAULT_JSON
    resolved_sha = sha_path or _DEFAULT_SHA256

    raw_bytes = _read_file_bytes(resolved_json)
    stored_digest = _read_stored_digest(resolved_sha)
    _verify_checksum(raw_bytes, stored_digest, resolved_json)
    artifact = _parse_artifact(raw_bytes, resolved_json)

    names = artifact.get("names")
    if not isinstance(names, list):
        raise DatasetIntegrityError(
            f"Dataset '{resolved_json.name}': campo 'names' ausente o invalido."
        )
    if not all(isinstance(n, str) for n in names):
        raise DatasetIntegrityError(
            f"Dataset '{resolved_json.name}': 'names' contiene elementos no-str."
        )
    version = str(artifact.get("version", ""))
    generated_at = str(artifact.get("generated_at", ""))
    return build_top_n(names, version=version, generated_at=generated_at)


def _read_file_bytes(path: Path) -> bytes:
    """Lee los bytes de `path`; convierte OSError en DatasetIntegrityError."""
    try:
        return path.read_bytes()
    except OSError as exc:
        raise DatasetIntegrityError(
            f"Dataset '{path.name}' no encontrado o no legible."
        ) from exc


def _read_stored_digest(path: Path) -> str:
    """Lee y devuelve el digest almacenado en el `.sha256` (strip de espacios)."""
    raw = _read_file_bytes(path)
    return raw.decode("ascii", errors="replace").strip()


def _verify_checksum(raw_bytes: bytes, stored: str, json_path: Path) -> None:
    """Compara el SHA-256 calculado contra el almacenado; lanza si difieren."""
    computed = hashlib.sha256(raw_bytes).hexdigest()
    if computed != stored:
        raise DatasetIntegrityError(
            f"Dataset '{json_path.name}': checksum invalido "
            f"(calculado={computed[:16]}…, esperado={stored[:16]}…)."
        )


def _parse_artifact(raw_bytes: bytes, json_path: Path) -> dict[str, object]:
    """Parsea el JSON y valida que sea un objeto; lanza DatasetIntegrityError si no."""
    try:
        artifact = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise DatasetIntegrityError(
            f"Dataset '{json_path.name}': JSON malformado."
        ) from exc
    if not isinstance(artifact, dict):
        raise DatasetIntegrityError(
            f"Dataset '{json_path.name}': se esperaba un objeto JSON."
        )
    return artifact


def build_top_n(names: Iterable[str], *, version: str, generated_at: str) -> TopNDataset:
    """Construye los indices normalizando (PEP 503), deduplicando y ordenando.

    Aplica `normalize_name` antes de deduplicar, garantizando que todos los miembros
    esten en forma canonica PEP 503 independientemente de si el artefacto fuente ya
    los traia normalizados (invariante defensivo, ADR-02 opcion A).
    Determinista: los buckets tienen orden estable.
    """
    unique = sorted(set(normalize_name(n) for n in names))
    by_length: dict[int, list[str]] = {}
    by_first_char: dict[str, list[str]] = {}
    for name in unique:
        by_length.setdefault(len(name), []).append(name)
        if name:
            by_first_char.setdefault(name[0], []).append(name)
    return TopNDataset(
        members=frozenset(unique),
        by_length={length: tuple(bucket) for length, bucket in by_length.items()},
        by_first_char={char: tuple(bucket) for char, bucket in by_first_char.items()},
        version=version,
        generated_at=generated_at,
    )
