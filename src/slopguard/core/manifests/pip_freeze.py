"""Parser de salida de `pip freeze` (R1.3).

Formato: `nombre==version` por linea (salida exacta de pip freeze).
Tambien acepta stdin cuando el llamador pasa el texto directamente.
Ignora comentarios, blancos, y entradas editable (p.ej. `-e git+...`).
Solo parsea pines exactos `==` (es el unico formato que produce pip freeze).
"""

from __future__ import annotations

import re
from pathlib import Path

from ..errors import ManifestParseError
from ..models import Dependency
from ..normalize import normalize_name, sanitize_for_output

# pip freeze emite exactamente `nombre==version`.
_FREEZE_LINE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)==([^\s]+)$"
)


def parse_pip_freeze(
    text: str,
    origin: str,
    *,
    max_deps: int,
) -> tuple[Dependency, ...]:
    """Parsea el texto de `pip freeze` y retorna dependencias.

    `origin` es la ruta relativa o etiqueta del manifiesto (p.ej. 'stdin').
    Malformado con texto que no sea comentario/blanco ni `nombre==version`
    levanta ManifestParseError con numero de linea (R1.8).
    """
    deps: list[Dependency] = []
    seen_names: set[str] = set()

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        dep = _parse_freeze_line(raw_line, lineno, origin)
        if dep is None:
            continue
        if dep.name in seen_names:
            continue  # dedup (R1.10)
        seen_names.add(dep.name)
        deps.append(dep)
        if len(deps) > max_deps:
            raise ManifestParseError(
                f"manifiesto supera el maximo de {max_deps} dependencias"
            )

    return tuple(deps)


def _parse_freeze_line(raw_line: str, lineno: int, origin: str) -> Dependency | None:
    """Parsea una linea individual de pip freeze; retorna None si debe ignorarse.

    Lanza ManifestParseError si la linea no es comentario/blanco/editable
    ni tiene el formato `nombre==version` esperado de pip freeze (R1.8).
    """
    line = raw_line.strip()

    if not line or line.startswith("#"):
        return None

    # Entradas editables: -e git+... (ignorar, R1.4 aplicado a freeze).
    if line.startswith(("-e ", "-e\t")):
        return None

    match = _FREEZE_LINE.match(line)
    if not match:
        safe_origin = sanitize_for_output(origin)
        raise ManifestParseError(
            f"linea {lineno} de '{safe_origin}' no es formato freeze "
            f"(`nombre==version`): '{sanitize_for_output(line[:80])}'"
        )

    raw_name = match.group(1)
    version = match.group(3)
    return Dependency(
        name=normalize_name(raw_name),
        # Saneamos version_pin igual que raw: un manifiesto malicioso podria
        # inyectar secuencias ANSI en la version (R6.5/NFR-Seg.5).
        version_pin=sanitize_for_output(version),
        raw=sanitize_for_output(raw_name),
        origin=origin,
    )


def parse_pip_freeze_file(
    path: Path,
    origin: str,
    *,
    max_manifest_bytes: int,
    max_deps: int,
) -> tuple[Dependency, ...]:
    """Lee un archivo en formato pip freeze y parsea su contenido."""
    _check_size(path, max_manifest_bytes)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        safe = sanitize_for_output(str(path.name))
        raise ManifestParseError(f"error al leer '{safe}'") from exc
    return parse_pip_freeze(text, origin, max_deps=max_deps)


def _check_size(path: Path, max_bytes: int) -> None:
    """Verifica el tamano del archivo antes de cargarlo (R1.9)."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        safe = sanitize_for_output(str(path.name))
        raise ManifestParseError(f"no se puede acceder a '{safe}'") from exc
    if size > max_bytes:
        raise ManifestParseError(
            f"manifiesto supera el tamano maximo ({max_bytes} bytes)"
        )
