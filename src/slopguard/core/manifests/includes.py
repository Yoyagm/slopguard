"""Resolucion de includes -r / -c en requirements.txt (R1.5, R1.6).

Reglas de seguridad:
- La ruta resuelta DEBE estar dentro del arbol del proyecto (project_root).
- Rutas absolutas → ManifestParseError.
- Rutas con escapes hacia arriba (../) que salgan del arbol → ManifestParseError.
- Archivo inexistente → ManifestParseError.
- Ciclos (mismo archivo ya visitado) → ManifestParseError.
- Profundidad > max_include_depth → ManifestParseError.
En todos los casos: exit 3, error_category=manifest_parse, sin leer
archivos arbitrarios ni omitir dependencias en silencio (R1.6).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..errors import ManifestParseError
from ..models import Dependency
from ..normalize import sanitize_for_output

# Tipo del callable que parsea un requirements.txt de forma recursiva.
# Evita importacion circular con requirements_txt.py.
_ParseFn = Callable[
    [Path, str, int, set[Path], int, int, int, "Path | None"],
    "tuple[Dependency, ...]",
]


def resolve_includes(  # noqa: PLR0913
    include_path_str: str,
    origin_file: Path,
    project_root: Path,
    seen_paths: set[Path],
    depth: int,
    parse_fn: _ParseFn,
    *,
    max_include_depth: int,
    max_manifest_bytes: int,
    max_deps: int,
) -> tuple[Dependency, ...]:
    """Resuelve una referencia -r/-c y retorna sus dependencias.

    `origin_file` es el archivo que contiene la directiva include.
    `seen_paths` se actualiza (mutacion intencional para detectar ciclos).
    `parse_fn` es el callable del parser de requirements_txt, pasado para
    evitar importacion circular entre este modulo y requirements_txt.
    """
    # Correccion off-by-one: `depth` empieza en 0 en el archivo raiz. Un include
    # de nivel N se permite cuando N <= max_include_depth. Con `>=` se cortaba
    # un nivel antes de lo declarado en R8 (default 10 permite 10 niveles reales).
    # Ejemplo: cadena a->b->c son 2 niveles de include; con max=2 debe resolverse.
    if depth + 1 > max_include_depth:
        safe = sanitize_for_output(include_path_str)
        raise ManifestParseError(
            f"profundidad maxima de includes ({max_include_depth}) superada "
            f"al intentar incluir '{safe}'"
        )

    include_path = _resolve_and_validate(include_path_str, origin_file, project_root)
    origin = _relative_origin(include_path, project_root)

    return parse_fn(
        include_path, origin, depth + 1, seen_paths,
        max_include_depth, max_manifest_bytes, max_deps, project_root,
    )


def _resolve_and_validate(
    raw: str,
    origin_file: Path,
    project_root: Path,
) -> Path:
    """Resuelve la ruta del include y valida el confinamiento (R1.6).

    - Ruta absoluta → error.
    - Ruta relativa: se resuelve respecto al directorio del archivo que incluye.
    - La ruta resuelta debe estar dentro de project_root.resolve().
    - El archivo debe existir.
    """
    if not raw:
        raise ManifestParseError("include sin ruta (linea vacia tras -r/-c)")

    raw_path = Path(raw)

    if raw_path.is_absolute():
        safe = sanitize_for_output(raw)
        raise ManifestParseError(
            f"include con ruta absoluta no permitido: '{safe}'"
        )

    # Resolver respecto al directorio del archivo que tiene el include.
    resolved = (origin_file.parent / raw_path).resolve()
    root_resolved = project_root.resolve()

    # Verificar confinamiento: la ruta resuelta debe comenzar con el project_root.
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        safe = sanitize_for_output(raw)
        raise ManifestParseError(
            f"include escapa del arbol del proyecto: '{safe}'"
        ) from exc

    if not resolved.exists():
        safe = sanitize_for_output(raw)
        raise ManifestParseError(f"archivo de include no encontrado: '{safe}'")

    if not resolved.is_file():
        safe = sanitize_for_output(raw)
        raise ManifestParseError(f"include no es un archivo: '{safe}'")

    return resolved


def _relative_origin(path: Path, project_root: Path) -> str:
    """Retorna la ruta relativa al project_root como origin saneado."""
    try:
        rel = path.relative_to(project_root.resolve())
        return sanitize_for_output(str(rel))
    except ValueError:
        return sanitize_for_output(path.name)
