"""Deteccion de tipo de manifiesto y punto de entrada unificado (R1.7-R1.9, T11).

Detecta por nombre/extension:
  - requirements*.txt       → parser requirements_txt
  - pyproject.toml          → parser pyproject_toml
  - stdin (`-`)             → parser pip_freeze (texto ya leido)
  - cualquier .txt restante → intenta requirements_txt
  - override --manifest-type {requirements, pyproject, freeze}

Chequea max_manifest_bytes ANTES de leer el contenido completo (R1.9).
Manifiesto vacio → 0 deps, exit 0 (R1.7).
Malformado → ManifestParseError con ruta (+linea si el parser la expone),
sin stacktrace crudo (R1.8).
"""

from __future__ import annotations

from pathlib import Path

from ..config import Config
from ..errors import ManifestParseError
from ..models import Dependency
from ..normalize import sanitize_for_output
from .pip_freeze import parse_pip_freeze, parse_pip_freeze_file
from .pyproject_toml import parse_pyproject_toml
from .requirements_txt import parse_requirements_txt_entry as parse_requirements_txt

# Tipos de manifiesto reconocidos (usados por --manifest-type).
MANIFEST_TYPES = frozenset({"requirements", "pyproject", "freeze"})


def detect_and_parse(
    path: Path,
    config: Config,
    *,
    manifest_type: str | None = None,
) -> tuple[Dependency, ...]:
    """Detecta el tipo de manifiesto, parsea y dedup por nombre normalizado.

    `manifest_type` es el override de --manifest-type; si es None se detecta
    automaticamente por nombre/extension.

    Retorna un tuple de `Dependency` ya deduplicado. Tuple vacio = 0 deps.
    Lanza `ManifestParseError` si el tipo es invalido, el archivo es ilegible
    o el formato es incorrecto.
    """
    resolved_type = _resolve_type(path, manifest_type)

    if resolved_type == "pyproject":
        raw = parse_pyproject_toml(
            path,
            origin=_safe_origin(path),
            max_manifest_bytes=config.max_manifest_bytes,
            max_deps=config.max_deps,
        )
    elif resolved_type == "freeze":
        raw = parse_pip_freeze_file(
            path,
            origin=_safe_origin(path),
            max_manifest_bytes=config.max_manifest_bytes,
            max_deps=config.max_deps,
        )
    else:
        # requirements (default)
        raw = parse_requirements_txt(
            path,
            origin=_safe_origin(path),
            max_manifest_bytes=config.max_manifest_bytes,
            max_deps=config.max_deps,
            max_include_depth=config.max_include_depth,
            project_root=path.parent,
        )

    return _dedup(raw)


def detect_and_parse_stdin(
    text: str,
    config: Config,
) -> tuple[Dependency, ...]:
    """Parsea texto de stdin (formato pip freeze) (R1.3).

    Chequea max_manifest_bytes sobre la longitud en bytes del texto antes de
    parsearlo completo (R1.9).
    """
    byte_size = len(text.encode("utf-8"))
    if byte_size > config.max_manifest_bytes:
        raise ManifestParseError(
            f"entrada stdin supera el tamano maximo ({config.max_manifest_bytes} bytes)"
        )

    raw = parse_pip_freeze(text, origin="stdin", max_deps=config.max_deps)
    return _dedup(raw)


def _resolve_type(path: Path, manifest_type: str | None) -> str:
    """Determina el tipo de parser a usar."""
    if manifest_type is not None:
        safe_type = sanitize_for_output(manifest_type)
        if manifest_type not in MANIFEST_TYPES:
            raise ManifestParseError(
                f"tipo de manifiesto desconocido: '{safe_type}'. "
                f"Valores validos: {', '.join(sorted(MANIFEST_TYPES))}"
            )
        return manifest_type

    name = path.name.lower()

    if name == "pyproject.toml":
        return "pyproject"

    # requirements*.txt (p.ej. requirements.txt, requirements-dev.txt, etc.)
    if name.startswith("requirements") and name.endswith(".txt"):
        return "requirements"

    # Cualquier otro .txt: intentar como requirements.
    if name.endswith(".txt"):
        return "requirements"

    # Fallback: si no se reconoce la extension, informar.
    safe_name = sanitize_for_output(path.name)
    raise ManifestParseError(
        f"tipo de manifiesto no reconocido para '{safe_name}'. "
        f"Use --manifest-type {{requirements,pyproject,freeze}} para forzarlo."
    )


def _dedup(deps: tuple[Dependency, ...]) -> tuple[Dependency, ...]:
    """Deduplication final por nombre normalizado (R1.10).

    Los parsers ya hacen dedup internamente, pero este paso garantiza
    que cuando varios parsers se componen no haya duplicados.
    """
    seen: set[str] = set()
    result: list[Dependency] = []
    for dep in deps:
        if dep.name not in seen:
            seen.add(dep.name)
            result.append(dep)
    return tuple(result)


def _safe_origin(path: Path) -> str:
    """Retorna el nombre de archivo como origin saneado (sin ruta absoluta)."""
    return sanitize_for_output(path.name)
