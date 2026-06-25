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

H4-T18: detect_ecosystem(path, override) — seleccion de ecosistema npm/pypi.
Precedencia estricta: override → stdin-guard → auto-deteccion (R1.2/R1.3/R1.5).

H4-T19: detect_and_parse/detect_and_parse_stdin — despacho de parser por ecosistema.
Con ecosystem_id="npm" se despacha a parse_package_json (Forma A, §3.3); con
ecosystem_id="pypi" (default) se preserva el comportamiento anterior intacto (R11).
detect_and_parse_stdin con ecosystem_id="npm" parsea el texto como package.json,
reutilizando el nucleo de T14 tras chequear max_manifest_bytes en bytes (§3.6).
"""

from __future__ import annotations

from pathlib import Path

from ..config import Config
from ..errors import InvalidConfigError, ManifestParseError
from ..models import Dependency
from ..normalize import sanitize_for_output
from .package_json import _parse_package_json_content, parse_package_json
from .pip_freeze import parse_pip_freeze, parse_pip_freeze_file
from .pyproject_toml import parse_pyproject_toml
from .requirements_txt import parse_requirements_txt_entry as parse_requirements_txt

# Tipos de manifiesto reconocidos (usados por --manifest-type).
MANIFEST_TYPES = frozenset({"requirements", "pyproject", "freeze"})

# Ecosistemas soportados (R1.4).
_SUPPORTED_ECOSYSTEMS: frozenset[str] = frozenset({"pypi", "npm"})


def detect_ecosystem(path: Path | None, override: str | None) -> str:
    """Detecta el ecosistema (pypi/npm) con precedencia estricta (H4-T18, R1.2/R1.3/R1.5).

    Precedencia: override → stdin-guard → auto-deteccion por nombre de archivo.
    Raises InvalidConfigError (override invalido o stdin sin --ecosystem).
    Raises ManifestParseError (nombre de archivo no reconocido).
    """
    if override is not None:
        return _resolve_override(override)

    if path is None:
        raise InvalidConfigError(
            "La entrada por stdin requiere --ecosystem explicito "
            "(no hay nombre de archivo del que inferir el ecosistema)."
        )

    return _autodetect_by_name(path)


def _resolve_override(override: str) -> str:
    """Valida y retorna el override de ecosistema (R1.3/R1.4)."""
    if override not in _SUPPORTED_ECOSYSTEMS:
        safe = sanitize_for_output(override)
        available = ", ".join(sorted(_SUPPORTED_ECOSYSTEMS))
        raise InvalidConfigError(
            f"Ecosistema '{safe}' no soportado. "
            f"Disponibles: {available}."
        )
    return override


def _autodetect_by_name(path: Path) -> str:
    """Auto-detecta ecosistema por nombre de archivo (R1.2)."""
    name = path.name.lower()

    if name == "package.json":
        return "npm"

    if name == "pyproject.toml":
        return "pypi"

    # requirements*.txt y cualquier otro .txt se tratan como manifiesto Python (pypi).
    if name.endswith(".txt"):
        return "pypi"

    safe_name = sanitize_for_output(path.name)
    raise ManifestParseError(
        f"No se puede determinar el ecosistema para '{safe_name}'. "
        f"Use --ecosystem {{npm,pypi}} para forzarlo."
    )


def detect_and_parse(
    path: Path,
    config: Config,
    *,
    ecosystem_id: str = "pypi",
    manifest_type: str | None = None,
) -> tuple[Dependency, ...]:
    """Detecta el tipo de manifiesto, parsea y dedup por nombre normalizado.

    Con ecosystem_id="npm" (H4-T19, §3.6) despacha directamente a
    parse_package_json (Forma A), ignorando manifest_type (no aplica a npm).
    Con ecosystem_id="pypi" (default) preserva el comportamiento anterior:
    deteccion por nombre + parsers Python (cero regresion, R11).
    """
    if ecosystem_id == "npm":
        return _dedup(
            parse_package_json(
                path,
                path.parent,  # ignorado por Forma A (package.json no tiene includes)
                max_manifest_bytes=config.max_manifest_bytes,
                max_deps=config.max_deps,
                max_include_depth=config.max_include_depth,
            )
        )

    return _dedup(_parse_pypi_manifest(path, config, manifest_type))


def _parse_pypi_manifest(
    path: Path,
    config: Config,
    manifest_type: str | None,
) -> tuple[Dependency, ...]:
    """Rama pypi de detect_and_parse: deteccion por nombre + parsers Python (R11).

    `manifest_type` es el override de --manifest-type; si es None se detecta
    automaticamente por nombre/extension.

    Retorna tuple de Dependency (sin deduplicar; la dedup la hace detect_and_parse).
    Lanza ManifestParseError si el tipo es invalido, el archivo es ilegible
    o el formato es incorrecto.
    """
    resolved_type = _resolve_type(path, manifest_type)

    if resolved_type == "pyproject":
        return parse_pyproject_toml(
            path,
            origin=_safe_origin(path),
            max_manifest_bytes=config.max_manifest_bytes,
            max_deps=config.max_deps,
        )
    if resolved_type == "freeze":
        return parse_pip_freeze_file(
            path,
            origin=_safe_origin(path),
            max_manifest_bytes=config.max_manifest_bytes,
            max_deps=config.max_deps,
        )
    # requirements (default)
    return parse_requirements_txt(
        path,
        origin=_safe_origin(path),
        max_manifest_bytes=config.max_manifest_bytes,
        max_deps=config.max_deps,
        max_include_depth=config.max_include_depth,
        project_root=path.parent,
    )


def detect_and_parse_stdin(
    text: str,
    config: Config,
    *,
    ecosystem_id: str = "pypi",
) -> tuple[Dependency, ...]:
    """Parsea texto de stdin segun el ecosistema (H4-T19, §3.6).

    Con ecosystem_id="npm" el texto se interpreta como package.json en memoria,
    reutilizando el nucleo de T14 (_parse_package_json_content) tras chequear
    max_manifest_bytes en bytes. origin="stdin" saneado.

    Con ecosystem_id="pypi" (default) preserva el comportamiento anterior:
    formato pip-freeze (cero regresion, R11).

    Chequea max_manifest_bytes sobre la longitud en bytes del texto antes de
    parsearlo completo (R1.9/R2.2).
    """
    byte_size = len(text.encode("utf-8"))
    if byte_size > config.max_manifest_bytes:
        raise ManifestParseError(
            f"entrada stdin supera el tamano maximo ({config.max_manifest_bytes} bytes)"
        )

    if ecosystem_id == "npm":
        deps = _parse_package_json_content(text, origin="stdin")
        if len(deps) > config.max_deps:
            raise ManifestParseError(
                f"entrada stdin supera el maximo de {config.max_deps} dependencias"
            )
        return _dedup(deps)

    # Rama pypi: pip-freeze como hoy (R11, cero regresion).
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
