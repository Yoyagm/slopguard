"""Parser de pyproject.toml (R1.2).

Extrae [project].dependencies y [project.optional-dependencies] via tomllib
(stdlib Python 3.11+). Produce nombres normalizados PEP 503 + version_pin.
Las dependencias de optional-dependencies se incluyen todas (todas las extras).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from ..errors import ManifestParseError
from ..models import Dependency
from ..normalize import normalize_name, sanitize_for_output

# Misma regex de pin exacto que requirements_txt para consistencia.
_EXACT_PIN = re.compile(r"==\s*([^\s,;]+)")
# Nombre de paquete al inicio de una especificacion PEP 508.
_PEP508_NAME = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")


def parse_pyproject_toml(
    path: Path,
    origin: str,
    *,
    max_manifest_bytes: int,
    max_deps: int,
) -> tuple[Dependency, ...]:
    """Parsea un pyproject.toml y retorna dependencias de [project].

    Extrae tanto `[project].dependencies` como todas las claves de
    `[project.optional-dependencies]`. Dedup por nombre normalizado (R1.10).
    """
    _check_size(path, max_manifest_bytes)
    data = _load_toml(path, origin)

    project = data.get("project")
    if not isinstance(project, dict):
        return ()  # pyproject.toml sin seccion [project]: 0 deps, no es error

    deps: list[Dependency] = []
    seen_names: set[str] = set()

    _collect_main_deps(project, origin, deps, seen_names, max_deps)
    _collect_optional_deps(project, origin, deps, seen_names, max_deps)

    return tuple(deps)


def _collect_main_deps(
    project: dict[str, object],
    origin: str,
    deps: list[Dependency],
    seen_names: set[str],
    max_deps: int,
) -> None:
    """Agrega dependencias principales de [project].dependencies."""
    main_deps = project.get("dependencies", [])
    if not isinstance(main_deps, list):
        safe = sanitize_for_output(origin)
        raise ManifestParseError(
            f"'{safe}': [project].dependencies debe ser una lista"
        )
    _collect_specs(main_deps, origin, deps, seen_names, max_deps)


def _collect_optional_deps(
    project: dict[str, object],
    origin: str,
    deps: list[Dependency],
    seen_names: set[str],
    max_deps: int,
) -> None:
    """Agrega dependencias de [project.optional-dependencies] (todas las extras)."""
    opt_deps = project.get("optional-dependencies", {})
    if not isinstance(opt_deps, dict):
        safe = sanitize_for_output(origin)
        raise ManifestParseError(
            f"'{safe}': [project.optional-dependencies] debe ser una tabla"
        )
    for extra_name, extra_list in opt_deps.items():
        if not isinstance(extra_list, list):
            safe = sanitize_for_output(origin)
            safe_extra = sanitize_for_output(str(extra_name))
            raise ManifestParseError(
                f"'{safe}': optional-dependencies['{safe_extra}'] debe ser una lista"
            )
        _collect_specs(extra_list, origin, deps, seen_names, max_deps)


def _collect_specs(
    specs: list[object],
    origin: str,
    deps: list[Dependency],
    seen_names: set[str],
    max_deps: int,
) -> None:
    """Agrega dependencias de una lista de specs PEP 508 a `deps`."""
    for spec in specs:
        if not isinstance(spec, str):
            safe = sanitize_for_output(origin)
            raise ManifestParseError(
                f"'{safe}': especificacion de dependencia no es una cadena: {spec!r}"
            )

        dep = _parse_pep508(spec, origin)
        if dep is None:
            continue  # linea vacia o no parseable como nombre

        if dep.name in seen_names:
            continue  # dedup (R1.10)

        seen_names.add(dep.name)
        deps.append(dep)

        if len(deps) > max_deps:
            raise ManifestParseError(
                f"manifiesto supera el maximo de {max_deps} dependencias"
            )


def _parse_pep508(spec: str, origin: str) -> Dependency | None:
    """Extrae nombre normalizado y version_pin de una especificacion PEP 508."""
    stripped = spec.strip()
    if not stripped:
        return None

    match = _PEP508_NAME.match(stripped)
    if not match:
        safe = sanitize_for_output(origin)
        raise ManifestParseError(
            f"'{safe}': especificacion invalida: '{sanitize_for_output(stripped[:80])}'"
        )

    raw_name = match.group(1)
    rest = stripped[match.end():]
    pin_match = _EXACT_PIN.search(rest)
    raw_pin = pin_match.group(1) if pin_match else None
    # Sanear version_pin: un pyproject.toml malicioso podria inyectar secuencias
    # ANSI en la version, que se emite en salida humana y JSON (R6.5/NFR-Seg.5).
    version_pin = sanitize_for_output(raw_pin) if raw_pin is not None else None

    return Dependency(
        name=normalize_name(raw_name),
        version_pin=version_pin,
        raw=sanitize_for_output(raw_name),
        origin=origin,
    )


def _check_size(path: Path, max_bytes: int) -> None:
    """Verifica el tamanio del archivo antes de cargarlo (R1.9)."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        safe = sanitize_for_output(str(path.name))
        raise ManifestParseError(f"no se puede acceder a '{safe}'") from exc
    if size > max_bytes:
        raise ManifestParseError(
            f"manifiesto supera el tamano maximo ({max_bytes} bytes)"
        )


def _load_toml(path: Path, origin: str) -> dict[str, object]:
    """Carga y parsea el TOML; convierte errores en ManifestParseError (R1.8)."""
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        safe = sanitize_for_output(origin)
        # Sanear el mensaje de tomllib: aunque actualmente solo expone linea/columna,
        # el contrato entre versiones no lo garantiza y el mensaje podria arrastrar
        # fragmentos del contenido del manifiesto (R6.5, defensa en profundidad).
        safe_exc = sanitize_for_output(str(exc))
        raise ManifestParseError(f"TOML invalido en '{safe}': {safe_exc}") from exc
    except OSError as exc:
        safe = sanitize_for_output(origin)
        raise ManifestParseError(f"error al leer '{safe}'") from exc
