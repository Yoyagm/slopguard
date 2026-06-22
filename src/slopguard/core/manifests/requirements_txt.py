"""Parser de requirements.txt (R1.1, R1.4, R1.11).

Extrae dependencias de formato pip: nombre normalizado PEP 503 + version_pin.
Ignora silenciosamente: comentarios, lineas en blanco, -e (editable), --hash,
URLs (http://, https://), VCS (git+, svn+, hg+, bzr+), opciones globales
(--index-url, --extra-index-url, --trusted-host, --require-hashes, --no-binary,
--only-binary, -f / --find-links) y cualquier flag --... que no sea una
dependencia. Las referencias -r se resuelven con `includes.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..errors import ManifestParseError
from ..models import Dependency
from ..normalize import normalize_name, sanitize_for_output
from .includes import _ParseFn, resolve_includes

# Detecta una URL de esquema o VCS al inicio de la linea.
_URL_SCHEMES = re.compile(r"^(?:https?://|git\+|svn\+|hg\+|bzr\+)", re.IGNORECASE)

# Opciones de pip que empiezan con guion y no son dependencias.
_OPTION_LINE = re.compile(
    r"^(?:-[iecrfhv]|--(index-url|extra-index-url|trusted-host|"
    r"require-hashes|no-binary|only-binary|find-links|pre|no-index|hash)[^\w]?|--[a-z])",
    re.IGNORECASE,
)

# Especificadores de version reconocidos tras el nombre.
# El grupo opcional `(?:\[[^\]]*\])?` consume la seccion de extras PEP 508
# (p.ej. `[standard]` en `uvicorn[standard]==0.20.0`) antes del especificador,
# para que group(3) capture el specifier completo incluyendo el pin ==X (R1.11).
_NAME_VERSION = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[[^\]]*\])?"
    r"(\s*(?:[><=!~^]+\s*[^\s;#,]+(?:\s*,\s*[><=!~^]+\s*[^\s;#,]+)*)?)"
)

# Captura solo la parte ==X (pin exacto).
_EXACT_PIN = re.compile(r"==\s*([^\s,;]+)")


class _ReqParser:
    """Estado de parseo de un requirements.txt (encapsula todo el contexto)."""

    def __init__(
        self,
        max_manifest_bytes: int,
        max_deps: int,
        max_include_depth: int,
        project_root: Path,
    ) -> None:
        self._max_manifest_bytes = max_manifest_bytes
        self._max_deps = max_deps
        self._max_include_depth = max_include_depth
        self._project_root = project_root

    def parse(
        self,
        path: Path,
        origin: str,
        depth: int,
        seen_paths: set[Path],
    ) -> tuple[Dependency, ...]:
        """Parsea `path` y retorna sus dependencias normalizadas.

        `seen_paths` es la PILA de la rama actual de recursion (no el conjunto
        global de todos los visitados). Se agrega la ruta al entrar y se elimina
        al salir (try/finally), permitiendo que un archivo compartido por dos
        ramas distintas (patron diamante) se procese en ambas sin falso ciclo.
        Solo un ciclo REAL (A→B→A en la misma rama) permanece en la pila y
        dispara el error. (Fix: falso positivo con includes en diamante.)
        """
        resolved = path.resolve()
        if resolved in seen_paths:
            safe = sanitize_for_output(str(path.name))
            raise ManifestParseError(f"ciclo de inclusion detectado en '{safe}'")

        seen_paths.add(resolved)
        try:
            content = _read_bounded(path, self._max_manifest_bytes)

            deps: list[Dependency] = []
            seen_names: set[str] = set()
            for lineno, raw_line in enumerate(content.splitlines(), start=1):
                result = self._process_line(raw_line, lineno, origin, path, depth, seen_paths)
                if result is None:
                    continue
                _merge_result(result, deps, seen_names)
                if len(deps) > self._max_deps:
                    raise ManifestParseError(
                        f"manifiesto supera el maximo de {self._max_deps} dependencias"
                    )

            return tuple(deps)
        finally:
            seen_paths.discard(resolved)

    def _process_line(  # noqa: PLR0913
        self,
        raw_line: str,
        lineno: int,
        origin: str,
        path: Path,
        depth: int,
        seen_paths: set[Path],
    ) -> Dependency | tuple[Dependency, ...] | None:
        """Procesa una linea del requirements.txt y retorna el resultado."""
        line = raw_line.strip()
        if not line or line.startswith("#"):
            return None
        if "#" in line:
            line = line[: line.index("#")].strip()
        if not line:
            return None

        # Forma con espacio/tab: `-r base.txt` y `-c constraints.txt`.
        # Forma pegada: `-rbase.txt` y `-cbase.txt` (tambien valida para pip).
        # R1.6: no omitir deps en silencio → detectar ambas formas explicitamente.
        _PREFIX_LEN = 2  # longitud del prefijo '-r' / '-c'
        if line.startswith(("-r ", "-r\t", "-c ", "-c\t")):
            include_path_str = line[_PREFIX_LEN:].strip()
        elif (line.startswith("-r") or line.startswith("-c")) and len(line) > _PREFIX_LEN:
            include_path_str = line[_PREFIX_LEN:].strip()
        else:
            include_path_str = None

        if include_path_str is not None:
            return resolve_includes(
                include_path_str, path, self._project_root, seen_paths, depth,
                self._as_parse_fn(),
                max_include_depth=self._max_include_depth,
                max_manifest_bytes=self._max_manifest_bytes,
                max_deps=self._max_deps,
            )

        if _should_ignore(line):
            return None

        return _parse_dep_line(line, lineno, origin)

    def _as_parse_fn(self) -> _ParseFn:
        """Retorna un callable compatible con `_ParseFn` para includes.py."""
        def _fn(  # noqa: PLR0913
            path: Path,
            origin: str,
            depth: int,
            seen_paths: set[Path],
            max_include_depth: int,
            max_manifest_bytes: int,
            max_deps: int,
            project_root: Path | None,
        ) -> tuple[Dependency, ...]:
            parser = _ReqParser(
                max_manifest_bytes=max_manifest_bytes,
                max_deps=max_deps,
                max_include_depth=max_include_depth,
                project_root=project_root or path.parent,
            )
            return parser.parse(path, origin, depth, seen_paths)

        return _fn


def parse_requirements_txt(  # noqa: PLR0913
    path: Path,
    origin: str,
    depth: int,
    seen_paths: set[Path],
    max_include_depth: int,
    max_manifest_bytes: int,
    max_deps: int,
    project_root: Path | None,
) -> tuple[Dependency, ...]:
    """Parsea un requirements.txt (firma compatible con `_ParseFn` de includes.py)."""
    parser = _ReqParser(
        max_manifest_bytes=max_manifest_bytes,
        max_deps=max_deps,
        max_include_depth=max_include_depth,
        project_root=project_root or path.parent,
    )
    return parser.parse(path, origin, depth, seen_paths)


def parse_requirements_txt_entry(  # noqa: PLR0913
    path: Path,
    origin: str,
    *,
    max_manifest_bytes: int,
    max_deps: int,
    max_include_depth: int,
    project_root: Path | None = None,
) -> tuple[Dependency, ...]:
    """Punto de entrada publico con argumentos con nombre (para detect.py y tests)."""
    return parse_requirements_txt(
        path, origin, 0, set(), max_include_depth, max_manifest_bytes, max_deps,
        project_root,
    )


def _merge_result(
    result: Dependency | tuple[Dependency, ...],
    deps: list[Dependency],
    seen_names: set[str],
) -> None:
    """Agrega resultado de una linea a la lista de deps sin duplicados."""
    if isinstance(result, tuple):
        for dep in result:
            if dep.name not in seen_names:
                seen_names.add(dep.name)
                deps.append(dep)
    elif result.name not in seen_names:
        seen_names.add(result.name)
        deps.append(result)


def _should_ignore(line: str) -> bool:
    """True si la linea debe ignorarse (editable, URL, VCS, opcion)."""
    if line.startswith(("-e ", "-e\t")):
        return True
    if _URL_SCHEMES.match(line):
        return True
    if _OPTION_LINE.match(line):
        return True
    return line.startswith("-")


def _parse_dep_line(line: str, lineno: int, origin: str) -> Dependency:
    """Parsea una linea de dependencia y retorna un Dependency."""
    match = _NAME_VERSION.match(line)
    if not match:
        safe_origin = sanitize_for_output(origin)
        raise ManifestParseError(
            f"linea {lineno} de '{safe_origin}' no es parseable: "
            f"'{sanitize_for_output(line[:80])}'"
        )

    raw_name = match.group(1)
    version_spec = match.group(3).strip() if match.group(3) else ""
    norm_name = normalize_name(raw_name)
    pin_match = _EXACT_PIN.search(version_spec)
    raw_pin = pin_match.group(1) if pin_match else None
    # Sanear version_pin igual que raw: un manifiesto malicioso podria
    # inyectar secuencias ANSI en la version (R6.5/NFR-Seg.5).
    version_pin = sanitize_for_output(raw_pin) if raw_pin is not None else None

    return Dependency(
        name=norm_name,
        version_pin=version_pin,
        raw=sanitize_for_output(raw_name),
        origin=origin,
    )


def _read_bounded(path: Path, max_bytes: int) -> str:
    """Lee el archivo verificando el limite de tamano antes de parsear (R1.9)."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        safe = sanitize_for_output(str(path.name))
        raise ManifestParseError(
            f"no se puede acceder al manifiesto '{safe}'"
        ) from exc

    if size > max_bytes:
        raise ManifestParseError(
            f"manifiesto supera el tamano maximo ({max_bytes} bytes)"
        )

    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        safe = sanitize_for_output(str(path.name))
        raise ManifestParseError(f"error al leer '{safe}'") from exc
