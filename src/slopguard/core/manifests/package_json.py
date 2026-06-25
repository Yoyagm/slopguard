"""Parser de package.json — nucleo de parseo y punto de entrada Forma A (C2, §3.3).

Nucleo que acepta contenido ya leido (str/bytes) para ser reutilizable tanto
desde la ruta de archivo (H4-T16: parse_package_json) como desde stdin
(H4-T19: detect_and_parse_stdin con ecosystem_id="npm").

Comportamiento del nucleo:
- json.loads del contenido; malformado/top-level no-objeto/
  dependencies|devDependencies no-objeto => ManifestParseError con origin saneado.
- Itera claves de `dependencies` luego `devDependencies`.
- Normaliza cada nombre con las reglas npm (lowercase, scoped sin colapsar `/`).
- Deduplica por nombre normalizado: un mismo nombre en ambos bloques produce
  un solo Dependency (R2.5).
- version_pin = specifier solo si es pin exacto del registry (semver exacto
  sin prefijos de rango ni specifiers no-registro); si no, None.
- Sin dependencies/devDependencies o vacios => () (0 deps, exit 0, R2.3).
- Ignora peerDependencies, optionalDependencies, bundledDependencies (R2.6).
- Excluye specifiers no-registro (file:, link:, workspace:, git/git+, github:,
  tarball http(s)://) — R2.7: se omiten de forma explicita, no se consultan
  al registry, se registran como omitidas. Solo specifiers de version del
  registry (semver/dist-tag) se evaluan.

H4-T16 anade parse_package_json(path, project_root, *, max_manifest_bytes,
max_deps, max_include_depth) conformando el Protocol ManifestParser (Forma A):
- path.stat() comprueba max_manifest_bytes ANTES de leer (R2.2).
- Al superar max_deps => ManifestParseError (R2.2).
- project_root y max_include_depth se aceptan por conformidad de firma y se
  IGNORAN (package.json no soporta includes; ambos parametros son no-ops).
- origin se deriva internamente de path.name saneado.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..adapters.npm import _normalize_npm_name
from ..errors import ManifestParseError
from ..models import Dependency
from ..normalize import sanitize_for_output

_logger = logging.getLogger(__name__)

# Pin exacto del registry npm: un specifier sin prefijo de rango ni specifier
# no-registro. Semver exacto `X.Y.Z` y dist-tags simples ("latest", "next") SI
# son pin; un rango ("^1.2.3", ">=2.0.0", "~1.0", "||") NO lo es.
_IS_RANGE_SPECIFIER = re.compile(r"^[~^<>=!*]|^\|\|")

# Specifiers no-registro (R2.7): prefijos que indican que la dependencia no
# proviene del registry npm publico y por tanto no se puede evaluar como paquete
# publicado. Se excluyen de forma explicita (omision registrada, no silenciosa).
#
# Cubren:
#   file:         => ruta local al sistema de ficheros
#   link:         => enlace simbolico (yarn workspaces)
#   workspace:    => workspace de monorepo (yarn/pnpm)
#   git://        => URL git directa
#   git+          => URL git con protocolo (git+https://, git+ssh://, etc.)
#   github:       => shorthand de GitHub (usuario/repo)
#   http://       => tarball HTTP
#   https://      => tarball HTTPS
_NON_REGISTRY_PREFIXES: tuple[str, ...] = (
    "file:",
    "link:",
    "workspace:",
    "git://",
    "git+",
    "github:",
    "http://",
    "https://",
)

# Bloques de dependencias a procesar (en orden de iteracion). peer/optional/
# bundledDependencies se ignoran POR CONSTRUCCION: el loop solo itera estos
# dos bloques, nunca los demas (R2.6).
_DEP_BLOCKS: tuple[str, ...] = ("dependencies", "devDependencies")


def _is_exact_registry_pin(spec: str) -> bool:
    """True si `spec` es un pin exacto de version del registry (no un rango).

    Un pin exacto NO empieza por caracteres de rango (`~^<>=!*`) ni por `||`.
    Un specifier vacio no es un pin.
    """
    if not spec:
        return False
    return not bool(_IS_RANGE_SPECIFIER.match(spec))


def _is_non_registry_specifier(spec: str) -> bool:
    """True si `spec` es un specifier no-registro (R2.7, §3.3).

    Detecta: file:, link:, workspace:, git://, git+, github:, http://, https://.
    Un spec no-string ya se normaliza a "" antes de llegar aqui y devuelve False
    (no es no-registro: se evalua como dependencia de version desconocida).
    """
    if not spec:
        return False
    spec_lower = spec.lower()
    return any(spec_lower.startswith(prefix) for prefix in _NON_REGISTRY_PREFIXES)


def _parse_dep_block(
    block: dict[str, object],
    origin: str,
    deps: list[Dependency],
    seen_names: set[str],
    omitted: list[str],
) -> None:
    """Extrae Dependency por cada entrada del bloque de dependencias.

    Normaliza el nombre; si ya esta visto (dedup R2.5) lo ignora.
    Excluye specifiers no-registro (R2.7): los registra en `omitted` y los
    omite explicitamente (no se consultan al registry).
    version_pin solo si es pin exacto del registry.
    """
    for raw_name, spec_raw in block.items():
        spec = spec_raw if isinstance(spec_raw, str) else ""
        if _is_non_registry_specifier(spec):
            # R2.7: omitida explicita — no viaja al registry.
            safe_name = sanitize_for_output(raw_name)
            safe_spec = sanitize_for_output(spec[:80])
            omitted.append(safe_name)
            _logger.debug(
                "package.json: dependencia omitida (specifier no-registro): "
                "%s => %s",
                safe_name,
                safe_spec,
            )
            continue
        normalized = _normalize_npm_name(raw_name)
        if normalized in seen_names:
            continue
        seen_names.add(normalized)
        version_pin = sanitize_for_output(spec) if _is_exact_registry_pin(spec) else None
        deps.append(
            Dependency(
                name=normalized,
                version_pin=version_pin,
                raw=sanitize_for_output(raw_name),
                origin=origin,
            )
        )


def _load_json_object(content: str | bytes, origin: str) -> dict[str, object]:
    """Carga el contenido como JSON y verifica que sea un objeto de nivel superior.

    Lanza ManifestParseError si el JSON esta malformado o el top-level no es dict.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError) as exc:
        safe = sanitize_for_output(origin)
        raise ManifestParseError(
            f"'{safe}' no es JSON valido: {sanitize_for_output(str(exc)[:120])}"
        ) from exc
    if not isinstance(data, dict):
        safe = sanitize_for_output(origin)
        raise ManifestParseError(
            f"'{safe}': el top-level de package.json debe ser un objeto JSON."
        )
    return data


def _collect_dep_blocks(
    data: dict[str, object],
    origin: str,
    deps: list[Dependency],
    seen_names: set[str],
    omitted: list[str],
) -> None:
    """Itera _DEP_BLOCKS y acumula Dependency en `deps`, omitidas en `omitted`.

    Lanza ManifestParseError si un bloque existe pero no es un objeto JSON.
    """
    for block_key in _DEP_BLOCKS:
        block = data.get(block_key)
        if block is None:
            continue
        if not isinstance(block, dict):
            safe = sanitize_for_output(origin)
            raise ManifestParseError(
                f"'{safe}': el bloque '{block_key}' debe ser un objeto JSON, "
                f"no {type(block).__name__!r}."
            )
        _parse_dep_block(block, origin, deps, seen_names, omitted)


def _parse_package_json_content(
    content: str | bytes,
    origin: str,
) -> tuple[Dependency, ...]:
    """Nucleo de parseo de package.json sobre contenido ya leido.

    `content` es el JSON ya leido como str o bytes.
    `origin` es el identificador saneado del origen (nombre de archivo o "stdin").

    Lanza ManifestParseError ante JSON malformado, top-level no-objeto o bloque
    de dependencias no-objeto. Devuelve tuple vacio si no hay dependencias (R2.3).
    Specifiers no-registro (R2.7) se omiten explicitamente (log DEBUG).
    """
    data = _load_json_object(content, origin)
    deps: list[Dependency] = []
    seen_names: set[str] = set()
    omitted: list[str] = []

    _collect_dep_blocks(data, origin, deps, seen_names, omitted)

    if omitted:
        _logger.debug(
            "package.json (%s): %d dependencia(s) omitida(s) (no-registro): %s",
            sanitize_for_output(origin),
            len(omitted),
            omitted,
        )
    return tuple(deps)


# ---------------------------------------------------------------------------
# H4-T16: punto de entrada Forma A — cumple Protocol ManifestParser (§3.3).
# ---------------------------------------------------------------------------


def parse_package_json(
    path: Path,
    project_root: Path,  # ignorado: package.json no soporta includes (Forma A, §3.3)
    *,
    max_manifest_bytes: int,
    max_deps: int,
    max_include_depth: int,  # ignorado: package.json no soporta includes (Forma A, §3.3)
) -> tuple[Dependency, ...]:
    """Parsea package.json desde `path` aplicando los limites indicados (Forma A, §3.3).

    Cumple la firma del Protocol ManifestParser para enchufarse en detect_and_parse.
    `project_root` y `max_include_depth` se aceptan por conformidad de Protocol y se
    ignoran explicitamente (package.json no soporta includes; ambos son no-ops).

    Comportamiento:
    - Comprueba `max_manifest_bytes` via path.stat() ANTES de leer (R2.2).
    - Lanza ManifestParseError si el archivo supera max_manifest_bytes o no es accesible.
    - Parsea el contenido con el nucleo `_parse_package_json_content`.
    - Lanza ManifestParseError si el numero de dependencias supera max_deps (R2.2).
    - `origin` se deriva de path.name saneado (no se acepta como parametro, igual que
      los parsers PyPI via _safe_origin).
    """
    origin = sanitize_for_output(path.name)

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ManifestParseError(
            f"no se puede acceder al manifiesto '{origin}'"
        ) from exc

    if size > max_manifest_bytes:
        raise ManifestParseError(
            f"manifiesto '{origin}' supera el tamano maximo ({max_manifest_bytes} bytes)"
        )

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ManifestParseError(f"error al leer '{origin}'") from exc

    deps = _parse_package_json_content(content, origin)

    if len(deps) > max_deps:
        raise ManifestParseError(
            f"manifiesto '{origin}' supera el maximo de {max_deps} dependencias"
        )

    return deps
