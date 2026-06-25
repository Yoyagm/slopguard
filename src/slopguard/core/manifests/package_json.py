"""Parser de package.json — nucleo de parseo (H4-T14, C2, §3.3).

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

H4-T15 anade la exclusion de specifiers no-registro (file:, link:, workspace:,
git/git+, github:, tarball http(s)://) sobre este nucleo.
H4-T16 anade parse_package_json(path, project_root, *, max_manifest_bytes,
max_deps, max_include_depth) conformando el Protocol ManifestParser (Forma A).
"""

from __future__ import annotations

import json
import re

from ..adapters.npm import _normalize_npm_name
from ..errors import ManifestParseError
from ..models import Dependency
from ..normalize import sanitize_for_output

# Pin exacto del registry npm: un specifier sin prefijo de rango ni specifier
# no-registro. Semver exacto `X.Y.Z` y dist-tags simples ("latest", "next") SI
# son pin; un rango ("^1.2.3", ">=2.0.0", "~1.0", "||") NO lo es.
_IS_RANGE_SPECIFIER = re.compile(r"^[~^<>=!*]|^\|\|")

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


def _parse_dep_block(
    block: dict[str, object],
    origin: str,
    deps: list[Dependency],
    seen_names: set[str],
) -> None:
    """Extrae Dependency por cada entrada del bloque de dependencias.

    Normaliza el nombre; si ya esta visto (dedup R2.5) lo ignora.
    version_pin solo si es pin exacto del registry.
    """
    for raw_name, spec_raw in block.items():
        spec = spec_raw if isinstance(spec_raw, str) else ""
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


def _parse_package_json_content(
    content: str | bytes,
    origin: str,
) -> tuple[Dependency, ...]:
    """Nucleo de parseo de package.json sobre contenido ya leido.

    `content` es el JSON ya leido como str o bytes.
    `origin` es el identificador saneado del origen (nombre de archivo o "stdin").

    Lanza ManifestParseError si:
    - el JSON esta malformado,
    - el top-level no es un objeto,
    - dependencies o devDependencies existen pero no son objetos.

    Devuelve tuple vacio si no hay dependencias (R2.3).
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

    deps: list[Dependency] = []
    seen_names: set[str] = set()

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
        _parse_dep_block(block, origin, deps, seen_names)

    return tuple(deps)
