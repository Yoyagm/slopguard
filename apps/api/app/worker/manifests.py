"""Detección de manifiestos soportados en el diff de un PR (R6.2/R6.4).

El worker solo escanea los archivos del PR que son manifiestos que el motor entiende, y para cada
uno necesita el ecosistema (`pypi`/`npm`) que se pasa como override a `ScanService.scan_text`
(la entrada llega como texto, sin disco del que autodetectar). Un archivo no soportado se ignora;
si NINGÚN archivo cambiado es soportado, el Check Run es `neutral` "sin manifiestos que revisar".
"""

from __future__ import annotations

from pathlib import PurePosixPath

ECOSYSTEM_PYPI = "pypi"
ECOSYSTEM_NPM = "npm"

# Mapa nombre-de-archivo exacto → ecosistema. Los nombres del PR vienen como rutas POSIX.
_EXACT_NAMES: dict[str, str] = {
    "pyproject.toml": ECOSYSTEM_PYPI,
    "package.json": ECOSYSTEM_NPM,
    "package-lock.json": ECOSYSTEM_NPM,
}


def detect_ecosystem(file_path: str) -> str | None:
    """Devuelve el ecosistema del manifiesto en `file_path`, o None si no es uno soportado.

    `file_path` es la ruta del archivo dentro del repo (POSIX). Solo se mira el nombre del
    archivo (no la ruta completa), así un `requirements.txt` en cualquier subcarpeta cuenta.
    """
    name = PurePosixPath(file_path).name
    if name in _EXACT_NAMES:
        return _EXACT_NAMES[name]
    # requirements.txt, requirements-dev.txt, requirements.prod.txt, ... → pypi.
    if name == "requirements.txt" or (
        name.startswith("requirements") and name.endswith(".txt")
    ):
        return ECOSYSTEM_PYPI
    return None


def supported_manifests(changed_paths: list[str]) -> list[tuple[str, str]]:
    """Filtra los manifiestos soportados del diff. Devuelve [(path, ecosystem), ...].

    Determinista: preserva el orden de `changed_paths` y deduplica por ruta (un mismo archivo
    no se escanea dos veces aunque aparezca repetido en el diff).
    """
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for path in changed_paths:
        if path in seen:
            continue
        ecosystem = detect_ecosystem(path)
        if ecosystem is not None:
            seen.add(path)
            result.append((path, ecosystem))
    return result
