"""Contrato del parser de manifiestos: protocolo y tipo de retorno.

Todo parser concreto implementa `ManifestParser` y produce un
`tuple[Dependency, ...]` ya con nombres normalizados PEP 503.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..models import Dependency


class ManifestParser(Protocol):
    """Interfaz de un parser de manifiesto.

    Recibe la ruta al archivo fuente y el directorio raiz del proyecto
    (necesario para confinar includes) y devuelve las dependencias ya
    normalizadas y deduplicadas.
    """

    def parse(
        self,
        path: Path,
        project_root: Path,
        *,
        max_manifest_bytes: int,
        max_deps: int,
        max_include_depth: int,
    ) -> tuple[Dependency, ...]:
        """Parsea el manifiesto y retorna sus dependencias.

        Lanza `ManifestParseError` ante formato invalido, tamanio excedido,
        include escapado/ciclico/inexistente. Nunca propaga stacktraces crudos.
        """
        ...
