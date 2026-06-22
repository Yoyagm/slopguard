"""Registro de adapters: factory por ecosystem_id (R10.2).

`get_adapter` es el unico punto de creacion de adapters concretos. Las capas
y el scoring NUNCA importan este modulo (R10.1 / import-linter); lo usa el
orquestador (engine.py) y, en tests, el harness.
"""

from __future__ import annotations

from ..config import Config
from .pypi import PypiAdapter

# ecosystem_id del adapter por defecto.
_DEFAULT_ECOSYSTEM = "pypi"


def get_adapter(
    ecosystem_id: str = _DEFAULT_ECOSYSTEM,
    *,
    config: Config | None = None,
    use_cache: bool = True,
) -> PypiAdapter:
    """Retorna el adapter concreto para el ecosistema dado.

    En Hito 1 solo "pypi" esta soportado. Cualquier otro `ecosystem_id`
    lanza `ValueError` en vez de retornar un adapter sin contrato verificado.

    `config` es opcional: si no se pasa, se usan los defaults de `Config`.
    """
    resolved_config = config if config is not None else Config()
    if ecosystem_id == "pypi":
        return PypiAdapter(resolved_config, use_cache=use_cache)
    raise ValueError(
        f"Ecosistema '{ecosystem_id}' no soportado en Hito 1. "
        f"Ecosistemas disponibles: ['pypi']."
    )
