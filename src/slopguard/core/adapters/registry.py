"""Registro de adapters: factory por ecosystem_id (R1.1, R1.4, C5).

`get_adapter` es el unico punto de creacion de adapters concretos. Las capas
y el scoring NUNCA importan este modulo (R10.1 / import-linter); lo usa el
orquestador (engine.py) y, en tests, el harness.
"""

from __future__ import annotations

from ..config import Config
from .npm import NpmAdapter
from .pypi import PypiAdapter

# ecosystem_id del adapter por defecto.
_DEFAULT_ECOSYSTEM = "pypi"

# Ecosistemas disponibles: lista canonica para mensajes de error (R1.4).
_AVAILABLE_ECOSYSTEMS: list[str] = ["npm", "pypi"]


def get_adapter(
    ecosystem_id: str = _DEFAULT_ECOSYSTEM,
    *,
    config: Config | None = None,
    use_cache: bool = True,
) -> PypiAdapter | NpmAdapter:
    """Retorna el adapter concreto para el ecosistema dado (R1.1, R1.4).

    - "pypi" -> PypiAdapter
    - "npm"  -> NpmAdapter  (H4-T13, C5)

    Cualquier otro `ecosystem_id` lanza `ValueError` listando los disponibles
    (R1.4), en vez de retornar un adapter sin contrato verificado.

    `config` es opcional: si no se pasa, se usan los defaults de `Config`.
    """
    resolved_config = config if config is not None else Config()
    if ecosystem_id == "pypi":
        return PypiAdapter(resolved_config, use_cache=use_cache)
    if ecosystem_id == "npm":
        return NpmAdapter(resolved_config, use_cache=use_cache)
    raise ValueError(
        f"Ecosistema '{ecosystem_id}' no soportado. "
        f"Ecosistemas disponibles: {_AVAILABLE_ECOSYSTEMS}."
    )
