"""H4-T28: aislamiento de la watchlist por ecosistema (ADR-8, R8.2/NFR-Seg.3).

Tests unitarios SIN red: la clave de cache de la watchlist se prefija por ecosistema
(`npm:`/`pypi:`), de modo que una corrida npm y una PyPI del MISMO host/path NO comparten
blob de corpus (un match por nombre normalizado no cruza ecosistemas). Un `ecosystem_id`
fuera de la tabla cerrada es `ValueError` fail-closed. El camino de red/parseo del corpus
ya lo cubre `test_h2_watchlist.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from slopguard.core.config import Config
from slopguard.core.threatintel.watchlist import WatchlistSource


def _config(**overrides: Any) -> Config:
    base: dict[str, Any] = {"connect_timeout_s": 2.0, "read_timeout_s": 2.0}
    base.update(overrides)
    return Config(**base)


def test_cache_key_watchlist_se_prefija_por_ecosistema() -> None:
    npm = WatchlistSource(_config(), ecosystem_id="npm", use_cache=False)
    pypi = WatchlistSource(_config(), ecosystem_id="pypi", use_cache=False)
    assert npm._cache_key.startswith("npm:")
    assert pypi._cache_key.startswith("pypi:")
    # Mismo host/path, distinto prefijo => NO comparten blob de corpus (R8.2).
    assert npm._cache_key != pypi._cache_key


def test_ecosystem_id_fuera_de_tabla_es_value_error() -> None:
    with pytest.raises(ValueError):
        WatchlistSource(_config(), ecosystem_id="cargo", use_cache=False)
