"""H4-T28: aislamiento de la Capa 3 (OSV) por ecosistema (ADR-5, R8.1/R8.2/NFR-Seg.3).

Tests unitarios SIN red. El camino de red (MAL-*, degradacion, charset, paginacion) ya lo
cubre `test_h2_osv.py`; aqui se fija la NUEVA superficie de la parametrizacion por ecosistema:

- el body del `querybatch` lleva la constante de ecosistema correcta (`npm`/`PyPI`),
- la clave de cache se prefija por ecosistema (`npm:`/`pypi:`),
- el validador de blob RECHAZA un blob del ecosistema ajeno —aislamiento por VALIDADOR
  ademas de por clave— en AMBAS direcciones npm<->pypi (la direccion pypi-rechaza-npm ya
  esta en test_h2_osv via parametrize; aqui se cubre npm-acepta-npm y npm-rechaza-pypi),
- un `ecosystem_id` fuera de la tabla cerrada es `ValueError` fail-closed.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from slopguard.core.config import Config
from slopguard.core.threatintel import osv
from slopguard.core.threatintel.osv import OsvSource
from slopguard.core.threatintel.source import MaliceState


def _config(**overrides: Any) -> Config:
    """Config base con timeouts cortos (no se toca la red en estos tests)."""
    base: dict[str, Any] = {
        "connect_timeout_s": 2.0,
        "read_timeout_s": 2.0,
        "osv_timeout_total_por_lote_s": 2.0,
        "osv_reintentos": 1,
    }
    base.update(overrides)
    return Config(**base)


def _npm_source() -> OsvSource:
    return OsvSource(_config(), ecosystem_id="npm", use_cache=False)


def _pypi_source() -> OsvSource:
    return OsvSource(_config(), ecosystem_id="pypi", use_cache=False)


def test_build_body_lleva_la_constante_de_ecosistema_correcta() -> None:
    # La constante viaja en el body; nunca se refleja un valor del usuario (R8.1).
    assert '"ecosystem": "npm"' in json.dumps(_npm_source()._build_body(["react"]))
    assert '"ecosystem": "PyPI"' in json.dumps(_pypi_source()._build_body(["react"]))


def test_cache_key_se_prefija_por_ecosistema() -> None:
    assert _npm_source()._cache_key("react") == "npm:react"
    assert _pypi_source()._cache_key("react") == "pypi:react"
    assert _npm_source()._cache_key("react") != _pypi_source()._cache_key("react")


def test_to_blob_persiste_el_ecosistema_npm() -> None:
    # Un result CLEAN (sin vulns) serializa con ecosystem "npm" (2a capa de aislamiento).
    result = osv._parse_batch_response({"results": [{"vulns": []}]}, ["react"])["react"]
    blob = _npm_source()._to_blob(result)
    assert blob["ecosystem"] == "npm"
    assert blob["name"] == "react"


def test_validador_npm_acepta_su_blob_y_rechaza_el_de_pypi() -> None:
    npm_clean = {"source": "osv", "ecosystem": "npm", "name": "react", "state": "clean"}
    pypi_clean = {"source": "osv", "ecosystem": "pypi", "name": "react", "state": "clean"}
    npm = _npm_source()
    aceptado = npm._validate_osv_blob(dict(npm_clean), "react")
    assert aceptado is not None and aceptado.state is MaliceState.CLEAN
    # Un blob del ecosistema ajeno NO es legible (rechazo por validador, no solo por clave).
    assert npm._validate_osv_blob(dict(pypi_clean), "react") is None


def test_validador_pypi_rechaza_blob_npm() -> None:
    npm_clean = {"source": "osv", "ecosystem": "npm", "name": "react", "state": "clean"}
    assert _pypi_source()._validate_osv_blob(npm_clean, "react") is None


def test_ecosystem_id_fuera_de_tabla_es_value_error() -> None:
    with pytest.raises(ValueError):
        OsvSource(_config(), ecosystem_id="cargo", use_cache=False)


# --------------------------------------------------------------------------- #
# Camino de red END-TO-END npm (query_batch real salvo el POST). Cierra el hueco
# de la auditoria: que la constante de ecosistema npm llegue al POST real (no solo
# a _build_body aislado) y que el lote npm degrade fail-closed igual que pypi.
# --------------------------------------------------------------------------- #


class _FakeHttp:
    """Transporte falso: captura el body del POST y devuelve un payload fijo."""

    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload
        self.last_body: dict[str, object] | None = None

    def post_json(self, _url: str, body: dict[str, object], **_kw: object) -> dict[str, object]:
        self.last_body = body
        return self._payload


def test_query_batch_npm_mal_es_malicious_y_el_body_lleva_npm() -> None:
    source = _npm_source()
    fake = _FakeHttp({"results": [{"vulns": [{"id": "MAL-2025-47868"}]}]})
    source._http = fake  # type: ignore[assignment]  # camino de red real salvo el POST
    resolved = source.query_batch(["bioql"])
    assert resolved["bioql"].state is MaliceState.MALICIOUS
    assert [a.id for a in resolved["bioql"].advisories] == ["MAL-2025-47868"]
    # La constante npm viaja en el POST real (integrado), no solo en _build_body aislado.
    assert fake.last_body is not None
    assert '"ecosystem": "npm"' in json.dumps(fake.last_body)


def test_query_batch_npm_respuesta_desalineada_es_unverifiable_no_clean() -> None:
    # NFR-Degr.1: un lote npm con results mas corto que queries degrada a UNVERIFIABLE,
    # jamas CLEAN (mismo fail-closed que pypi, verificado por la ruta npm).
    source = _npm_source()
    source._http = _FakeHttp({"results": []})  # type: ignore[assignment]  # 0 resultados, 1 query
    resolved = source.query_batch(["bioql"])
    assert resolved["bioql"].state is MaliceState.UNVERIFIABLE
