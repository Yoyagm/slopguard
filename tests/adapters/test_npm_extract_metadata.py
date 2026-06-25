"""Tests del mapeo packument npm -> PackageMetadata (H4-T06, ADR-1, §3.2).

Cubre R4.2 (mapeo campo-por-campo) y R4.4 (anómalo => flags False/None, fail-closed).
No requiere red ni fixture de fetch: `_extract_metadata` es una funcion pura que
transforma un dict (entrada no confiable) en un `PackageMetadata` normalizado.

Reglas de la tabla §3.2:
- first_release_epoch <- time.created (ISO->epoch UTC; ausente/invalido => None)
- releases_count      <- len(versions) (no-dict => 0)
- has_repo_url        <- repository: dict url:str http(s) O str http(s)
- has_description     <- description: str no vacio
- has_author          <- author: str no vacio O dict name:str no vacio
- has_license         <- license: str no vacio O dict {type:str} (SPDX legacy)
- has_classifiers     <- keywords: lista no vacia
- in_top_n            <- dataset npm inyectado
- name                <- _normalize_npm_name(name_consultado), NO payload["name"]
"""

from __future__ import annotations

import pytest

from slopguard.core.adapters.base import PackageMetadata
from slopguard.core.adapters.npm import _extract_metadata
from slopguard.core.dataset.top_n import build_top_n

# ---------------------------------------------------------------------------
# Fixture: TopNDataset minimo para tests (sin red, sin SHA-256).
# ---------------------------------------------------------------------------

_TOP_N_WITH_LODASH = build_top_n(
    ["lodash", "@scope/util"],
    version="test",
    generated_at="2024-01-01T00:00:00Z",
)

_TOP_N_EMPTY = build_top_n([], version="test", generated_at="2024-01-01T00:00:00Z")


# ---------------------------------------------------------------------------
# Packument de ejemplo completo (todos los campos presentes y validos).
# ---------------------------------------------------------------------------

_FULL_PACKUMENT: dict[str, object] = {
    "name": "lodash",
    "description": "Lodash modular utilities.",
    "time": {
        "created": "2012-04-23T16:17:12.327Z",
        "modified": "2024-01-01T00:00:00.000Z",
        "4.17.21": "2021-02-20T15:42:16.891Z",
    },
    "versions": {
        "4.17.20": {},
        "4.17.21": {},
    },
    "repository": {"type": "git", "url": "https://github.com/lodash/lodash.git"},
    "author": {"name": "John-David Dalton", "email": "john.david.dalton@gmail.com"},
    "license": "MIT",
    "keywords": ["modules", "stdlib", "util"],
}


# ---------------------------------------------------------------------------
# Tests: packument completo -> todos los flags True / valores correctos.
# ---------------------------------------------------------------------------


def test_nombre_normalizado_del_consultado_no_del_payload() -> None:
    # El nombre debe venir del argumento `name`, no de `payload["name"]`.
    meta = _extract_metadata({"name": "DIFERENTE"}, "lodash", _TOP_N_EMPTY)
    assert meta.name == "lodash"


def test_nombre_scoped_normalizado() -> None:
    meta = _extract_metadata({}, "@Scope/Name", _TOP_N_EMPTY)
    assert meta.name == "@scope/name"


def test_full_packument_first_release_epoch() -> None:
    meta = _extract_metadata(_FULL_PACKUMENT, "lodash", _TOP_N_EMPTY)
    # 2012-04-23T16:17:12.327Z -> epoch UTC
    assert meta.first_release_epoch is not None
    assert meta.first_release_epoch == pytest.approx(1335197832.327, abs=1.0)


def test_full_packument_releases_count() -> None:
    meta = _extract_metadata(_FULL_PACKUMENT, "lodash", _TOP_N_EMPTY)
    assert meta.releases_count == 2


def test_full_packument_has_repo_url_dict() -> None:
    meta = _extract_metadata(_FULL_PACKUMENT, "lodash", _TOP_N_EMPTY)
    assert meta.has_repo_url is True


def test_full_packument_has_description() -> None:
    meta = _extract_metadata(_FULL_PACKUMENT, "lodash", _TOP_N_EMPTY)
    assert meta.has_description is True


def test_full_packument_has_author_dict() -> None:
    meta = _extract_metadata(_FULL_PACKUMENT, "lodash", _TOP_N_EMPTY)
    assert meta.has_author is True


def test_full_packument_has_license_str() -> None:
    meta = _extract_metadata(_FULL_PACKUMENT, "lodash", _TOP_N_EMPTY)
    assert meta.has_license is True


def test_full_packument_has_classifiers_keywords() -> None:
    meta = _extract_metadata(_FULL_PACKUMENT, "lodash", _TOP_N_EMPTY)
    assert meta.has_classifiers is True


def test_full_packument_in_top_n_true() -> None:
    meta = _extract_metadata(_FULL_PACKUMENT, "lodash", _TOP_N_WITH_LODASH)
    assert meta.in_top_n is True


def test_full_packument_in_top_n_false() -> None:
    meta = _extract_metadata(_FULL_PACKUMENT, "lodash", _TOP_N_EMPTY)
    assert meta.in_top_n is False


# ---------------------------------------------------------------------------
# Tests: campos ausentes -> fail-closed (R4.4).
# ---------------------------------------------------------------------------


def test_payload_vacio_produce_defaults_seguros() -> None:
    meta = _extract_metadata({}, "react", _TOP_N_EMPTY)
    assert isinstance(meta, PackageMetadata)
    assert meta.name == "react"
    assert meta.first_release_epoch is None
    assert meta.releases_count == 0
    assert meta.has_repo_url is False
    assert meta.has_description is False
    assert meta.has_author is False
    assert meta.has_license is False
    assert meta.has_classifiers is False
    assert meta.in_top_n is False


def test_time_ausente_produce_none() -> None:
    meta = _extract_metadata({"versions": {"1.0.0": {}}}, "pkg", _TOP_N_EMPTY)
    assert meta.first_release_epoch is None


def test_time_no_dict_produce_none() -> None:
    meta = _extract_metadata({"time": "cadena-invalida"}, "pkg", _TOP_N_EMPTY)
    assert meta.first_release_epoch is None


def test_time_sin_campo_created_produce_none() -> None:
    meta = _extract_metadata(
        {"time": {"modified": "2024-01-01T00:00:00Z"}}, "pkg", _TOP_N_EMPTY
    )
    assert meta.first_release_epoch is None


def test_time_created_invalido_produce_none() -> None:
    meta = _extract_metadata(
        {"time": {"created": "no-es-una-fecha"}}, "pkg", _TOP_N_EMPTY
    )
    assert meta.first_release_epoch is None


def test_versions_no_dict_produce_cero() -> None:
    meta = _extract_metadata({"versions": ["1.0.0", "2.0.0"]}, "pkg", _TOP_N_EMPTY)
    assert meta.releases_count == 0


def test_versions_ausente_produce_cero() -> None:
    meta = _extract_metadata({}, "pkg", _TOP_N_EMPTY)
    assert meta.releases_count == 0


# ---------------------------------------------------------------------------
# Tests: has_repo_url - formas validas e invalidas.
# ---------------------------------------------------------------------------


def test_repo_url_dict_http() -> None:
    payload: dict[str, object] = {"repository": {"url": "https://github.com/x/y"}}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_repo_url is True


def test_repo_url_dict_no_http() -> None:
    payload: dict[str, object] = {"repository": {"url": "git+ssh://github.com/x/y"}}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_repo_url is False


def test_repo_url_dict_sin_url() -> None:
    payload: dict[str, object] = {"repository": {"type": "git"}}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_repo_url is False


def test_repo_url_str_http() -> None:
    payload: dict[str, object] = {"repository": "https://github.com/x/y"}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_repo_url is True


def test_repo_url_str_no_http() -> None:
    payload: dict[str, object] = {"repository": "github:x/y"}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_repo_url is False


def test_repo_url_tipo_invalido() -> None:
    payload: dict[str, object] = {"repository": 42}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_repo_url is False


# ---------------------------------------------------------------------------
# Tests: has_description.
# ---------------------------------------------------------------------------


def test_description_str_no_vacio() -> None:
    payload: dict[str, object] = {"description": "A useful library."}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_description is True


def test_description_vacio() -> None:
    payload: dict[str, object] = {"description": ""}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_description is False


def test_description_solo_espacios() -> None:
    payload: dict[str, object] = {"description": "   "}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_description is False


def test_description_no_str() -> None:
    payload: dict[str, object] = {"description": 123}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_description is False


# ---------------------------------------------------------------------------
# Tests: has_author - forma string y forma objeto.
# ---------------------------------------------------------------------------


def test_author_str_no_vacio() -> None:
    payload: dict[str, object] = {"author": "Jane Doe <jane@example.com>"}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_author is True


def test_author_str_vacio() -> None:
    payload: dict[str, object] = {"author": ""}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_author is False


def test_author_dict_con_name() -> None:
    payload: dict[str, object] = {"author": {"name": "Jane Doe", "email": "j@x.com"}}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_author is True


def test_author_dict_sin_name() -> None:
    payload: dict[str, object] = {"author": {"email": "j@x.com"}}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_author is False


def test_author_dict_name_vacio() -> None:
    payload: dict[str, object] = {"author": {"name": ""}}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_author is False


def test_author_tipo_invalido() -> None:
    payload: dict[str, object] = {"author": 42}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_author is False


# ---------------------------------------------------------------------------
# Tests: has_license - forma string y forma objeto SPDX legacy.
# ---------------------------------------------------------------------------


def test_license_str_mit() -> None:
    payload: dict[str, object] = {"license": "MIT"}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_license is True


def test_license_str_vacio() -> None:
    payload: dict[str, object] = {"license": ""}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_license is False


def test_license_dict_con_type() -> None:
    payload: dict[str, object] = {"license": {"type": "MIT", "url": "https://..."}}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_license is True


def test_license_dict_sin_type() -> None:
    payload: dict[str, object] = {"license": {"url": "https://..."}}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_license is False


def test_license_dict_type_vacio() -> None:
    payload: dict[str, object] = {"license": {"type": ""}}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_license is False


def test_license_tipo_invalido() -> None:
    payload: dict[str, object] = {"license": ["MIT"]}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_license is False


# ---------------------------------------------------------------------------
# Tests: has_classifiers (keywords).
# ---------------------------------------------------------------------------


def test_keywords_lista_no_vacia() -> None:
    payload: dict[str, object] = {"keywords": ["util", "array"]}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_classifiers is True


def test_keywords_lista_vacia() -> None:
    payload: dict[str, object] = {"keywords": []}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_classifiers is False


def test_keywords_no_lista() -> None:
    payload: dict[str, object] = {"keywords": "util"}
    assert _extract_metadata(payload, "pkg", _TOP_N_EMPTY).has_classifiers is False


def test_keywords_ausentes() -> None:
    assert _extract_metadata({}, "pkg", _TOP_N_EMPTY).has_classifiers is False


# ---------------------------------------------------------------------------
# Tests: in_top_n con dataset npm.
# ---------------------------------------------------------------------------


def test_in_top_n_scoped() -> None:
    meta = _extract_metadata({}, "@scope/util", _TOP_N_WITH_LODASH)
    assert meta.in_top_n is True


def test_in_top_n_false_no_miembro() -> None:
    meta = _extract_metadata({}, "axios", _TOP_N_WITH_LODASH)
    assert meta.in_top_n is False


# ---------------------------------------------------------------------------
# Tests: tipo de retorno siempre es PackageMetadata (nunca lanza por payload anomalo).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"time": None, "versions": None},
        {"time": 123, "versions": "cadena"},
        {"repository": True, "author": [], "license": {}, "keywords": "str"},
        {"description": 0, "author": 0, "license": 0},
    ],
)
def test_payload_anomalo_nunca_lanza(payload: dict[str, object]) -> None:
    # R4.4: entrada anomala => fail-closed (flags False/None), nunca excepcion.
    meta = _extract_metadata(payload, "pkg", _TOP_N_EMPTY)
    assert isinstance(meta, PackageMetadata)
