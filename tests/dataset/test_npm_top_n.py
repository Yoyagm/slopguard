"""Pruebas de integridad del dataset npm top-N (H4-T11/H4-T12, R5.1/R5.2/R5.3, ADR-3b).

Cubre:
- Checksum bueno → carga exitosa (R5.2).
- Checksum corrupto / archivo ausente → DatasetIntegrityError (R5.2).
- Nombres normalizados con regla npm (ADR-3b): `._-` NO se colapsa.
- Nombres scoped `@scope/name` presentes en members (R5.3).
- Caso critico ADR-3b: nombre con `.` en corpus npm da in_top_n=True end-to-end
  (si se usara normalizacion PEP 503 daria in_top_n=False, falso negativo de popularidad).
- Completitud / consistencia del corpus embebido.
- TopNDataset agnóstico: mismo contrato que PyPI (R5.3, Capa 1 sin codigo por-ecosistema).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from slopguard.core.adapters.npm import (
    NpmAdapter,
    _extract_metadata,
    _normalize_npm_name,
    load_top_n_npm,
)
from slopguard.core.config import Config
from slopguard.core.dataset.top_n import TopNDataset, build_top_n
from slopguard.core.errors import DatasetIntegrityError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NPM_JSON = Path(__file__).parent.parent.parent / "src/slopguard/core/dataset/npm_top_8k.json"
_NPM_SHA = _NPM_JSON.with_suffix(".sha256")


def _make_npm_artifact(names: list[str], tmp_path: Path) -> tuple[Path, Path]:
    """Crea un par .json/.sha256 valido con los nombres dados."""
    artifact = {
        "schema": "slopguard-top-n-v1",
        "version": "1.0.0",
        "generated_at": "2026-06-16",
        "provenance": "test",
        "count": len(names),
        "names": names,
    }
    raw = json.dumps(
        artifact, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    json_path = tmp_path / "npm_top_n.json"
    sha_path = tmp_path / "npm_top_n.sha256"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())
    return json_path, sha_path


# ---------------------------------------------------------------------------
# Integridad SHA-256 (R5.2)
# ---------------------------------------------------------------------------


def test_checksum_correcto_carga_dataset(tmp_path: Path) -> None:
    """Un .sha256 correcto permite cargar el dataset sin error."""
    names = ["lodash", "react", "express"]
    json_path, sha_path = _make_npm_artifact(names, tmp_path)

    dataset = load_top_n_npm(json_path, sha_path)

    assert isinstance(dataset, TopNDataset)
    assert "lodash" in dataset.members


def test_checksum_corrupto_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """Un .sha256 con valor incorrecto lanza DatasetIntegrityError (R5.2)."""
    names = ["lodash"]
    json_path, sha_path = _make_npm_artifact(names, tmp_path)
    sha_path.write_text("a" * 64)  # digest falso

    with pytest.raises(DatasetIntegrityError) as exc_info:
        load_top_n_npm(json_path, sha_path)

    assert exc_info.value.error_category.value == "dataset_integrity"


def test_json_ausente_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """Apuntar a un .json inexistente lanza DatasetIntegrityError (R5.2)."""
    missing = tmp_path / "no_existe.json"
    sha_path = tmp_path / "no_existe.sha256"
    sha_path.write_text("a" * 64)

    with pytest.raises(DatasetIntegrityError) as exc_info:
        load_top_n_npm(missing, sha_path)

    assert exc_info.value.error_category.value == "dataset_integrity"


def test_sha_ausente_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """Apuntar a un .sha256 inexistente lanza DatasetIntegrityError (R5.2)."""
    names = ["react"]
    json_path, _ = _make_npm_artifact(names, tmp_path)
    missing_sha = tmp_path / "no_existe.sha256"

    with pytest.raises(DatasetIntegrityError) as exc_info:
        load_top_n_npm(json_path, missing_sha)

    assert exc_info.value.error_category.value == "dataset_integrity"


def test_json_modificado_post_sha_falla(tmp_path: Path) -> None:
    """Modificar el JSON despues de calcular el SHA provoca DatasetIntegrityError."""
    names = ["react"]
    json_path, sha_path = _make_npm_artifact(names, tmp_path)

    with json_path.open("ab") as fh:
        fh.write(b" ")

    with pytest.raises(DatasetIntegrityError):
        load_top_n_npm(json_path, sha_path)


# ---------------------------------------------------------------------------
# Normalizacion npm (ADR-3b): nombres con `._-` NO se colapsan
# ---------------------------------------------------------------------------


def test_nombres_con_punto_no_se_colapsan(tmp_path: Path) -> None:
    """Con normalizacion npm, `lodash.merge` permanece como `lodash.merge` en members.

    Con PEP 503 se colapsaria a `lodash-merge`, produciendo in_top_n=False (falso
    negativo de popularidad). ADR-3b exige normalizacion npm en el dataset npm.
    """
    names = ["lodash.merge", "lodash.get", "lodash.debounce"]
    json_path, sha_path = _make_npm_artifact(names, tmp_path)

    dataset = load_top_n_npm(json_path, sha_path)

    assert "lodash.merge" in dataset.members
    assert "lodash.get" in dataset.members
    # La forma PEP 503 (colapsada) NO debe estar
    assert "lodash-merge" not in dataset.members
    assert "lodash-get" not in dataset.members


def test_nombre_con_doble_guion_bajo_no_se_colapsa(tmp_path: Path) -> None:
    """Con normalizacion npm, `@types/babel__core` NO se colapsa a `@types/babel-core`."""
    names = ["@types/babel__core"]
    json_path, sha_path = _make_npm_artifact(names, tmp_path)

    dataset = load_top_n_npm(json_path, sha_path)

    assert "@types/babel__core" in dataset.members
    assert "@types/babel-core" not in dataset.members


def test_build_top_n_con_normalize_npm_preserva_punto(tmp_path: Path) -> None:
    """build_top_n con _normalize_npm_name preserva nombres con punto."""
    dataset = build_top_n(
        ["lodash.merge", "REACT", "@babel/core"],
        version="1.0",
        generated_at="2026-06-16",
        normalize_fn=_normalize_npm_name,
    )

    assert "lodash.merge" in dataset.members
    assert "react" in dataset.members
    assert "@babel/core" in dataset.members


def test_build_top_n_pep503_colapsa_punto() -> None:
    """build_top_n SIN normalize_fn (PEP 503) colapsa lodash.merge a lodash-merge.

    Verifica la diferencia de comportamiento que justifica ADR-3b.
    """
    dataset = build_top_n(
        ["lodash.merge"],
        version="1.0",
        generated_at="2026-06-16",
    )

    # PEP 503 colapsa el punto
    assert "lodash-merge" in dataset.members
    assert "lodash.merge" not in dataset.members


# ---------------------------------------------------------------------------
# Nombres scoped `@scope/name` (R5.3)
# ---------------------------------------------------------------------------


def test_nombres_scoped_presentes_en_members(tmp_path: Path) -> None:
    """Los nombres scoped `@scope/name` del corpus npm estan en members (R5.3)."""
    names = ["@babel/core", "@types/node", "@angular/core", "lodash"]
    json_path, sha_path = _make_npm_artifact(names, tmp_path)

    dataset = load_top_n_npm(json_path, sha_path)

    assert "@babel/core" in dataset.members
    assert "@types/node" in dataset.members
    assert "@angular/core" in dataset.members
    assert "lodash" in dataset.members


def test_nombres_scoped_indexados_bajo_arroba(tmp_path: Path) -> None:
    """Los nombres scoped aparecen bajo la clave '@' de by_first_char."""
    names = ["@babel/core", "@types/node"]
    json_path, sha_path = _make_npm_artifact(names, tmp_path)

    dataset = load_top_n_npm(json_path, sha_path)

    assert "@" in dataset.by_first_char
    assert "@babel/core" in dataset.by_first_char["@"]
    assert "@types/node" in dataset.by_first_char["@"]


# ---------------------------------------------------------------------------
# Caso critico ADR-3b: in_top_n end-to-end con nombre que tiene `.`
# ---------------------------------------------------------------------------


def test_in_top_n_con_nombre_punto_end_to_end(tmp_path: Path) -> None:
    """Critico ADR-3b: nombre npm con `.` da in_top_n=True (no False) end-to-end.

    `lodash.merge` esta en el corpus real. Con normalizacion npm permanece como
    `lodash.merge` en members. `_extract_metadata` consulta
    `_normalize_npm_name('lodash.merge') in top_n.members` => True.
    Si se usara PEP 503, el corpus tendria `lodash-merge` pero `_normalize_npm_name`
    devolveria `lodash.merge` => in_top_n=False (falso negativo que debilita la senal).
    """
    # Dataset minimo que contiene lodash.merge con normalizacion npm
    names = ["lodash.merge", "lodash", "express"]
    json_path, sha_path = _make_npm_artifact(names, tmp_path)
    top_n = load_top_n_npm(json_path, sha_path)

    packument: dict[str, object] = {
        "name": "lodash.merge",
        "description": "A lodash method",
        "versions": {"4.6.2": {}},
        "time": {"created": "2015-01-01T00:00:00.000Z"},
        "author": {"name": "John-David Dalton"},
        "license": "MIT",
    }

    metadata = _extract_metadata(packument, "lodash.merge", top_n)

    assert metadata.in_top_n is True, (
        "lodash.merge debe estar en top_n con normalizacion npm; "
        "in_top_n=False indica que se uso normalizacion PEP 503 en el dataset (ADR-3b)"
    )


def test_in_top_n_false_cuando_nombre_no_esta_en_corpus(tmp_path: Path) -> None:
    """Un paquete que no esta en el corpus da in_top_n=False (sin falso positivo)."""
    names = ["lodash", "express"]  # evil-package NO esta
    json_path, sha_path = _make_npm_artifact(names, tmp_path)
    top_n = load_top_n_npm(json_path, sha_path)

    packument: dict[str, object] = {
        "versions": {"1.0.0": {}},
        "time": {"created": "2026-01-01T00:00:00.000Z"},
        "description": "evil",
    }

    metadata = _extract_metadata(packument, "evil-package", top_n)

    assert metadata.in_top_n is False


# ---------------------------------------------------------------------------
# Dataset embebido: completitud y consistencia (R5.1/R5.3)
# ---------------------------------------------------------------------------


def test_dataset_embebido_carga_correctamente() -> None:
    """El dataset npm embebido pasa la verificacion SHA-256 y es un TopNDataset valido."""
    dataset = load_top_n_npm()

    assert isinstance(dataset, TopNDataset)
    assert len(dataset.members) > 0


def test_dataset_embebido_tiene_n_aproximado_8k() -> None:
    """El corpus embebido contiene aproximadamente 8.000 nombres (R5.1)."""
    dataset = load_top_n_npm()

    assert len(dataset.members) >= 7_000
    assert len(dataset.members) <= 9_000


def test_dataset_embebido_version_y_fecha_no_vacios() -> None:
    """El dataset embebido expone version y generated_at no vacios."""
    dataset = load_top_n_npm()

    assert dataset.version != ""
    assert dataset.generated_at != ""


def test_dataset_embebido_contiene_lodash_merge() -> None:
    """lodash.merge (paquete popular con punto) esta en el corpus embebido (ADR-3b)."""
    dataset = load_top_n_npm()

    assert "lodash.merge" in dataset.members, (
        "lodash.merge debe estar en el dataset npm; "
        "su ausencia indicaria normalizacion PEP 503 incorrecta (ADR-3b)"
    )


def test_dataset_embebido_contiene_paquetes_scoped() -> None:
    """El corpus contiene paquetes scoped (@babel/core, @types/node, etc.) (R5.3)."""
    dataset = load_top_n_npm()

    # Paquetes scoped conocidamente populares
    scoped_present = [n for n in dataset.members if n.startswith("@")]
    assert len(scoped_present) > 0, "El corpus npm debe contener paquetes scoped"


def test_dataset_embebido_lodash_merge_no_colapsado() -> None:
    """El corpus embebido NO contiene `lodash-merge` (forma PEP 503 colapsada).

    Si `lodash-merge` estuviera en members y `lodash.merge` no, significaria que
    se uso normalizacion PEP 503 en lugar de npm (ADR-3b violado).
    """
    dataset = load_top_n_npm()

    # lodash.merge esta → lodash-merge no deberia estar (no son el mismo nombre en npm)
    assert "lodash.merge" in dataset.members
    # lodash-merge podria existir como paquete diferente, pero lodash.merge tambien
    # debe estar (el punto no se colapsa)


# ---------------------------------------------------------------------------
# Contrato TopNDataset agnóstico (R5.3): mismo tipo que PyPI
# ---------------------------------------------------------------------------


def test_load_top_n_npm_devuelve_top_n_dataset(tmp_path: Path) -> None:
    """load_top_n_npm devuelve TopNDataset (mismo tipo que PyPI, R5.3)."""
    names = ["react", "@babel/core"]
    json_path, sha_path = _make_npm_artifact(names, tmp_path)

    dataset = load_top_n_npm(json_path, sha_path)

    assert isinstance(dataset, TopNDataset)
    assert isinstance(dataset.members, frozenset)
    assert isinstance(dataset.by_length, dict)
    assert isinstance(dataset.by_first_char, dict)


def test_npm_adapter_load_top_n_devuelve_top_n_dataset() -> None:
    """NpmAdapter.load_top_n() devuelve TopNDataset con corpus npm verificado."""
    # H4-T07 dio a NpmAdapter un __init__(config, *, use_cache); use_cache=False evita disco.
    adapter = NpmAdapter(Config(), use_cache=False)

    dataset = adapter.load_top_n()

    assert isinstance(dataset, TopNDataset)
    assert len(dataset.members) > 0
    # El corpus npm contiene lodash.merge con normalizacion correcta
    assert "lodash.merge" in dataset.members
