"""Pruebas de carga e integridad del dataset top-N (T20, R3.9, NFR-Seg.7)."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from slopguard.core.dataset.top_n import TopNDataset, build_top_n, load_top_n
from slopguard.core.errors import DatasetIntegrityError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_EMBEDDED_JSON = Path(__file__).parent.parent / "src/slopguard/core/dataset/pypi_top_10k.json"
_EMBEDDED_SHA = _EMBEDDED_JSON.with_suffix(".sha256")


def _make_artifact(names: list[str], tmp_path: Path) -> tuple[Path, Path]:
    """Crea un par .json/.sha256 valido en `tmp_path` con los nombres dados."""
    artifact = {
        "schema": "slopguard-top-n-v1",
        "version": "1.0.0",
        "generated_at": "2026-06-22",
        "provenance": "test",
        "count": len(names),
        "names": names,
    }
    raw = json.dumps(
        artifact, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    json_path = tmp_path / "top_n.json"
    sha_path = tmp_path / "top_n.sha256"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())
    return json_path, sha_path


# ---------------------------------------------------------------------------
# Carga del artefacto embebido
# ---------------------------------------------------------------------------


def test_carga_artefacto_embebido() -> None:
    """La carga sin argumentos devuelve un TopNDataset con 10 000 nombres."""
    dataset = load_top_n()

    assert isinstance(dataset, TopNDataset)
    assert len(dataset.members) == 10_000


def test_artefacto_embebido_version_y_fecha() -> None:
    """El dataset embebido expone version y generated_at no vacios."""
    dataset = load_top_n()

    assert dataset.version != ""
    assert dataset.generated_at != ""


def test_indices_precomputados_correctos(tmp_path: Path) -> None:
    """Los indices by_length y by_first_char agrupan correctamente."""
    names = ["requests", "flask", "django", "flask-login", "numpy"]
    json_path, sha_path = _make_artifact(names, tmp_path)

    dataset = load_top_n(json_path, sha_path)

    # by_length
    assert "flask" in dataset.by_length[5]
    assert "numpy" in dataset.by_length[5]
    assert "requests" in dataset.by_length[8]

    # by_first_char
    assert "requests" in dataset.by_first_char["r"]
    assert "flask" in dataset.by_first_char["f"]
    assert "flask-login" in dataset.by_first_char["f"]

    # members
    assert dataset.members == frozenset(names)


def test_indices_son_tuplas_no_listas(tmp_path: Path) -> None:
    """Los buckets de by_length y by_first_char son tuple, no list (inmutabilidad real)."""
    names = ["requests", "flask"]
    json_path, sha_path = _make_artifact(names, tmp_path)

    dataset = load_top_n(json_path, sha_path)

    for bucket in dataset.by_length.values():
        assert isinstance(bucket, tuple)
    for bucket in dataset.by_first_char.values():
        assert isinstance(bucket, tuple)


def test_dataset_es_inmutable(tmp_path: Path) -> None:
    """TopNDataset rechaza mutacion directa de sus atributos (frozen dataclass)."""
    names = ["requests"]
    json_path, sha_path = _make_artifact(names, tmp_path)

    dataset = load_top_n(json_path, sha_path)

    with pytest.raises(dataclasses.FrozenInstanceError):
        dataset.version = "hack"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Verificacion de integridad: checksum invalido
# ---------------------------------------------------------------------------


def test_checksum_invalido_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """Un .sha256 con valor incorrecto produce DatasetIntegrityError."""
    names = ["requests"]
    json_path, sha_path = _make_artifact(names, tmp_path)
    sha_path.write_text("a" * 64)  # digest falso

    with pytest.raises(DatasetIntegrityError) as exc_info:
        load_top_n(json_path, sha_path)

    assert exc_info.value.error_category.value == "dataset_integrity"


def test_json_modificado_post_sha_falla(tmp_path: Path) -> None:
    """Modificar el JSON despues de calcular el SHA provoca error de integridad."""
    names = ["requests"]
    json_path, sha_path = _make_artifact(names, tmp_path)

    # Append de un byte cambia el digest
    with json_path.open("ab") as fh:
        fh.write(b" ")

    with pytest.raises(DatasetIntegrityError):
        load_top_n(json_path, sha_path)


# ---------------------------------------------------------------------------
# Archivos ausentes
# ---------------------------------------------------------------------------


def test_json_ausente_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """Apuntar a un .json inexistente produce DatasetIntegrityError."""
    missing = tmp_path / "no_existe.json"
    sha_path = tmp_path / "no_existe.sha256"
    sha_path.write_text("a" * 64)

    with pytest.raises(DatasetIntegrityError) as exc_info:
        load_top_n(missing, sha_path)

    assert exc_info.value.error_category.value == "dataset_integrity"


def test_sha_ausente_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """Apuntar a un .sha256 inexistente produce DatasetIntegrityError."""
    names = ["requests"]
    json_path, _ = _make_artifact(names, tmp_path)
    missing_sha = tmp_path / "no_existe.sha256"

    with pytest.raises(DatasetIntegrityError) as exc_info:
        load_top_n(json_path, missing_sha)

    assert exc_info.value.error_category.value == "dataset_integrity"


# ---------------------------------------------------------------------------
# JSON malformado / estructura invalida
# ---------------------------------------------------------------------------


def test_json_malformado_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """Un archivo .json con contenido no-JSON produce DatasetIntegrityError."""
    raw = b"not-valid-json{{{!"
    json_path = tmp_path / "bad.json"
    sha_path = tmp_path / "bad.sha256"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())

    with pytest.raises(DatasetIntegrityError):
        load_top_n(json_path, sha_path)


def test_json_sin_campo_names_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """Un JSON sin el campo 'names' produce DatasetIntegrityError."""
    artifact = {"version": "1.0", "generated_at": "2026-01-01"}
    raw = json.dumps(artifact).encode("utf-8")
    json_path = tmp_path / "no_names.json"
    sha_path = tmp_path / "no_names.sha256"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())

    with pytest.raises(DatasetIntegrityError):
        load_top_n(json_path, sha_path)


def test_json_no_es_objeto_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """Un JSON que es un array (no un objeto) produce DatasetIntegrityError."""
    raw = json.dumps(["requests", "flask"]).encode("utf-8")
    json_path = tmp_path / "array.json"
    sha_path = tmp_path / "array.sha256"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())

    with pytest.raises(DatasetIntegrityError):
        load_top_n(json_path, sha_path)


# ---------------------------------------------------------------------------
# build_top_n: propiedades basicas
# ---------------------------------------------------------------------------


def test_build_top_n_deduplica_y_ordena() -> None:
    """build_top_n deduplica nombres y produce buckets con orden estable."""
    names = ["z-lib", "a-lib", "a-lib", "b-lib"]
    dataset = build_top_n(names, version="1.0", generated_at="2026-01-01")

    assert dataset.members == frozenset({"z-lib", "a-lib", "b-lib"})
    # Todos estan en by_length[5]
    assert set(dataset.by_length[5]) == {"z-lib", "a-lib", "b-lib"}
    # Orden estable dentro del bucket (sorted)
    assert dataset.by_length[5] == ("a-lib", "b-lib", "z-lib")


def test_build_top_n_campos_version_y_fecha() -> None:
    """build_top_n preserva version y generated_at exactamente."""
    dataset = build_top_n([], version="2.0", generated_at="2026-06-22")

    assert dataset.version == "2.0"
    assert dataset.generated_at == "2026-06-22"


# ---------------------------------------------------------------------------
# Validacion de tipos en 'names' (hallazgo yellow R3.9 / NFR-Seg.7)
# ---------------------------------------------------------------------------


def test_names_con_enteros_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """names=[3,1,2] (todo-int) debe producir DatasetIntegrityError, no TypeError."""
    artifact = {
        "schema": "slopguard-top-n-v1",
        "version": "1.0.0",
        "generated_at": "2026-06-22",
        "provenance": "test",
        "count": 3,
        "names": [3, 1, 2],
    }
    raw = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("utf-8")
    json_path = tmp_path / "int_names.json"
    sha_path = tmp_path / "int_names.sha256"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())

    with pytest.raises(DatasetIntegrityError) as exc_info:
        load_top_n(json_path, sha_path)

    assert exc_info.value.error_category.value == "dataset_integrity"
    assert "no-str" in str(exc_info.value)


def test_names_con_tipos_mixtos_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """names=[1, 2, None, 'requests'] (mixto) lanza DatasetIntegrityError, no TypeError."""
    artifact = {
        "schema": "slopguard-top-n-v1",
        "version": "1.0.0",
        "generated_at": "2026-06-22",
        "provenance": "test",
        "count": 4,
        "names": [1, 2, None, "requests"],
    }
    raw = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("utf-8")
    json_path = tmp_path / "mixed_names.json"
    sha_path = tmp_path / "mixed_names.sha256"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())

    with pytest.raises(DatasetIntegrityError) as exc_info:
        load_top_n(json_path, sha_path)

    assert exc_info.value.error_category.value == "dataset_integrity"


def test_names_con_null_unico_lanza_dataset_integrity_error(tmp_path: Path) -> None:
    """names=[null] lanza DatasetIntegrityError."""
    artifact = {
        "schema": "slopguard-top-n-v1",
        "version": "1.0.0",
        "generated_at": "2026-06-22",
        "provenance": "test",
        "count": 1,
        "names": [None],
    }
    raw = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("utf-8")
    json_path = tmp_path / "null_names.json"
    sha_path = tmp_path / "null_names.sha256"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())

    with pytest.raises(DatasetIntegrityError):
        load_top_n(json_path, sha_path)


# ---------------------------------------------------------------------------
# Invariante de normalizacion PEP 503 en build_top_n (hallazgo yellow ADR-02)
# ---------------------------------------------------------------------------


def test_build_top_n_normaliza_nombres_con_mayusculas() -> None:
    """build_top_n normaliza nombres en mayusculas a lowercase PEP 503."""
    dataset = build_top_n(
        ["Requests", "FLASK", "Django"],
        version="1.0",
        generated_at="2026-06-22",
    )

    assert "requests" in dataset.members
    assert "flask" in dataset.members
    assert "django" in dataset.members
    # Las versiones en mayuscula NO deben estar
    assert "Requests" not in dataset.members
    assert "FLASK" not in dataset.members


def test_build_top_n_normaliza_separadores_pep503() -> None:
    """build_top_n colapsa runs de separadores PEP 503 (._-) a '-'."""
    dataset = build_top_n(
        ["my_lib", "my.lib", "my---lib"],
        version="1.0",
        generated_at="2026-06-22",
    )

    # Los tres se normalizan al mismo nombre 'my-lib' → solo un miembro
    assert dataset.members == frozenset({"my-lib"})
    assert len(dataset.members) == 1


def test_build_top_n_nombres_ya_normalizados_no_se_duplican() -> None:
    """Nombres ya normalizados no generan duplicados al pasar por normalize_name."""
    names = ["requests", "flask", "numpy"]
    dataset = build_top_n(names, version="1.0", generated_at="2026-06-22")

    assert dataset.members == frozenset(names)
    assert len(dataset.members) == 3


def test_indices_reflejan_nombres_normalizados(tmp_path: Path) -> None:
    """Si el JSON contiene 'Requests' (mayuscula), el indice usa 'requests' (normalizado)."""
    artifact = {
        "schema": "slopguard-top-n-v1",
        "version": "1.0.0",
        "generated_at": "2026-06-22",
        "provenance": "test",
        "count": 2,
        "names": ["Requests", "Flask"],
    }
    raw = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("utf-8")
    json_path = tmp_path / "upper.json"
    sha_path = tmp_path / "upper.sha256"
    json_path.write_bytes(raw)
    sha_path.write_text(hashlib.sha256(raw).hexdigest())

    dataset = load_top_n(json_path, sha_path)

    assert "requests" in dataset.members
    assert "flask" in dataset.members
    assert "Requests" not in dataset.members
    # Los indices tambien usan la forma normalizada
    assert "requests" in dataset.by_length[8]
    assert "flask" in dataset.by_first_char["f"]


# ---------------------------------------------------------------------------
# Indices contra fixture conocido (T20 criterio de aceptacion)
# ---------------------------------------------------------------------------


def test_indices_by_length_contiene_todos_los_nombres_de_la_longitud_correcta(
    tmp_path: Path,
) -> None:
    """by_length agrupa correctamente: cada nombre aparece en la clave de su longitud."""
    names = ["ab-cd", "efghi", "j", "kl", "requests", "pip", "setuptools"]
    json_path, sha_path = _make_artifact(names, tmp_path)

    dataset = load_top_n(json_path, sha_path)

    for name in names:
        length = len(name)
        assert name in dataset.by_length[length], (
            f"'{name}' (len={length}) no encontrado en by_length[{length}]"
        )


def test_indices_by_first_char_contiene_todos_los_nombres_con_ese_primer_caracter(
    tmp_path: Path,
) -> None:
    """by_first_char agrupa correctamente: cada nombre aparece bajo su primer caracter."""
    names = ["requests", "redis", "flask", "fastapi", "numpy", "nose"]
    json_path, sha_path = _make_artifact(names, tmp_path)

    dataset = load_top_n(json_path, sha_path)

    for name in names:
        char = name[0]
        assert name in dataset.by_first_char[char], (
            f"'{name}' no encontrado en by_first_char['{char}']"
        )


def test_members_es_exactamente_el_conjunto_de_nombres_del_fixture(
    tmp_path: Path,
) -> None:
    """members coincide exactamente con el frozenset de los nombres del fixture."""
    names = ["boto3", "botocore", "certifi", "charset-normalizer", "idna"]
    json_path, sha_path = _make_artifact(names, tmp_path)

    dataset = load_top_n(json_path, sha_path)

    assert dataset.members == frozenset(names)


def test_buckets_ordenados_dentro_de_by_length(tmp_path: Path) -> None:
    """Los buckets de by_length tienen orden lexicografico estable (sorted)."""
    # Todos de longitud 5
    names = ["zebra", "apple", "mango", "berry"]
    json_path, sha_path = _make_artifact(names, tmp_path)

    dataset = load_top_n(json_path, sha_path)

    bucket = dataset.by_length[5]
    assert bucket == tuple(sorted(names))


def test_lista_names_vacia_produce_dataset_vacio(tmp_path: Path) -> None:
    """Un JSON con names=[] produce un TopNDataset con indices vacios."""
    json_path, sha_path = _make_artifact([], tmp_path)

    dataset = load_top_n(json_path, sha_path)

    assert dataset.members == frozenset()
    assert dict(dataset.by_length) == {}
    assert dict(dataset.by_first_char) == {}
