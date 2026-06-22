"""Pruebas del subsistema de manifiestos (T12, R1.1-R1.11).

Cubre:
- requirements.txt: nombre normalizado + version_pin, ignorar ruido (R1.1, R1.4, R1.11)
- pyproject.toml: [project].dependencies + optional-dependencies (R1.2)
- pip_freeze: formato nombre==version, stdin '-' (R1.3)
- includes -r/-c: resolucion confinada, ciclos, profundidad, escape, inexistente (R1.5, R1.6)
- detect: deteccion auto + override --manifest-type (T11)
- limites de tamano/deps → ManifestParseError exit 3 (R1.9)
- vacio → 0 deps (R1.7)
- malformado → ManifestParseError con nombre de archivo (R1.8)
- dedup por nombre normalizado (R1.10)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from slopguard.core.config import Config
from slopguard.core.errors import ManifestParseError
from slopguard.core.manifests.detect import detect_and_parse, detect_and_parse_stdin
from slopguard.core.manifests.pip_freeze import parse_pip_freeze, parse_pip_freeze_file
from slopguard.core.manifests.pyproject_toml import parse_pyproject_toml
from slopguard.core.manifests.requirements_txt import (
    parse_requirements_txt_entry as parse_requirements_txt,
)

CFG = Config()


# ---------------------------------------------------------------------------
# requirements_txt: casos basicos
# ---------------------------------------------------------------------------


def test_requirements_nombre_normalizado(tmp_path: Path) -> None:
    """PEP 503: runs de ._- colapsan a -, lowercase (R1.1)."""
    (tmp_path / "r.txt").write_text("My_Package==1.0\n", encoding="utf-8")
    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    assert len(deps) == 1
    assert deps[0].name == "my-package"
    assert deps[0].version_pin == "1.0"


def test_requirements_version_pin_exacto(tmp_path: Path) -> None:
    """Solo == se extrae como pin; especificadores como >= no dan pin."""
    (tmp_path / "r.txt").write_text("requests>=2.0\nflask==2.3.1\n", encoding="utf-8")
    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].version_pin is None
    assert by_name["flask"].version_pin == "2.3.1"


def test_requirements_ignora_comentarios_y_blancos(tmp_path: Path) -> None:
    """Lineas ignoradas: comentarios, blancos (R1.4)."""
    content = "\n# comentario\nrequests==2.28.0\n\n# otro\n"
    (tmp_path / "r.txt").write_text(content, encoding="utf-8")
    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    assert len(deps) == 1
    assert deps[0].name == "requests"


def test_requirements_ignora_editable_y_urls(tmp_path: Path) -> None:
    """Editable (-e), URL http/https, VCS git+ se ignoran (R1.4)."""
    content = (
        "-e git+https://github.com/org/repo.git#egg=mylib\n"
        "https://example.com/pkg.whl\n"
        "git+https://github.com/org/other.git@v1.0\n"
        "requests==2.28.0\n"
    )
    (tmp_path / "r.txt").write_text(content, encoding="utf-8")
    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    assert len(deps) == 1
    assert deps[0].name == "requests"


def test_requirements_ignora_hash_y_opciones_globales(tmp_path: Path) -> None:
    """--hash, --index-url, -f, etc. se ignoran (R1.4)."""
    content = (
        "--index-url https://pypi.org/simple/\n"
        "--extra-index-url https://other.org/\n"
        "--trusted-host example.com\n"
        "--require-hashes\n"
        "-f /local/wheels\n"
        "requests==2.28.0 --hash=sha256:abc123\n"
        "flask==2.3.1\n"
    )
    (tmp_path / "r.txt").write_text(content, encoding="utf-8")
    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    names = {d.name for d in deps}
    assert names == {"requests", "flask"}


def test_requirements_dedup(tmp_path: Path) -> None:
    """Dependencias repetidas: solo se incluye la primera (R1.10)."""
    (tmp_path / "r.txt").write_text("requests==2.0\nRequests==2.1\n", encoding="utf-8")
    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    assert len(deps) == 1
    assert deps[0].name == "requests"
    assert deps[0].version_pin == "2.0"  # primera aparicion


def test_requirements_vacio(tmp_path: Path) -> None:
    """Manifiesto vacio → 0 dependencias, no es error (R1.7)."""
    (tmp_path / "r.txt").write_text("# solo comentarios\n\n", encoding="utf-8")
    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    assert deps == ()


# ---------------------------------------------------------------------------
# pyproject_toml
# ---------------------------------------------------------------------------


def test_pyproject_extrae_dependencias_principales(tmp_path: Path) -> None:
    """[project].dependencies → nombre normalizado + version_pin (R1.2)."""
    content = (
        "[project]\n"
        'dependencies = ["requests>=2.0", "Flask==2.3.1", "My_Lib"]\n'
    )
    (tmp_path / "pyproject.toml").write_text(content, encoding="utf-8")
    deps = parse_pyproject_toml(
        tmp_path / "pyproject.toml",
        origin="pyproject.toml",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
    )
    by_name = {d.name: d for d in deps}
    assert "requests" in by_name
    assert by_name["requests"].version_pin is None
    assert by_name["flask"].version_pin == "2.3.1"
    assert "my-lib" in by_name


def test_pyproject_extrae_optional_dependencies(tmp_path: Path) -> None:
    """[project.optional-dependencies] todas las extras se incluyen (R1.2)."""
    content = (
        "[project]\n"
        'dependencies = ["requests"]\n'
        "[project.optional-dependencies]\n"
        'dev = ["pytest>=8"]\n'
        'docs = ["sphinx==7.0.0"]\n'
    )
    (tmp_path / "pyproject.toml").write_text(content, encoding="utf-8")
    deps = parse_pyproject_toml(
        tmp_path / "pyproject.toml",
        origin="pyproject.toml",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
    )
    names = {d.name for d in deps}
    assert names == {"requests", "pytest", "sphinx"}


def test_pyproject_sin_project_retorna_vacio(tmp_path: Path) -> None:
    """pyproject.toml sin [project] → 0 deps, no es error."""
    (tmp_path / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools"]\n', encoding="utf-8"
    )
    deps = parse_pyproject_toml(
        tmp_path / "pyproject.toml",
        origin="pyproject.toml",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
    )
    assert deps == ()


def test_pyproject_dedup(tmp_path: Path) -> None:
    """Dependencia en main y en una extra: dedup (R1.10)."""
    content = (
        "[project]\n"
        'dependencies = ["requests==2.0"]\n'
        "[project.optional-dependencies]\n"
        'dev = ["requests==2.1", "pytest"]\n'
    )
    (tmp_path / "pyproject.toml").write_text(content, encoding="utf-8")
    deps = parse_pyproject_toml(
        tmp_path / "pyproject.toml",
        origin="pyproject.toml",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
    )
    names = [d.name for d in deps]
    assert names.count("requests") == 1
    # La primera aparicion (main) tiene pin 2.0.
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].version_pin == "2.0"


def test_pyproject_toml_malformado(tmp_path: Path) -> None:
    """TOML invalido → ManifestParseError con nombre del archivo (R1.8)."""
    (tmp_path / "pyproject.toml").write_text(
        "esto no = es toml valido [[[", encoding="utf-8"
    )
    with pytest.raises(ManifestParseError, match=r"pyproject\.toml"):
        parse_pyproject_toml(
            tmp_path / "pyproject.toml",
            origin="pyproject.toml",
            max_manifest_bytes=CFG.max_manifest_bytes,
            max_deps=CFG.max_deps,
        )


# ---------------------------------------------------------------------------
# pip_freeze
# ---------------------------------------------------------------------------


def test_pip_freeze_basico() -> None:
    """Formato nombre==version (R1.3)."""
    text = "requests==2.28.0\nflask==2.3.1\n"
    deps = parse_pip_freeze(text, origin="stdin", max_deps=CFG.max_deps)
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].version_pin == "2.28.0"
    assert by_name["flask"].version_pin == "2.3.1"


def test_pip_freeze_ignora_comentarios_y_editables() -> None:
    """Blancos, comentarios y -e se ignoran (R1.4 aplicado a freeze)."""
    text = "# comentario\n\n-e git+https://x.com/r.git\nrequests==2.28.0\n"
    deps = parse_pip_freeze(text, origin="stdin", max_deps=CFG.max_deps)
    assert len(deps) == 1
    assert deps[0].name == "requests"


def test_pip_freeze_normaliza_nombre() -> None:
    """Nombres se normalizan PEP 503."""
    text = "My_Package==1.0\n"
    deps = parse_pip_freeze(text, origin="stdin", max_deps=CFG.max_deps)
    assert deps[0].name == "my-package"


def test_pip_freeze_malformado_con_linea() -> None:
    """Linea que no es nombre==version → ManifestParseError con numero de linea (R1.8)."""
    text = "requests>=2.0\n"  # freeze no emite >= solo ==
    with pytest.raises(ManifestParseError, match="linea 1"):
        parse_pip_freeze(text, origin="stdin", max_deps=CFG.max_deps)


def test_pip_freeze_desde_archivo(tmp_path: Path) -> None:
    """Lee archivo de freeze (R1.3)."""
    (tmp_path / "freeze.txt").write_text("requests==2.28.0\n", encoding="utf-8")
    deps = parse_pip_freeze_file(
        tmp_path / "freeze.txt",
        origin="freeze.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
    )
    assert len(deps) == 1


# ---------------------------------------------------------------------------
# includes: -r / -c
# ---------------------------------------------------------------------------


def test_includes_resuelve_dependencias(tmp_path: Path) -> None:
    """La directiva -r incluye las deps del archivo referenciado (R1.5)."""
    (tmp_path / "base.txt").write_text("requests==2.28.0\n", encoding="utf-8")
    (tmp_path / "dev.txt").write_text("-r base.txt\npytest==8.0.0\n", encoding="utf-8")

    deps = parse_requirements_txt(
        tmp_path / "dev.txt",
        origin="dev.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    names = {d.name for d in deps}
    assert names == {"requests", "pytest"}


def test_includes_ciclo_detectado(tmp_path: Path) -> None:
    """Ciclo de includes → ManifestParseError (R1.5/R1.6)."""
    (tmp_path / "a.txt").write_text("-r b.txt\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("-r a.txt\n", encoding="utf-8")
    with pytest.raises(ManifestParseError, match="ciclo"):
        parse_requirements_txt(
            tmp_path / "a.txt",
            origin="a.txt",
            max_manifest_bytes=CFG.max_manifest_bytes,
            max_deps=CFG.max_deps,
            max_include_depth=CFG.max_include_depth,
            project_root=tmp_path,
        )


def test_includes_profundidad_maxima(tmp_path: Path) -> None:
    """Profundidad > max_include_depth → ManifestParseError (R1.5).

    Semantica corregida: depth empieza en 0 (archivo raiz); un include de
    nivel N se permite cuando N <= max_include_depth. Con max=1, una cadena
    a→b→c (2 niveles reales de include) debe fallar al intentar incluir c
    (depth=1, depth+1=2, 2 > 1).
    """
    (tmp_path / "c.txt").write_text("requests\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("-r c.txt\n", encoding="utf-8")
    (tmp_path / "a.txt").write_text("-r b.txt\n", encoding="utf-8")
    with pytest.raises(ManifestParseError, match="profundidad"):
        parse_requirements_txt(
            tmp_path / "a.txt",
            origin="a.txt",
            max_manifest_bytes=CFG.max_manifest_bytes,
            max_deps=CFG.max_deps,
            max_include_depth=1,
            project_root=tmp_path,
        )


def test_includes_escape_dotdot(tmp_path: Path) -> None:
    """Include con ../ que escapa del arbol → ManifestParseError (R1.6)."""
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "reqs.txt").write_text("-r ../../../etc/passwd\n", encoding="utf-8")
    with pytest.raises(ManifestParseError, match="escapa"):
        parse_requirements_txt(
            sub / "reqs.txt",
            origin="reqs.txt",
            max_manifest_bytes=CFG.max_manifest_bytes,
            max_deps=CFG.max_deps,
            max_include_depth=CFG.max_include_depth,
            project_root=sub,
        )


def test_includes_ruta_absoluta_rechazada(tmp_path: Path) -> None:
    """Include con ruta absoluta → ManifestParseError (R1.6)."""
    (tmp_path / "r.txt").write_text(
        f"-r {tmp_path / 'otro.txt'}\n", encoding="utf-8"
    )
    with pytest.raises(ManifestParseError, match="absoluta"):
        parse_requirements_txt(
            tmp_path / "r.txt",
            origin="r.txt",
            max_manifest_bytes=CFG.max_manifest_bytes,
            max_deps=CFG.max_deps,
            max_include_depth=CFG.max_include_depth,
            project_root=tmp_path,
        )


def test_includes_archivo_inexistente(tmp_path: Path) -> None:
    """Include a archivo que no existe → ManifestParseError (R1.6)."""
    (tmp_path / "r.txt").write_text("-r no_existe.txt\n", encoding="utf-8")
    with pytest.raises(ManifestParseError, match="no encontrado"):
        parse_requirements_txt(
            tmp_path / "r.txt",
            origin="r.txt",
            max_manifest_bytes=CFG.max_manifest_bytes,
            max_deps=CFG.max_deps,
            max_include_depth=CFG.max_include_depth,
            project_root=tmp_path,
        )


# ---------------------------------------------------------------------------
# detect: deteccion automatica y override --manifest-type
# ---------------------------------------------------------------------------


def test_detect_requirements_por_nombre(tmp_path: Path) -> None:
    """requirements.txt detectado por nombre (T11)."""
    (tmp_path / "requirements.txt").write_text("flask==2.3.1\n", encoding="utf-8")
    deps = detect_and_parse(tmp_path / "requirements.txt", CFG)
    assert len(deps) == 1
    assert deps[0].name == "flask"


def test_detect_pyproject_por_nombre(tmp_path: Path) -> None:
    """pyproject.toml detectado por nombre (T11)."""
    content = "[project]\ndependencies = [\"requests\"]\n"
    (tmp_path / "pyproject.toml").write_text(content, encoding="utf-8")
    deps = detect_and_parse(tmp_path / "pyproject.toml", CFG)
    assert any(d.name == "requests" for d in deps)


def test_detect_override_freeze(tmp_path: Path) -> None:
    """override --manifest-type freeze fuerza el parser de pip freeze (T11)."""
    (tmp_path / "locks.txt").write_text("requests==2.28.0\n", encoding="utf-8")
    deps = detect_and_parse(tmp_path / "locks.txt", CFG, manifest_type="freeze")
    assert len(deps) == 1
    assert deps[0].version_pin == "2.28.0"


def test_detect_tipo_invalido(tmp_path: Path) -> None:
    """Tipo de manifiesto desconocido → ManifestParseError."""
    (tmp_path / "r.txt").write_text("requests\n", encoding="utf-8")
    with pytest.raises(ManifestParseError, match="desconocido"):
        detect_and_parse(tmp_path / "r.txt", CFG, manifest_type="unknown_type")


def test_detect_extension_no_reconocida(tmp_path: Path) -> None:
    """Extension no reconocida sin override → ManifestParseError."""
    (tmp_path / "deps.yaml").write_text("requests\n", encoding="utf-8")
    with pytest.raises(ManifestParseError):
        detect_and_parse(tmp_path / "deps.yaml", CFG)


def test_detect_vacio_retorna_cero_deps(tmp_path: Path) -> None:
    """Manifiesto vacio → 0 deps, no es error (R1.7)."""
    (tmp_path / "requirements.txt").write_text("# vacio\n\n", encoding="utf-8")
    deps = detect_and_parse(tmp_path / "requirements.txt", CFG)
    assert deps == ()


def test_detect_stdin_freeze() -> None:
    """stdin con formato freeze parsea correctamente (R1.3)."""
    text = "requests==2.28.0\nflask==2.3.1\n"
    deps = detect_and_parse_stdin(text, CFG)
    assert len(deps) == 2


# ---------------------------------------------------------------------------
# Limites de tamano y deps (R1.9)
# ---------------------------------------------------------------------------


def test_limite_tamano_requirements(tmp_path: Path) -> None:
    """Archivo mayor que max_manifest_bytes → ManifestParseError antes de parsear (R1.9)."""
    (tmp_path / "r.txt").write_bytes(b"x" * 100)
    cfg_small = Config(max_manifest_bytes=50)
    with pytest.raises(ManifestParseError, match="tamano"):
        parse_requirements_txt(
            tmp_path / "r.txt",
            origin="r.txt",
            max_manifest_bytes=cfg_small.max_manifest_bytes,
            max_deps=cfg_small.max_deps,
            max_include_depth=cfg_small.max_include_depth,
            project_root=tmp_path,
        )


def test_limite_tamano_pyproject(tmp_path: Path) -> None:
    """pyproject.toml mayor que max_manifest_bytes → ManifestParseError (R1.9)."""
    (tmp_path / "pyproject.toml").write_bytes(b"x" * 100)
    cfg_small = Config(max_manifest_bytes=50)
    with pytest.raises(ManifestParseError, match="tamano"):
        parse_pyproject_toml(
            tmp_path / "pyproject.toml",
            origin="pyproject.toml",
            max_manifest_bytes=cfg_small.max_manifest_bytes,
            max_deps=cfg_small.max_deps,
        )


def test_limite_tamano_freeze(tmp_path: Path) -> None:
    """Archivo freeze mayor que max_manifest_bytes → ManifestParseError (R1.9)."""
    (tmp_path / "freeze.txt").write_bytes(b"x" * 100)
    cfg_small = Config(max_manifest_bytes=50)
    with pytest.raises(ManifestParseError, match="tamano"):
        parse_pip_freeze_file(
            tmp_path / "freeze.txt",
            origin="freeze.txt",
            max_manifest_bytes=cfg_small.max_manifest_bytes,
            max_deps=cfg_small.max_deps,
        )


def test_limite_deps_requirements(tmp_path: Path) -> None:
    """Mas deps que max_deps → ManifestParseError (R1.9)."""
    lines = "\n".join(f"pkg{i}==1.0" for i in range(5))
    (tmp_path / "r.txt").write_text(lines, encoding="utf-8")
    cfg_small = Config(max_deps=3)
    with pytest.raises(ManifestParseError, match="maximo"):
        parse_requirements_txt(
            tmp_path / "r.txt",
            origin="r.txt",
            max_manifest_bytes=cfg_small.max_manifest_bytes,
            max_deps=cfg_small.max_deps,
            max_include_depth=cfg_small.max_include_depth,
            project_root=tmp_path,
        )


def test_limite_deps_stdin(tmp_path: Path) -> None:
    """stdin con mas bytes que max_manifest_bytes → ManifestParseError (R1.9)."""
    text = "requests==2.0\n"
    cfg_small = Config(max_manifest_bytes=5)
    with pytest.raises(ManifestParseError, match="tamano"):
        detect_and_parse_stdin(text, cfg_small)


# ---------------------------------------------------------------------------
# Mensaje de error sin stacktrace y con nombre de archivo (R1.8, R6.5)
# ---------------------------------------------------------------------------


def test_mensaje_error_requirements_no_tiene_ruta_absoluta(tmp_path: Path) -> None:
    """El mensaje de error no debe contener la ruta absoluta del sistema (R6.5)."""
    (tmp_path / "r.txt").write_text("!!!invalido!!!\n", encoding="utf-8")
    with pytest.raises(ManifestParseError) as exc_info:
        parse_requirements_txt(
            tmp_path / "r.txt",
            origin="r.txt",
            max_manifest_bytes=CFG.max_manifest_bytes,
            max_deps=CFG.max_deps,
            max_include_depth=CFG.max_include_depth,
            project_root=tmp_path,
        )
    msg = str(exc_info.value)
    # No debe contener el path absoluto del sistema.
    assert str(tmp_path) not in msg


def test_requirements_origin_en_dependency(tmp_path: Path) -> None:
    """El origin de la Dependency es el nombre del archivo (sin ruta absoluta)."""
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    deps = parse_requirements_txt(
        tmp_path / "requirements.txt",
        origin="requirements.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    assert deps[0].origin == "requirements.txt"


# ---------------------------------------------------------------------------
# Bug fix: include en diamante NO debe tratarse como ciclo (red)
# ---------------------------------------------------------------------------


def test_includes_diamante_no_es_ciclo(tmp_path: Path) -> None:
    """Include en diamante: top→a→shared y top→b→shared no debe ser ciclo.

    Un ciclo REAL es A→B→A en la misma rama. Un archivo compartido por dos
    ramas distintas es un patron legitimo (diamante) que debe procesarse sin
    error. Reproducido el bug: 'seen_paths' global disparaba falso ciclo.
    (Fix de pila por rama con try/finally en _ReqParser.parse.)
    """
    (tmp_path / "shared.txt").write_text("requests==2.28.0\n", encoding="utf-8")
    (tmp_path / "a.txt").write_text("-r shared.txt\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("-r shared.txt\n", encoding="utf-8")
    (tmp_path / "top.txt").write_text(
        "-r a.txt\n-r b.txt\nflask==2.3.1\n", encoding="utf-8"
    )

    deps = parse_requirements_txt(
        tmp_path / "top.txt",
        origin="top.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    names = {d.name for d in deps}
    # requests de shared.txt (deduplicado) + flask de top.txt
    assert "requests" in names
    assert "flask" in names


# ---------------------------------------------------------------------------
# Bug fix: version_pin con ANSI/CRLF saneado en los tres parsers (red)
# ---------------------------------------------------------------------------


def test_freeze_version_pin_con_ansi_saneado() -> None:
    """version_pin en pip freeze no debe contener secuencias ANSI (R6.5).

    Un manifiesto malicioso podria inyectar ESC[31m en la version.
    Reproducido el bug: version_pin='2.0\\x1b[31m' sin sanear.
    """
    text = "requests==2.0\x1b[31m\n"
    deps = parse_pip_freeze(text, origin="stdin", max_deps=CFG.max_deps)
    # El parser de freeze acepta cualquier no-espacio en la version.
    # El version_pin resultante debe estar saneado.
    assert len(deps) == 1
    pin = deps[0].version_pin
    assert pin is not None
    assert "\x1b" not in pin
    assert "[31m" not in pin


def test_requirements_version_pin_con_crlf_saneado(tmp_path: Path) -> None:
    """version_pin en requirements.txt no debe contener CR/LF (R6.5)."""
    # Escribir una linea con CR embebido en la version.
    (tmp_path / "r.txt").write_bytes(b"requests==2.0\r\n")
    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    assert len(deps) == 1
    pin = deps[0].version_pin
    assert pin is not None
    assert "\r" not in pin
    assert "\n" not in pin


def test_pyproject_error_toml_saneado(tmp_path: Path) -> None:
    """Error de TOML invalido: el mensaje no expone control chars (R6.5).

    tomllib puede incluir fragmentos del contenido en el mensaje de error.
    Aunque en Python 3.11 la descripcion es generalmente solo linea/columna,
    el fix sanea el mensaje de exc por defensa en profundidad.
    El test verifica que el mensaje de ManifestParseError no contiene
    secuencias ANSI/C0 provenientes del archivo malformado.
    """
    # Un TOML con un caracter de control ilegal (ESC) causa TOMLDecodeError.
    # El mensaje del error podria incluir repr del char; lo saneamos.
    raw = b'[project]\ndependencies = ["requests==2.0\x1b[31m"]\n'
    (tmp_path / "pyproject.toml").write_bytes(raw)

    with pytest.raises(ManifestParseError) as exc_info:
        parse_pyproject_toml(
            tmp_path / "pyproject.toml",
            origin="pyproject.toml",
            max_manifest_bytes=CFG.max_manifest_bytes,
            max_deps=CFG.max_deps,
        )
    msg = str(exc_info.value)
    # El mensaje de error no debe contener bytes de control raw (solo repr
    # como '\\x1b' que son literales seguros, no el byte real 0x1b).
    assert "\x1b" not in msg, f"ESC raw en mensaje de error: {msg!r}"
    assert "pyproject.toml" in msg  # el nombre del archivo si debe aparecer


# ---------------------------------------------------------------------------
# Bug fix: version_pin con extras paquete[extra]==X (red)
# ---------------------------------------------------------------------------


def test_requirements_extras_conserva_version_pin(tmp_path: Path) -> None:
    """uvicorn[standard]==0.20.0 debe preservar version_pin='0.20.0' (R1.11).

    Reproducido el bug: _NAME_VERSION no consumia la seccion de extras [...]
    y group(3) quedaba vacio, resultando en version_pin=None.
    """
    (tmp_path / "r.txt").write_text(
        "uvicorn[standard]==0.20.0\nrequests[security]==2.31.0\n",
        encoding="utf-8",
    )
    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    by_name = {d.name: d for d in deps}
    assert by_name["uvicorn"].version_pin == "0.20.0", (
        f"se esperaba '0.20.0', se obtuvo {by_name['uvicorn'].version_pin!r}"
    )
    assert by_name["requests"].version_pin == "2.31.0"


def test_requirements_extras_sin_pin_no_falla(tmp_path: Path) -> None:
    """paquete[extra] sin pin debe parsear con version_pin=None (no crashear)."""
    (tmp_path / "r.txt").write_text("uvicorn[standard]>=0.18\n", encoding="utf-8")
    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    assert len(deps) == 1
    assert deps[0].name == "uvicorn"
    assert deps[0].version_pin is None


# ---------------------------------------------------------------------------
# Bug fix: include pegado '-rfile.txt' (sin espacio) (yellow)
# ---------------------------------------------------------------------------


def test_includes_forma_pegada_sin_espacio(tmp_path: Path) -> None:
    """'-rbase.txt' (sin espacio) debe resolverse como include, no ignorarse.

    Reproducido el bug: _should_ignore retornaba True para cualquier linea
    que empieza con '-', silenciando las deps de base.txt (viola R1.6).
    """
    (tmp_path / "base.txt").write_text("requests==2.28.0\n", encoding="utf-8")
    (tmp_path / "r.txt").write_text("-rbase.txt\nflask==2.3.1\n", encoding="utf-8")

    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    names = {d.name for d in deps}
    assert "requests" in names, "requests de base.txt no fue incluido (forma pegada)"
    assert "flask" in names


def test_includes_forma_pegada_c_sin_espacio(tmp_path: Path) -> None:
    """'-cconstraints.txt' (forma -c pegada) debe resolverse como include."""
    (tmp_path / "constraints.txt").write_text("boto3==1.34.0\n", encoding="utf-8")
    (tmp_path / "r.txt").write_text(
        "-cconstraints.txt\npytest==8.0.0\n", encoding="utf-8"
    )

    deps = parse_requirements_txt(
        tmp_path / "r.txt",
        origin="r.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    names = {d.name for d in deps}
    assert "boto3" in names
    assert "pytest" in names


# ---------------------------------------------------------------------------
# Bug fix: profundidad maxima semantica correcta (yellow)
# ---------------------------------------------------------------------------


def test_includes_profundidad_maxima_semantica_correcta(tmp_path: Path) -> None:
    """Con max_include_depth=2, una cadena a→b→c (2 niveles) debe resolverse.

    Antes del fix (>= en vez de >), se cortaba un nivel antes de lo declarado
    y se requeria max=3 para resolver 2 niveles reales.
    """
    (tmp_path / "c.txt").write_text("boto3==1.34.0\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("-r c.txt\n", encoding="utf-8")
    (tmp_path / "a.txt").write_text("-r b.txt\nrequests==2.28.0\n", encoding="utf-8")

    # Con max=2 deben resolverse los 2 niveles de include (b y c).
    deps = parse_requirements_txt(
        tmp_path / "a.txt",
        origin="a.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=2,
        project_root=tmp_path,
    )
    names = {d.name for d in deps}
    assert "boto3" in names
    assert "requests" in names


# ---------------------------------------------------------------------------
# T12: override --manifest-type con detect_and_parse
# ---------------------------------------------------------------------------


def test_detect_override_requirements_sobre_archivo_txt(tmp_path: Path) -> None:
    """manifest_type='requirements' fuerza el parser de requirements sobre cualquier .txt."""
    (tmp_path / "lockfile.txt").write_text("flask==2.3.1\nrequests\n", encoding="utf-8")
    deps = detect_and_parse(tmp_path / "lockfile.txt", CFG, manifest_type="requirements")
    names = {d.name for d in deps}
    assert "flask" in names
    assert "requests" in names


def test_detect_override_pyproject_sobre_archivo_txt(tmp_path: Path) -> None:
    """manifest_type='pyproject' fuerza el parser de pyproject sobre un archivo no .toml."""
    content = "[project]\ndependencies = [\"boto3==1.34.0\"]\n"
    (tmp_path / "pyproject_alt.txt").write_text(content, encoding="utf-8")
    deps = detect_and_parse(
        tmp_path / "pyproject_alt.txt", CFG, manifest_type="pyproject"
    )
    assert any(d.name == "boto3" for d in deps)


def test_detect_override_freeze_sobre_requirements(tmp_path: Path) -> None:
    """manifest_type='freeze' fuerza el parser freeze sobre un requirements.txt (T11)."""
    (tmp_path / "requirements.txt").write_text(
        "requests==2.28.0\nflask==2.3.1\n", encoding="utf-8"
    )
    deps = detect_and_parse(
        tmp_path / "requirements.txt", CFG, manifest_type="freeze"
    )
    # freeze espera nombre==version; estas lineas son validas en ambos formatos.
    names = {d.name for d in deps}
    assert "requests" in names
    assert "flask" in names


# ---------------------------------------------------------------------------
# T12: saneo ANSI/C0-C1/CRLF en mensajes de error (R6.5)
# ---------------------------------------------------------------------------


def test_error_malformado_sin_filtrado_de_contenido(tmp_path: Path) -> None:
    """Manifiesto con contenido malicioso: salida (raw/error) saneada (R6.5).

    Verifica dos cosas:
    (1) Una linea malformada con ANSI en el nombre produce un error cuyo mensaje
        no contiene secuencias de control (el fragmento que se muestra esta saneado).
    (2) Una linea valida con ANSI en el nombre produce un Dependency cuyo campo
        `raw` esta saneado (el nombre bruto saneado no contiene controles).
    """
    # Caso (1): linea que el parser no puede reconocer (empieza con control char)
    # → ManifestParseError con mensaje saneado.
    malicioso_no_parseable = "\x1b[31mpkg-invalido\n"
    (tmp_path / "r.txt").write_bytes(malicioso_no_parseable.encode("utf-8"))

    with pytest.raises(ManifestParseError) as exc_info:
        parse_requirements_txt(
            tmp_path / "r.txt",
            origin="r.txt",
            max_manifest_bytes=CFG.max_manifest_bytes,
            max_deps=CFG.max_deps,
            max_include_depth=CFG.max_include_depth,
            project_root=tmp_path,
        )
    msg = str(exc_info.value)
    assert "\x1b" not in msg, f"ESC en mensaje de error: {msg!r}"
    assert "\x00" not in msg

    # Caso (2): linea valida con ANSI en el resto del nombre → raw saneado.
    # El nombre `pkg` se extrae; el campo raw no debe tener controles.
    con_ansi = "pkg\x1b[31m==1.0\n"
    (tmp_path / "r2.txt").write_bytes(con_ansi.encode("utf-8"))
    deps2 = parse_requirements_txt(
        tmp_path / "r2.txt",
        origin="r2.txt",
        max_manifest_bytes=CFG.max_manifest_bytes,
        max_deps=CFG.max_deps,
        max_include_depth=CFG.max_include_depth,
        project_root=tmp_path,
    )
    assert len(deps2) == 1
    assert "\x1b" not in deps2[0].raw, f"ESC en raw: {deps2[0].raw!r}"


def test_freeze_error_con_crlf_saneado() -> None:
    """Error de formato freeze con CRLF en la linea: mensaje saneado (R6.5)."""
    text = "requests\r\n"  # sin == version, formato invalido para freeze
    with pytest.raises(ManifestParseError) as exc_info:
        parse_pip_freeze(text, origin="stdin", max_deps=CFG.max_deps)
    msg = str(exc_info.value)
    assert "\r" not in msg
    assert "\n" not in msg or msg.count("\n") == 0  # sin CR/LF intercalado
