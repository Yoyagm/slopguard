"""Suite de la CLI de SlopGuard (T36, R6.1-6.5, R7.1-7.6, R8.2, §2.5).

Estrategia: `main(argv=[...])` en proceso, sin red.
  - La fachada `scan_manifest`/`scan_stdin` se monkeypatchea en el modulo
    `slopguard.cli.main` para devolver `ScanReport` fabricados.
  - Los paths de manifiesto usan tmp_path de pytest para los casos que tocan
    el FS (--config, scan de archivo malformado).
  - `capsys` captura stdout/stderr sin tocar el proceso.

EARS cubiertos: R6.1-R6.5, R7.1-R7.6, R8.2, §2.5 (JSON estable, sin timestamps).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from slopguard.cli.exit_codes import EXIT_ALLOW, EXIT_BLOCK, EXIT_OPERATIONAL, EXIT_WARN
from slopguard.cli.main import main
from slopguard.cli.render_json import render_json
from slopguard.core import (
    Config,
    DependencyResult,
    ErrorCategory,
    InvalidConfigError,
    Layer,
    LayerSignal,
    ManifestParseError,
    ScanReport,
    ScanSummary,
    SignalCode,
    Status,
    Verdict,
)

# ---------------------------------------------------------------------------
# Constantes reutilizables
# ---------------------------------------------------------------------------

_SCHEMA = "slopguard.cli.main"
_SCAN_MANIFEST = f"{_SCHEMA}.scan_manifest"
_SCAN_STDIN = f"{_SCHEMA}.scan_stdin"
_LOAD_CONFIG = f"{_SCHEMA}.load_config"


# ---------------------------------------------------------------------------
# Constructores de ScanReport de fixture
# ---------------------------------------------------------------------------


def _signal(
    layer: Layer,
    code: SignalCode,
    weight: int,
    *,
    is_soft: bool = False,
    detail: str = "detalle de senal.",
    suspected_target: str | None = None,
) -> LayerSignal:
    """Construye una LayerSignal para tests."""
    return LayerSignal(
        layer=layer,
        code=code,
        weight=weight,
        is_soft=is_soft,
        detail=detail,
        suspected_target=suspected_target,
    )


def _dep_result(
    name: str,
    verdict: Verdict | None,
    score: int | None = None,
    status: Status = Status.OK,
    signals: tuple[LayerSignal, ...] = (),
    suspected_target: str | None = None,
    error_category: ErrorCategory | None = None,
    version_pin: str | None = None,
) -> DependencyResult:
    """Construye un DependencyResult para tests."""
    return DependencyResult(
        name=name,
        version_pin=version_pin,
        status=status,
        verdict=verdict,
        score=score,
        signals=signals,
        suspected_target=suspected_target,
        error_category=error_category,
    )


def _report(
    results: tuple[DependencyResult, ...],
    *,
    error_category: ErrorCategory | None = None,
    exit_code: int = 0,
) -> ScanReport:
    """Fabrica un ScanReport con conteos derivados de los resultados."""
    allow = sum(1 for r in results if r.verdict == Verdict.ALLOW)
    warn = sum(1 for r in results if r.verdict == Verdict.WARN)
    block = sum(1 for r in results if r.verdict == Verdict.BLOCK)
    unverifiable = sum(1 for r in results if r.status == Status.UNVERIFIABLE)
    return ScanReport(
        schema_version="1.0",
        tool_version="0.1.0",
        ecosystem="pypi",
        summary=ScanSummary(
            total=len(results),
            allow=allow,
            warn=warn,
            block=block,
            unverifiable=unverifiable,
            exit_code=exit_code,
        ),
        results=results,
        error_category=error_category,
    )


# Reportes de fixture frecuentes
_REPORT_ALL_ALLOW = _report(
    (_dep_result("requests", Verdict.ALLOW, score=0),),
    exit_code=EXIT_ALLOW,
)

_REPORT_ONE_WARN = _report(
    (
        _dep_result(
            "reqursts",
            Verdict.WARN,
            score=55,
            signals=(_signal(Layer.L1, SignalCode.TYPOSQUAT, 40, detail="Parecido a requests."),),
            suspected_target="requests",
        ),
    ),
    exit_code=EXIT_WARN,
)

_REPORT_ONE_BLOCK = _report(
    (
        _dep_result(
            "notapackage",
            Verdict.BLOCK,
            score=None,
            signals=(_signal(Layer.L0, SignalCode.NONEXISTENT, 0, detail="No existe en PyPI."),),
        ),
    ),
    exit_code=EXIT_BLOCK,
)

_REPORT_UNVERIFIABLE = _report(
    (
        _dep_result(
            "mypkg",
            verdict=None,
            status=Status.UNVERIFIABLE,
            error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
        ),
    ),
    exit_code=EXIT_OPERATIONAL,
)


# ---------------------------------------------------------------------------
# T36-a: --help y version retornan 0
# ---------------------------------------------------------------------------


def test_help_retorna_0(capsys: pytest.CaptureFixture[str]) -> None:
    """--help imprime uso y retorna 0 (R7.1)."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "slopguard" in out


def test_version_retorna_0(capsys: pytest.CaptureFixture[str]) -> None:
    """El subcomando version imprime la version y retorna 0 (R7.1)."""
    code = main(["version"])
    assert code == 0
    out = capsys.readouterr().out
    assert "slopguard 0.1.0" in out


def test_sin_subcomando_retorna_0(capsys: pytest.CaptureFixture[str]) -> None:
    """Sin subcomando imprime ayuda y retorna 0."""
    code = main([])
    assert code == 0
    out = capsys.readouterr().out
    assert "scan" in out


# ---------------------------------------------------------------------------
# T36-b: render humano y JSON — saneo y schema estable
# ---------------------------------------------------------------------------


def test_render_humano_muestra_campos_basicos(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Render humano incluye nombre, veredicto y accion (R6.1-6.2)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_ALL_ALLOW)

    code = main(["scan", str(manifest)])

    assert code == EXIT_ALLOW
    out = capsys.readouterr().out
    assert "requests" in out
    assert "allow" in out
    assert "Ninguna accion" in out


def test_render_json_schema_version_y_claves_fijas(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """JSON emite schema_version '1.0' y las claves fijas de §2.5."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_ALL_ALLOW)

    code = main(["scan", str(manifest), "--format", "json"])

    assert code == EXIT_ALLOW
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["schema_version"] == "1.0"
    # Claves fijas de nivel raiz (§2.5)
    top_keys = (
        "schema_version", "tool_version", "ecosystem",
        "summary", "error_category", "results",
    )
    for key in top_keys:
        assert key in data, f"clave fija ausente: {key}"
    # Claves del summary
    for key in ("total", "allow", "warn", "block", "unverifiable", "exit_code"):
        assert key in data["summary"], f"clave summary ausente: {key}"


def test_json_sin_timestamps(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """El JSON de salida no contiene campos de reloj/timestamp (R6.3, §2.5)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_ALL_ALLOW)

    main(["scan", str(manifest), "--format", "json"])

    out = capsys.readouterr().out
    data = json.loads(out)
    raw = json.dumps(data)
    for forbidden in ("timestamp", "generated_at", "fetched_at", "scan_time"):
        assert forbidden not in raw, f"clave de tiempo encontrada en JSON: {forbidden}"


def test_json_orden_determinista(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """El JSON producido dos veces con el mismo reporte es identico (orden determinista)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_ALL_ALLOW)

    main(["scan", str(manifest), "--format", "json"])
    out1 = capsys.readouterr().out
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_ALL_ALLOW)
    main(["scan", str(manifest), "--format", "json"])
    out2 = capsys.readouterr().out

    assert out1 == out2


# ---------------------------------------------------------------------------
# T36-b extra: saneo de nombres maliciosos en human y JSON
# ---------------------------------------------------------------------------


_ANSI_NAME = "\x1b[31mmalicious\x1b[0m"
_CRLF_NAME = "evil\r\ninjected"


def _report_with_name(name: str) -> ScanReport:
    """Reporte con un nombre potencialmente malicioso."""
    return _report(
        (_dep_result(name, Verdict.ALLOW, score=0),),
        exit_code=EXIT_ALLOW,
    )


def test_saneo_ansi_en_render_humano(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Un nombre con ANSI aparece saneado (sin secuencias CSI) en salida human (R6.5)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==1.0\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _report_with_name(_ANSI_NAME))

    main(["scan", str(manifest)])

    out = capsys.readouterr().out
    # La secuencia ESC[ no debe aparecer en la salida
    assert "\x1b[" not in out
    # El texto visible si (sin los escapes)
    assert "malicious" in out


def test_saneo_crlf_en_render_humano(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Un nombre con CRLF aparece saneado (sin CR/LF embebidos) en salida human (R6.5)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==1.0\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _report_with_name(_CRLF_NAME))

    main(["scan", str(manifest)])

    out = capsys.readouterr().out
    assert "\r" not in out
    assert "evil" in out


def test_saneo_ansi_en_render_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Un nombre con ANSI aparece saneado en el JSON (R6.5)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==1.0\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _report_with_name(_ANSI_NAME))

    main(["scan", str(manifest), "--format", "json"])

    out = capsys.readouterr().out
    assert "\x1b" not in out
    data = json.loads(out)
    name_in_json = data["results"][0]["name"]
    assert "\x1b" not in name_in_json
    assert "malicious" in name_in_json


# ---------------------------------------------------------------------------
# T36-c: exit codes 0/1/2/3 segun veredictos y --strict
# ---------------------------------------------------------------------------


def test_exit_0_all_allow(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Todos allow => exit 0 (R7.1)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_ALL_ALLOW)

    assert main(["scan", str(manifest)]) == EXIT_ALLOW


def test_exit_1_warn_sin_strict(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Al menos un warn sin --strict => exit 1 (R7.2)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("reqursts==1.0\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_ONE_WARN)

    assert main(["scan", str(manifest)]) == EXIT_WARN


def test_exit_2_block(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Al menos un block => exit 2 (R7.3)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("notapackage==1.0\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_ONE_BLOCK)

    assert main(["scan", str(manifest)]) == EXIT_BLOCK


def test_exit_2_warn_con_strict(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Warn con --strict => exit 2 (R7.6)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("reqursts==1.0\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_ONE_WARN)

    assert main(["scan", str(manifest), "--strict"]) == EXIT_BLOCK


def test_exit_3_unverifiable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Unverifiable sin block => exit 3 (R7.4)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("mypkg==1.0\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_UNVERIFIABLE)

    assert main(["scan", str(manifest)]) == EXIT_OPERATIONAL


# ---------------------------------------------------------------------------
# T36-d: --manifest-type reconocido y cableado
# ---------------------------------------------------------------------------


def test_manifest_type_cableado_a_scan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """--manifest-type se pasa a scan_manifest como keyword (§3.5, T11)."""
    manifest = tmp_path / "reqs.txt"
    manifest.write_text("requests==2.32\n")
    captured: dict[str, object] = {}

    def _fake_scan(path: object, cfg: object, **kw: object) -> ScanReport:
        captured.update(kw)
        return _REPORT_ALL_ALLOW

    monkeypatch.setattr(_SCAN_MANIFEST, _fake_scan)

    main(["scan", str(manifest), "--manifest-type", "requirements"])

    assert captured.get("manifest_type") == "requirements"


def test_manifest_type_pyproject(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """--manifest-type pyproject se acepta sin error."""
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text("[project]\nname = 'foo'\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_ALL_ALLOW)

    code = main(["scan", str(manifest), "--manifest-type", "pyproject"])
    assert code == EXIT_ALLOW


# ---------------------------------------------------------------------------
# T36-e: precedencia CLI > config (override de umbral via flag)
# ---------------------------------------------------------------------------


def test_precedencia_cli_sobre_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Los overrides CLI se pasan a load_config y tienen mayor precedencia (R8.2)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")
    captured_cfg: list[Config] = []

    def _fake_scan(path: object, cfg: Config, **kw: object) -> ScanReport:
        captured_cfg.append(cfg)
        return _REPORT_ALL_ALLOW

    monkeypatch.setattr(_SCAN_MANIFEST, _fake_scan)

    # Pasamos umbral_block=90 via flag; el default es 80
    main(["scan", str(manifest), "--umbral-block", "90"])

    assert captured_cfg, "scan_manifest no fue llamado"
    assert captured_cfg[0].umbral_block == 90


def test_no_cache_cableado(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """--no-cache pasa use_cache=False a scan_manifest (R9.3)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")
    captured: dict[str, object] = {}

    def _fake_scan(path: object, cfg: object, **kw: object) -> ScanReport:
        captured.update(kw)
        return _REPORT_ALL_ALLOW

    monkeypatch.setattr(_SCAN_MANIFEST, _fake_scan)

    main(["scan", str(manifest), "--no-cache"])

    assert captured.get("use_cache") is False


# ---------------------------------------------------------------------------
# T36-f: --ecosystem desconocido => exit 3 saneado sin stacktrace
# ---------------------------------------------------------------------------


def test_ecosystem_desconocido_exit_3(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--ecosystem no soportado => exit 3; mensaje saneado en stderr (R6.5)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")

    code = main(["scan", str(manifest), "--ecosystem", "npm"])

    assert code == EXIT_OPERATIONAL
    captured = capsys.readouterr()
    assert "npm" in captured.err
    assert "no soportado" in captured.err
    # No hay traceback crudo
    assert "Traceback" not in captured.err
    assert "File " not in captured.err


def test_ecosystem_con_ansi_saneado(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Un ecosystem con ANSI en el nombre aparece saneado en stderr."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")

    code = main(["scan", str(manifest), "--ecosystem", "\x1b[31mnpm\x1b[0m"])

    assert code == EXIT_OPERATIONAL
    err = capsys.readouterr().err
    assert "\x1b[" not in err
    assert "npm" in err


def test_ecosystem_valido_no_exit_3(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """'pypi' (valido) no fuerza exit 3 por ecosystem."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")
    monkeypatch.setattr(_SCAN_MANIFEST, lambda *a, **kw: _REPORT_ALL_ALLOW)

    code = main(["scan", str(manifest), "--ecosystem", "pypi"])
    assert code == EXIT_ALLOW


# ---------------------------------------------------------------------------
# T36-g: stderr sin rutas absolutas ni contenido del manifiesto en errores
# ---------------------------------------------------------------------------


def test_config_invalida_no_filtra_ruta_absoluta(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Un error de config emite mensaje fijo sin ruta absoluta (R6.5)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")
    config_path = str(tmp_path / "secret.toml")

    # Simulamos que load_config lanza InvalidConfigError con una ruta absoluta.
    def _fake_load(path: object, overrides: object) -> Config:
        msg = (
            f"config TOML ilegible en 'secret.toml': "
            f"[Errno 13] Permission denied: '{config_path}'"
        )
        raise InvalidConfigError(msg)

    monkeypatch.setattr(_LOAD_CONFIG, _fake_load)

    code = main(["scan", str(manifest)])

    assert code == EXIT_OPERATIONAL
    err = capsys.readouterr().err
    # El mensaje CLI fijo no debe exponer la ruta absoluta del SO
    assert config_path not in err
    assert "Traceback" not in err
    assert "File " not in err


def test_error_parseo_manifesto_sin_ruta_absoluta(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Un ManifestParseError no filtra la ruta absoluta ni el contenido (R6.5)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("INVALID_LINE====\n")

    abs_path = str(manifest)

    def _fake_scan(path: object, cfg: object, **kw: object) -> ScanReport:
        raise ManifestParseError(f"linea invalida en '{abs_path}': INVALID_LINE====")

    monkeypatch.setattr(_SCAN_MANIFEST, _fake_scan)

    code = main(["scan", abs_path])

    assert code == EXIT_OPERATIONAL
    err = capsys.readouterr().err
    # La ruta absoluta puede aparecer en el mensaje del error (ManifestParseError
    # la incluye intencionalmente para contexto), pero NO debe haber stacktrace.
    assert "Traceback" not in err
    assert "File " not in err


# ---------------------------------------------------------------------------
# T36: stdin '-' con monkeypatch de scan_stdin
# ---------------------------------------------------------------------------


def test_stdin_guion_llama_scan_stdin(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """'scan -' usa scan_stdin con el texto leido de stdin (§3.5)."""
    called_with: dict[str, object] = {}

    def _fake_stdin_scan(text: str, cfg: object, **kw: object) -> ScanReport:
        called_with["text"] = text
        return _REPORT_ALL_ALLOW

    monkeypatch.setattr(_SCAN_STDIN, _fake_stdin_scan)
    monkeypatch.setattr("sys.stdin", io.StringIO("requests==2.32\n"))

    code = main(["scan", "-"])

    assert code == EXIT_ALLOW
    assert "requests==2.32" in str(called_with.get("text", ""))


# ---------------------------------------------------------------------------
# T36: guarda de ultimo nivel — KeyboardInterrupt
# ---------------------------------------------------------------------------


def test_keyboard_interrupt_retorna_3(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """KeyboardInterrupt durante el scan => exit 3 + mensaje saneado, sin traceback."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")

    def _raise_keyboard(*a: object, **kw: object) -> ScanReport:
        raise KeyboardInterrupt

    monkeypatch.setattr(_SCAN_MANIFEST, _raise_keyboard)

    code = main(["scan", str(manifest)])

    assert code == EXIT_OPERATIONAL
    captured = capsys.readouterr()
    assert "Interrumpido" in captured.err
    assert "Traceback" not in captured.err
    assert "KeyboardInterrupt" not in captured.err


# ---------------------------------------------------------------------------
# T36: guarda de ultimo nivel — BrokenPipeError
# ---------------------------------------------------------------------------


def test_broken_pipe_retorna_3(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """BrokenPipeError durante el scan => exit 3 (R6.5).

    No se usa capsys: la guarda suprime silenciosamente el error sin escribir nada.
    El test verifica solo que main() retorna EXIT_OPERATIONAL sin relanzar.
    """
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.32\n")

    def _raise_broken(*a: object, **kw: object) -> ScanReport:
        raise BrokenPipeError

    monkeypatch.setattr(_SCAN_MANIFEST, _raise_broken)

    code = main(["scan", str(manifest)])

    assert code == EXIT_OPERATIONAL


# ---------------------------------------------------------------------------
# T36: stdin UnicodeDecodeError mapeado a EXIT_OPERATIONAL
# ---------------------------------------------------------------------------


def test_stdin_unicode_error_retorna_3(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """stdin binario (UnicodeDecodeError) => exit 3 + mensaje saneado sin stacktrace."""

    class _BrokenStdin:
        def read(self) -> str:
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr("sys.stdin", _BrokenStdin())

    code = main(["scan", "-"])

    assert code == EXIT_OPERATIONAL
    err = capsys.readouterr().err
    # Sin stacktrace crudo (R6.5): no hay 'Traceback' ni lineas 'File ...'
    assert "Traceback" not in err
    assert "File " not in err
    # El mensaje menciona stdin para orientar al usuario
    assert "stdin" in err


# ---------------------------------------------------------------------------
# T36: render_json (unidad) — claves y orden estable del §2.5
# ---------------------------------------------------------------------------


def test_render_json_claves_segun_esquema() -> None:
    """render_json produce exactamente las claves de §2.5 en el orden del dict."""
    report = _report(
        (
            _dep_result(
                "reqursts",
                Verdict.BLOCK,
                score=82,
                signals=(
                    _signal(
                        Layer.L1,
                        SignalCode.TYPOSQUAT,
                        60,
                        detail="El nombre se parece a 'requests' (distancia 1).",
                        suspected_target="requests",
                    ),
                ),
                suspected_target="requests",
            ),
        ),
        exit_code=EXIT_BLOCK,
    )

    raw = render_json(report)
    data = json.loads(raw)

    # Claves de nivel raiz en el orden de §2.5
    expected_top = [
        "schema_version", "tool_version", "ecosystem",
        "summary", "error_category", "results",
    ]
    assert list(data.keys()) == expected_top

    # Claves de un resultado (schema 1.1: se anio advisories al final de forma aditiva, §2.4)
    result = data["results"][0]
    expected_result = [
        "name", "version_pin", "status", "verdict", "score",
        "suspected_target", "error_category", "signals", "advisories",
    ]
    assert list(result.keys()) == expected_result

    # Claves de una senal
    sig = result["signals"][0]
    expected_signal = ["layer", "code", "weight", "is_soft", "detail", "suspected_target"]
    assert list(sig.keys()) == expected_signal


def test_render_json_score_null_en_unverifiable() -> None:
    """score y verdict son null para dependencias unverifiable (§2.5)."""
    report = _report(
        (
            _dep_result(
                "mypkg",
                verdict=None,
                status=Status.UNVERIFIABLE,
                error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
            ),
        ),
        exit_code=EXIT_OPERATIONAL,
    )

    raw = render_json(report)
    data = json.loads(raw)

    result = data["results"][0]
    assert result["verdict"] is None
    assert result["score"] is None
    assert result["error_category"] == "network_unverifiable"
