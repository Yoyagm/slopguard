"""Tests de validación de límites + ecosistema (H5-T17, R3.2/R3.3).

Verifica:
- Tamaño del manifiesto > max_manifest_bytes → 422 (INVALID_INPUT) antes del parseo.
- Nº de dependencias > max_deps → 422 (INVALID_INPUT) antes del escaneo costoso.
- El motor NO se llega a invocar cuando se superan límites (no hay trabajo pesado).
- Override de ecosistema gana sobre autodetección (R3.2).
- Settings expone scan_max_manifest_bytes / scan_max_deps como campos configurables.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from slopguard.core import Config, ScanReport, ScanSummary

import app.services.scan as scan_module
from app.services.scan import (
    ScanErrorCategory,
    ScanService,
    ScanServiceError,
    build_scan_service,
)
from app.settings import Settings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_report() -> ScanReport:
    """Reporte vacío (allow): el motor NUNCA debe producirlo si se superan los límites."""
    return ScanReport(
        schema_version="1.2",
        tool_version="0.0.0-test",
        ecosystem="pypi",
        summary=ScanSummary(
            total=0, allow=0, warn=0, block=0, unverifiable=0, exit_code=0
        ),
        results=(),
        error_category=None,
    )


def _service(
    *,
    max_manifest_bytes: int = 5_000_000,
    max_deps: int = 5000,
) -> ScanService:
    return ScanService(
        wrapper_timeout_s=5.0,
        max_manifest_bytes=max_manifest_bytes,
        max_deps=max_deps,
    )


# ---------------------------------------------------------------------------
# Límite de tamaño — scan_text (contenido inline)
# ---------------------------------------------------------------------------


async def test_oversized_content_raises_invalid_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Contenido que supera max_manifest_bytes → INVALID_INPUT antes de llamar al motor."""
    engine_called = {"flag": False}

    def _engine(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        engine_called["flag"] = True
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_stdin", _engine)
    service = _service(max_manifest_bytes=10)  # límite muy pequeño
    oversized = "x" * 11  # 11 bytes > 10

    with pytest.raises(ScanServiceError) as exc_info:
        await service.scan_text(oversized)

    assert exc_info.value.category is ScanErrorCategory.INVALID_INPUT
    assert not engine_called["flag"], "el motor NO debe invocarse cuando se supera el tamaño"


async def test_content_at_exact_limit_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Contenido exactamente igual al límite (= max_manifest_bytes) es aceptado."""
    engine_called = {"flag": False}

    def _engine(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        engine_called["flag"] = True
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_stdin", _engine)
    service = _service(max_manifest_bytes=5)
    exact = "x" * 5  # exactamente 5 bytes ASCII

    await service.scan_text(exact)

    assert engine_called["flag"], "contenido en el límite exacto debe llegar al motor"


async def test_oversized_content_error_message_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """El mensaje de error no filtra el contenido del manifiesto (NFR-Seg-3)."""
    monkeypatch.setattr(scan_module, "scan_stdin", lambda *a, **kw: _clean_report())
    service = _service(max_manifest_bytes=5)
    secret_content = "secret-token-abc123"  # contenido «sensible»

    with pytest.raises(ScanServiceError) as exc_info:
        await service.scan_text(secret_content)

    error_msg = str(exc_info.value)
    assert secret_content not in error_msg, "el contenido del manifiesto NO debe filtrarse al error"


# ---------------------------------------------------------------------------
# Límite de tamaño — scan_path (archivo en disco)
# ---------------------------------------------------------------------------


async def test_oversized_file_raises_invalid_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Archivo que supera max_manifest_bytes → INVALID_INPUT sin leer el contenido."""
    engine_called = {"flag": False}

    def _engine(path: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        engine_called["flag"] = True
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_manifest", _engine)
    big_file = tmp_path / "requirements.txt"
    big_file.write_bytes(b"x" * 11)  # 11 bytes

    service = _service(max_manifest_bytes=10)

    with pytest.raises(ScanServiceError) as exc_info:
        await service.scan_path(big_file)

    assert exc_info.value.category is ScanErrorCategory.INVALID_INPUT
    # el motor NO debe invocarse cuando el archivo supera el límite
    assert not engine_called["flag"]


async def test_file_within_limit_proceeds_to_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Archivo dentro del límite llega al motor normalmente."""
    engine_called = {"flag": False}

    def _engine(path: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        engine_called["flag"] = True
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_manifest", _engine)
    ok_file = tmp_path / "requirements.txt"
    ok_file.write_bytes(b"x" * 5)

    service = _service(max_manifest_bytes=10)
    await service.scan_path(ok_file)

    assert engine_called["flag"]


async def test_unreadable_file_does_not_raise_limit_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Si stat() falla (archivo no existe), no se lanza INVALID_INPUT por límite de tamaño.

    El motor informará el error al intentar leer el archivo: la validación de límites
    no debe solapar con el manejo de «archivo no encontrado».
    """
    engine_called = {"flag": False}

    def _engine(path: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        engine_called["flag"] = True
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_manifest", _engine)
    nonexistent = tmp_path / "requirements.txt"  # no se crea

    service = _service(max_manifest_bytes=10)
    # No debe levantar ScanServiceError(INVALID_INPUT) por límite; el motor verá el fallo
    await service.scan_path(nonexistent)

    assert engine_called["flag"]


# ---------------------------------------------------------------------------
# Límite de nº de dependencias — check_deps_count
# ---------------------------------------------------------------------------


def test_check_deps_count_raises_when_exceeded() -> None:
    """check_deps_count > max_deps → INVALID_INPUT."""
    service = _service(max_deps=10)

    with pytest.raises(ScanServiceError) as exc_info:
        service.check_deps_count(11)

    assert exc_info.value.category is ScanErrorCategory.INVALID_INPUT


def test_check_deps_count_passes_at_exact_limit() -> None:
    """check_deps_count == max_deps → aceptado."""
    service = _service(max_deps=10)
    service.check_deps_count(10)  # no debe lanzar


def test_check_deps_count_passes_below_limit() -> None:
    service = _service(max_deps=100)
    service.check_deps_count(50)  # no debe lanzar


def test_check_deps_count_error_message_does_not_leak_content() -> None:
    """El mensaje de error solo menciona el límite, no datos de entrada."""
    service = _service(max_deps=5)
    with pytest.raises(ScanServiceError) as exc_info:
        service.check_deps_count(6)

    msg = str(exc_info.value)
    assert "5" in msg  # menciona el límite configurado
    assert "6" not in msg  # no filtra el valor recibido


# ---------------------------------------------------------------------------
# Ecosistema: override gana sobre autodetección (R3.2)
# ---------------------------------------------------------------------------


async def test_ecosystem_override_wins_over_filename(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Override pypi sobre package.json (que autodetectaría npm) debe ganar (R3.2)."""
    captured: dict[str, str] = {}

    def _engine(path: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        captured["ecosystem"] = ecosystem_id
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_manifest", _engine)
    service = _service()
    await service.scan_path(Path("/repo/package.json"), ecosystem="pypi")

    assert captured["ecosystem"] == "pypi"


async def test_ecosystem_override_npm_wins_over_requirements_txt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Override npm sobre requirements.txt (que autodetectaría pypi) debe ganar (R3.2)."""
    captured: dict[str, str] = {}

    def _engine(path: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        captured["ecosystem"] = ecosystem_id
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_manifest", _engine)
    service = _service()
    await service.scan_path(Path("/repo/requirements.txt"), ecosystem="npm")

    assert captured["ecosystem"] == "npm"


async def test_autodetection_npm_without_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sin override, package.json autodetecta npm correctamente (R3.2)."""
    captured: dict[str, str] = {}

    def _engine(path: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        captured["ecosystem"] = ecosystem_id
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_manifest", _engine)
    service = _service()
    await service.scan_path(Path("/repo/package.json"))

    assert captured["ecosystem"] == "npm"


async def test_autodetection_pypi_without_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sin override, requirements.txt autodetecta pypi correctamente (R3.2)."""
    captured: dict[str, str] = {}

    def _engine(path: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        captured["ecosystem"] = ecosystem_id
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_manifest", _engine)
    service = _service()
    await service.scan_path(Path("/repo/requirements.txt"))

    assert captured["ecosystem"] == "pypi"


async def test_invalid_override_raises_invalid_input() -> None:
    """Override con ecosistema desconocido → INVALID_INPUT (R3.2)."""
    service = _service()

    with pytest.raises(ScanServiceError) as exc_info:
        await service.scan_text("x==1\n", ecosystem="ruby-gems")

    assert exc_info.value.category is ScanErrorCategory.INVALID_INPUT


async def test_inline_text_no_ecosystem_defaults_to_pypi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Texto inline sin ecosistema: default pypi sin lanzar error (R3.2)."""
    captured: dict[str, str] = {}

    def _engine(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        captured["ecosystem"] = ecosystem_id
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_stdin", _engine)
    service = _service()
    await service.scan_text("requests==2.0\n")

    assert captured["ecosystem"] == "pypi"


# ---------------------------------------------------------------------------
# build_scan_service acepta los límites desde Settings
# ---------------------------------------------------------------------------


def test_build_scan_service_wires_limits() -> None:
    """build_scan_service transfiere max_manifest_bytes y max_deps al ScanService."""
    service = build_scan_service(
        wrapper_timeout_s=60.0,
        anthropic_api_key=None,
        max_manifest_bytes=1024,
        max_deps=50,
    )

    assert service.max_manifest_bytes == 1024
    assert service.max_deps == 50


def test_build_scan_service_uses_defaults_when_not_specified() -> None:
    """Sin pasar límites, build_scan_service usa los defaults (5 MB / 5000 deps)."""
    service = build_scan_service(wrapper_timeout_s=60.0, anthropic_api_key=None)

    assert service.max_manifest_bytes == 5_000_000
    assert service.max_deps == 5000


# ---------------------------------------------------------------------------
# Settings expone los campos configurables (R3.3)
# ---------------------------------------------------------------------------


def test_settings_default_max_manifest_bytes() -> None:
    """Settings.scan_max_manifest_bytes tiene el mismo default que Config.max_manifest_bytes."""
    settings = Settings()
    assert settings.scan_max_manifest_bytes == 5_000_000


def test_settings_default_max_deps() -> None:
    """Settings.scan_max_deps tiene el mismo default que Config.max_deps."""
    settings = Settings()
    assert settings.scan_max_deps == 5000


def test_settings_max_manifest_bytes_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    """scan_max_manifest_bytes se puede sobreescribir por variable de entorno."""
    monkeypatch.setenv("SCAN_MAX_MANIFEST_BYTES", "1000000")
    settings = Settings()
    assert settings.scan_max_manifest_bytes == 1_000_000


def test_settings_max_deps_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    """scan_max_deps se puede sobreescribir por variable de entorno."""
    monkeypatch.setenv("SCAN_MAX_DEPS", "100")
    settings = Settings()
    assert settings.scan_max_deps == 100
