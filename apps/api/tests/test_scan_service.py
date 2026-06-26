"""Tests del Scan Service (H5-T15, ADR-3): frontera in-process fail-closed.

Foco en la INVARIANTE de seguridad (R3.5/R9.1): timeout de envoltura y fallos
inesperados del motor NUNCA producen un reporte "limpio"; siempre un `ScanServiceError`
con categoría saneada. UNVERIFIABLE/parcial jamás colapsa a CLEAN/`allow`.

El motor real se reemplaza por dobles (monkeypatch sobre el namespace del módulo) para
ejercitar timeouts y excepciones de forma determinista, sin red ni archivos reales.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import pytest
from slopguard.core import (
    Config,
    InvalidConfigError,
    ScanReport,
    ScanSummary,
)

import app.services.scan as scan_module
from app.services.scan import (
    ScanErrorCategory,
    ScanService,
    ScanServiceError,
    build_scan_service,
)


def _clean_report() -> ScanReport:
    """Un reporte sin hallazgos (allow): el resultado que el fail-closed JAMÁS debe sintetizar."""
    summary = ScanSummary(
        total=1, allow=1, warn=0, block=0, unverifiable=0, exit_code=0
    )
    return ScanReport(
        schema_version="1.2",
        tool_version="0.0.0-test",
        ecosystem="pypi",
        summary=summary,
        results=(),
        error_category=None,
    )


def _fake_engine_returning(
    report: ScanReport,
) -> Callable[..., ScanReport]:
    """Crea un doble síncrono del motor que ignora los argumentos y devuelve `report`."""

    def _engine(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        return report

    return _engine


# --- Happy path: el servicio devuelve el reporte del motor tal cual --------------------


async def test_scan_text_returns_engine_report(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = _clean_report()
    monkeypatch.setattr(scan_module, "scan_stdin", _fake_engine_returning(expected))

    service = ScanService(wrapper_timeout_s=5.0)
    report = await service.scan_text("requests==2.0\n")

    assert report is expected


async def test_scan_path_autodetects_ecosystem(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str] = {}

    def _engine(path: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        captured["ecosystem"] = ecosystem_id
        captured["path"] = path
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_manifest", _engine)

    service = ScanService(wrapper_timeout_s=5.0)
    await service.scan_path(Path("/repo/package.json"))

    assert captured["ecosystem"] == "npm"  # autodetectado por el nombre de archivo
    assert captured["path"] == "/repo/package.json"


async def test_override_wins_over_autodetection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, str] = {}

    def _engine(path: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        captured["ecosystem"] = ecosystem_id
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_manifest", _engine)

    service = ScanService(wrapper_timeout_s=5.0)
    # package.json autodetectaría npm, pero el override pypi debe ganar (R3.2).
    await service.scan_path(Path("/repo/package.json"), ecosystem="pypi")

    assert captured["ecosystem"] == "pypi"


# --- Fail-closed: TIMEOUT nunca produce un reporte limpio (núcleo de la tarea) ----------


async def test_timeout_raises_error_never_clean_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _slow_engine(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        # Supera el timeout de envoltura; jamás debe traducirse a un veredicto.
        time.sleep(0.3)
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_stdin", _slow_engine)

    service = ScanService(wrapper_timeout_s=0.05)
    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_text("requests==2.0\n")

    assert excinfo.value.category is ScanErrorCategory.TIMEOUT
    # La aguja: el reporte limpio NO se filtró como mensaje ni como resultado.
    assert "allow" not in str(excinfo.value).lower()


async def test_timeout_does_not_return_a_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifica que el camino de timeout NO tiene retorno: solo levanta excepción."""

    def _hang(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        time.sleep(0.3)
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_stdin", _hang)
    service = ScanService(wrapper_timeout_s=0.05)

    result: ScanReport | None = None
    try:
        result = await service.scan_text("x==1\n")
    except ScanServiceError:
        pass
    assert result is None  # nunca llegó a producir un ScanReport


# --- Fail-closed: excepción inesperada del motor → ENGINE_FAILURE, nunca CLEAN ---------


async def test_unexpected_engine_exception_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_detail = "/abs/path/with/PII/and/manifest/content"

    def _boom(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        raise RuntimeError(secret_detail)

    monkeypatch.setattr(scan_module, "scan_stdin", _boom)

    service = ScanService(wrapper_timeout_s=5.0)
    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_text("requests==2.0\n")

    assert excinfo.value.category is ScanErrorCategory.ENGINE_FAILURE
    # El detalle crudo (posible PII/ruta) no se filtra al mensaje saneado.
    assert secret_detail not in str(excinfo.value)


async def test_domain_error_from_facade_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defensa en profundidad: si la fachada lanzara un SlopGuardError, no degrada a CLEAN."""

    def _domain_error(
        content: str, config: Config, *, ecosystem_id: str
    ) -> ScanReport:
        raise InvalidConfigError("config rota dentro del motor")

    monkeypatch.setattr(scan_module, "scan_stdin", _domain_error)

    service = ScanService(wrapper_timeout_s=5.0)
    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_text("x==1\n")

    assert excinfo.value.category is ScanErrorCategory.ENGINE_FAILURE


# --- Validación de entrada: ecosistema inválido → INVALID_INPUT (422), sin escanear ----


async def test_invalid_override_is_invalid_input() -> None:
    service = ScanService(wrapper_timeout_s=5.0)
    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_text("x==1\n", ecosystem="ruby-gems")

    assert excinfo.value.category is ScanErrorCategory.INVALID_INPUT


async def test_unrecognized_manifest_name_is_invalid_input() -> None:
    service = ScanService(wrapper_timeout_s=5.0)
    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_path(Path("/repo/Gemfile.lock"))

    assert excinfo.value.category is ScanErrorCategory.INVALID_INPUT


async def test_inline_text_without_ecosystem_defaults_to_pypi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, str] = {}

    def _engine(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        captured["ecosystem"] = ecosystem_id
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_stdin", _engine)
    service = ScanService(wrapper_timeout_s=5.0)
    await service.scan_text("requests==2.0\n")  # sin ecosystem ni filename

    assert captured["ecosystem"] == "pypi"


# --- Construcción del Config: Capa 4 off salvo flag server-side (R7.2) ------------------


async def test_layer4_disabled_when_no_anthropic_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, bool] = {}

    def _engine(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        captured["enable_layer4"] = config.enable_layer4
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_stdin", _engine)
    service = build_scan_service(wrapper_timeout_s=5.0, anthropic_api_key=None)
    await service.scan_text("x==1\n")

    assert captured["enable_layer4"] is False


async def test_layer4_enabled_when_anthropic_key_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, bool] = {}

    def _engine(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        captured["enable_layer4"] = config.enable_layer4
        return _clean_report()

    monkeypatch.setattr(scan_module, "scan_stdin", _engine)
    service = build_scan_service(
        wrapper_timeout_s=5.0, anthropic_api_key="sk-ant-test"
    )
    await service.scan_text("x==1\n")

    assert captured["enable_layer4"] is True
