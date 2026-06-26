"""Tests adversariales del Scan Service (H5-T18, R3.3/R3.4/R7.3).

Estos tests son la red de seguridad del INVARIANTE más importante del SaaS: el motor
es fail-closed y el SaaS nunca debe romperlo. Mentalidad adversarial (skill
`adversarial-reviewer`, persona Saboteur): se intenta *forzar* al servicio a emitir un
veredicto limpio (`allow`/CLEAN) cuando no debería, y se verifica que NUNCA lo hace.

Cobertura por criterio de aceptación de H5-T18:

  AC-1  Timeout de envoltura ⇒ error saneado fail-closed; un test FUERZA el timeout
        (motor que bloquea indefinidamente) y verifica que NO hay veredicto limpio.
  AC-2  Un ScanReport UNVERIFIABLE/parcial NUNCA se mapea a CLEAN/allow.
  AC-3  Excepción del motor ⇒ error saneado, sin filtrar stacktrace/secretos.
  AC-4  DTO fiel: ScanReport → ScanDTO 1:1 (ecosystem, exit_code, señales por capa).
  AC-5  Límites excedidos ⇒ INVALID_INPUT (el router lo traduce a 422).
  AC-6  Override de ecosistema gana sobre la autodetección.

Hermeticidad (R7.3, sin red ni servicios): el motor real se reemplaza por dobles
síncronos vía monkeypatch sobre el namespace del módulo `app.services.scan`. El
bloqueo del timeout se modela con un `threading.Event` que JAMÁS se libera —
determinista en cualquier máquina, sin depender de `sleep` ni del reloj de pared.
"""

from __future__ import annotations

import datetime
import threading
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from slopguard.core import (
    Config,
    DependencyResult,
    ErrorCategory,
    Layer,
    LayerSignal,
    ScanReport,
    ScanSummary,
    SignalCode,
    Status,
    Verdict,
)

import app.services.scan as scan_module
from app.schemas.scan import ScanDTO
from app.services.scan import (
    ScanErrorCategory,
    ScanService,
    ScanServiceError,
)
from app.services.scan_mapper import scan_report_to_dto

# ---------------------------------------------------------------------------
# Constructores de dobles del motor (objetos reales del core, zero-deps)
# ---------------------------------------------------------------------------

_SCAN_ID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
_NOW = datetime.datetime(2026, 6, 25, 9, 0, 0, tzinfo=datetime.UTC)


def _clean_allow_report() -> ScanReport:
    """Reporte 100% limpio (allow): el veredicto que el fail-closed JAMÁS debe sintetizar.

    Es la «trampa» de los tests adversariales: el motor doble lo devolvería si llegara a
    completarse, así que si el servicio lo deja escapar tras un timeout/fallo, lo cazamos.
    """
    return ScanReport(
        schema_version="1.2",
        tool_version="0.0.0-test",
        ecosystem="pypi",
        summary=ScanSummary(
            total=1, allow=1, warn=0, block=0, unverifiable=0, exit_code=0
        ),
        results=(
            DependencyResult(
                name="requests",
                version_pin="2.31.0",
                status=Status.OK,
                verdict=Verdict.ALLOW,
                score=5,
                signals=(),
                suspected_target=None,
                error_category=None,
            ),
        ),
        error_category=None,
    )


def _partial_unverifiable_report() -> ScanReport:
    """Reporte parcial: una dep verificada (allow) y otra NO verificable (red caída).

    El motor degrada a UNVERIFIABLE sin score ni veredicto (R9.1). El SaaS debe portar
    ese estado tal cual; jamás debe colapsar la dep no verificable a `allow`.
    """
    unverifiable = DependencyResult(
        name="ghost-pkg",
        version_pin=None,
        status=Status.UNVERIFIABLE,
        verdict=None,  # invariante: unverifiable nunca trae veredicto
        score=None,  # ni score
        signals=(),
        suspected_target=None,
        error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
    )
    return ScanReport(
        schema_version="1.2",
        tool_version="0.0.0-test",
        ecosystem="pypi",
        # exit_code != 0 porque el lote no es plenamente verificable.
        summary=ScanSummary(
            total=1, allow=0, warn=0, block=0, unverifiable=1, exit_code=3
        ),
        results=(unverifiable,),
        error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
    )


def _full_signal_report() -> ScanReport:
    """Reporte rico para el test de fidelidad del DTO (AC-4): señales en 2 capas, npm.

    Incluye un veredicto block-override (score None) y señales L0/L1 para verificar que
    el mapeo preserva `ecosystem`, `exit_code` del summary y las señales por capa.
    """
    l0_signal = LayerSignal(
        layer=Layer.L0,
        code=SignalCode.NEW_PACKAGE,
        weight=5,
        is_soft=True,
        is_llm_channel=False,
        detail="paquete reciente",
        suspected_target=None,
    )
    l1_signal = LayerSignal(
        layer=Layer.L1,
        code=SignalCode.TYPOSQUAT,
        weight=50,
        is_soft=False,
        is_llm_channel=False,
        detail="similar a lodash",
        suspected_target="lodash",
    )
    blocked = DependencyResult(
        name="l0dash",
        version_pin=None,
        status=Status.OK,
        verdict=Verdict.BLOCK,
        score=None,  # block-override: sin score numérico
        signals=(l0_signal, l1_signal),
        suspected_target="lodash",
        error_category=None,
    )
    return ScanReport(
        schema_version="1.2",
        tool_version="0.9.0",
        ecosystem="npm",
        summary=ScanSummary(
            total=1, allow=0, warn=0, block=1, unverifiable=0, exit_code=2
        ),
        results=(blocked,),
        error_category=None,
    )


def _engine_returning(report: ScanReport) -> Callable[..., ScanReport]:
    """Doble síncrono del motor que ignora los argumentos y devuelve `report`."""

    def _engine(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        return report

    return _engine


@pytest.fixture
def blocking_engine() -> Iterator[threading.Event]:
    """Doble del motor que se bloquea hasta que `release` se libere (o nunca).

    Sustituye `scan_stdin` por una función que espera sobre un `Event` que el test NO
    libera: el thread del motor queda colgado de forma determinista y el ÚNICO camino de
    salida es el timeout de envoltura. El `finally` libera el evento al terminar el test
    para que el thread del threadpool no quede colgado entre tests.

    Yields el `Event` por si un test quisiera, excepcionalmente, desbloquear el motor.
    """
    release = threading.Event()

    def _hang(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        # Bloqueo determinista: no depende de `sleep` ni del reloj. Si el timeout NO
        # saltara, el `wait` colgaría el test (fallo visible), nunca un falso verde.
        release.wait()
        # Si alguna vez se libera, devolvería un allow limpio: la «trampa» del fail-closed.
        return _clean_allow_report()

    monkeypatch_target = "scan_stdin"
    original = getattr(scan_module, monkeypatch_target)
    setattr(scan_module, monkeypatch_target, _hang)
    try:
        yield release
    finally:
        release.set()  # desbloquea el thread colgado del threadpool
        setattr(scan_module, monkeypatch_target, original)


# ===========================================================================
# AC-1: el timeout de envoltura JAMÁS produce un veredicto limpio (test estrella)
# ===========================================================================


async def test_forced_timeout_raises_timeout_never_a_report(
    blocking_engine: threading.Event,
) -> None:
    """AC-1: con el motor BLOQUEADO, el timeout salta y NO se devuelve ScanReport.

    Este es el test estrella (mentalidad Saboteur): el motor devolvería un `allow` limpio
    si llegara a completarse, pero está colgado. El servicio DEBE levantar TIMEOUT y
    nunca colarse al camino de retorno. Capturamos el posible retorno para probar que es
    inalcanzable.
    """
    service = ScanService(wrapper_timeout_s=0.05)

    report: ScanReport | None = None
    with pytest.raises(ScanServiceError) as excinfo:
        report = await service.scan_text("requests==2.31.0\n")

    assert report is None, "el timeout NUNCA debe producir un ScanReport"
    assert excinfo.value.category is ScanErrorCategory.TIMEOUT


async def test_forced_timeout_message_does_not_leak_allow(
    blocking_engine: threading.Event,
) -> None:
    """AC-1: el error de timeout no filtra ningún rastro de veredicto limpio.

    La aguja: ni "allow" ni "clean" ni "ok" deben aparecer en el mensaje saneado, para
    que ningún consumidor (CI, dashboard) interprete el timeout como un visto bueno.
    """
    service = ScanService(wrapper_timeout_s=0.05)

    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_text("requests==2.31.0\n")

    message = str(excinfo.value).lower()
    assert "allow" not in message
    assert "clean" not in message


async def test_timeout_category_maps_to_no_success_exit(
    blocking_engine: threading.Event,
) -> None:
    """AC-1: la categoría de timeout es TIMEOUT (504), nunca una categoría 'de éxito'.

    Defensa adicional: el contrato de error expone una categoría estable y discreta; un
    timeout no puede confundirse con INVALID_INPUT (que el cliente podría reintentar como
    si su entrada fuese el problema) ni desaparecer.
    """
    service = ScanService(wrapper_timeout_s=0.05)

    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_text("x==1\n")

    # Un timeout es TIMEOUT, no INVALID_INPUT: el cliente no debe creer que su entrada es
    # el problema (lo reintentaría en vano). Comparamos contra el valor crudo del enum
    # para que el chequeo no sea trivialmente cierto por estrechamiento de tipos.
    assert excinfo.value.category is ScanErrorCategory.TIMEOUT
    assert excinfo.value.category.value != ScanErrorCategory.INVALID_INPUT.value


# ===========================================================================
# AC-2: UNVERIFIABLE / parcial NUNCA colapsa a CLEAN/allow
# ===========================================================================


async def test_partial_unverifiable_report_is_not_rewritten(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-2: el servicio porta el reporte parcial TAL CUAL; no lo «limpia».

    El motor ya devuelve UNVERIFIABLE sin veredicto; el servicio no debe inventar un
    `allow`. Verificamos que el objeto devuelto es exactamente el del motor.
    """
    partial = _partial_unverifiable_report()
    monkeypatch.setattr(scan_module, "scan_stdin", _engine_returning(partial))

    service = ScanService(wrapper_timeout_s=5.0)
    report = await service.scan_text("ghost-pkg\n")

    assert report is partial
    assert report.summary.allow == 0
    assert report.results[0].status is Status.UNVERIFIABLE
    assert report.results[0].verdict is None  # jamás allow


def test_unverifiable_report_maps_to_dto_without_allow() -> None:
    """AC-2: ScanReport UNVERIFIABLE → ScanDTO mantiene status/veredicto degradados.

    Cruza la frontera del DTO (lo que viaja al cliente): un parcial debe seguir siendo
    visiblemente unverifiable, con `verdict=None` y `score=None`. Nunca `allow`.
    """
    dto: ScanDTO = scan_report_to_dto(
        _partial_unverifiable_report(),
        scan_id=_SCAN_ID,
        origin="on_demand",
        created_at=_NOW,
    )

    assert dto.summary.allow == 0
    result = dto.results[0]
    assert result.status == "unverifiable"
    assert result.verdict is None
    assert result.score is None
    assert result.error_category == "network_unverifiable"
    # Aguja: ninguna dep del DTO quedó marcada como allow.
    assert all(r.verdict != "allow" for r in dto.results)


def test_unverifiable_report_dto_error_category_preserved() -> None:
    """AC-2: el `error_category` global del reporte parcial sobrevive al mapeo.

    Es la señal de que el escaneo NO fue totalmente verificable; perderla equivaldría a
    presentar un falso «todo bien».
    """
    dto = scan_report_to_dto(
        _partial_unverifiable_report(),
        scan_id=_SCAN_ID,
        origin="on_demand",
        created_at=_NOW,
    )

    assert dto.error_category == "network_unverifiable"
    assert dto.summary.exit_code != 0  # un parcial nunca sale con éxito (0)


# ===========================================================================
# AC-3: excepción del motor ⇒ error saneado, sin filtrar stacktrace/secretos
# ===========================================================================


async def test_engine_exception_is_sanitized_no_secret_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-3: una excepción cruda del motor no filtra su detalle (ruta/PII/secreto).

    El doble lanza un RuntimeError cuyo texto contiene un «secreto» sintético; el mensaje
    saneado del ScanServiceError NO debe contenerlo, y la categoría es ENGINE_FAILURE.
    """
    secret = "ANTHROPIC_API_KEY=sk-ant-LEAK-0xDEADBEEF /home/runner/manifest.txt"

    def _boom(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        raise RuntimeError(secret)

    monkeypatch.setattr(scan_module, "scan_stdin", _boom)

    service = ScanService(wrapper_timeout_s=5.0)
    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_text("requests==2.0\n")

    assert excinfo.value.category is ScanErrorCategory.ENGINE_FAILURE
    message = str(excinfo.value)
    assert secret not in message
    assert "sk-ant-LEAK" not in message
    assert "/home/runner" not in message


async def test_engine_exception_chains_cause_for_internal_debug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-3: el detalle crudo NO se pierde para el log interno, pero NO está en el mensaje.

    El servicio encadena la causa (`raise ... from exc`): el stacktrace queda disponible
    para el observabilidad server-side, mientras el `str()` saneado viaja al cliente. Esto
    evita el anti-patrón de tragar la excepción (except vacío) sin filtrar el secreto.
    """
    secret = "secret-token-internal"

    def _boom(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        raise ValueError(secret)

    monkeypatch.setattr(scan_module, "scan_stdin", _boom)

    service = ScanService(wrapper_timeout_s=5.0)
    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_text("x==1\n")

    # La causa encadenada conserva el detalle para debug interno...
    assert isinstance(excinfo.value.__cause__, ValueError)
    # ...pero el mensaje saneado expuesto al cliente no lo filtra.
    assert secret not in str(excinfo.value)


async def test_engine_exception_never_returns_clean_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-3 + AC-1 (fail-closed): una excepción del motor NUNCA degrada a un allow.

    Cruce de criterios (promovido por adversarial-reviewer): el camino de fallo del motor
    no debe sintetizar un reporte. Capturamos el posible retorno para probar que es
    inalcanzable, igual que en el timeout.
    """

    def _boom(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(scan_module, "scan_stdin", _boom)

    service = ScanService(wrapper_timeout_s=5.0)
    report: ScanReport | None = None
    with pytest.raises(ScanServiceError):
        report = await service.scan_text("x==1\n")

    assert report is None


# ===========================================================================
# AC-4: DTO fiel — mapeo 1:1 (ecosystem, exit_code de ScanSummary, señales por capa)
# ===========================================================================


def test_dto_preserves_ecosystem_and_exit_code() -> None:
    """AC-4: `ecosystem` y `summary.exit_code` se mapean 1:1 desde el ScanReport."""
    dto = scan_report_to_dto(
        _full_signal_report(),
        scan_id=_SCAN_ID,
        origin="on_demand",
        created_at=_NOW,
    )

    assert dto.ecosystem == "npm"
    assert dto.summary.exit_code == 2
    assert dto.summary.block == 1
    assert dto.tool_version == "0.9.0"


def test_dto_preserves_per_layer_signals() -> None:
    """AC-4: las señales por capa se mapean fielmente (layer como int, code estable)."""
    dto = scan_report_to_dto(
        _full_signal_report(),
        scan_id=_SCAN_ID,
        origin="on_demand",
        created_at=_NOW,
    )

    signals = dto.results[0].signals
    assert len(signals) == 2

    by_layer = {s.layer: s for s in signals}
    assert by_layer[0].code == "new_package"  # Layer.L0.value == 0
    assert by_layer[0].is_soft is True
    assert by_layer[1].code == "typosquat"  # Layer.L1.value == 1
    assert by_layer[1].is_soft is False
    assert by_layer[1].suspected_target == "lodash"


def test_dto_block_override_keeps_null_score() -> None:
    """AC-4: un block-override conserva `score=None` y `verdict='block'` en el DTO."""
    dto = scan_report_to_dto(
        _full_signal_report(),
        scan_id=_SCAN_ID,
        origin="on_demand",
        created_at=_NOW,
    )

    result = dto.results[0]
    assert result.verdict == "block"
    assert result.score is None
    assert result.status == "ok"


async def test_service_to_dto_is_faithful(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-4: la cadena servicio → DTO preserva ecosystem, exit_code y señales por capa."""
    source = _full_signal_report()
    monkeypatch.setattr(scan_module, "scan_manifest", _engine_returning(source))

    service = ScanService(wrapper_timeout_s=5.0)
    report = await service.scan_path(Path("/repo/package.json"))
    dto = scan_report_to_dto(
        report, scan_id=_SCAN_ID, origin="pull_request", created_at=_NOW
    )

    assert dto.ecosystem == source.ecosystem
    assert dto.summary.exit_code == source.summary.exit_code
    assert len(dto.results[0].signals) == len(source.results[0].signals)
    assert dto.origin == "pull_request"


# ===========================================================================
# AC-5: límites excedidos ⇒ INVALID_INPUT (router → 422), sin invocar el motor
# ===========================================================================


async def test_oversized_inline_content_rejected_before_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-5: contenido > max_manifest_bytes ⇒ INVALID_INPUT y el motor NO se invoca."""
    engine_invoked = {"flag": False}

    def _engine(content: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        engine_invoked["flag"] = True
        return _clean_allow_report()

    monkeypatch.setattr(scan_module, "scan_stdin", _engine)
    service = ScanService(wrapper_timeout_s=5.0, max_manifest_bytes=8)

    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_text("x" * 9)  # 9 bytes > 8

    assert excinfo.value.category is ScanErrorCategory.INVALID_INPUT
    assert engine_invoked["flag"] is False


def test_deps_count_over_limit_is_invalid_input() -> None:
    """AC-5: nº de dependencias > max_deps ⇒ INVALID_INPUT (router → 422)."""
    service = ScanService(wrapper_timeout_s=5.0, max_deps=3)

    with pytest.raises(ScanServiceError) as excinfo:
        service.check_deps_count(4)

    assert excinfo.value.category is ScanErrorCategory.INVALID_INPUT


def test_deps_count_at_limit_is_accepted() -> None:
    """AC-5 (frontera): exactamente max_deps NO se rechaza (límite inclusivo)."""
    service = ScanService(wrapper_timeout_s=5.0, max_deps=3)
    service.check_deps_count(3)  # no debe lanzar


async def test_oversized_file_rejected_before_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-5: archivo > max_manifest_bytes ⇒ INVALID_INPUT sin leer su contenido."""
    engine_invoked = {"flag": False}

    def _engine(path: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        engine_invoked["flag"] = True
        return _clean_allow_report()

    monkeypatch.setattr(scan_module, "scan_manifest", _engine)
    big = tmp_path / "requirements.txt"
    big.write_bytes(b"x" * 20)
    service = ScanService(wrapper_timeout_s=5.0, max_manifest_bytes=10)

    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_path(big)

    assert excinfo.value.category is ScanErrorCategory.INVALID_INPUT
    assert engine_invoked["flag"] is False


# ===========================================================================
# AC-6: override de ecosistema gana sobre la autodetección
# ===========================================================================


async def test_ecosystem_override_beats_filename_autodetection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-6: package.json autodetectaría npm, pero override='pypi' debe ganar (R3.2)."""
    captured: dict[str, str] = {}

    def _engine(path: str, config: Config, *, ecosystem_id: str) -> ScanReport:
        captured["ecosystem"] = ecosystem_id
        return _clean_allow_report()

    monkeypatch.setattr(scan_module, "scan_manifest", _engine)
    service = ScanService(wrapper_timeout_s=5.0)

    await service.scan_path(Path("/repo/package.json"), ecosystem="pypi")

    assert captured["ecosystem"] == "pypi"


async def test_invalid_ecosystem_override_is_invalid_input() -> None:
    """AC-6 (borde): un override de ecosistema desconocido ⇒ INVALID_INPUT, sin escanear."""
    service = ScanService(wrapper_timeout_s=5.0)

    with pytest.raises(ScanServiceError) as excinfo:
        await service.scan_text("x==1\n", ecosystem="cargo")

    assert excinfo.value.category is ScanErrorCategory.INVALID_INPUT
