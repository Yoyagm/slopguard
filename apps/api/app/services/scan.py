"""Scan Service: frontera ÚNICA del SaaS con el motor `slopguard` (ADR-3, R7.3).

Responsabilidad acotada: invocar el motor zero-deps **in-process** por su fachada
pública (`slopguard.core`), aislando coste y duración sin romper el fail-closed. El
motor es síncrono y bloqueante (hace I/O de red por dependencia); este módulo lo
ejecuta en un threadpool (`anyio.to_thread.run_sync`) para no bloquear el event loop
de FastAPI, y lo envuelve en un **timeout de envoltura** (`asyncio.wait_for`).

INVARIANTE DE SEGURIDAD (clave, R3.5/R9.1): el timeout de envoltura es una red de
seguridad de PROCESO, NO un reemplazo del fail-closed del motor. Si salta —o si el
motor lanza algo inesperado— este servicio levanta `ScanServiceError` con una
categoría saneada; JAMÁS sintetiza un `ScanReport` "limpio". Es decir: degradado o
parcial ⇒ error explícito, nunca `allow`. UNVERIFIABLE/timeout nunca colapsan a CLEAN.

Frontera de arquitectura (ADR-5, import-linter contrato 6): este módulo importa SOLO
la fachada pública `slopguard.core`; nunca módulos internos del motor. El inverso
(`slopguard → app`) queda prohibido por contrato.

NO-FUGA (NFR-Seg-3): el contenido del manifiesto y la `ANTHROPIC_API_KEY` NUNCA se
loguean. Los mensajes de error son estables y saneados, sin contenido del manifiesto.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import anyio.to_thread
from slopguard.core import (
    Config,
    ScanReport,
    SlopGuardError,
    detect_ecosystem,
    scan_manifest,
    scan_stdin,
)

# Ecosistema por defecto cuando no hay override ni nombre de archivo del que inferir
# (entrada inline tipo pip-freeze). Coincide con el default congelado de la fachada.
_DEFAULT_ECOSYSTEM = "pypi"

# Firma común de las dos funciones de entrada de la fachada que envolvemos: ambas son
# `(str, Config, *, ecosystem_id=...) -> ScanReport`. `scan_manifest` acepta `str | Path`
# pero aquí siempre le pasamos `str`, así que el alias positional-str es exacto.
_EngineFn = Callable[..., ScanReport]


class ScanErrorCategory(StrEnum):
    """Categoría saneada del fallo del Scan Service (mapeada a HTTP por el router).

    - INVALID_INPUT → 422: ecosistema/entrada inválidos antes de escanear (no parsea
      el contenido completo). El motor nunca llegó a correr.
    - TIMEOUT → 504: el timeout de envoltura saltó (escaneo patológicamente largo).
    - ENGINE_FAILURE → 502: el motor lanzó algo inesperado (no un error del dominio).

    En NINGÚN caso se devuelve un reporte: el fallo es explícito (fail-closed).
    """

    INVALID_INPUT = "invalid_input"
    TIMEOUT = "timeout"
    ENGINE_FAILURE = "engine_failure"


class ScanServiceError(Exception):
    """Falla saneada del Scan Service: lleva su categoría estable y un mensaje apto para CI.

    NUNCA contiene el contenido del manifiesto, rutas absolutas ni secretos. El router
    la traduce a una respuesta de error saneada (R9.2); jamás a un veredicto limpio.
    """

    def __init__(self, message: str, category: ScanErrorCategory) -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True, slots=True)
class ScanService:
    """Frontera in-process con el motor. Construido con la política de proceso del SaaS.

    `wrapper_timeout_s` es el timeout de envoltura (Settings.scan_wrapper_timeout_s).
    `max_manifest_bytes` y `max_deps` controlan el rechazo temprano (H5-T17, R3.3):
    el SaaS devuelve 422 ANTES del parseo completo si se superan estos límites,
    ahorrando trabajo pesado. Los defaults coinciden con los del motor pero son
    configurables por entorno (Settings.scan_max_manifest_bytes / scan_max_deps).
    `enable_layer4` activa la Capa 4 (LLM) server-side: SOLO debe ser True si hay
    `ANTHROPIC_API_KEY` en el entorno del proceso (el motor la lee de `os.environ`); en
    caso contrario el motor degrada a `llm_assessment=null` por construcción (R7.2).
    """

    wrapper_timeout_s: float
    max_manifest_bytes: int = 5_000_000
    max_deps: int = 5000
    enable_layer4: bool = False

    async def scan_text(
        self, content: str, *, ecosystem: str | None = None
    ) -> ScanReport:
        """Escanea contenido inline (pegado/subido) tipo pip-freeze o package.json.

        Sin nombre de archivo del que inferir: si `ecosystem` es None se asume el
        ecosistema por defecto (`pypi`) en vez de fallar, ya que la entrada inline del
        dashboard es texto plano. El override explícito siempre gana (R3.2).

        Valida el tamaño del contenido ANTES del parseo completo (H5-T17, R3.3): si
        supera `max_manifest_bytes`, rechaza con INVALID_INPUT sin invocar el motor.
        """
        self._check_manifest_size(content)
        ecosystem_id = self._resolve_ecosystem(path=None, override=ecosystem)
        config = self._build_config()
        return await self._run_in_threadpool(
            scan_stdin, content, config, ecosystem_id=ecosystem_id
        )

    async def scan_path(
        self, path: Path, *, ecosystem: str | None = None
    ) -> ScanReport:
        """Escanea un manifiesto en disco (escaneo desde repo conectado).

        El ecosistema se autodetecta por el nombre del archivo salvo override (R3.2).
        Valida el tamaño del archivo ANTES del parseo completo (H5-T17, R3.3): si supera
        `max_manifest_bytes`, rechaza con INVALID_INPUT sin invocar el motor.
        """
        self._check_path_size(path)
        ecosystem_id = self._resolve_ecosystem(path=path, override=ecosystem)
        config = self._build_config()
        return await self._run_in_threadpool(
            scan_manifest, str(path), config, ecosystem_id=ecosystem_id
        )

    def _check_manifest_size(self, content: str) -> None:
        """Rechaza con INVALID_INPUT si el contenido supera `max_manifest_bytes` (R3.3).

        La comprobación es sobre bytes UTF-8 (coherente con el motor). Se hace ANTES del
        parseo completo: si el tamaño supera el límite, no se invoca el motor.
        """
        byte_size = len(content.encode("utf-8"))
        if byte_size > self.max_manifest_bytes:
            raise ScanServiceError(
                "el manifiesto supera el tamaño máximo permitido "
                f"({self.max_manifest_bytes} bytes)",
                ScanErrorCategory.INVALID_INPUT,
            )

    def _check_path_size(self, path: Path) -> None:
        """Rechaza con INVALID_INPUT si el archivo supera `max_manifest_bytes` (R3.3).

        Consulta solo el tamaño del archivo (stat) sin leer su contenido completo: la
        comprobación temprana ahorra I/O cuando el archivo es demasiado grande.
        """
        try:
            file_size = path.stat().st_size
        except OSError:
            # Si no se puede stat el archivo, dejamos que el motor informe el error.
            return
        if file_size > self.max_manifest_bytes:
            raise ScanServiceError(
                "el manifiesto supera el tamaño máximo permitido "
                f"({self.max_manifest_bytes} bytes)",
                ScanErrorCategory.INVALID_INPUT,
            )

    def check_deps_count(self, count: int) -> None:
        """Rechaza con INVALID_INPUT si el nº de dependencias supera `max_deps` (R3.3).

        Llamada por el router/Scan Service una vez que el número de deps es conocido
        (p.ej. parseando el JSON inline rápidamente) pero antes del escaneo costoso.
        Público para que el router pueda invocarla sin acceder a métodos privados.
        """
        if count > self.max_deps:
            raise ScanServiceError(
                f"el manifiesto supera el máximo de dependencias permitido ({self.max_deps})",
                ScanErrorCategory.INVALID_INPUT,
            )

    def _resolve_ecosystem(self, *, path: Path | None, override: str | None) -> str:
        """Resuelve el ecosistema (override gana → autodetección). Inválido ⇒ 422.

        `detect_ecosystem` exige un override explícito cuando no hay nombre de archivo
        (stdin-guard). Para la entrada inline degradamos ese caso al ecosistema por
        defecto en vez de propagar el error, de modo que el dashboard pueda pegar texto
        sin elegir ecosistema. Cualquier override/ nombre realmente inválido sí aborta.
        """
        if path is None and override is None:
            return _DEFAULT_ECOSYSTEM
        try:
            return detect_ecosystem(path, override)
        except SlopGuardError as exc:
            # Entrada inválida (override desconocido o nombre no reconocido): saneamos sin
            # parsear el contenido. No se incluye el mensaje crudo del motor.
            raise ScanServiceError(
                "ecosistema o manifiesto no soportado",
                ScanErrorCategory.INVALID_INPUT,
            ) from exc

    def _build_config(self) -> Config:
        """Construye el `Config` del motor. Capa 4 off salvo flag server-side (R7.2).

        El resto de defaults (límites, timeouts por-dep, capas 0-3) se preservan tal
        cual los congela el motor: el SaaS no reimplementa la política del core.
        """
        try:
            return Config(enable_layer4=self.enable_layer4)
        except SlopGuardError as exc:
            # Un Config fuera de dominio es un fallo de configuración del servicio, no del
            # input del usuario: lo tratamos como fallo del motor (502), no como 422.
            raise ScanServiceError(
                "configuración del motor inválida",
                ScanErrorCategory.ENGINE_FAILURE,
            ) from exc

    async def _run_in_threadpool(
        self,
        engine_fn: _EngineFn,
        content_or_path: str,
        config: Config,
        *,
        ecosystem_id: str,
    ) -> ScanReport:
        """Ejecuta una función del motor en un thread con timeout de envoltura fail-closed.

        El motor es síncrono; `anyio.to_thread.run_sync` lo saca del event loop. El
        `asyncio.wait_for` acota la duración total: si vence, levantamos `TIMEOUT` —NUNCA
        un reporte sintético—. Cualquier excepción NO prevista del motor (el dominio ya
        devuelve `error_category` dentro del reporte, sin lanzar) se sanea a
        `ENGINE_FAILURE`. En todos los caminos de fallo: error explícito, jamás `allow`.
        """
        runner = _make_runner(engine_fn, content_or_path, config, ecosystem_id)
        try:
            return await asyncio.wait_for(
                anyio.to_thread.run_sync(runner), timeout=self.wrapper_timeout_s
            )
        except TimeoutError as exc:
            # El hilo del motor puede seguir vivo (los threads no se cancelan); es aceptable
            # como red de seguridad: el escaneo no produce veredicto, solo error explícito.
            raise ScanServiceError(
                "el escaneo excedió el tiempo máximo permitido",
                ScanErrorCategory.TIMEOUT,
            ) from exc
        except SlopGuardError as exc:
            # Defensa en profundidad: la fachada captura sus errores operacionales y los
            # convierte en reporte, así que esto no debería ocurrir. Si ocurriera, jamás
            # se degrada a limpio: se sanea a fallo del motor.
            raise ScanServiceError(
                "el motor de escaneo falló", ScanErrorCategory.ENGINE_FAILURE
            ) from exc
        except Exception as exc:
            # Cualquier fallo inesperado (bug, recurso agotado) ⇒ error saneado, NUNCA un
            # reporte limpio. El mensaje no expone el detalle crudo (puede traer rutas/PII).
            raise ScanServiceError(
                "el motor de escaneo falló de forma inesperada",
                ScanErrorCategory.ENGINE_FAILURE,
            ) from exc


def _make_runner(
    engine_fn: _EngineFn,
    content_or_path: str,
    config: Config,
    ecosystem_id: str,
) -> Callable[[], ScanReport]:
    """Empaqueta la llamada síncrona al motor en un thunk sin argumentos para el threadpool.

    `engine_fn` es `scan_stdin` o `scan_manifest`; ambos comparten la firma
    `(str, Config, *, ecosystem_id=...) -> ScanReport`. El thunk no captura más estado
    que el necesario: el threadpool no ve ni Settings ni secretos.
    """

    def _call() -> ScanReport:
        return engine_fn(content_or_path, config, ecosystem_id=ecosystem_id)

    return _call


def build_scan_service(
    *,
    wrapper_timeout_s: float,
    anthropic_api_key: str | None,
    max_manifest_bytes: int = 5_000_000,
    max_deps: int = 5000,
) -> ScanService:
    """Construye el `ScanService` desde la política del proceso (Settings).

    La Capa 4 (LLM) se habilita SOLO si hay clave Anthropic configurada (R7.2). El motor
    además exige `ANTHROPIC_API_KEY` en `os.environ` para evaluar; si la clave está en
    Settings pero no en el entorno, el motor degrada a `llm_assessment=null` (seguro). No
    mutamos `os.environ` desde aquí: la clave la inyecta el despliegue (12-factor).

    `max_manifest_bytes` y `max_deps` provienen de `Settings.scan_max_manifest_bytes` /
    `Settings.scan_max_deps` (H5-T17, R3.3): el SaaS rechaza con 422 antes del parseo
    completo cuando se superan estos límites.
    """
    return ScanService(
        wrapper_timeout_s=wrapper_timeout_s,
        max_manifest_bytes=max_manifest_bytes,
        max_deps=max_deps,
        enable_layer4=anthropic_api_key is not None,
    )
