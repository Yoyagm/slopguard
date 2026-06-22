"""Orquestacion de fetch concurrente con presupuesto de timeout por dependencia.

Implementa T22 (alto riesgo) sobre el contrato `EcosystemAdapter` (ADR-03):

- **Concurrencia**: `ThreadPoolExecutor(max_workers=concurrencia_max)` despacha un
  trabajo por nombre UNICO. Los nombres se normalizan y deduplican ANTES de despachar,
  de modo que el mismo paquete NUNCA se consulta dos veces por corrida (R9.4 / NFR-Rend.2).
- **Reintentos**: SOLO los fallos transitorios (timeout, conexion caida/reset, 5xx) se
  reintentan, con backoff exponencial base 0.5s, hasta `reintentos_red` veces y acotado
  por `timeout_total_por_dep_s`. Al agotar el presupuesto o los reintentos => UNVERIFIABLE,
  nunca `allow` (R2.5, NFR-Degr.1). 404 => NOT_FOUND (no se reintenta); 4xx != 404 =>
  UNVERIFIABLE (no se reintenta como transitorio).
- **Presupuesto**: `timeout_total_por_dep_s` acota la SECUENCIA de intentos+esperas, no la
  duracion interna de un `fetch_attempt` ya iniciado. El deadline se evalua al inicio del
  loop y antes de cada backoff; ademas no se inicia un nuevo intento si el margen restante
  es menor a un intento minimo (`connect_timeout_s+read_timeout_s` aproximado por el peor
  caso de socket). Limite DURO por dependencia = deadline + a lo sumo un round-trip ya en
  vuelo: un unico `fetch_attempt` puede consumir hasta `connect_timeout_s+read_timeout_s`
  (~15s con los defaults) acotado por el timeout de socket del cliente HTTP. Es un limite
  blando-superior, no un corte instantaneo a mitad de un round-trip; la cota dura real la
  impone el timeout de socket de `SecureHttpClient`.

Frontera de arquitectura (R10.1): este modulo vive en `core.adapters` (no en `core.layers`
ni `core.scoring`), por lo que SI puede coordinar el adapter. Las capas/scoring siguen sin
importar red ni adapter concreto: reciben los `FetchOutcome` ya resueltos como entrada.

Distincion transitorio/permanente sin romper la frontera: `EcosystemAdapter.fetch` colapsa
toda anomalia a `FetchOutcome(UNVERIFIABLE)` sin revelar la causa, asi que no es reintentable
de forma segura. Un adapter que quiera reintentos transitorios implementa el protocolo
opcional `RetryableAdapter.fetch_attempt`, que ademas del `FetchOutcome` reporta si el fallo
fue transitorio. Si el adapter no lo implementa, `fetch_many` cae a `fetch()` y NO reintenta
(degradacion segura: marca `unverifiable`, jamas `allow`).
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ..errors import DatasetIntegrityError, InvalidConfigError
from .base import FetchOutcome, FetchState

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..config import Config
    from .base import EcosystemAdapter

# Base del backoff exponencial en segundos (R2.5: base 0.5s).
_BACKOFF_BASE_S: float = 0.5

# Outcome canonico de degradacion segura cuando se agota el presupuesto/reintentos.
_UNVERIFIABLE: FetchOutcome = FetchOutcome(state=FetchState.UNVERIFIABLE)


@dataclass(frozen=True, slots=True)
class FetchAttempt:
    """Resultado de UN intento de fetch, con la senal de transitoriedad.

    `is_transient=True` indica un fallo reintentable (timeout, conexion caida, 5xx);
    cualquier otro caso (FOUND, NOT_FOUND, 4xx!=404, anomalia permanente) es definitivo.
    """

    outcome: FetchOutcome
    is_transient: bool


@runtime_checkable
class RetryableAdapter(Protocol):
    """Adapter que distingue fallos transitorios para habilitar reintentos seguros.

    Es un superset OPCIONAL de `EcosystemAdapter`: si un adapter lo implementa,
    `fetch_many` reintenta solo sus fallos transitorios; si no, usa `fetch()` sin
    reintentar (degradacion segura). No rompe la frontera R10.1: vive en el adapter.
    """

    def fetch_attempt(self, name: str) -> FetchAttempt:
        """Un intento de fetch que reporta ademas si el fallo fue transitorio."""
        ...


def fetch_many(
    adapter: EcosystemAdapter,
    names: Iterable[str],
    config: Config,
) -> dict[str, FetchOutcome]:
    """Resuelve concurrentemente el `FetchOutcome` de cada nombre, deduplicado.

    Normaliza y deduplica los nombres antes de despachar (un trabajo por paquete unico,
    R9.4/NFR-Rend.2), los evalua en paralelo con `concurrencia_max` workers y aplica el
    presupuesto de timeout + reintentos con backoff por dependencia (R2.5). El dict
    resultante se indexa por nombre NORMALIZADO; cada valor es FOUND/NOT_FOUND/UNVERIFIABLE,
    nunca `allow` (la decision de veredicto vive aguas abajo en el scoring).
    """
    unique_names = _dedup_normalized(adapter, names)
    if not unique_names:
        return {}
    workers = max(1, min(config.concurrencia_max, len(unique_names)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = pool.map(lambda name: _fetch_with_budget(adapter, name, config), unique_names)
        return dict(zip(unique_names, outcomes, strict=True))


def _dedup_normalized(adapter: EcosystemAdapter, names: Iterable[str]) -> tuple[str, ...]:
    """Normaliza cada nombre y deduplica preservando el primer orden de aparicion.

    La dedup ocurre ANTES de despachar a la pool: garantiza que el mismo paquete no se
    consulta dos veces por corrida (R9.4/NFR-Rend.2). El orden estable hace `fetch_many`
    determinista respecto a la entrada (R5.7).
    """
    seen: set[str] = set()
    unique: list[str] = []
    for raw in names:
        normalized = adapter.normalize_name(raw)
        if normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)
    return tuple(unique)


def _fetch_with_budget(
    adapter: EcosystemAdapter,
    name: str,
    config: Config,
) -> FetchOutcome:
    """Worker de la pool: aisla las excepciones por-dependencia (NFR-Degr.1/R6.5).

    Solo las excepciones OPERACIONALES TOTALES (`DatasetIntegrityError`,
    `InvalidConfigError`) se propagan para abortar todo el lote (exit 3 total). CUALQUIER
    otra excepcion inesperada de un worker se degrada a UNVERIFIABLE por-dependencia, sin
    filtrar el mensaje: una dep envenenada nunca tumba el escaneo completo ni escapa como
    stacktrace via `pool.map` (que re-lanzaria la excepcion al consumir el generador).
    """
    try:
        return _fetch_one(adapter, name, config)
    except (DatasetIntegrityError, InvalidConfigError):
        raise  # operacional total: aborta el lote completo (exit 3)
    except Exception:
        return _UNVERIFIABLE  # degradacion segura por-dependencia (no aborta el lote)


def _fetch_one(
    adapter: EcosystemAdapter,
    name: str,
    config: Config,
) -> FetchOutcome:
    """Ejecuta el fetch de un nombre respetando reintentos, backoff y presupuesto.

    Mide el presupuesto con `time.monotonic` (reloj monotono, inmune a saltos del reloj
    de pared). Solo reintenta fallos transitorios y solo si el adapter los distingue
    (`RetryableAdapter`); de lo contrario hace un unico intento via `fetch()`.
    """
    if not isinstance(adapter, RetryableAdapter):
        return adapter.fetch(name)
    deadline = time.monotonic() + config.timeout_total_por_dep_s
    return _retry_transient(adapter, name, config, deadline)


def _retry_transient(
    adapter: RetryableAdapter,
    name: str,
    config: Config,
    deadline: float,
) -> FetchOutcome:
    """Reintenta SOLO fallos transitorios con backoff exponencial dentro del presupuesto.

    En cada vuelta: si el deadline ya paso, agota; si no, intenta. Si el fallo no es
    transitorio, devuelve su outcome inmediatamente (404/4xx!=404/anomalia permanente NO
    se reintentan). Si es transitorio y aun hay reintentos y margen de backoff, espera y
    reintenta; si no, agota => UNVERIFIABLE (degradacion segura, nunca `allow`).

    Contrato de presupuesto (ver docstring del modulo): el deadline acota la SECUENCIA de
    intentos+esperas; el chequeo `time.monotonic() >= deadline` impide INICIAR un intento
    una vez rebasado el presupuesto. La duracion interna de un `fetch_attempt` ya en vuelo
    la acota el timeout de socket de `SecureHttpClient` (`connect_timeout_s+read_timeout_s`),
    de modo que el peor caso por dependencia es `deadline + un round-trip`, no instantaneo.
    """
    max_attempts = config.reintentos_red + 1  # intento inicial + reintentos
    attempt = 0
    while True:
        if time.monotonic() >= deadline:
            return _UNVERIFIABLE  # presupuesto rebasado: no se inicia un nuevo intento
        result = adapter.fetch_attempt(name)
        if not result.is_transient:
            return result.outcome  # 404/4xx!=404/anomalia permanente: definitivo
        attempt += 1
        if attempt >= max_attempts:
            return _UNVERIFIABLE  # reintentos agotados (degradacion segura)
        if not _sleep_within_budget(attempt - 1, deadline):
            return _UNVERIFIABLE  # sin margen de backoff dentro del presupuesto


def _sleep_within_budget(attempt: int, deadline: float) -> bool:
    """Espera el backoff del intento `attempt` sin rebasar el deadline.

    Backoff exponencial base 0.5s: `0.5 * 2**attempt` (0.5s, 1.0s, 2.0s, ...). Si la
    espera completa no cabe en el presupuesto restante, NO duerme y reporta False para
    cortar (preferimos agotar a UNVERIFIABLE antes que exceder el presupuesto por dep).
    """
    backoff = _BACKOFF_BASE_S * (2**attempt)
    remaining = deadline - time.monotonic()
    if backoff > remaining:
        return False
    time.sleep(backoff)
    return True
