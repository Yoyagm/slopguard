"""RetryableAdapter + reuso de concurrencia: NpmAdapter + fetch_many (H4-T08).

Verifica que `NpmAdapter` satisface `RetryableAdapter` en tiempo de ejecucion y que
`fetch_many` (de `concurrent.py`) reintenta sus fallos transitorios SIN ningun camino
de concurrencia nuevo (NFR-Rend.1). El mismo `_retry_transient`/presupuesto de PyPI
se activa para npm por la simple presencia de `fetch_attempt`.

Criterios de aceptacion (EARS H4-T08):
- R4.1: UNVERIFIABLE transitorio (5xx/timeout) se reintenta dentro del presupuesto;
  FOUND despues de transitorios => FOUND final.
- R4.1 permanente: NOT_FOUND/4xx/cap NO se reintentan; el primer resultado es definitivo.
- NFR-Rend.1: ninguna rama de concurrencia nueva en el adapter npm; el adapter delega
  en `concurrent.py` mediante el Protocol `RetryableAdapter`.

El reloj y las esperas se simulan (monkeypatch del modulo `concurrent`) para que el
backoff sea determinista y rapido, sin tocar el reloj real.
"""

from __future__ import annotations

import threading
from typing import Any
from urllib.parse import quote

import pytest

from slopguard.core.adapters.base import FetchState
from slopguard.core.adapters.concurrent import RetryableAdapter, fetch_many
from slopguard.core.adapters.npm import NpmAdapter
from slopguard.core.config import Config
from slopguard.core.errors import NetworkUnverifiableError

# Rutas de monkeypatch del reloj/espera del modulo bajo prueba.
_TIME_MONOTONIC = "slopguard.core.adapters.concurrent.time.monotonic"
_TIME_SLEEP = "slopguard.core.adapters.concurrent.time.sleep"

# Packument npm minimo bien formado (mismo fixture que test_npm_fetch.py).
_GOOD_PACKUMENT: dict[str, Any] = {
    "name": "lodash",
    "description": "Lodash modular utilities.",
    "time": {"created": "2012-04-23T16:17:12.327Z"},
    "versions": {"4.17.20": {}, "4.17.21": {}},
    "repository": {"type": "git", "url": "https://github.com/lodash/lodash.git"},
    "author": {"name": "John-David Dalton"},
    "license": "MIT",
    "keywords": ["modules", "util"],
}


# ---------------------------------------------------------------------------
# Doble del cliente HTTP (mismo patron que test_npm_fetch.py)
# ---------------------------------------------------------------------------


class _StubHttp:
    """Doble de `SecureHttpClient` guionado por URL encodeada."""

    def __init__(self, scripts: dict[str, list[Any]]) -> None:
        self._scripts = {k: list(v) for k, v in scripts.items()}
        self._calls: dict[str, int] = {}
        self._lock = threading.Lock()

    def get_json(self, url: str, **_: Any) -> dict[str, Any]:
        encoded = url.rsplit("/", maxsplit=1)[1]
        with self._lock:
            count = self._calls.get(encoded, 0) + 1
            self._calls[encoded] = count
        steps = self._scripts[encoded]
        step = steps[min(count - 1, len(steps) - 1)]
        if isinstance(step, BaseException):
            raise step
        assert isinstance(step, dict)
        return step


def _http_error(status_code: int, *, is_transient: bool) -> NetworkUnverifiableError:
    return NetworkUnverifiableError(
        f"respuesta HTTP {status_code}",
        status_code=status_code,
        is_transient=is_transient,
    )


def _timeout_error() -> NetworkUnverifiableError:
    return NetworkUnverifiableError("timeout de red", is_transient=True)


def _enc(name: str) -> str:
    return quote(name, safe="")


def _make_adapter(scripts: dict[str, list[Any]]) -> NpmAdapter:
    """NpmAdapter real con transporte sustituido por el stub guionado."""
    adapter = NpmAdapter(Config(), use_cache=False)
    adapter._http = _StubHttp(scripts)  # type: ignore[assignment]
    return adapter


# ---------------------------------------------------------------------------
# Fixture de reloj simulado (identico a test_concurrent.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Reloj monotono simulado; cada sleep avanza el reloj sin esperar."""
    state = {"now": 1000.0}
    slept: list[float] = []

    def fake_monotonic() -> float:
        return state["now"]

    def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        state["now"] += seconds

    monkeypatch.setattr(_TIME_MONOTONIC, fake_monotonic)
    monkeypatch.setattr(_TIME_SLEEP, fake_sleep)
    return slept


# ---------------------------------------------------------------------------
# Protocol check (R4.1 / NFR-Rend.1)
# ---------------------------------------------------------------------------


def test_npm_adapter_satisface_retryable_adapter() -> None:
    """`NpmAdapter` satisface `RetryableAdapter` en tiempo de ejecucion (NFR-Rend.1).

    `isinstance(adapter, RetryableAdapter)` = True => `fetch_many` activa el camino
    de reintentos SIN ninguna condicion especial para npm: el Protocol es la unica clave.
    """
    adapter = _make_adapter({})
    assert isinstance(adapter, RetryableAdapter)
    assert adapter.ecosystem_id == "npm"


# ---------------------------------------------------------------------------
# Reintento de transitorios via fetch_many (R4.1)
# ---------------------------------------------------------------------------


def test_fetch_many_reintenta_transitorio_npm(fake_clock: list[float]) -> None:
    """fetch_many reintenta un fallo transitorio de NpmAdapter y devuelve FOUND.

    Guion: timeout (transitorio) -> FOUND. El primer intento falla, el reintento
    (via `_retry_transient` de `concurrent.py`) entrega FOUND. Demuestra que
    `concurrent.py` reutiliza su camino existente sin logica nueva para npm.
    """
    config = Config()  # reintentos_red=2, timeout_total_por_dep_s=30
    adapter = _make_adapter(
        {_enc("lodash"): [_timeout_error(), _GOOD_PACKUMENT]}
    )

    results = fetch_many(adapter, ["lodash"], config)

    assert results["lodash"].state is FetchState.FOUND
    assert results["lodash"].metadata is not None
    assert len(fake_clock) == 1  # un backoff (0.5s, primer reintento)


def test_fetch_many_dos_transitorios_luego_found_npm(fake_clock: list[float]) -> None:
    """fetch_many aguanta dos transitorios y resuelve FOUND en el tercer intento.

    Confirma que el presupuesto de reintentos (reintentos_red=2 por defecto) permite
    hasta 2 reintentos (3 intentos totales) usando la misma logica que PyPI.
    """
    config = Config()
    adapter = _make_adapter(
        {_enc("react"): [_timeout_error(), _timeout_error(), _GOOD_PACKUMENT]}
    )

    results = fetch_many(adapter, ["react"], config)

    assert results["react"].state is FetchState.FOUND
    assert len(fake_clock) == 2  # dos backoffs (0.5s + 1.0s)


def test_fetch_many_agota_reintentos_devuelve_unverifiable_npm(
    fake_clock: list[float],
) -> None:
    """Al agotar reintentos el resultado es UNVERIFIABLE, nunca CLEAN (R4.1/NFR-Degr.1).

    Guion: tres transitorios con reintentos_red=2 (3 intentos maximo). El tercer
    intento tambien falla => presupuesto agotado => UNVERIFIABLE.
    """
    config = Config()  # reintentos_red=2
    adapter = _make_adapter(
        {
            _enc("flaky"): [
                _timeout_error(),
                _timeout_error(),
                _timeout_error(),
            ]
        }
    )

    results = fetch_many(adapter, ["flaky"], config)

    assert results["flaky"].state is FetchState.UNVERIFIABLE


# ---------------------------------------------------------------------------
# Permanentes no se reintentan (R4.1)
# ---------------------------------------------------------------------------


def test_fetch_many_not_found_es_permanente_npm() -> None:
    """404 => NOT_FOUND definitivo: fetch_many no lo reintenta (R4.1).

    Un 404 npm nunca es transitorio: el adapter lo devuelve con is_transient=False
    y `_retry_transient` lo retorna inmediatamente, sin backoff.
    """
    config = Config()
    adapter = _make_adapter(
        {_enc("ghost-pkg"): [_http_error(404, is_transient=False)]}
    )

    results = fetch_many(adapter, ["ghost-pkg"], config)

    assert results["ghost-pkg"].state is FetchState.NOT_FOUND


def test_fetch_many_4xx_permanente_no_reintenta_npm() -> None:
    """4xx != 404 => UNVERIFIABLE permanente: no se reintenta (R4.1).

    403/410 etc. son anomalias definitivas. `is_transient=False` corta `_retry_transient`
    en el primer intento sin consumir reintentos.
    """
    config = Config()
    adapter = _make_adapter(
        {_enc("forbidden"): [_http_error(403, is_transient=False)]}
    )

    results = fetch_many(adapter, ["forbidden"], config)

    assert results["forbidden"].state is FetchState.UNVERIFIABLE


# ---------------------------------------------------------------------------
# Dedup npm: normalize_name npm + un solo intento por nombre (NFR-Rend.2)
# ---------------------------------------------------------------------------


def test_fetch_many_deduplica_nombres_npm() -> None:
    """fetch_many normaliza y deduplica nombres npm antes de despachar (NFR-Rend.2).

    `lodash` y `Lodash` normalizan al mismo nombre: se consulta UNA sola vez.
    """
    config = Config()
    adapter = _make_adapter({_enc("lodash"): [_GOOD_PACKUMENT]})

    results = fetch_many(adapter, ["lodash", "Lodash", "LODASH"], config)

    # Solo un resultado (nombre normalizado) y el stub se llamo una vez.
    assert len(results) == 1
    assert results["lodash"].state is FetchState.FOUND
    stub: _StubHttp = adapter._http  # type: ignore[assignment]
    assert stub._calls.get(_enc("lodash"), 0) == 1


def test_fetch_many_scoped_dedup_npm() -> None:
    """Nombres scoped npm se normalizan y deducan correctamente (R3.1/NFR-Rend.2).

    `@scope/pkg` y `@SCOPE/PKG` normalizan al mismo nombre; un solo intento.
    """
    config = Config()
    adapter = _make_adapter({_enc("@scope/pkg"): [_GOOD_PACKUMENT]})

    results = fetch_many(adapter, ["@scope/pkg", "@SCOPE/PKG"], config)

    assert len(results) == 1
    assert results["@scope/pkg"].state is FetchState.FOUND


# ---------------------------------------------------------------------------
# Multiples dependencias en paralelo (NFR-Rend.1 / NFR-Rend.2)
# ---------------------------------------------------------------------------


def test_fetch_many_multiples_dependencias_npm() -> None:
    """fetch_many resuelve varias dependencias npm en paralelo, cada una independiente.

    Confirma que el camino concurrente existente (ThreadPoolExecutor de `concurrent.py`)
    funciona con NpmAdapter igual que con PypiAdapter, sin nuevo codigo de concurrencia.
    """
    config = Config()
    adapter = _make_adapter(
        {
            _enc("lodash"): [_GOOD_PACKUMENT],
            _enc("react"): [_http_error(404, is_transient=False)],
            _enc("express"): [_timeout_error()],
        }
    )

    results = fetch_many(adapter, ["lodash", "react", "express"], config)

    assert results["lodash"].state is FetchState.FOUND
    assert results["react"].state is FetchState.NOT_FOUND
    assert results["express"].state is FetchState.UNVERIFIABLE
