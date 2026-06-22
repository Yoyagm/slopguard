"""Pruebas del orquestador de fetch concurrente (T22, R2.5, R9.4, NFR-Rend.2/Degr.1).

Verifica las invariantes de alto riesgo de la concurrencia + presupuesto por dependencia:

- **Dedup** de nombres normalizados antes de despachar: el mismo paquete no se consulta
  dos veces por corrida (R9.4/NFR-Rend.2).
- **Paralelismo** acotado por `concurrencia_max`.
- **Reintentos**: SOLO transitorios; backoff exponencial base 0.5s; permanentes (404,
  4xx!=404, FOUND) NUNCA se reintentan.
- **Presupuesto**: el tiempo total por dependencia no excede `timeout_total_por_dep_s`;
  al agotarlo => UNVERIFIABLE, nunca `allow` (R2.5/NFR-Degr.1).
- **Degradacion segura**: un adapter SIN `fetch_attempt` no reintenta y marca unverifiable.

El reloj y las esperas se simulan (monkeypatch de `time.monotonic`/`time.sleep` del modulo)
para hacer el backoff y el presupuesto deterministas y rapidos, sin tocar el reloj real.
"""

from __future__ import annotations

import dataclasses
import threading
import time
from typing import TYPE_CHECKING

import pytest

from slopguard.core.adapters.base import FetchOutcome, FetchState, PackageMetadata
from slopguard.core.adapters.concurrent import FetchAttempt, RetryableAdapter, fetch_many
from slopguard.core.config import Config

if TYPE_CHECKING:
    from collections.abc import Sequence

    from slopguard.core.dataset.top_n import TopNDataset

# Ruta de monkeypatch del reloj/espera del modulo bajo prueba (mypy-strict friendly).
_TIME_MONOTONIC = "slopguard.core.adapters.concurrent.time.monotonic"
_TIME_SLEEP = "slopguard.core.adapters.concurrent.time.sleep"

# ---------------------------------------------------------------------------
# Dobles de prueba
# ---------------------------------------------------------------------------

_META = PackageMetadata(
    name="requests",
    first_release_epoch=1_297_500_000.0,
    releases_count=148,
    has_repo_url=True,
    has_description=True,
    has_author=True,
    has_license=True,
    has_classifiers=True,
    in_top_n=True,
)
_FOUND = FetchOutcome(state=FetchState.FOUND, metadata=_META)
_NOT_FOUND = FetchOutcome(state=FetchState.NOT_FOUND)
_UNVERIFIABLE = FetchOutcome(state=FetchState.UNVERIFIABLE)


class _ScriptedAdapter:
    """Adapter `RetryableAdapter` que devuelve un guion de `FetchAttempt` por nombre.

    Registra cada `fetch_attempt` (thread-safe) para asertar conteos de intentos y dedup.
    """

    ecosystem_id = "pypi"

    def __init__(self, scripts: dict[str, list[FetchAttempt]]) -> None:
        self._scripts = {k: list(v) for k, v in scripts.items()}
        self._calls: list[str] = []
        self._lock = threading.Lock()

    def normalize_name(self, raw: str) -> str:
        return raw.lower().replace("_", "-").replace(".", "-")

    def fetch_attempt(self, name: str) -> FetchAttempt:
        with self._lock:
            self._calls.append(name)
        steps = self._scripts[name]
        # El ultimo paso se repite si se pide mas (no deberia, pero es defensivo).
        index = min(self._calls.count(name) - 1, len(steps) - 1)
        return steps[index]

    def fetch(self, name: str) -> FetchOutcome:  # pragma: no cover - no usado aqui
        return self.fetch_attempt(name).outcome

    def load_top_n(self) -> TopNDataset:  # pragma: no cover - no usado aqui
        raise NotImplementedError

    def get_downloads(self, name: str) -> None:  # pragma: no cover - hook reservado
        return None

    @property
    def calls(self) -> list[str]:
        return list(self._calls)


class _PlainAdapter:
    """Adapter base SIN `fetch_attempt`: ejercita la rama de degradacion segura."""

    ecosystem_id = "pypi"

    def __init__(self, outcomes: dict[str, FetchOutcome]) -> None:
        self._outcomes = outcomes
        self.calls: list[str] = []

    def normalize_name(self, raw: str) -> str:
        return raw.lower().replace("_", "-")

    def fetch(self, name: str) -> FetchOutcome:
        self.calls.append(name)
        return self._outcomes[name]

    def load_top_n(self) -> TopNDataset:  # pragma: no cover - no usado aqui
        raise NotImplementedError

    def get_downloads(self, name: str) -> None:  # pragma: no cover - hook reservado
        return None


def _transient() -> FetchAttempt:
    return FetchAttempt(outcome=_UNVERIFIABLE, is_transient=True)


def _found() -> FetchAttempt:
    return FetchAttempt(outcome=_FOUND, is_transient=False)


def _not_found() -> FetchAttempt:
    return FetchAttempt(outcome=_NOT_FOUND, is_transient=False)


def _permanent_unverifiable() -> FetchAttempt:
    return FetchAttempt(outcome=_UNVERIFIABLE, is_transient=False)


@pytest.fixture
def fake_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Reloj monotono simulado: cada `sleep(s)` avanza el reloj `s` segundos.

    Devuelve la lista de duraciones dormidas para asertar el backoff exacto sin esperas.
    """
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
# Dedup + paralelismo (R9.4, NFR-Rend.2)
# ---------------------------------------------------------------------------


def test_dedup_normalizado_no_consulta_dos_veces() -> None:
    """Nombres que normalizan al mismo paquete se consultan UNA sola vez (R9.4).

    Cubre dos formas de colision: casing puro ('Requests'/'REQUESTS' -> 'requests') y
    colapso de separadores ('zope_interface'/'zope.interface' -> 'zope-interface').
    """
    adapter = _ScriptedAdapter({"requests": [_found()], "zope-interface": [_found()]})
    names = [
        "requests", "Requests", "REQUESTS",
        "zope_interface", "zope.interface", "ZOPE-INTERFACE",
    ]

    result = fetch_many(adapter, names, Config())

    assert sorted(adapter.calls) == ["requests", "zope-interface"]  # dos consultas unicas
    assert set(result) == {"requests", "zope-interface"}  # indexado por nombre normalizado
    assert result["requests"] is _FOUND


def test_lista_vacia_no_despacha() -> None:
    """Sin nombres no se crea pool ni se consulta nada."""
    adapter = _ScriptedAdapter({})
    assert fetch_many(adapter, [], Config()) == {}


def test_resultado_por_nombre_normalizado() -> None:
    """Cada nombre unico recibe su outcome, indexado por su forma normalizada."""
    adapter = _ScriptedAdapter({
        "requests": [_found()],
        "fakepkg": [_not_found()],
        "weird": [_permanent_unverifiable()],
    })

    result = fetch_many(adapter, ["requests", "fakepkg", "weird"], Config())

    assert result["requests"].state is FetchState.FOUND
    assert result["fakepkg"].state is FetchState.NOT_FOUND
    assert result["weird"].state is FetchState.UNVERIFIABLE


def test_paralelismo_respeta_concurrencia_max() -> None:
    """No corren mas de `concurrencia_max` fetches en simultaneo."""
    barrier_max = {"value": 0}
    active = {"value": 0}
    lock = threading.Lock()
    gate = threading.Event()

    class _SlowAdapter:
        ecosystem_id = "pypi"

        def normalize_name(self, raw: str) -> str:
            return raw

        def fetch_attempt(self, name: str) -> FetchAttempt:
            with lock:
                active["value"] += 1
                barrier_max["value"] = max(barrier_max["value"], active["value"])
            gate.wait(timeout=1.0)
            with lock:
                active["value"] -= 1
            return _found()

        def fetch(self, name: str) -> FetchOutcome:  # pragma: no cover
            return self.fetch_attempt(name).outcome

        def load_top_n(self) -> TopNDataset:  # pragma: no cover
            raise NotImplementedError

        def get_downloads(self, name: str) -> None:  # pragma: no cover
            return None

    adapter = _SlowAdapter()
    config = dataclasses.replace(Config(), concurrencia_max=3)
    names = [f"pkg{i}" for i in range(12)]

    # Libera la barrera tras un instante para que los workers terminen.
    threading.Timer(0.2, gate.set).start()
    result = fetch_many(adapter, names, config)

    assert len(result) == 12
    assert barrier_max["value"] <= 3  # nunca mas de concurrencia_max en vuelo


# ---------------------------------------------------------------------------
# Reintentos transitorios + backoff (R2.5)
# ---------------------------------------------------------------------------


def test_transitorio_se_reintenta_y_luego_found(fake_clock: list[float]) -> None:
    """Un transitorio seguido de FOUND => FOUND tras 1 reintento con backoff 0.5s."""
    adapter = _ScriptedAdapter({"requests": [_transient(), _found()]})

    result = fetch_many(adapter, ["requests"], Config())

    assert result["requests"].state is FetchState.FOUND
    assert adapter.calls.count("requests") == 2  # intento + 1 reintento
    assert fake_clock == [0.5]  # backoff base exacto


def test_backoff_exponencial_base_05(fake_clock: list[float]) -> None:
    """Con reintentos_red=2 y transitorio persistente: backoff 0.5s, 1.0s => UNVERIFIABLE."""
    adapter = _ScriptedAdapter({"x-pkg": [_transient(), _transient(), _transient()]})
    config = dataclasses.replace(Config(), reintentos_red=2, timeout_total_por_dep_s=100.0)

    result = fetch_many(adapter, ["x-pkg"], config)

    assert result["x-pkg"].state is FetchState.UNVERIFIABLE
    assert adapter.calls.count("x-pkg") == 3  # intento inicial + 2 reintentos
    assert fake_clock == [0.5, 1.0]  # dos esperas de backoff, base 0.5s


def test_transitorio_agotado_es_unverifiable_nunca_allow(fake_clock: list[float]) -> None:
    """Agotar reintentos en transitorio => UNVERIFIABLE; jamas un outcome 'positivo'."""
    adapter = _ScriptedAdapter({"flaky": [_transient(), _transient(), _transient()]})

    result = fetch_many(adapter, ["flaky"], Config())  # reintentos_red=2 por defecto

    assert result["flaky"].state is FetchState.UNVERIFIABLE
    assert result["flaky"].metadata is None  # nunca FOUND


# ---------------------------------------------------------------------------
# Permanentes NO se reintentan (clasificacion de Convenciones)
# ---------------------------------------------------------------------------


def test_404_no_se_reintenta(fake_clock: list[float]) -> None:
    """NOT_FOUND es definitivo: un solo intento, sin backoff."""
    adapter = _ScriptedAdapter({"ghost": [_not_found(), _found()]})

    result = fetch_many(adapter, ["ghost"], Config())

    assert result["ghost"].state is FetchState.NOT_FOUND
    assert adapter.calls.count("ghost") == 1  # no se reintenta
    assert fake_clock == []


def test_4xx_distinto_de_404_no_se_reintenta(fake_clock: list[float]) -> None:
    """UNVERIFIABLE permanente (403/410) no se reintenta como transitorio."""
    adapter = _ScriptedAdapter({"forbidden": [_permanent_unverifiable(), _found()]})

    result = fetch_many(adapter, ["forbidden"], Config())

    assert result["forbidden"].state is FetchState.UNVERIFIABLE
    assert adapter.calls.count("forbidden") == 1  # anomalia permanente: sin reintento
    assert fake_clock == []


def test_found_no_se_reintenta(fake_clock: list[float]) -> None:
    """FOUND es definitivo desde el primer intento."""
    adapter = _ScriptedAdapter({"requests": [_found(), _transient()]})

    result = fetch_many(adapter, ["requests"], Config())

    assert result["requests"].state is FetchState.FOUND
    assert adapter.calls.count("requests") == 1


# ---------------------------------------------------------------------------
# Presupuesto de timeout por dependencia (R2.5) — no se excede
# ---------------------------------------------------------------------------


def test_presupuesto_corta_backoff_que_no_cabe(fake_clock: list[float]) -> None:
    """Si el backoff no cabe en el presupuesto restante, no duerme y agota a UNVERIFIABLE."""
    adapter = _ScriptedAdapter({"slow": [_transient(), _transient(), _transient()]})
    # Presupuesto 0.3s < primer backoff 0.5s: nunca llega a dormir.
    config = dataclasses.replace(Config(), reintentos_red=2, timeout_total_por_dep_s=0.3)

    result = fetch_many(adapter, ["slow"], config)

    assert result["slow"].state is FetchState.UNVERIFIABLE
    assert adapter.calls.count("slow") == 1  # solo el intento inicial
    assert fake_clock == []  # ninguna espera (no cabia en presupuesto)


def test_presupuesto_permite_solo_un_backoff(fake_clock: list[float]) -> None:
    """Presupuesto que cabe un backoff (0.5s) pero no el segundo (1.0s) => corta antes."""
    adapter = _ScriptedAdapter({"slow": [_transient(), _transient(), _transient()]})
    config = dataclasses.replace(Config(), reintentos_red=2, timeout_total_por_dep_s=0.6)

    result = fetch_many(adapter, ["slow"], config)

    assert result["slow"].state is FetchState.UNVERIFIABLE
    assert adapter.calls.count("slow") == 2  # intento inicial + 1 reintento (backoff 0.5s)
    assert fake_clock == [0.5]  # el segundo backoff (1.0s) no cabia en lo restante (0.1s)


def test_presupuesto_agotado_antes_del_primer_intento(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Si el reloj ya rebaso el deadline al entrar, no se consulta y => UNVERIFIABLE."""
    clock = {"now": 0.0}

    def advancing_monotonic() -> float:
        # Primera lectura fija el deadline; la segunda ya lo rebasa.
        clock["now"] += 1000.0
        return clock["now"]

    monkeypatch.setattr(_TIME_MONOTONIC, advancing_monotonic)
    adapter = _ScriptedAdapter({"x": [_transient()]})
    config = dataclasses.replace(Config(), timeout_total_por_dep_s=1.0)

    result = fetch_many(adapter, ["x"], config)

    assert result["x"].state is FetchState.UNVERIFIABLE
    assert adapter.calls == []  # nunca se llego a consultar


# ---------------------------------------------------------------------------
# Degradacion segura con adapter base (sin fetch_attempt)
# ---------------------------------------------------------------------------


def test_adapter_plano_no_reintenta_usa_fetch() -> None:
    """Un adapter base sin `fetch_attempt` usa `fetch()` y NO reintenta (degradacion segura)."""
    adapter = _PlainAdapter({"requests": _FOUND, "ghost": _NOT_FOUND, "down": _UNVERIFIABLE})

    result = fetch_many(adapter, ["requests", "ghost", "down"], Config())

    assert result["requests"].state is FetchState.FOUND
    assert result["ghost"].state is FetchState.NOT_FOUND
    assert result["down"].state is FetchState.UNVERIFIABLE  # nunca allow
    assert adapter.calls.count("down") == 1  # sin reintentos


def test_protocolo_runtime_checkable() -> None:
    """`RetryableAdapter` distingue por estructura: con/sin `fetch_attempt`."""
    assert isinstance(_ScriptedAdapter({}), RetryableAdapter)
    assert not isinstance(_PlainAdapter({}), RetryableAdapter)


def test_determinismo_orden_de_entrada() -> None:
    """El dict resultante es estable y completo bajo permutacion de la entrada (R5.7)."""
    scripts: dict[str, list[FetchAttempt]] = {
        "a-pkg": [_found()],
        "b-pkg": [_not_found()],
        "c-pkg": [_permanent_unverifiable()],
    }
    order_one: Sequence[str] = ["a-pkg", "b-pkg", "c-pkg"]
    order_two: Sequence[str] = ["c-pkg", "a-pkg", "b-pkg"]

    result_one = fetch_many(_ScriptedAdapter(scripts), order_one, Config())
    result_two = fetch_many(_ScriptedAdapter(scripts), order_two, Config())

    assert {k: v.state for k, v in result_one.items()} == {
        k: v.state for k, v in result_two.items()
    }


def test_now_no_se_usa_reloj_real_en_budget(fake_clock: list[float]) -> None:
    """Smoke: el presupuesto usa el reloj monotono del modulo (no time.time)."""
    start = time.time()
    adapter = _ScriptedAdapter({"x": [_transient(), _transient(), _transient()]})
    config = dataclasses.replace(Config(), reintentos_red=2, timeout_total_por_dep_s=100.0)

    result = fetch_many(adapter, ["x"], config)

    assert result["x"].state is FetchState.UNVERIFIABLE
    assert time.time() - start < 1.0  # no durmio de verdad (reloj simulado)
