"""Capas 0/2 agnosticas operan sobre datos npm end-to-end (H4-T45, R7).

Las Capas 0 (existencia + edad) y 2 (metadata) son PURAS y agnosticas de ecosistema:
consumen solo `FetchOutcome`/`PackageMetadata` (`core.adapters.base`), nunca un adapter
concreto ni la red. Esta suite verifica que, alimentadas con datos ORIGINADOS por el
camino npm, emiten EXACTAMENTE las mismas senales (mismos codigos/pesos/semantica de
veredicto) que para el equivalente PyPI. No toca las capas; entra por la frontera.

Trazabilidad EARS:
- R7.1: un `FetchOutcome(NOT_FOUND)` originado por un 404 npm (via `NpmAdapter` con
  transporte mockeado, T07) => Capa 0 emite `NONEXISTENT` (peso 0, override, no blanda),
  con la MISMA semantica de veredicto (override => block) que PyPI.
- R7.2: un `PackageMetadata` npm poblado por `_extract_metadata` (T06), con flags
  equivalentes a uno PyPI, => Capa 2 (y la edad de Capa 0) emiten las MISMAS senales
  blandas (`WEAK_METADATA`/`LOW_VERIFIABILITY`/`NEW_PACKAGE`), mismos codigos/pesos.
- R4.4: un `PackageMetadata` npm con flags degradados (`time` ausente, `versions` no-dict)
  => no inventa senales.

Este test atrapa un bug que dejara INERTES las Capas 0/2 para npm por un `PackageMetadata`
mal poblado: T09 solo verifica el mapeo del adapter; T38 solo cubre no-regresion PyPI.
Ninguno comprueba que el resultado del camino npm fluya a traves de las capas agnosticas
produciendo la misma senalizacion que PyPI.
"""

from __future__ import annotations

import datetime
from typing import Any

import pytest

from slopguard.core.adapters.base import (
    FetchOutcome,
    FetchState,
    PackageMetadata,
)
from slopguard.core.adapters.npm import NpmAdapter, _extract_metadata
from slopguard.core.config import Config
from slopguard.core.dataset.top_n import build_top_n
from slopguard.core.errors import NetworkUnverifiableError
from slopguard.core.layers import layer0_existence, layer2_metadata
from slopguard.core.models import Layer, SignalCode

# Epoch de referencia para la edad determinista (2024-06-01T00:00:00Z).
_NOW = 1_717_200_000.0
_SECONDS_PER_DAY = 86_400.0
_DEFAULT_CONFIG = Config()

# Dataset top-N minimo (sin red, sin SHA-256) para `_extract_metadata`.
_TOP_N_EMPTY = build_top_n([], version="test", generated_at="2024-01-01")


# ---------------------------------------------------------------------------
# Stub de transporte: reproduce el patron de tests/adapters/test_npm_fetch.py.
# El dataset npm embebido se carga de verdad en __init__ (camino real, ADR-02);
# solo se sustituye el cliente HTTP para controlar la respuesta sin red.
# ---------------------------------------------------------------------------


class _StubHttp:
    """Doble de `SecureHttpClient`: mapea cada URL a un payload dict o a una excepcion."""

    def __init__(self, scripts: dict[str, Any]) -> None:
        self._scripts = scripts
        self.urls: list[str] = []

    def get_json(self, url: str, **_: Any) -> dict[str, Any]:
        self.urls.append(url)
        encoded = url.rsplit("/", maxsplit=1)[1]
        step = self._scripts[encoded]
        if isinstance(step, BaseException):
            raise step
        assert isinstance(step, dict)
        return step


def _make_adapter(scripts: dict[str, Any]) -> NpmAdapter:
    """`NpmAdapter` real con el cliente HTTP sustituido por un stub guionado (sin red)."""
    adapter = NpmAdapter(Config(), use_cache=False)
    adapter._http = _StubHttp(scripts)  # type: ignore[assignment]
    return adapter


def _http_404() -> NetworkUnverifiableError:
    """El error tipado que `SecureHttpClient` elevaria ante un 404 del registry npm."""
    return NetworkUnverifiableError(
        "respuesta HTTP 404 no verificable",
        status_code=404,
        is_transient=False,
    )


def _pypi_equivalent_outcome(meta: PackageMetadata) -> FetchOutcome:
    """Construye un `FetchOutcome` FOUND 'PyPI' con los MISMOS flags que `meta`.

    No invoca el adapter PyPI (no es el SUT): replica el contrato agnostico
    `PackageMetadata` con identicos flags, que es lo unico que ven las capas. Asi se
    compara senal-a-senal el resultado npm contra el equivalente PyPI sin red.
    """
    pypi_meta = PackageMetadata(
        name=meta.name,
        first_release_epoch=meta.first_release_epoch,
        releases_count=meta.releases_count,
        has_repo_url=meta.has_repo_url,
        has_description=meta.has_description,
        has_author=meta.has_author,
        has_license=meta.has_license,
        has_classifiers=meta.has_classifiers,
        in_top_n=meta.in_top_n,
    )
    return FetchOutcome(state=FetchState.FOUND, metadata=pypi_meta)


def _signal_tuples(signals: list[Any]) -> list[tuple[SignalCode, int, bool, Layer]]:
    """Proyecta cada senal a (codigo, peso, is_soft, capa) para comparar igualdad estable.

    Excluye `detail` a proposito: el texto humano puede divergir por ecosistema
    (riesgo cosmetico conocido, §open_risks, decidido en T46), pero la SENALIZACION
    (codigo/peso/dureza/capa) debe ser identica entre npm y PyPI (R7).
    """
    return sorted(
        (s.code, s.weight, s.is_soft, s.layer) for s in signals
    )


# ===========================================================================
# R7.1 — 404 npm => Capa 0 emite NONEXISTENT (override), misma semantica que PyPI
# ===========================================================================


class TestR71NpmNotFoundOverride:
    """R7.1: un 404 originado por el fetch npm dispara el override de inexistencia."""

    def test_404_npm_produce_not_found_outcome(self) -> None:
        # Arrange: un 404 del registry npm via NpmAdapter (transporte mockeado, T07).
        adapter = _make_adapter({"ghost-npm-pkg": _http_404()})
        # Act
        outcome = adapter.fetch("ghost-npm-pkg")
        # Assert: el camino npm produce el FetchOutcome agnostico NOT_FOUND, sin lanzar.
        assert outcome.state is FetchState.NOT_FOUND
        assert outcome.metadata is None

    def test_404_npm_capa0_emite_nonexistent_override(self) -> None:
        # Arrange: el outcome NOT_FOUND originado por npm entra a la Capa 0 agnostica.
        adapter = _make_adapter({"ghost-npm-pkg": _http_404()})
        outcome = adapter.fetch("ghost-npm-pkg")
        # Act
        signals = layer0_existence.evaluate(outcome, _DEFAULT_CONFIG, now_epoch=_NOW)
        # Assert: una unica senal de override de inexistencia (peso 0, dura).
        assert len(signals) == 1
        signal = signals[0]
        assert signal.code is SignalCode.NONEXISTENT
        assert signal.layer is Layer.L0
        assert signal.weight == 0
        assert signal.is_soft is False  # override, no entra al scoring blando
        assert signal.suspected_target is None

    def test_404_scoped_npm_tambien_dispara_override(self) -> None:
        # Un paquete scoped inexistente (404) tambien cae al override sin codigo de npm.
        adapter = _make_adapter({"%40scope%2Fghost": _http_404()})
        outcome = adapter.fetch("@scope/ghost")
        signals = layer0_existence.evaluate(outcome, _DEFAULT_CONFIG, now_epoch=_NOW)
        assert len(signals) == 1
        assert signals[0].code is SignalCode.NONEXISTENT

    def test_404_npm_senalizacion_identica_a_pypi(self) -> None:
        """Misma semantica de veredicto: el NONEXISTENT de npm es indistinguible del de PyPI.

        Un `FetchOutcome(NOT_FOUND)` (mismo contrato agnostico) produce la MISMA senal sin
        importar el ecosistema que lo origino: la capa no ramifica por ecosistema (R7.1).
        """
        npm_outcome = _make_adapter({"ghost-npm-pkg": _http_404()}).fetch("ghost-npm-pkg")
        # Un NOT_FOUND 'PyPI' es el mismo estado del contrato agnostico.
        pypi_outcome = FetchOutcome(state=FetchState.NOT_FOUND)

        npm_signals = layer0_existence.evaluate(npm_outcome, _DEFAULT_CONFIG, now_epoch=_NOW)
        pypi_signals = layer0_existence.evaluate(pypi_outcome, _DEFAULT_CONFIG, now_epoch=_NOW)

        assert _signal_tuples(npm_signals) == _signal_tuples(pypi_signals)


# ===========================================================================
# R7.2 — metadata npm equivalente => mismas senales blandas que PyPI
# ===========================================================================

# Packument npm que mapea a metadata "debil" (releases<=min, faltan>=2 campos, sin repo)
# pero con primera release RECIENTE (paquete nuevo): dispara WEAK_METADATA + LOW_VERIF
# en Capa 2 y NEW_PACKAGE en Capa 0.
_RECENT_EPOCH = _NOW - 10 * _SECONDS_PER_DAY


def _weak_recent_packument() -> dict[str, Any]:
    """Packument npm: 1 release, recien publicado, sin repo, sin description ni author."""
    # 10 dias antes de _NOW, en ISO-8601 UTC, para que `time.created` parsee a _RECENT_EPOCH.
    created_iso = (
        datetime.datetime.fromtimestamp(_RECENT_EPOCH, tz=datetime.UTC)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return {
        "name": "newish",
        "time": {"created": created_iso},
        "versions": {"0.0.1": {}},  # 1 release == releases_min
        "license": "MIT",  # tiene licencia y keywords...
        "keywords": ["x"],  # ...para que falten EXACTAMENTE 2 campos (desc, author)
        # sin `repository`, `description`, `author` => 2 faltantes + sin repo.
    }


class TestR72NpmSoftSignalsMatchPypi:
    """R7.2: metadata npm equivalente a una PyPI => identicas senales blandas L2 y edad L0."""

    def test_metadata_npm_poblada_por_extract_metadata(self) -> None:
        """El packument npm mapea a una metadata con los flags esperados (precondicion)."""
        meta = _extract_metadata(_weak_recent_packument(), "newish", _TOP_N_EMPTY)
        assert meta.releases_count == 1
        assert meta.has_repo_url is False
        assert meta.has_description is False
        assert meta.has_author is False
        assert meta.has_license is True
        assert meta.has_classifiers is True
        assert meta.first_release_epoch == pytest.approx(_RECENT_EPOCH, abs=1.0)

    def test_capa2_npm_emite_weak_y_low_verifiability(self) -> None:
        # Arrange: metadata npm debil via el camino real de mapeo.
        meta = _extract_metadata(_weak_recent_packument(), "newish", _TOP_N_EMPTY)
        outcome = FetchOutcome(state=FetchState.FOUND, metadata=meta)
        # Act
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        # Assert: ambas senales blandas presentes con sus codigos.
        codes = {s.code for s in signals}
        assert SignalCode.WEAK_METADATA in codes
        assert SignalCode.LOW_VERIFIABILITY in codes

    def test_capa2_npm_senalizacion_identica_a_pypi(self) -> None:
        """Capa 2 produce las MISMAS senales (codigo/peso/dureza/capa) que el equivalente PyPI."""
        meta = _extract_metadata(_weak_recent_packument(), "newish", _TOP_N_EMPTY)
        npm_outcome = FetchOutcome(state=FetchState.FOUND, metadata=meta)
        pypi_outcome = _pypi_equivalent_outcome(meta)

        npm_signals = layer2_metadata.evaluate(npm_outcome, _DEFAULT_CONFIG)
        pypi_signals = layer2_metadata.evaluate(pypi_outcome, _DEFAULT_CONFIG)

        assert _signal_tuples(npm_signals) == _signal_tuples(pypi_signals)

    def test_capa0_edad_npm_emite_new_package(self) -> None:
        # Arrange: metadata npm con primera release reciente (10 dias < umbral 90).
        meta = _extract_metadata(_weak_recent_packument(), "newish", _TOP_N_EMPTY)
        outcome = FetchOutcome(state=FetchState.FOUND, metadata=meta)
        # Act
        signals = layer0_existence.evaluate(outcome, _DEFAULT_CONFIG, now_epoch=_NOW)
        # Assert: senal blanda de paquete nuevo, peso 15.
        assert len(signals) == 1
        signal = signals[0]
        assert signal.code is SignalCode.NEW_PACKAGE
        assert signal.weight == 15
        assert signal.is_soft is True
        assert signal.layer is Layer.L0

    def test_capa0_edad_npm_senalizacion_identica_a_pypi(self) -> None:
        """La edad de Capa 0 produce la MISMA senal NEW_PACKAGE que el equivalente PyPI."""
        meta = _extract_metadata(_weak_recent_packument(), "newish", _TOP_N_EMPTY)
        npm_outcome = FetchOutcome(state=FetchState.FOUND, metadata=meta)
        pypi_outcome = _pypi_equivalent_outcome(meta)

        npm_signals = layer0_existence.evaluate(npm_outcome, _DEFAULT_CONFIG, now_epoch=_NOW)
        pypi_signals = layer0_existence.evaluate(pypi_outcome, _DEFAULT_CONFIG, now_epoch=_NOW)

        assert _signal_tuples(npm_signals) == _signal_tuples(pypi_signals)

    def test_full_packument_npm_popular_completo_sin_senales_blandas(self) -> None:
        """Un packument npm completo y viejo (lodash-like) => sin senales L0/L2 (como PyPI)."""
        old_epoch = _NOW - 4000 * _SECONDS_PER_DAY  # muy anterior al umbral de edad
        created_iso = (
            datetime.datetime.fromtimestamp(old_epoch, tz=datetime.UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
        full_packument: dict[str, Any] = {
            "name": "lodash",
            "description": "Lodash modular utilities.",
            "time": {"created": created_iso},
            "versions": {str(i): {} for i in range(30)},  # >> releases_populares
            "repository": {"url": "https://github.com/lodash/lodash.git"},
            "author": {"name": "JDD"},
            "license": "MIT",
            "keywords": ["util"],
        }
        meta = _extract_metadata(full_packument, "lodash", _TOP_N_EMPTY)
        npm_outcome = FetchOutcome(state=FetchState.FOUND, metadata=meta)
        pypi_outcome = _pypi_equivalent_outcome(meta)

        npm_l0 = layer0_existence.evaluate(npm_outcome, _DEFAULT_CONFIG, now_epoch=_NOW)
        npm_l2 = layer2_metadata.evaluate(npm_outcome, _DEFAULT_CONFIG)
        pypi_l0 = layer0_existence.evaluate(pypi_outcome, _DEFAULT_CONFIG, now_epoch=_NOW)
        pypi_l2 = layer2_metadata.evaluate(pypi_outcome, _DEFAULT_CONFIG)

        # Paquete popular y completo: ninguna senal blanda, en npm igual que en PyPI.
        assert npm_l0 == []
        assert npm_l2 == []
        assert _signal_tuples(npm_l0) == _signal_tuples(pypi_l0)
        assert _signal_tuples(npm_l2) == _signal_tuples(pypi_l2)

    def test_cap_l2_npm_identico_a_pypi(self) -> None:
        """El cap c2_max_contrib se aplica igual: aporte total identico npm/PyPI."""
        # Packument que dispara WEAK(7)+LOW(5)=12 -> capado a 10, igual que en PyPI.
        capped_packument: dict[str, Any] = {
            "name": "weak",
            "versions": {"0.0.1": {}},  # 1 release
            # sin repo, sin description, sin author, sin license, sin keywords:
            # 4 faltantes >= metadata_faltantes_min y sin repo => ambas senales.
        }
        meta = _extract_metadata(capped_packument, "weak", _TOP_N_EMPTY)
        npm_outcome = FetchOutcome(state=FetchState.FOUND, metadata=meta)
        pypi_outcome = _pypi_equivalent_outcome(meta)

        npm_signals = layer2_metadata.evaluate(npm_outcome, _DEFAULT_CONFIG)
        pypi_signals = layer2_metadata.evaluate(pypi_outcome, _DEFAULT_CONFIG)

        npm_total = sum(s.weight for s in npm_signals)
        assert npm_total == _DEFAULT_CONFIG.c2_max_contrib  # capado a 10
        assert _signal_tuples(npm_signals) == _signal_tuples(pypi_signals)


# ===========================================================================
# R4.4 — metadata npm degradada => no inventa senales en las capas agnosticas
# ===========================================================================


class TestR44NpmDegradedNoInventedSignals:
    """R4.4: flags degradados (`time` ausente, `versions` no-dict) => no inventa senal."""

    def test_time_ausente_no_emite_new_package(self) -> None:
        # `time` ausente => first_release_epoch None => la edad de Capa 0 no dispara.
        meta = _extract_metadata({"versions": {"1.0.0": {}}}, "pkg", _TOP_N_EMPTY)
        assert meta.first_release_epoch is None
        outcome = FetchOutcome(state=FetchState.FOUND, metadata=meta)
        signals = layer0_existence.evaluate(outcome, _DEFAULT_CONFIG, now_epoch=_NOW)
        assert all(s.code is not SignalCode.NEW_PACKAGE for s in signals)

    def test_versions_no_dict_releases_cero_dispara_weak_no_inventa_otra(self) -> None:
        """`versions` no-dict => releases_count 0 (fail-closed), no un conteo inventado.

        Con 0 releases y campos ausentes, Capa 2 emite las senales blandas reglamentarias
        (WEAK + LOW), pero el conteo no se inventa: deriva del mapeo fail-closed (R4.4).
        """
        meta = _extract_metadata({"versions": "not-a-dict"}, "pkg", _TOP_N_EMPTY)
        assert meta.releases_count == 0
        outcome = FetchOutcome(state=FetchState.FOUND, metadata=meta)
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        codes = {s.code for s in signals}
        # Solo las senales reglamentarias L2 (sin codigos espurios).
        assert codes <= {SignalCode.WEAK_METADATA, SignalCode.LOW_VERIFIABILITY}
        assert codes  # al menos LOW_VERIFIABILITY (sin repo)

    def test_payload_anomalo_completo_no_emite_new_package_ni_crashea(self) -> None:
        """Packument totalmente anomalo => fail-closed: sin NEW_PACKAGE, capas no lanzan."""
        meta = _extract_metadata(
            {"time": 123, "versions": "x", "repository": True}, "pkg", _TOP_N_EMPTY
        )
        outcome = FetchOutcome(state=FetchState.FOUND, metadata=meta)
        l0 = layer0_existence.evaluate(outcome, _DEFAULT_CONFIG, now_epoch=_NOW)
        l2 = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        assert all(s.code is not SignalCode.NEW_PACKAGE for s in l0)
        # Capa 2 puede emitir blandas reglamentarias, pero nunca codigos fuera del conjunto.
        assert {s.code for s in l2} <= {
            SignalCode.WEAK_METADATA,
            SignalCode.LOW_VERIFIABILITY,
        }
