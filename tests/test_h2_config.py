"""Suite H2-T02 (+ H2-T16 fragments): config Capa 3, modelos Advisory/Protocol,
cache blob y transporte post_json con servidor local malicioso.

Cubre SOLO los subsistemas asignados a esta ola:
  - core/config.py   : defaults R5, host/path/degraded_status, precedencia, dot-segments
  - core/models.py   : Advisory frozen+slots, DependencyResult.advisories aditivo,
                       nuevos SignalCode/Layer
  - core/threatintel/source.py : ThreatIntelResult frozen, MaliceState, Protocol
  - core/net/http_client.py    : post_json, allowlist por-instancia, redirect handler,
                                 429->retry
  - core/cache/disk_cache.py   : get_blob/put_blob (complemento test_disk_cache_blob.py)

Mentalidad security-pen-testing en las secciones de red y cache.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config, load_config
from slopguard.core.errors import InvalidConfigError, NetworkUnverifiableError
from slopguard.core.models import (
    Advisory,
    DependencyResult,
    Layer,
    SignalCode,
    Status,
    Verdict,
)
from slopguard.core.net import http_client as hc
from slopguard.core.net.http_client import SecureHttpClient
from slopguard.core.threatintel.source import (
    MaliceState,
    ThreatIntelResult,
)

# ---------------------------------------------------------------------------
# Constantes de test
# ---------------------------------------------------------------------------

_NOW: float = 1_717_200_000.0  # epoch fijo (alineado con conftest)
_OSV_TTL = 6 * 3600
_WATCHLIST_TTL = 24 * 3600

# Advisory canónico reutilizable
_ADV_URL = "https://osv.dev/vulnerability/MAL-2025-47868"
_ADV1 = Advisory(id="MAL-2025-47868", kind="malicious", url=_ADV_URL, source="osv")
_ADV_MIN_URL = "https://osv.dev/vulnerability/MAL-1"
_ADV_MIN = Advisory(id="MAL-1", kind="malicious", url=_ADV_MIN_URL, source="osv")


# ===========================================================================
# SECCION 1 — Modelos (H2-T01 / H2-T16)
# ===========================================================================


class TestAdvisoryModel:
    """Advisory: frozen+slots, campos obligatorios, inmutabilidad."""

    def test_advisory_construido_correctamente(self) -> None:
        assert _ADV1.id == "MAL-2025-47868"
        assert _ADV1.kind == "malicious"
        assert _ADV1.url == _ADV_URL
        assert _ADV1.source == "osv"

    def test_advisory_frozen_rechaza_mutacion(self) -> None:
        adv = Advisory(id="MAL-1", kind="malicious", url="u", source="osv")
        with pytest.raises((AttributeError, TypeError)):
            adv.id = "MAL-2"  # type: ignore[misc]

    def test_advisory_slots_no_permite_atributo_nuevo(self) -> None:
        adv = Advisory(id="MAL-1", kind="malicious", url="u", source="osv")
        # frozen+slots: intento de nuevo atributo lanza AttributeError o TypeError
        with pytest.raises((AttributeError, TypeError)):
            adv.extra = "x"  # type: ignore[attr-defined]

    def test_advisory_igualdad_valor(self) -> None:
        a = Advisory(id="MAL-1", kind="malicious", url="u", source="osv")
        b = Advisory(id="MAL-1", kind="malicious", url="u", source="osv")
        assert a == b

    def test_advisory_distintos_son_diferentes(self) -> None:
        a = Advisory(id="MAL-1", kind="malicious", url="u1", source="osv")
        b = Advisory(id="MAL-2", kind="malicious", url="u2", source="osv")
        assert a != b


class TestDependencyResultAdvisories:
    """DependencyResult.advisories: aditivo con default () — retro-compat (R-Compat.1)."""

    def _base(self) -> DependencyResult:
        return DependencyResult(
            name="requests",
            version_pin=None,
            status=Status.OK,
            verdict=Verdict.ALLOW,
            score=10,
            signals=(),
            suspected_target=None,
            error_category=None,
        )

    def test_advisories_default_tupla_vacia(self) -> None:
        r = self._base()
        assert r.advisories == ()
        assert isinstance(r.advisories, tuple)

    def test_advisories_con_datos(self) -> None:
        r = DependencyResult(
            name="bioql",
            version_pin=None,
            status=Status.OK,
            verdict=Verdict.BLOCK,
            score=None,
            signals=(),
            suspected_target=None,
            error_category=None,
            advisories=(_ADV1,),
        )
        assert len(r.advisories) == 1
        assert r.advisories[0].id == "MAL-2025-47868"

    def test_advisories_frozen_rechaza_mutacion(self) -> None:
        r = self._base()
        with pytest.raises((AttributeError, TypeError)):
            r.advisories = ()  # type: ignore[misc]


class TestNewSignalCodes:
    """Nuevos SignalCode y Layer L3 del Hito 2."""

    def test_layer_l3_existe(self) -> None:
        assert Layer.L3.value == 3

    def test_signal_code_malicious(self) -> None:
        assert SignalCode.MALICIOUS.value == "malicious"

    def test_signal_code_known_hallucination(self) -> None:
        assert SignalCode.KNOWN_HALLUCINATION.value == "known_hallucination"

    def test_signal_code_threatintel_unverifiable(self) -> None:
        assert SignalCode.THREATINTEL_UNVERIFIABLE.value == "threatintel_unverifiable"

    def test_todos_los_nuevos_en_el_enum(self) -> None:
        """Los tres nuevos codigos coexisten con los del Hito 1 sin colision."""
        codes = {c.value for c in SignalCode}
        assert "malicious" in codes
        assert "known_hallucination" in codes
        assert "threatintel_unverifiable" in codes
        # Hito 1 intactos
        assert "nonexistent" in codes
        assert "typosquat" in codes


# ===========================================================================
# SECCION 2 — Modelos de transporte threat-intel (H2-T03 / H2-T16)
# ===========================================================================


class TestMaliceState:
    """MaliceState: StrEnum con los 4 valores del contrato §2.2."""

    def test_valores_correctos(self) -> None:
        assert MaliceState.CLEAN.value == "clean"
        assert MaliceState.MALICIOUS.value == "malicious"
        assert MaliceState.KNOWN_HALLUCINATION.value == "known_hallucination"
        assert MaliceState.UNVERIFIABLE.value == "unverifiable"

    def test_str_enum_serializable(self) -> None:
        assert MaliceState.MALICIOUS.value == "malicious"


class TestThreatIntelResult:
    """ThreatIntelResult: frozen+slots, defaults, invariantes del contrato."""

    def test_clean_sin_advisories(self) -> None:
        r = ThreatIntelResult(name="requests", state=MaliceState.CLEAN)
        assert r.advisories == ()
        assert r.watchlist_source is None
        assert r.watchlist_date is None
        assert r.unverifiable_reason is None

    def test_malicious_con_advisories(self) -> None:
        r = ThreatIntelResult(name="bioql", state=MaliceState.MALICIOUS, advisories=(_ADV_MIN,))
        assert len(r.advisories) == 1
        assert r.advisories[0].id == "MAL-1"

    def test_unverifiable_con_razon(self) -> None:
        r = ThreatIntelResult(
            name="flaky", state=MaliceState.UNVERIFIABLE, unverifiable_reason="timeout"
        )
        assert r.unverifiable_reason == "timeout"

    def test_known_hallucination_con_atribucion(self) -> None:
        r = ThreatIntelResult(
            name="djangoo",
            state=MaliceState.KNOWN_HALLUCINATION,
            watchlist_source="depscope.dev",
            watchlist_date="2026-06-20",
        )
        assert r.watchlist_source == "depscope.dev"
        assert r.watchlist_date == "2026-06-20"

    def test_frozen_rechaza_mutacion(self) -> None:
        r = ThreatIntelResult(name="x", state=MaliceState.CLEAN)
        with pytest.raises((AttributeError, TypeError)):
            r.name = "y"  # type: ignore[misc]

    def test_advisories_es_tupla(self) -> None:
        r = ThreatIntelResult(name="x", state=MaliceState.MALICIOUS, advisories=(_ADV_MIN,))
        assert isinstance(r.advisories, tuple)


class TestThreatIntelSourceProtocol:
    """ThreatIntelSource es un Protocol; verificamos duck-typing y frontera de import."""

    def test_implementacion_minima_satisface_protocolo(self) -> None:
        """Un objeto con los atributos y metodo del contrato es valido."""

        class MinimalSource:
            source_id = "test"
            extra_allowed_hosts: frozenset[str] = frozenset({"api.osv.dev"})

            def query_batch(self, names: Any) -> dict[str, ThreatIntelResult]:
                return {n: ThreatIntelResult(name=n, state=MaliceState.CLEAN) for n in names}

        src = MinimalSource()
        result = src.query_batch(["requests", "flask"])
        assert set(result.keys()) == {"requests", "flask"}
        # Verificamos que satisface el Protocol en runtime (duck-typing)
        _ = src.source_id
        _ = src.extra_allowed_hosts

    def test_source_no_importa_net(self) -> None:
        """source.py no expone simbolos de core.net (refuerza el contrato import-linter 2)."""
        import slopguard.core.threatintel.source as source_mod  # noqa: PLC0415

        # Modulo de origen de cada simbolo expuesto por source.py.
        source_attrs = {
            v.__module__
            for v in vars(source_mod).values()
            if hasattr(v, "__module__")
        }
        # Coincidencia EXACTA por prefijo de paquete (no substring): ningun simbolo
        # expuesto debe provenir de core.net ni de un submodulo suyo.
        net_attrs = {
            m
            for m in source_attrs
            if m == "slopguard.core.net" or (m or "").startswith("slopguard.core.net.")
        }
        assert net_attrs == set(), f"source.py expone simbolos de core.net: {net_attrs}"


# ===========================================================================
# SECCION 3 — Config Capa 3 (H2-T02 / H2-T16)
# ===========================================================================


class TestConfigL3Defaults:
    """Defaults de Capa 3 — tabla R5 (una sola fuente de verdad)."""

    def test_enable_layer3_default_true(self) -> None:
        assert Config().enable_layer3 is True

    def test_osv_host_default(self) -> None:
        assert Config().osv_host == "api.osv.dev"

    def test_osv_query_path_default(self) -> None:
        assert Config().osv_query_path == "/v1/querybatch"

    def test_osv_batch_max_default(self) -> None:
        assert Config().osv_batch_max == 1000

    def test_osv_ttl_cache_horas_default(self) -> None:
        assert Config().osv_ttl_cache_horas == 6

    def test_osv_timeout_total_default(self) -> None:
        assert Config().osv_timeout_total_por_lote_s == 30.0

    def test_osv_reintentos_default(self) -> None:
        assert Config().osv_reintentos == 2

    def test_enable_watchlist_default_false(self) -> None:
        assert Config().enable_watchlist is False

    def test_watchlist_host_default(self) -> None:
        assert Config().watchlist_host == "depscope.dev"

    def test_watchlist_source_path_default(self) -> None:
        assert Config().watchlist_source_path == "/api/benchmark/hallucinations"

    def test_watchlist_ttl_cache_horas_default(self) -> None:
        assert Config().watchlist_ttl_cache_horas == 24

    def test_watchlist_timeout_total_default(self) -> None:
        assert Config().watchlist_timeout_total_s == 30.0

    def test_threatintel_degraded_status_default(self) -> None:
        assert Config().threatintel_degraded_status == "unverifiable"


class TestConfigL3Precedencia:
    """Precedencia CLI > archivo > defaults para campos de Capa 3 (R5.1)."""

    def test_cli_override_enable_layer3(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        assert load_config(None, {"enable_layer3": False}).enable_layer3 is False

    def test_archivo_override_osv_batch_max(self, tmp_path: Path) -> None:
        f = tmp_path / ".slopguard.toml"
        f.write_text("osv_batch_max = 500\n", encoding="utf-8")
        assert load_config(f, {}).osv_batch_max == 500

    def test_cli_supera_archivo_en_degraded_status(self, tmp_path: Path) -> None:
        f = tmp_path / ".slopguard.toml"
        f.write_text('threatintel_degraded_status = "warn"\n', encoding="utf-8")
        cfg = load_config(f, {"threatintel_degraded_status": "unverifiable"})
        assert cfg.threatintel_degraded_status == "unverifiable"

    def test_defaults_cuando_no_hay_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        cfg = load_config(None, {})
        assert cfg.enable_layer3 is True
        assert cfg.enable_watchlist is False
        assert cfg.osv_host == "api.osv.dev"

    def test_enable_watchlist_toml(self, tmp_path: Path) -> None:
        f = tmp_path / ".slopguard.toml"
        f.write_text("enable_watchlist = true\n", encoding="utf-8")
        assert load_config(f, {}).enable_watchlist is True


class TestConfigL3ValidacionHost:
    """Validacion de osv_host / watchlist_host (R5.2, §3.6, anti-SSRF)."""

    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1",        # IP v4
            "::1",              # IP v6
            "169.254.169.254",  # metadata cloud
            "localhost",        # host interno
            "api.osv.dev:443",  # puerto explicito
            "user@api.osv.dev", # userinfo
            "api.osv.dev/v1",   # path incrustado
            "evil.com",         # dominio no cerrado
            "",                 # cadena vacia
        ],
    )
    def test_osv_host_invalido_es_error(self, host: str) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"osv_host": host})

    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1",
            "localhost",
            "depscope.dev:80",
            "user@depscope.dev",
            "evil.com",
        ],
    )
    def test_watchlist_host_invalido_es_error(self, host: str) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"watchlist_host": host})

    def test_osv_host_valido_aceptado(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        assert load_config(None, {"osv_host": "api.osv.dev"}).osv_host == "api.osv.dev"

    def test_watchlist_host_valido_aceptado(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        cfg = load_config(None, {"watchlist_host": "depscope.dev"})
        assert cfg.watchlist_host == "depscope.dev"


class TestConfigL3ValidacionPath:
    """Validacion de osv_query_path / watchlist_source_path (R5.2, §3.6).

    Hallazgo amarillo corregido: dot-segments '..' deben rechazarse aunque el charset
    base los permita, para evitar path-traversal dentro del mismo host (EARS R5.2).
    """

    def test_dot_segments_rechazados_en_osv_path(self) -> None:
        """'/v1/../admin' debe rechazarse — hallazgo amarillo H2-T16."""
        with pytest.raises(InvalidConfigError, match=r"'\.\.'"):
            load_config(None, {"osv_query_path": "/v1/../admin"})

    def test_dot_segments_doble_nivel_rechazado(self) -> None:
        with pytest.raises(InvalidConfigError, match=r"'\.\.'"):
            load_config(None, {"osv_query_path": "/v1/../../etc"})

    def test_dot_segments_watchlist_rechazados(self) -> None:
        with pytest.raises(InvalidConfigError, match=r"'\.\.'"):
            load_config(None, {"watchlist_source_path": "/api/../admin"})

    def test_path_sin_slash_inicial_rechazado(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"osv_query_path": "v1/querybatch"})

    def test_path_con_espacio_rechazado(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"osv_query_path": "/v1/query batch"})

    def test_path_crlf_saneado_y_aceptado(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CRLF se sanea ANTES de la validacion de path (sanitize_for_output).

        El saneador convierte '/v1/query\\r\\nbatch' en '/v1/querybatch',
        que es un path valido. La defensa contra CRLF la aplica la capa de
        sanitize_for_output (STR_FIELDS), no la regex de path.
        """
        monkeypatch.chdir(tmp_path)
        cfg = load_config(None, {"osv_query_path": "/v1/query\r\nbatch"})
        assert "\r" not in cfg.osv_query_path
        assert "\n" not in cfg.osv_query_path

    def test_path_valido_aceptado(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        cfg = load_config(None, {"osv_query_path": "/v1/querybatch"})
        assert cfg.osv_query_path == "/v1/querybatch"

    def test_path_con_subdirectorios_valido(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        cfg = load_config(None, {"watchlist_source_path": "/api/benchmark/hallucinations"})
        assert cfg.watchlist_source_path == "/api/benchmark/hallucinations"


class TestConfigL3ValidacionDegradedStatus:
    """Validacion de threatintel_degraded_status (R5.2)."""

    def test_valor_unverifiable_aceptado(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        cfg = load_config(None, {"threatintel_degraded_status": "unverifiable"})
        assert cfg.threatintel_degraded_status == "unverifiable"

    def test_valor_warn_aceptado(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        cfg = load_config(None, {"threatintel_degraded_status": "warn"})
        assert cfg.threatintel_degraded_status == "warn"

    def test_valor_invalido_es_error(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"threatintel_degraded_status": "block"})

    def test_valor_inventado_es_error(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"threatintel_degraded_status": "allow_all"})


class TestConfigL3ValidacionRangos:
    """Campos numericos de Capa 3 deben ser > 0 (R5.2)."""

    @pytest.mark.parametrize(
        "field",
        [
            "osv_batch_max",
            "osv_ttl_cache_horas",
            "osv_timeout_total_por_lote_s",
            "watchlist_ttl_cache_horas",
            "watchlist_timeout_total_s",
        ],
    )
    def test_campo_cero_rechazado(self, field: str) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {field: 0})

    def test_osv_reintentos_cero_aceptado(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """osv_reintentos=0 significa 'sin reintentos'; no esta en _STRICTLY_POSITIVE."""
        monkeypatch.chdir(tmp_path)
        assert load_config(None, {"osv_reintentos": 0}).osv_reintentos == 0

    def test_bool_rechazado_en_campo_int_l3(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"osv_batch_max": True})


class TestConfigL3BoolFields:
    """Campos booleanos de Capa 3: exigen isinstance bool estricto (R5.2)."""

    def test_entero_rechazado_para_enable_layer3(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"enable_layer3": 1})

    def test_string_rechazado_para_enable_watchlist(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"enable_watchlist": "true"})

    def test_false_aceptado_para_enable_layer3(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        assert load_config(None, {"enable_layer3": False}).enable_layer3 is False


# ===========================================================================
# SECCION 4 — HTTP post_json + allowlist por-instancia (RISK-H2-1)
# ===========================================================================


class _FakeResponse:
    """Doble de respuesta urllib para test sin socket."""

    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self._body = io.BytesIO(body)
        self._raw_headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.headers = self

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._raw_headers.get(key.lower(), default)

    def read(self, size: int) -> bytes:
        return self._body.read(size)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        self._body.close()


def _osv_client() -> SecureHttpClient:
    """Cliente con allowlist efectiva = {pypi.org, api.osv.dev}."""
    return SecureHttpClient(extra_allowed_hosts=frozenset({"api.osv.dev"}))


def _inject_response(
    monkeypatch: pytest.MonkeyPatch,
    client: SecureHttpClient,
    body: bytes,
    headers: dict[str, str] | None = None,
) -> None:
    """Inyecta una respuesta falsa en el opener del cliente."""

    def fake_open(_req: object, timeout: float) -> _FakeResponse:
        return _FakeResponse(body, headers)

    monkeypatch.setattr(client._opener, "open", fake_open)


class TestPostJsonAllowlist:
    """post_json rechaza URLs fuera del allowlist efectivo (NFR-Seg.1)."""

    def test_url_osv_aceptada_por_allowlist_efectivo(self) -> None:
        """api.osv.dev en extra => _validate_url no lanza."""
        _osv_client()._validate_url("https://api.osv.dev/v1/querybatch")

    def test_post_a_host_no_permitido_rechazado(self) -> None:
        with pytest.raises(NetworkUnverifiableError, match="allowlist"):
            _osv_client()._validate_url("https://evil.com/v1/querybatch")

    def test_post_a_depscope_sin_watchlist_rechazado(self) -> None:
        """depscope.dev NO en allowlist cuando watchlist off."""
        with pytest.raises(NetworkUnverifiableError, match="allowlist"):
            _osv_client()._validate_url("https://depscope.dev/api/hallucinations")

    def test_post_a_depscope_con_watchlist_aceptado(self) -> None:
        client = SecureHttpClient(
            extra_allowed_hosts=frozenset({"api.osv.dev", "depscope.dev"})
        )
        client._validate_url("https://depscope.dev/api/hallucinations")

    def test_post_http_scheme_rechazado(self) -> None:
        with pytest.raises(NetworkUnverifiableError):
            _osv_client()._validate_url("http://api.osv.dev/v1/querybatch")

    def test_base_allowed_hosts_no_contaminada(self) -> None:
        """ALLOWED_HOSTS base debe ser exactamente {pypi.org} (ADR-09)."""
        assert hc.ALLOWED_HOSTS == frozenset({"pypi.org"})

    def test_extra_no_modifica_la_constante_global(self) -> None:
        _osv_client()
        assert hc.ALLOWED_HOSTS == frozenset({"pypi.org"})

    def test_allowlist_efectivo_es_union(self) -> None:
        client = SecureHttpClient(extra_allowed_hosts=frozenset({"api.osv.dev"}))
        assert client._allowed_hosts == frozenset({"pypi.org", "api.osv.dev"})

    def test_post_json_serializa_y_devuelve_dict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        resp_body = json.dumps({"results": []}).encode()
        client = _osv_client()
        _inject_response(monkeypatch, client, resp_body)
        result = client.post_json(
            "https://api.osv.dev/v1/querybatch",
            {"queries": []},
            connect_timeout_s=1.0,
            read_timeout_s=5.0,
            max_response_bytes=100_000,
            max_json_depth=10,
        )
        assert result == {"results": []}

    def test_post_json_body_no_serializable_lanza(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cuerpo no serializable => NetworkUnverifiableError, nunca TypeError crudo."""
        client = _osv_client()

        def fake_open(_req: object, timeout: float) -> _FakeResponse:
            return _FakeResponse(b'{"ok":1}')

        monkeypatch.setattr(client._opener, "open", fake_open)
        with pytest.raises(NetworkUnverifiableError):
            client.post_json(
                "https://api.osv.dev/v1/querybatch",
                {"queries": [object()]},
                connect_timeout_s=1.0,
                read_timeout_s=5.0,
                max_response_bytes=100_000,
                max_json_depth=10,
            )

    def test_post_json_respuesta_lista_lanza(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Si la respuesta JSON no es un objeto (ej. lista) => NetworkUnverifiableError."""
        client = _osv_client()
        _inject_response(monkeypatch, client, b"[1,2,3]")
        with pytest.raises(NetworkUnverifiableError, match="no es un objeto"):
            client.post_json(
                "https://api.osv.dev/v1/querybatch",
                {"queries": []},
                connect_timeout_s=1.0,
                read_timeout_s=5.0,
                max_response_bytes=100_000,
                max_json_depth=10,
            )


# ---------------------------------------------------------------------------
# Servidor HTTP local malicioso
# ---------------------------------------------------------------------------


class _LocalServer:
    """Servidor HTTP local de prueba en un hilo daemon."""

    def __init__(self, handler_class: type[BaseHTTPRequestHandler]) -> None:
        self._server = HTTPServer(("127.0.0.1", 0), handler_class)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()


class _RedirectHandler(BaseHTTPRequestHandler):
    """Servidor que devuelve un redirect 302 a una URL configurable."""

    redirect_to: str = ""

    def do_POST(self) -> None:
        self.send_response(302)
        self.send_header("Location", self.__class__.redirect_to)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


class _RateLimitHandler(BaseHTTPRequestHandler):
    """Servidor que siempre devuelve 429 (rate limit)."""

    def do_POST(self) -> None:
        self.send_response(429)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"rate limited"}')

    def log_message(self, *_args: object) -> None:
        pass


class _JsonBombHandler(BaseHTTPRequestHandler):
    """Servidor que devuelve un JSON con profundidad excesiva."""

    def do_POST(self) -> None:
        bomb = b'{"a":' * 100 + b"1" + b"}" * 100
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(bomb)))
        self.end_headers()
        self.wfile.write(bomb)

    def log_message(self, *_args: object) -> None:
        pass


class _BigBodyHandler(BaseHTTPRequestHandler):
    """Servidor que devuelve un cuerpo mayor que max_response_bytes."""

    def do_POST(self) -> None:
        body = b"x" * 200
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


def _monkeypatch_client_for_http(
    monkeypatch: pytest.MonkeyPatch, client: SecureHttpClient
) -> None:
    """Parchea el cliente para que acepte http://127.0.0.1 en tests de servidor local.

    En produccion la allowlist solo admite https. Para tests de red local se parchea
    `_is_allowed` para permitir http sin TLS (convencion del proyecto, ver test_net.py).
    """
    monkeypatch.setattr(hc, "_is_allowed", lambda scheme, host, allowed=None: True)
    # El loopback usa puerto efimero: neutraliza el rechazo de puerto explicito (A10 SSRF)
    # SOLO para el test de red local, igual que la allowlist http (convencion del proyecto).
    monkeypatch.setattr(hc, "_reject_port_and_userinfo", lambda _parts: None)
    http_handler = urllib.request.HTTPHandler()
    opener = urllib.request.OpenerDirector()
    opener.add_handler(http_handler)
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    monkeypatch.setattr(client, "_opener", opener)


def _fake_req() -> urllib.request.Request:
    """Objeto Request minimo valido para llamar al redirect handler en tests."""
    return urllib.request.Request("https://api.osv.dev/v1/querybatch")


class TestRedirectHandlerConAllowlistEfectivo:
    """El redirect handler usa el allowlist EFECTIVO de la instancia (fix SSRF §3.3)."""

    def test_redirect_cross_host_rechazado(self) -> None:
        """Redirect api.osv.dev -> host-arbitrario => NetworkUnverifiableError."""
        handler = hc._RejectRedirectHandler(_osv_client()._allowed_hosts)
        with pytest.raises(NetworkUnverifiableError):
            handler.redirect_request(
                _fake_req(), None, 302, "Found", None, "https://evil.com/x"
            )

    def test_redirect_osv_a_pypi_rechazado(self) -> None:
        """api.osv.dev -> pypi.org: ambos en el efectivo, pero redirect siempre rechazado."""
        handler = hc._RejectRedirectHandler(_osv_client()._allowed_hosts)
        with pytest.raises(NetworkUnverifiableError):
            handler.redirect_request(
                _fake_req(), None, 302, "Moved", None, "https://pypi.org/x"
            )

    def test_redirect_a_localhost_rechazado(self) -> None:
        handler = hc._RejectRedirectHandler(frozenset({"api.osv.dev", "pypi.org"}))
        with pytest.raises(NetworkUnverifiableError):
            handler.redirect_request(
                _fake_req(), None, 302, "Found", None, "https://localhost/x"
            )

    def test_redirect_dentro_del_efectivo_igual_rechazado(self) -> None:
        """Politica: no se sigue ningun redirect, aunque sea dentro del mismo host."""
        efectivo = frozenset({"api.osv.dev", "pypi.org"})
        handler = hc._RejectRedirectHandler(efectivo)
        with pytest.raises(NetworkUnverifiableError):
            handler.redirect_request(
                _fake_req(), None, 302, "Found", None, "https://api.osv.dev/x"
            )


class TestRateLimitYReintentos:
    """429 es transitorio (R1.7); clasificacion correcta de HTTP statuses."""

    def test_429_es_transitorio(self) -> None:
        assert hc._is_transient_http_status(429) is True

    def test_5xx_es_transitorio(self) -> None:
        assert hc._is_transient_http_status(500) is True
        assert hc._is_transient_http_status(503) is True

    def test_4xx_no_429_no_es_transitorio(self) -> None:
        assert hc._is_transient_http_status(400) is False
        assert hc._is_transient_http_status(404) is False
        assert hc._is_transient_http_status(403) is False

    def test_3xx_no_es_transitorio(self) -> None:
        assert hc._is_transient_http_status(302) is False

    def test_server_429_produce_network_error_transitorio(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Servidor local que devuelve 429 => is_transient=True, status_code=429."""
        server = _LocalServer(_RateLimitHandler)
        server.start()
        try:
            client = _osv_client()
            _monkeypatch_client_for_http(monkeypatch, client)
            with pytest.raises(NetworkUnverifiableError) as exc_info:
                client.post_json(
                    f"http://127.0.0.1:{server.port}/v1/querybatch",
                    {"queries": []},
                    connect_timeout_s=2.0,
                    read_timeout_s=2.0,
                    max_response_bytes=100_000,
                    max_json_depth=10,
                )
            assert exc_info.value.is_transient is True
            assert exc_info.value.status_code == 429
        finally:
            server.stop()

    def test_server_redirect_cross_host_lanza(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Servidor que devuelve redirect a host externo: rechazado."""

        class _Handler(_RedirectHandler):
            redirect_to = "https://evil.com/steal"

        server = _LocalServer(_Handler)
        server.start()
        try:
            client = _osv_client()
            # Reemplazamos opener con HTTP pero mantenemos el redirect handler REAL
            # inyectado con el conjunto efectivo de la instancia.
            http_handler = urllib.request.HTTPHandler()
            opener = urllib.request.OpenerDirector()
            opener.add_handler(http_handler)
            opener.add_handler(hc._RejectRedirectHandler(client._allowed_hosts))
            opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
            opener.add_handler(urllib.request.HTTPErrorProcessor())
            monkeypatch.setattr(client, "_opener", opener)
            monkeypatch.setattr(hc, "_is_allowed", lambda s, h, a=None: True)
            # Loopback con puerto efimero: neutraliza el rechazo de puerto (A10) en este test.
            monkeypatch.setattr(hc, "_reject_port_and_userinfo", lambda _parts: None)
            with pytest.raises(NetworkUnverifiableError):
                client.post_json(
                    f"http://127.0.0.1:{server.port}/v1/querybatch",
                    {"queries": []},
                    connect_timeout_s=2.0,
                    read_timeout_s=2.0,
                    max_response_bytes=100_000,
                    max_json_depth=10,
                )
        finally:
            server.stop()


class TestJsonBombYBodyGrande:
    """Defensas anti JSON-bomb y body excesivo en post_json (NFR-Seg.2)."""

    def test_json_bomb_desde_servidor_local(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Servidor con JSON profundidad > max_json_depth => NetworkUnverifiableError."""
        server = _LocalServer(_JsonBombHandler)
        server.start()
        try:
            client = _osv_client()
            _monkeypatch_client_for_http(monkeypatch, client)
            with pytest.raises(NetworkUnverifiableError):
                client.post_json(
                    f"http://127.0.0.1:{server.port}/v1/querybatch",
                    {"queries": []},
                    connect_timeout_s=2.0,
                    read_timeout_s=2.0,
                    max_response_bytes=10_000,
                    max_json_depth=50,
                )
        finally:
            server.stop()

    def test_body_excede_limite_lanza(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Body de 200 bytes con limite de 100 bytes => NetworkUnverifiableError."""
        server = _LocalServer(_BigBodyHandler)
        server.start()
        try:
            client = _osv_client()
            _monkeypatch_client_for_http(monkeypatch, client)
            with pytest.raises(NetworkUnverifiableError):
                client.post_json(
                    f"http://127.0.0.1:{server.port}/v1/querybatch",
                    {"queries": []},
                    connect_timeout_s=2.0,
                    read_timeout_s=2.0,
                    max_response_bytes=100,  # límite bajo
                    max_json_depth=10,
                )
        finally:
            server.stop()


# ===========================================================================
# SECCION 5 — Cache blob (DiskCache.get_blob / put_blob) — complemento
# ===========================================================================


def _cache(tmp_path: Path, *, enabled: bool = True) -> DiskCache:
    return DiskCache(tmp_path / "cache", 24, enabled=enabled)


def _blob_path(root: Path, namespace: str, key: str) -> Path:
    digest = hashlib.sha256(f"{namespace}:{key}".encode()).hexdigest()
    return root / f"{digest}.json"


def _identity_validator(payload: dict[str, Any]) -> dict[str, Any] | None:
    return payload


def _osv_payload(name: str = "bioql") -> dict[str, Any]:
    return {
        "source": "osv",
        "ecosystem": "pypi",
        "name": name,
        "state": "malicious",
        "advisories": [{"id": "MAL-2025-47868", "kind": "malicious", "source": "osv"}],
    }


class TestCacheBlobTTL:
    """TTL por-llamada: OSV 6h != watchlist 24h."""

    def test_blob_al_limite_exacto_es_hit(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        got = cache.get_blob(
            "osv",
            "pypi:bioql",
            _identity_validator,
            ttl_segundos=_OSV_TTL,
            now=_NOW + _OSV_TTL,
        )
        assert got is not None

    def test_blob_un_segundo_despues_es_miss(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        got = cache.get_blob(
            "osv",
            "pypi:bioql",
            _identity_validator,
            ttl_segundos=_OSV_TTL,
            now=_NOW + _OSV_TTL + 1,
        )
        assert got is None

    def test_watchlist_ttl_24h_mas_largo(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("watchlist", "depscope.dev/api", {"names": ["reqe"]}, now=_NOW)
        later = _NOW + _OSV_TTL + 1  # pasado el TTL de OSV pero no el de watchlist
        assert (
            cache.get_blob(
                "watchlist",
                "depscope.dev/api",
                _identity_validator,
                ttl_segundos=_WATCHLIST_TTL,
                now=later,
            )
            is not None
        )
        assert (
            cache.get_blob(
                "watchlist",
                "depscope.dev/api",
                _identity_validator,
                ttl_segundos=_OSV_TTL,
                now=later,
            )
            is None
        )


class TestCacheBlobSchemaDesviado:
    """Blob con schema incorrecto, corrupto o state=unverifiable => miss."""

    def test_schema_incorrecto_es_miss(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        path = _blob_path(tmp_path / "cache", "osv", "pypi:bioql")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            json.dumps(
                {**_osv_payload(), "cache_schema_version": "old", "fetched_at": _NOW}
            ).encode()
        )
        assert (
            cache.get_blob(
                "osv", "pypi:bioql", _identity_validator,
                ttl_segundos=_OSV_TTL, now=_NOW,
            )
            is None
        )

    def test_json_corrupto_es_miss_sin_crash(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        path = _blob_path(tmp_path / "cache", "osv", "pypi:bioql")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"no es json { ")
        assert (
            cache.get_blob(
                "osv", "pypi:bioql", _identity_validator,
                ttl_segundos=_OSV_TTL, now=_NOW,
            )
            is None
        )

    def test_blob_lista_en_vez_de_objeto_es_miss(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        path = _blob_path(tmp_path / "cache", "osv", "pypi:bioql")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"[1,2,3]")
        assert (
            cache.get_blob(
                "osv", "pypi:bioql", _identity_validator,
                ttl_segundos=_OSV_TTL, now=_NOW,
            )
            is None
        )

    def test_state_unverifiable_no_se_cachea(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        payload = {**_osv_payload("flaky"), "state": "unverifiable"}
        cache.put_blob("osv", "pypi:flaky", payload, now=_NOW)
        assert not _blob_path(tmp_path / "cache", "osv", "pypi:flaky").exists()


class TestCacheBlobPermsYAtomicidad:
    """Permisos 0700/0600 y escritura atomica (R9.7)."""

    def test_dir_0700_archivo_0600(self, tmp_path: Path) -> None:
        root = tmp_path / "cache"
        cache = DiskCache(root, 24, enabled=True)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        assert stat.S_IMODE(os.stat(root).st_mode) == 0o700
        path = _blob_path(root, "osv", "pypi:bioql")
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_blob_en_disco_es_json_no_pickle(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        raw = _blob_path(tmp_path / "cache", "osv", "pypi:bioql").read_bytes()
        parsed = json.loads(raw)
        assert parsed["source"] == "osv"


class TestCacheBlobNoCache:
    """--no-cache / enabled=False => ni lee ni escribe (R6.3)."""

    def test_disabled_no_escribe(self, tmp_path: Path) -> None:
        root = tmp_path / "cache"
        DiskCache(root, 24, enabled=False).put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        assert not _blob_path(root, "osv", "pypi:bioql").exists()

    def test_disabled_no_lee(self, tmp_path: Path) -> None:
        _cache(tmp_path).put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        disabled = DiskCache(tmp_path / "cache", 24, enabled=False)
        assert (
            disabled.get_blob(
                "osv", "pypi:bioql", _identity_validator,
                ttl_segundos=_OSV_TTL, now=_NOW,
            )
            is None
        )


class TestCacheBlobAntiTraversal:
    """Clave con '../' no escapa del root (sha256 elimina traversal por construccion)."""

    def test_clave_traversal_no_escapa(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:../../etc/passwd", _osv_payload("evil"), now=_NOW)
        root = tmp_path / "cache"
        if root.exists():
            archivos = [p.name for p in root.iterdir() if p.suffix == ".json"]
            assert all(
                all(c in "0123456789abcdef" for c in f.removesuffix(".json"))
                for f in archivos
            )

    def test_namespaces_no_colisionan(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "k", {"who": "osv"}, now=_NOW)
        cache.put_blob("watchlist", "k", {"who": "watchlist"}, now=_NOW)
        osv = cache.get_blob("osv", "k", _identity_validator, ttl_segundos=_OSV_TTL, now=_NOW)
        wl = cache.get_blob(
            "watchlist", "k", _identity_validator, ttl_segundos=_WATCHLIST_TTL, now=_NOW
        )
        assert osv is not None and osv["who"] == "osv"
        assert wl is not None and wl["who"] == "watchlist"

    def test_blob_separado_del_camino_tipado(self, tmp_path: Path) -> None:
        """sha256('osv:pypi:bioql') != sha256('pypi:bioql'): no colisionan."""
        blob = _blob_path(tmp_path / "cache", "osv", "pypi:bioql")
        typed_digest = hashlib.sha256(b"pypi:bioql").hexdigest()
        typed = tmp_path / "cache" / f"{typed_digest}.json"
        assert blob != typed


class TestCacheBlobNoPersistenciaUnverifiable:
    """UNVERIFIABLE nunca se persiste (degradacion segura, §2.5/ADR-10)."""

    def test_state_unverifiable_bloqueado_en_put(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:x", {"name": "x", "state": "unverifiable"}, now=_NOW)
        assert not _blob_path(tmp_path / "cache", "osv", "pypi:x").exists()

    def test_schema_version_fijado_por_put(self, tmp_path: Path) -> None:
        """put_blob sobreescribe cache_schema_version sin importar lo que pase el caller."""
        cache = _cache(tmp_path)
        payload = {**_osv_payload(), "cache_schema_version": "INTRUSO", "fetched_at": 0.0}
        cache.put_blob("osv", "pypi:bioql", payload, now=_NOW)
        raw = json.loads(_blob_path(tmp_path / "cache", "osv", "pypi:bioql").read_bytes())
        assert raw["cache_schema_version"] == "ti-1"
        assert raw["fetched_at"] == _NOW


# ===========================================================================
# SECCION 6 — Invariante estatica de allowlist (ADR-09 / Propiedad estructural 4)
# ===========================================================================


class TestAllowlistGuardiaEstatico:
    """Dos invariantes de ADR-09 verificadas como tests."""

    def test_base_es_exactamente_pypi_org(self) -> None:
        """La constante base NUNCA crece con hosts de Capa 3."""
        assert hc.ALLOWED_HOSTS == frozenset({"pypi.org"})

    def test_hosts_efectivos_posibles_son_subconjunto_cerrado(self) -> None:
        """Ningun host fuera de {pypi.org, api.osv.dev, depscope.dev} debe aparecer."""
        cerrado = frozenset({"pypi.org", "api.osv.dev", "depscope.dev"})
        osv_c = SecureHttpClient(extra_allowed_hosts=frozenset({"api.osv.dev"}))
        wl_c = SecureHttpClient(
            extra_allowed_hosts=frozenset({"api.osv.dev", "depscope.dev"})
        )
        base_c = SecureHttpClient()
        assert osv_c._allowed_hosts <= cerrado
        assert wl_c._allowed_hosts <= cerrado
        assert base_c._allowed_hosts <= cerrado

    def test_depscope_no_aparece_sin_watchlist(self) -> None:
        """Si watchlist off, depscope.dev no debe entrar en el allowlist."""
        assert _osv_client()._allowed_hosts == frozenset({"pypi.org", "api.osv.dev"})

    def test_redirect_handler_usa_conjunto_efectivo(self) -> None:
        """El redirect handler del cliente usa el conjunto efectivo, no la global."""
        client = SecureHttpClient(extra_allowed_hosts=frozenset({"api.osv.dev"}))
        efectivo = client._allowed_hosts
        assert efectivo == frozenset({"pypi.org", "api.osv.dev"})
        # Redirect a api.osv.dev SIGUE rechazado (politica: no redirects nunca)
        handler = hc._RejectRedirectHandler(efectivo)
        with pytest.raises(NetworkUnverifiableError):
            handler.redirect_request(
                _fake_req(), None, 302, "Found", None, "https://api.osv.dev/x"
            )
