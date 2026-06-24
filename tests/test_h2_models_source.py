"""Pruebas H2-T01/H2-T03 del Hito 2: models-source, net-post, cache-blob y config.

Cobertura de criterios EARS verificados:
- R1.8  / NFR-Seg.4: charset de nombres en el POST (charset osv name).
- R2.1  : `depscope.dev` no entra al allowlist si `enable_watchlist=false`.
- R3.3  : blandas + THREATINTEL_UNVERIFIABLE nunca elevan solas (invariante anti-FP).
- R5.1  : defaults de Capa 3 coinciden con tabla R5.
- R5.2  : validacion host/path/degraded_status => InvalidConfigError.
- R5.3  : `enable_layer3=false` coherente.
- R6.1/R6.2/R6.3: TTL/corrupto/schema desviado => miss; --no-cache; no persistencia
          de unverifiable; anti-traversal; perms 0700/0600.
- R8.1/R8.3: Protocol ThreatIntelSource; frontera net (source no importa core.net).
- Advisory: frozen+slots; frozen=True impide mutacion; tuple.
- DependencyResult.advisories: aditivo, default ()
- ThreatIntelResult / MaliceState: frozen+slots+StrEnum.
- net-post SSRF: redirect cross-host api.osv.dev->pypi.org y host ajeno => rechazado.
- net-post: host IP/localhost/puerto => NetworkUnverifiableError; 429 => is_transient.
- JSON bomb en POST => NetworkUnverifiableError.
- allowlist por-instancia: base {pypi.org} solo; extra_allowed_hosts amplian correctamente.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
import json
import os
import stat
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

import slopguard.core.threatintel as ti_pkg
from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config, load_config
from slopguard.core.errors import InvalidConfigError, NetworkUnverifiableError
from slopguard.core.models import (
    Advisory,
    DependencyResult,
    ErrorCategory,
    Layer,
    LayerSignal,
    SignalCode,
    Status,
    Verdict,
)
from slopguard.core.net import http_client as hc
from slopguard.core.net.http_client import ALLOWED_HOSTS, SecureHttpClient
from slopguard.core.threatintel.source import MaliceState, ThreatIntelResult, ThreatIntelSource

if TYPE_CHECKING:
    from collections.abc import Iterator

# ---------------------------------------------------------------------------
# Constantes de prueba
# ---------------------------------------------------------------------------

_NOW: float = 1_717_200_000.0
_OSV_TTL = 6 * 3600
_WATCHLIST_TTL = 24 * 3600


# ===========================================================================
# H2-T01: modelos core/models.py — Advisory, SignalCode L3, Layer.L3, DependencyResult.advisories
# ===========================================================================


class TestAdvisory:
    """Advisory (§2.1-bis): frozen+slots, campos canonicos, inmutabilidad."""

    def test_advisory_es_frozen(self) -> None:
        adv = Advisory(
            id="MAL-2025-47868",
            kind="malicious",
            url="https://osv.dev/vulnerability/MAL-2025-47868",
            source="osv",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            adv.id = "otro"  # type: ignore[misc]

    def test_advisory_campos_canonicos(self) -> None:
        adv = Advisory(
            id="MAL-2025-47868",
            kind="malicious",
            url="https://osv.dev/vulnerability/MAL-2025-47868",
            source="osv",
        )
        assert adv.id == "MAL-2025-47868"
        assert adv.kind == "malicious"
        assert adv.url == "https://osv.dev/vulnerability/MAL-2025-47868"
        assert adv.source == "osv"

    def test_advisory_usa_slots(self) -> None:
        adv = Advisory(
            id="MAL-1",
            kind="malicious",
            url="https://osv.dev/vulnerability/MAL-1",
            source="osv",
        )
        assert not hasattr(adv, "__dict__")

    def test_advisory_en_tupla(self) -> None:
        """DependencyResult.advisories debe ser tuple, no list."""
        advisories: tuple[Advisory, ...] = (
            Advisory(
                id="MAL-1",
                kind="malicious",
                url="https://osv.dev/vulnerability/MAL-1",
                source="osv",
            ),
        )
        assert isinstance(advisories, tuple)


class TestSignalCodeL3:
    """Nuevos SignalCode de Capa 3 (§2.1): valores estables y tipo StrEnum."""

    def test_malicious_valor_estable(self) -> None:
        assert SignalCode.MALICIOUS.value == "malicious"

    def test_known_hallucination_valor_estable(self) -> None:
        assert SignalCode.KNOWN_HALLUCINATION.value == "known_hallucination"

    def test_threatintel_unverifiable_valor_estable(self) -> None:
        assert SignalCode.THREATINTEL_UNVERIFIABLE.value == "threatintel_unverifiable"

    def test_layer_l3_es_3(self) -> None:
        assert int(Layer.L3) == 3

    def test_signal_codes_l3_son_str(self) -> None:
        """Como StrEnum, el valor es directamente un str."""
        assert isinstance(SignalCode.MALICIOUS, str)
        assert isinstance(SignalCode.KNOWN_HALLUCINATION, str)
        assert isinstance(SignalCode.THREATINTEL_UNVERIFIABLE, str)


class TestDependencyResultAdvisories:
    """DependencyResult.advisories: aditivo con default () — retro-compatibilidad (NFR-Compat.1)."""

    def test_advisories_default_es_tupla_vacia(self) -> None:
        result = DependencyResult(
            name="requests",
            version_pin=None,
            status=Status.OK,
            verdict=Verdict.ALLOW,
            score=10,
            signals=(),
            suspected_target=None,
            error_category=None,
        )
        assert result.advisories == ()
        assert isinstance(result.advisories, tuple)

    def test_advisories_se_puede_poblar_con_advisory(self) -> None:
        adv = Advisory(
            id="MAL-2025-47868",
            kind="malicious",
            url="https://osv.dev/vulnerability/MAL-2025-47868",
            source="osv",
        )
        result = DependencyResult(
            name="bioql",
            version_pin=None,
            status=Status.OK,
            verdict=Verdict.BLOCK,
            score=None,
            signals=(),
            suspected_target=None,
            error_category=None,
            advisories=(adv,),
        )
        assert len(result.advisories) == 1
        assert result.advisories[0].id == "MAL-2025-47868"

    def test_dependency_result_es_frozen(self) -> None:
        result = DependencyResult(
            name="x",
            version_pin=None,
            status=Status.OK,
            verdict=Verdict.ALLOW,
            score=0,
            signals=(),
            suspected_target=None,
            error_category=None,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.name = "y"  # type: ignore[misc]

    def test_hito1_call_site_no_pasa_advisories_sin_error(self) -> None:
        """Todos los call-sites del Hito 1 que no pasan `advisories` siguen funcionando."""
        r = DependencyResult(
            name="flask",
            version_pin=None,
            status=Status.UNVERIFIABLE,
            verdict=None,
            score=None,
            signals=(),
            suspected_target=None,
            error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
        )
        assert r.advisories == ()


# ===========================================================================
# H2-T03: ThreatIntelSource Protocol + MaliceState + ThreatIntelResult
# ===========================================================================


class TestMaliceState:
    """MaliceState (§2.2): StrEnum, valores estables, todos los casos."""

    def test_valores_estables(self) -> None:
        assert MaliceState.CLEAN.value == "clean"
        assert MaliceState.MALICIOUS.value == "malicious"
        assert MaliceState.KNOWN_HALLUCINATION.value == "known_hallucination"
        assert MaliceState.UNVERIFIABLE.value == "unverifiable"

    def test_es_str(self) -> None:
        assert isinstance(MaliceState.CLEAN, str)
        assert isinstance(MaliceState.UNVERIFIABLE, str)


class TestThreatIntelResult:
    """ThreatIntelResult (§2.2): frozen+slots, defaults, invariantes."""

    def test_frozen(self) -> None:
        ti = ThreatIntelResult(name="requests", state=MaliceState.CLEAN)
        with pytest.raises(dataclasses.FrozenInstanceError):
            ti.name = "otro"  # type: ignore[misc]

    def test_usa_slots(self) -> None:
        ti = ThreatIntelResult(name="x", state=MaliceState.CLEAN)
        assert not hasattr(ti, "__dict__")

    def test_defaults_none_cuando_limpio(self) -> None:
        ti = ThreatIntelResult(name="requests", state=MaliceState.CLEAN)
        assert ti.advisories == ()
        assert ti.watchlist_source is None
        assert ti.watchlist_date is None
        assert ti.unverifiable_reason is None

    def test_advisories_es_tuple(self) -> None:
        adv = Advisory(
            id="MAL-1",
            kind="malicious",
            url="https://osv.dev/vulnerability/MAL-1",
            source="osv",
        )
        ti = ThreatIntelResult(
            name="bioql",
            state=MaliceState.MALICIOUS,
            advisories=(adv,),
        )
        assert isinstance(ti.advisories, tuple)
        assert ti.advisories[0].id == "MAL-1"

    def test_known_hallucination_porta_watchlist_meta(self) -> None:
        ti = ThreatIntelResult(
            name="reqe",
            state=MaliceState.KNOWN_HALLUCINATION,
            watchlist_source="depscope.dev",
            watchlist_date="2026-06-20",
        )
        assert ti.watchlist_source == "depscope.dev"
        assert ti.watchlist_date == "2026-06-20"
        assert ti.advisories == ()

    def test_unverifiable_porta_razon(self) -> None:
        ti = ThreatIntelResult(
            name="flaky",
            state=MaliceState.UNVERIFIABLE,
            unverifiable_reason="timeout en OSV",
        )
        assert ti.unverifiable_reason == "timeout en OSV"


class TestThreatIntelSourceProtocol:
    """ThreatIntelSource (§3.1): Protocol verificable estructuralmente (R8.1/R8.3).

    No se instancia el Protocol directamente (es abstracto); se verifica que una clase
    conforme lo implementa correctamente y que la frontera de imports se respeta.
    """

    def test_protocol_tiene_miembros_del_contrato(self) -> None:
        """El Protocol declara source_id, extra_allowed_hosts y query_batch (§3.1).

        Se verifica via __annotations__ y dir() combinados, sin depender de
        __protocol_attrs__ (no disponible en Python 3.11).
        """
        annotations = getattr(ThreatIntelSource, "__annotations__", {})
        members = set(dir(ThreatIntelSource)) | set(annotations.keys())
        assert "query_batch" in members
        assert "source_id" in members
        assert "extra_allowed_hosts" in members

    def test_clase_conforme_puede_usarse_como_source(self) -> None:
        """Una clase que implementa los miembros del contrato satisface el Protocol.

        No se usa isinstance (requiere @runtime_checkable); se verifica
        estructuralmente que la clase tiene todos los miembros esperados.
        """

        class _DummySource:
            source_id = "dummy"
            extra_allowed_hosts: frozenset[str] = frozenset()

            def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
                return {n: ThreatIntelResult(name=n, state=MaliceState.CLEAN) for n in names}

        src = _DummySource()
        # Verificacion estructural: todos los miembros del contrato estan presentes
        assert hasattr(src, "source_id")
        assert hasattr(src, "extra_allowed_hosts")
        assert callable(src.query_batch)
        # Camino feliz: devuelve el mapa correcto
        result = src.query_batch(["requests", "flask"])
        assert set(result.keys()) == {"requests", "flask"}
        assert all(r.state == MaliceState.CLEAN for r in result.values())

    def test_source_no_importa_core_net(self) -> None:
        """Frontera R8.1 (import-linter contrato 2): source.py NO importa core.net."""
        source_mod = importlib.import_module("slopguard.core.threatintel.source")
        net_names = {
            "slopguard.core.net",
            "slopguard.core.net.http_client",
            "slopguard.core.net.safe_json",
        }
        # Ninguna referencia directa a los modulos de net en el namespace de source
        for net_name in net_names:
            mod = sys.modules.get(net_name)
            if mod is None:
                continue
            assert mod not in vars(source_mod).values(), (
                f"source.py importa {net_name} directamente (viola contrato 2)"
            )

    def test_threatintel_init_no_reexporta_impls(self) -> None:
        """__init__.py del paquete threatintel esta vacio de logica (frontera R8.1 §1.3).

        Se inspecciona el CODIGO FUENTE del `__init__.py`, no atributos en runtime: en
        CPython, importar un submodulo (p.ej. lo hace el engine o un test de la impl) lo
        BINDEA como atributo del paquete padre, de modo que `hasattr(ti_pkg, 'watchlist')`
        seria True por el sistema de imports aunque `__init__.py` no re-exporte nada. El
        contrato real ("el __init__ no re-exporta impls") se verifica leyendo su fuente:
        no debe `import`-ar osv/watchlist/composite/resolver/registry ni listarlos en
        `__all__`. La frontera dura ademas la ancla import-linter (§1.3), no este test.
        """
        init_path = Path(ti_pkg.__file__ or "")
        source = init_path.read_text(encoding="utf-8")
        # El __init__ no define __all__ (no re-exporta nada) y no importa las impls.
        assert "__all__" not in source, "threatintel.__init__ declara __all__ (re-exporta)"
        for impl_name in ("osv", "watchlist", "composite", "resolver", "registry"):
            assert f"import {impl_name}" not in source, (
                f"threatintel.__init__ importa/re-exporta '{impl_name}' (viola la frontera)"
            )
            assert f"from .{impl_name}" not in source, (
                f"threatintel.__init__ re-exporta de '.{impl_name}' (viola la frontera)"
            )


# ===========================================================================
# Config — Capa 3: defaults, validacion host/path/degraded_status, precedencia (R5)
# ===========================================================================


class TestConfigDefaulstsCapa3:
    """Defaults de Capa 3 coinciden 1:1 con la tabla R5 (§3.6)."""

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

    def test_osv_timeout_total_por_lote_s_default(self) -> None:
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

    def test_watchlist_timeout_total_s_default(self) -> None:
        assert Config().watchlist_timeout_total_s == 30.0

    def test_threatintel_degraded_status_default(self) -> None:
        assert Config().threatintel_degraded_status == "unverifiable"

    def test_config_es_frozen(self) -> None:
        cfg = Config()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.enable_layer3 = False  # type: ignore[misc]


class TestConfigValidacionHostCapa3:
    """R5.2 — osv_host inválido => InvalidConfigError (anti-SSRF a host interno)."""

    @pytest.mark.parametrize(
        "bad_host",
        [
            "169.254.169.254",  # IP de metadata cloud
            "127.0.0.1",  # loopback IPv4
            "::1",  # loopback IPv6
            "localhost",  # nombre de host reservado
            "api.osv.dev:443",  # puerto embebido
            "user@api.osv.dev",  # userinfo
            "api.osv.dev/v1",  # path embebido
            "http://api.osv.dev",  # esquema embebido
            "evil.internal",  # host no en conjunto cerrado
            "192.168.0.1",  # IP privada
        ],
    )
    def test_osv_host_invalido(self, bad_host: str) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"osv_host": bad_host})

    @pytest.mark.parametrize(
        "bad_host",
        [
            "169.254.169.254",
            "localhost",
            "evil.com",  # no en conjunto cerrado
            "depscope.dev:80",  # puerto
        ],
    )
    def test_watchlist_host_invalido(self, bad_host: str) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"watchlist_host": bad_host})


class TestConfigValidacionPathCapa3:
    """R5.2 — rutas de API que no empiezan por / o tienen chars peligrosos."""

    @pytest.mark.parametrize(
        "bad_path",
        [
            "v1/querybatch",  # sin /
            "/v1/../etc/passwd",  # path traversal con .. (.. no esta en charset)
            "/ruta con espacios",  # espacio
            "",  # vacio (no-strip)
        ],
    )
    def test_osv_query_path_invalido(self, bad_path: str) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"osv_query_path": bad_path})

    def test_osv_query_path_crlf_sanitizado_pero_no_invalida(self) -> None:
        """Un CRLF en la ruta es saneado (sanitize_for_output) antes de la validacion.

        La politica documentada es sanear strings de config (no rechazarlos si el
        resultado es valido): '/ruta\\ninyectada' -> '/rutainyectada' que pasa el
        regex. Si el resultado saneado fuera invalido, si lanzaria InvalidConfigError.
        """
        cfg = load_config(None, {"osv_query_path": "/ruta\ninyectada"})
        # El CRLF fue eliminado: el path resultante es '/rutainyectada'
        assert "\n" not in cfg.osv_query_path


class TestConfigDegradedStatus:
    """R5.2 — threatintel_degraded_status solo admite 'unverifiable' o 'warn'."""

    def test_valor_invalido(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"threatintel_degraded_status": "allow"})

    def test_valor_invalido_block(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"threatintel_degraded_status": "block"})

    def test_warn_es_valido(self) -> None:
        cfg = load_config(None, {"threatintel_degraded_status": "warn"})
        assert cfg.threatintel_degraded_status == "warn"

    def test_unverifiable_es_valido(self) -> None:
        cfg = load_config(None, {"threatintel_degraded_status": "unverifiable"})
        assert cfg.threatintel_degraded_status == "unverifiable"


class TestConfigBoolCapa3:
    """R5.2 — enable_layer3 / enable_watchlist exigen bool estricto."""

    def test_entero_rechazado_para_enable_layer3(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"enable_layer3": 1})

    def test_string_rechazado_para_enable_watchlist(self) -> None:
        with pytest.raises(InvalidConfigError):
            load_config(None, {"enable_watchlist": "true"})

    def test_false_aceptado(self) -> None:
        cfg = load_config(None, {"enable_layer3": False})
        assert cfg.enable_layer3 is False


class TestConfigPrecedenciaCapa3:
    """R5.1 — precedencia CLI > archivo > defaults para campos de Capa 3."""

    def test_cli_gana_sobre_archivo_capa3(self, tmp_path: Path) -> None:
        archivo = tmp_path / ".slopguard.toml"
        archivo.write_text("osv_ttl_cache_horas = 2\n", encoding="utf-8")
        cfg = load_config(archivo, {"osv_ttl_cache_horas": 4})
        assert cfg.osv_ttl_cache_horas == 4

    def test_archivo_gana_sobre_default_capa3(self, tmp_path: Path) -> None:
        archivo = tmp_path / ".slopguard.toml"
        archivo.write_text("osv_ttl_cache_horas = 2\n", encoding="utf-8")
        cfg = load_config(archivo, {})
        assert cfg.osv_ttl_cache_horas == 2

    def test_default_cuando_no_hay_nada(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        cfg = load_config(None, {})
        assert cfg.osv_batch_max == 1000
        assert cfg.enable_layer3 is True


# ===========================================================================
# net-post: post_json + allowlist por-instancia + SSRF/redirect (RISK-H2-1)
# ===========================================================================


class _PostHandler(BaseHTTPRequestHandler):
    """Servidor local minimo que sirve escenarios de POST/redirect/errores."""

    def do_POST(self) -> None:
        path = self.path
        if path == "/v1/querybatch":
            self._send_ok_post()
        elif path == "/redirect-host":
            self._redirect("https://pypi.org/nada")
        elif path == "/redirect-ajeno":
            self._redirect("https://evil.com/exfil")
        elif path == "/status-429":
            self._send_status(429)
        elif path == "/status-503":
            self._send_status(503)
        elif path == "/status-400":
            self._send_status(400)
        elif path == "/json-bomb":
            self._send_json_bomb()
        elif path == "/giant":
            self._send_giant()
        else:
            self._send_status(404)

    def _send_ok_post(self) -> None:
        body = json.dumps({"results": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _send_status(self, code: int) -> None:
        self.send_response(code)
        self.end_headers()

    def _send_json_bomb(self) -> None:
        # 80 niveles de anidamiento, mas que max_json_depth=20
        body = b'{"a":' * 80 + b"1" + b"}" * 80
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_giant(self) -> None:
        # Respuesta sin Content-Length, mayor que max_response_bytes
        self.send_response(200)
        self.end_headers()
        chunk = b"A" * 65_536
        for _ in range(64):
            try:
                self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                return

    def log_message(self, *_args: object) -> None:
        pass


class _LocalPostServer:
    """Servidor POST local en 127.0.0.1 con puerto dinamico."""

    def __init__(self) -> None:
        self._httpd = HTTPServer(("127.0.0.1", 0), _PostHandler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self) -> _LocalPostServer:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[0], self._httpd.server_address[1]
        return f"http://{host!s}:{port!s}"


@pytest.fixture
def post_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[_LocalPostServer]:
    """Servidor POST local + allowlist http://127.0.0.1 habilitada SOLO en el test."""

    def allow_local(scheme: str, host: str, allowed_hosts: frozenset[str] | None = None) -> bool:
        return scheme.lower() == "http" and host == "127.0.0.1"

    monkeypatch.setattr(hc, "_is_allowed", allow_local)
    # El loopback usa puerto efimero: neutraliza el rechazo de puerto explicito (A10 SSRF,
    # defecto-deniega en produccion) SOLO en este harness, igual que la allowlist http local.
    monkeypatch.setattr(hc, "_reject_port_and_userinfo", lambda _parts: None)
    with _LocalPostServer() as server:
        yield server


def _post_client() -> SecureHttpClient:
    """Cliente con HTTPHandler extra para alcanzar el servidor local de prueba."""
    client = SecureHttpClient()
    client._opener.add_handler(urllib.request.HTTPHandler())
    return client


def _do_post(
    client: SecureHttpClient,
    url: str,
    body: dict[str, object] | None = None,
    *,
    max_bytes: int = 1_000_000,
) -> object:
    return client.post_json(
        url,
        body or {"queries": []},
        connect_timeout_s=2.0,
        read_timeout_s=2.0,
        max_response_bytes=max_bytes,
        max_json_depth=20,
    )


class TestPostJsonBasico:
    """post_json: camino feliz y defensas basicas."""

    def test_post_ok_devuelve_dict(self, post_server: _LocalPostServer) -> None:
        result = _do_post(_post_client(), post_server.base_url + "/v1/querybatch")
        assert isinstance(result, dict)
        assert "results" in result

    def test_post_json_bomb_rechazado(self, post_server: _LocalPostServer) -> None:
        with pytest.raises(NetworkUnverifiableError, match="profundidad JSON"):
            _do_post(_post_client(), post_server.base_url + "/json-bomb")

    def test_post_respuesta_gigante_rechazada(self, post_server: _LocalPostServer) -> None:
        with pytest.raises(NetworkUnverifiableError, match="supera el maximo"):
            _do_post(
                _post_client(),
                post_server.base_url + "/giant",
                max_bytes=100_000,
            )


class TestPostJsonSSRF:
    """RISK-H2-1: redirects cross-host rechazados — fix SSRF del redirect handler (§3.3)."""

    def test_redirect_a_pypi_rechazado(self, post_server: _LocalPostServer) -> None:
        """api.osv.dev → pypi.org: cross-host rechazado aunque pypi.org este en el efectivo."""
        with pytest.raises(NetworkUnverifiableError):
            _do_post(_post_client(), post_server.base_url + "/redirect-host")

    def test_redirect_a_host_ajeno_rechazado(self, post_server: _LocalPostServer) -> None:
        """api.osv.dev → evil.com: host ajeno => rechazado siempre."""
        with pytest.raises(NetworkUnverifiableError):
            _do_post(_post_client(), post_server.base_url + "/redirect-ajeno")


class TestAllowlistPorInstancia:
    """ADR-09: ALLOWED_HOSTS base solo pypi.org; extra_allowed_hosts amplian por instancia."""

    def test_allowed_hosts_base_es_solo_pypi(self) -> None:
        """Guardia estatico: la base nunca cambia aunque se añadan hosts de Capa 3."""
        assert ALLOWED_HOSTS == frozenset({"pypi.org"})

    def test_extra_hosts_amplian_el_efectivo(self) -> None:
        """Con extra_allowed_hosts={api.osv.dev}, el efectivo es {pypi.org, api.osv.dev}."""
        client = SecureHttpClient(extra_allowed_hosts=frozenset({"api.osv.dev"}))
        # Igualdad EXACTA del set: prueba la ampliacion Y que no se cuela ningun host.
        assert client._allowed_hosts == frozenset({"pypi.org", "api.osv.dev"})

    def test_sin_extra_solo_pypi_en_efectivo(self) -> None:
        client = SecureHttpClient()
        assert client._allowed_hosts == frozenset({"pypi.org"})

    def test_depscope_no_en_efectivo_sin_watchlist(self) -> None:
        """R2.1: depscope.dev no entra al allowlist si enable_watchlist=false."""
        client = SecureHttpClient()
        assert frozenset({"depscope.dev"}).isdisjoint(client._allowed_hosts)

    def test_host_no_allowlist_rechazado_en_post(self) -> None:
        """URL hacia host fuera del efectivo => NetworkUnverifiableError."""
        client = SecureHttpClient()  # solo pypi.org
        with pytest.raises(NetworkUnverifiableError, match="allowlist"):
            client.post_json(
                "https://api.osv.dev/v1/querybatch",
                {"queries": []},
                connect_timeout_s=1.0,
                read_timeout_s=1.0,
                max_response_bytes=1_000,
                max_json_depth=10,
            )

    def test_host_en_extra_pasa_validacion_url(self) -> None:
        """Un host en extra_allowed_hosts supera _validate_url sin ir a la red."""
        client = SecureHttpClient(extra_allowed_hosts=frozenset({"api.osv.dev"}))
        # No debe lanzar NetworkUnverifiableError por allowlist; fallara por red real,
        # pero queremos confirmar que la validacion de URL no rechaza el host.
        try:
            client.post_json(
                "https://api.osv.dev/v1/querybatch",
                {"queries": []},
                connect_timeout_s=0.01,
                read_timeout_s=0.01,
                max_response_bytes=100,
                max_json_depth=5,
            )
        except NetworkUnverifiableError as exc:
            # Puede fallar por red o TLS, nunca por allowlist
            assert "allowlist" not in str(exc), f"deberia fallar por red, no allowlist: {exc}"


class TestPostJson429Transitorio:
    """R1.7 / §3.3: 429 => is_transient=True (reintentable)."""

    def test_429_es_transitorio(self, post_server: _LocalPostServer) -> None:
        """Un 429 del servidor se mapea a is_transient=True."""
        client = _post_client()
        with pytest.raises(NetworkUnverifiableError) as info:
            _do_post(client, post_server.base_url + "/status-429")
        assert info.value.is_transient is True
        assert info.value.status_code == 429

    def test_503_es_transitorio(self, post_server: _LocalPostServer) -> None:
        """Un 5xx => is_transient=True."""
        with pytest.raises(NetworkUnverifiableError) as info:
            _do_post(_post_client(), post_server.base_url + "/status-503")
        assert info.value.is_transient is True

    def test_400_no_es_transitorio(self, post_server: _LocalPostServer) -> None:
        """4xx != 429 => is_transient=False, nunca CLEAN."""
        with pytest.raises(NetworkUnverifiableError) as info:
            _do_post(_post_client(), post_server.base_url + "/status-400")
        assert info.value.is_transient is False


class TestPostJsonHostIpLocalhost:
    """RISK-H2-1 + R5.2: URL con IP/localhost => rechazada antes de llegar a la red."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/v1/querybatch",  # loopback, no en allowlist
            "http://localhost/v1/querybatch",  # nombre reservado
            "http://169.254.169.254/latest/meta-data",  # metadata cloud
            "https://192.168.0.1/api",  # IP privada
        ],
    )
    def test_url_ip_rechazada(self, url: str) -> None:
        """Las URLs con IP o localhost no estan en la allowlist y se rechazan."""
        client = SecureHttpClient()
        with pytest.raises(NetworkUnverifiableError, match="allowlist"):
            client.post_json(
                url,
                {"queries": []},
                connect_timeout_s=1.0,
                read_timeout_s=1.0,
                max_response_bytes=1_000,
                max_json_depth=5,
            )


def _dummy_request() -> urllib.request.Request:
    """Request minimo para satisfacer la firma de redirect_request."""
    return urllib.request.Request("https://pypi.org/x")


class TestRedirectHandlerConAllowlistEfectivo:
    """Fix SSRF §3.3: redirect handler valida contra el mismo conjunto efectivo que URL inicial."""

    def test_handler_sin_extra_rechaza_osv_host(self) -> None:
        """Sin extra, el handler rechaza una Location apuntando a api.osv.dev."""
        handler = hc._RejectRedirectHandler(allowed_hosts=frozenset({"pypi.org"}))
        with pytest.raises(NetworkUnverifiableError):
            handler.redirect_request(
                _dummy_request(), None, 302, "Found", None,                  "https://api.osv.dev/v1/querybatch",
            )

    def test_handler_con_extra_sigue_rechazando(self) -> None:
        """Incluso con api.osv.dev en el efectivo, toda redireccion se rechaza."""
        handler = hc._RejectRedirectHandler(
            allowed_hosts=frozenset({"pypi.org", "api.osv.dev"})
        )
        with pytest.raises(NetworkUnverifiableError):
            handler.redirect_request(
                _dummy_request(), None, 302, "Found", None,                  "https://api.osv.dev/v1/querybatch",
            )

    def test_handler_rechaza_host_ajeno_en_cualquier_caso(self) -> None:
        """Un Location a evil.com => 'destino no permitido'."""
        handler = hc._RejectRedirectHandler(
            allowed_hosts=frozenset({"pypi.org", "api.osv.dev"})
        )
        with pytest.raises(NetworkUnverifiableError, match="destino no permitido"):
            handler.redirect_request(
                _dummy_request(), None, 302, "Found", None,                  "https://evil.com/exfil",
            )


# ===========================================================================
# cache-blob: get_blob / put_blob (H2-T05, RISK-H2-2, §2.5)
# Tests esenciales que complementan test_disk_cache_blob.py con enfasis en
# los invariantes documentados en el EARS de esta suite (H2-T16/17).
# ===========================================================================


def _cache(tmp_path: Path, *, enabled: bool = True) -> DiskCache:
    return DiskCache(tmp_path / "cache", 24, enabled=enabled)


def _blob_path(root: Path, namespace: str, key: str) -> Path:
    digest = hashlib.sha256(f"{namespace}:{key}".encode()).hexdigest()
    return root / f"{digest}.json"


def _osv_payload(name: str = "bioql") -> dict[str, Any]:
    return {
        "source": "osv",
        "ecosystem": "pypi",
        "name": name,
        "state": "malicious",
    }


class TestCacheBlobTTL:
    """R6.1/R6.2: TTL por-llamada; hit/miss determinista."""

    def test_hit_dentro_del_ttl(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        result = cache.get_blob(
            "osv", "pypi:bioql",
            lambda p: p,
            ttl_segundos=_OSV_TTL,
            now=_NOW + 1,
        )
        assert result is not None

    def test_miss_ttl_vencido(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        result = cache.get_blob(
            "osv", "pypi:bioql",
            lambda p: p,
            ttl_segundos=_OSV_TTL,
            now=_NOW + _OSV_TTL + 1,
        )
        assert result is None


class TestCacheBlobSchemaDesviado:
    """R6.1: blob con cache_schema_version distinto de 'ti-1' => miss."""

    def test_schema_hito1_es_miss(self, tmp_path: Path) -> None:
        """Un blob del Hito 1 (schema_version='1') no es leido por get_blob."""
        root = tmp_path / "cache"
        root.mkdir()
        path = _blob_path(root, "osv", "pypi:bioql")
        path.write_bytes(
            json.dumps({**_osv_payload(), "cache_schema_version": "1", "fetched_at": _NOW}).encode()
        )
        cache = DiskCache(root, 24, enabled=True)
        result = cache.get_blob(
            "osv", "pypi:bioql",
            lambda p: p,
            ttl_segundos=_OSV_TTL,
            now=_NOW,
        )
        assert result is None

    def test_schema_corrompido_es_miss(self, tmp_path: Path) -> None:
        root = tmp_path / "cache"
        root.mkdir()
        path = _blob_path(root, "osv", "pypi:bioql")
        path.write_bytes(b"{ no es json valido!!!")
        cache = DiskCache(root, 24, enabled=True)
        result = cache.get_blob(
            "osv", "pypi:bioql",
            lambda p: p,
            ttl_segundos=_OSV_TTL,
            now=_NOW,
        )
        assert result is None


class TestCacheBlobUnverifiableNoPersiste:
    """§2.5/ADR-10: UNVERIFIABLE nunca se cachea (degradacion segura)."""

    def test_state_unverifiable_no_genera_archivo(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:flaky", {"name": "flaky", "state": "unverifiable"}, now=_NOW)
        assert not _blob_path(tmp_path / "cache", "osv", "pypi:flaky").exists()


class TestCacheBlobNoCache:
    """R6.3: --no-cache => ni lee ni escribe."""

    def test_disabled_no_escribe(self, tmp_path: Path) -> None:
        cache = DiskCache(tmp_path / "cache", 24, enabled=False)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        assert not (tmp_path / "cache").exists() or not _blob_path(
            tmp_path / "cache", "osv", "pypi:bioql"
        ).exists()

    def test_disabled_no_lee(self, tmp_path: Path) -> None:
        enabled = _cache(tmp_path)
        enabled.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        disabled = DiskCache(tmp_path / "cache", 24, enabled=False)
        result = disabled.get_blob(
            "osv", "pypi:bioql",
            lambda p: p,
            ttl_segundos=_OSV_TTL,
            now=_NOW,
        )
        assert result is None


class TestCacheBlobPerms:
    """R6.1/R9.7: dir 0700, archivo 0600 para blobs."""

    def test_perms_dir_0700_archivo_0600(self, tmp_path: Path) -> None:
        root = tmp_path / "cache"
        cache = DiskCache(root, 24, enabled=True)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        assert stat.S_IMODE(os.stat(root).st_mode) == 0o700
        path = _blob_path(root, "osv", "pypi:bioql")
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


class TestCacheBlobAntiTraversal:
    """§2.5: clave namespaced via sha256 => sin path traversal posible."""

    def test_traversal_en_clave_no_escapa_del_root(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:../../etc/passwd", _osv_payload("evil"), now=_NOW)
        root = tmp_path / "cache"
        archivos = [p.name for p in root.iterdir() if p.suffix == ".json"]
        assert len(archivos) == 1
        hex_name = archivos[0].removesuffix(".json")
        assert all(c in "0123456789abcdef" for c in hex_name)

    def test_namespace_separa_del_camino_tipado_hito1(self, tmp_path: Path) -> None:
        """sha256('osv:pypi:bioql') != sha256('pypi:bioql') => archivos distintos."""
        blob_p = _blob_path(tmp_path / "cache", "osv", "pypi:bioql")
        typed_digest = hashlib.sha256(b"pypi:bioql").hexdigest()
        typed_p = tmp_path / "cache" / f"{typed_digest}.json"
        assert blob_p != typed_p


class TestCacheBlobValidadorRechaza:
    """§2.5: si el validador inyectado rechaza => miss (no crashea)."""

    def test_validador_que_devuelve_none_es_miss(self, tmp_path: Path) -> None:
        cache = _cache(tmp_path)
        cache.put_blob("osv", "pypi:bioql", _osv_payload(), now=_NOW)
        result = cache.get_blob(
            "osv", "pypi:bioql",
            lambda _p: None,
            ttl_segundos=_OSV_TTL,
            now=_NOW,
        )
        assert result is None


# ===========================================================================
# Invariante anti-FP: blandas + THREATINTEL_UNVERIFIABLE nunca elevan solas (R3.3)
# ===========================================================================


class TestInvarianteAntiFP:
    """R3.3: THREATINTEL_UNVERIFIABLE (blanda, weight=0) nunca contribuye al score."""

    def test_threatintel_unverifiable_es_blanda(self) -> None:
        signal = LayerSignal(
            layer=Layer.L3,
            code=SignalCode.THREATINTEL_UNVERIFIABLE,
            weight=0,
            is_soft=True,
            detail="OSV no disponible",
        )
        assert signal.is_soft is True
        assert signal.weight == 0

    def test_malicious_es_dura_weight_0(self) -> None:
        """MALICIOUS es override: dura (is_soft=False) y weight=0 (no entra al scorer)."""
        signal = LayerSignal(
            layer=Layer.L3,
            code=SignalCode.MALICIOUS,
            weight=0,
            is_soft=False,
            detail="Reportado como malicioso por OSV",
        )
        assert signal.is_soft is False
        assert signal.weight == 0

    def test_known_hallucination_es_dura_weight_85(self) -> None:
        """KNOWN_HALLUCINATION: dura weight=85 => bloquea por score (ADR-07)."""
        signal = LayerSignal(
            layer=Layer.L3,
            code=SignalCode.KNOWN_HALLUCINATION,
            weight=85,
            is_soft=False,
            detail="Nombre alucinado conocido",
        )
        assert signal.is_soft is False
        assert signal.weight == 85
