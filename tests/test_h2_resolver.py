"""Suite del resolver de threat-intel (H2-T09 / RISK-H2-3): dedup GLOBAL + chunking +
degradacion segura de lote, ejercitada tanto con fuentes stub (contrato puro) como
con el camino REAL OSV/watchlist sobre un servidor HTTP local malicioso.

`resolve_threatintel` es la barrera que el engine intercala ENTRE la Capa 0
(existencia, concurrente) y el bucle por-dep. Es agnostico de la fuente concreta:
recibe un `ThreatIntelSource` y los nombres FOUND (ya normalizados). Esta suite NO
re-prueba las fuentes (eso vive en `test_h2_osv.py`/`test_h2_watchlist.py`/
`test_h2_composite.py`): prueba la ORQUESTACION del resolver y sus invariantes de
seguridad, mas un puñado de casos extremo-a-extremo a traves de fuentes reales.

Metodologia de seguridad (feed externo NO confiable, supply-chain T1195.001):

- DEGRADACION SEGURA (NFR-Degr.1 / R1.6): un chunk que LANZA (red agotada, feed
  envenenado que hace crashear a la fuente) o que devuelve cobertura PARCIAL degrada
  TODOS sus nombres a UNVERIFIABLE, jamas CLEAN. Un feed hostil nunca aborta el
  escaneo ni produce un falso limpio. `KeyboardInterrupt`/`SystemExit` SI propagan.
- COBERTURA TOTAL (§3.2 punto 4 / §4.1 tests 1-2): el dict devuelto tiene UNA entrada
  por cada nombre unico de `found_names` (nunca ausente) y `set(keys) ⊆ set(found)`
  (la fuente nunca inyecta nombres fuera del lote: se descartan los inventados).
- DEDUP GLOBAL (R6.4/R6.6): el dedup ocurre ANTES del chunking ⇒ ningun nombre cae en
  dos chunks (claves disjuntas) ⇒ <=1 consulta por nombre por corrida. Orden de primera
  aparicion preservado (determinismo, R3.5).
- CHUNKING (R6.5): > osv_batch_max ⇒ multiples lotes sin exceder el limite por request;
  casos en la FRONTERA de chunk (ultimo de un chunk, primero del siguiente).
- PARSEO DEFENSIVO end-to-end (RISK-H2-2): a traves de fuentes reales, MAL-/no-MAL/
  truncado/len-mismatch/corpus envenenado se resuelven sin inyectar falsos veredictos.
- PRIVACIDAD (NFR-Priv.1): a OSV solo viaja {ecosystem, name}; a depscope un GET pelado;
  jamas manifiesto/version/ruta.

Niveles:
  1. Contrato puro con fuentes STUB (sin red ni disco): dedup, chunking, cobertura,
     degradacion, conteo de consultas. Rapido y deterministico.
  2. Camino REAL OSV(+watchlist) sobre servidor HTTP local: el resolver maneja
     CompositeSource con OsvSource/WatchlistSource genuinos apuntados al loopback.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, ClassVar

import pytest

from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config
from slopguard.core.models import Advisory
from slopguard.core.net import http_client as hc
from slopguard.core.net.http_client import SecureHttpClient
from slopguard.core.threatintel import resolver as rv
from slopguard.core.threatintel.composite import CompositeSource
from slopguard.core.threatintel.osv import OsvSource
from slopguard.core.threatintel.resolver import resolve_threatintel
from slopguard.core.threatintel.source import MaliceState, ThreatIntelResult
from slopguard.core.threatintel.watchlist import WatchlistSource

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


# ===========================================================================
# Helpers de resultados canonicos + Config de pruebas
# ===========================================================================

_ADV = Advisory(
    id="MAL-2025-1",
    kind="malicious",
    url="https://osv.dev/vulnerability/MAL-2025-1",
    source="osv",
)


def _clean(name: str) -> ThreatIntelResult:
    return ThreatIntelResult(name=name, state=MaliceState.CLEAN)


def _malicious(name: str) -> ThreatIntelResult:
    return ThreatIntelResult(name=name, state=MaliceState.MALICIOUS, advisories=(_ADV,))


def _hallucination(name: str) -> ThreatIntelResult:
    return ThreatIntelResult(
        name=name,
        state=MaliceState.KNOWN_HALLUCINATION,
        watchlist_source="depscope-hallucinations",
        watchlist_date="2026-06-20",
    )


def _unverifiable(name: str) -> ThreatIntelResult:
    return ThreatIntelResult(
        name=name, state=MaliceState.UNVERIFIABLE, unverifiable_reason="fuente caida"
    )


def _cfg(**overrides: Any) -> Config:
    """Config base con timeouts cortos para que la red de prueba no demore."""
    base: dict[str, Any] = {
        "connect_timeout_s": 2.0,
        "read_timeout_s": 2.0,
        "osv_timeout_total_por_lote_s": 2.0,
        "osv_reintentos": 1,
        "watchlist_timeout_total_s": 2.0,
    }
    base.update(overrides)
    return Config(**base)


# ===========================================================================
# Stub de fuente que registra los lotes recibidos (sin red ni disco)
# ===========================================================================


class _RecordingSource:
    """Fuente falsa que registra cada lote y devuelve resultados prefijados.

    `calls` acumula los lotes (cada uno una lista de nombres) para verificar el
    chunking, el dedup y el conteo de consultas por nombre. Por defecto un nombre
    no mapeado se resuelve CLEAN (camino feliz); los tests sustituyen el mapeo o
    `default_state` segun necesiten.
    """

    source_id: str = "recording"
    extra_allowed_hosts: frozenset[str] = frozenset()

    def __init__(
        self,
        results: dict[str, ThreatIntelResult] | None = None,
        *,
        default_state: MaliceState = MaliceState.CLEAN,
    ) -> None:
        self._results = results or {}
        self._default_state = default_state
        self.calls: list[list[str]] = []

    def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
        """Registra el lote y devuelve cobertura total por nombre (mapeo o default)."""
        batch = list(names)
        self.calls.append(batch)
        return {
            name: self._results.get(
                name, ThreatIntelResult(name=name, state=self._default_state)
            )
            for name in batch
        }


class _RaisingSource:
    """Fuente que LANZA en `query_batch` (feed envenenado que hace crashear la fuente).

    `exc` controla la excepcion; por defecto un `ValueError` (subclase de Exception ⇒
    debe degradarse a UNVERIFIABLE). Para verificar que `KeyboardInterrupt`/`SystemExit`
    propagan, los tests inyectan esas clases explicitamente.
    """

    source_id: str = "raising"
    extra_allowed_hosts: frozenset[str] = frozenset()

    def __init__(self, exc: BaseException | None = None) -> None:
        self._exc = exc or ValueError("feed hostil")
        self.calls = 0

    def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
        """Cuenta la llamada y lanza la excepcion configurada (no devuelve nada)."""
        self.calls += 1
        raise self._exc


class _PartialSource:
    """Fuente que devuelve cobertura PARCIAL (omite algunos nombres del lote).

    Simula una fuente con un bug de cobertura: el resolver debe rellenar los nombres
    ausentes con UNVERIFIABLE (jamas dejarlos fuera del dict ni asumirlos CLEAN).
    """

    source_id: str = "partial"
    extra_allowed_hosts: frozenset[str] = frozenset()

    def __init__(self, return_only: set[str], state: MaliceState = MaliceState.CLEAN) -> None:
        self._return_only = return_only
        self._state = state

    def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
        """Devuelve resultado SOLO para los nombres de `_return_only`."""
        return {
            name: ThreatIntelResult(name=name, state=self._state)
            for name in names
            if name in self._return_only
        }


class _InventingSource:
    """Fuente que inventa una clave fuera del lote pedido (debe descartarse, §4.1 test 1)."""

    source_id: str = "inventing"
    extra_allowed_hosts: frozenset[str] = frozenset()

    def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
        """Resuelve CLEAN los nombres pedidos + un nombre INVENTADO que no se pidio."""
        out = {name: ThreatIntelResult(name=name, state=MaliceState.CLEAN) for name in names}
        out["nombre-inventado-fuera-del-lote"] = _malicious("nombre-inventado-fuera-del-lote")
        return out


class _BadValueSource:
    """Fuente que devuelve un valor que NO es `ThreatIntelResult` para un nombre.

    El resolver debe tratar ese valor corrupto como cobertura ausente ⇒ UNVERIFIABLE
    (defensa en profundidad: una fuente mal implementada no inyecta basura tipada).
    """

    source_id: str = "badvalue"
    extra_allowed_hosts: frozenset[str] = frozenset()

    def query_batch(self, names: Sequence[str]) -> dict[str, ThreatIntelResult]:
        """Devuelve un dict con un valor no-`ThreatIntelResult` para el primer nombre."""
        out: dict[str, ThreatIntelResult] = {}
        for i, name in enumerate(names):
            if i == 0:
                out[name] = "no-soy-un-result"  # type: ignore[assignment]
            else:
                out[name] = ThreatIntelResult(name=name, state=MaliceState.CLEAN)
        return out


# ===========================================================================
# 1. source=None y lote vacio (R5.3)
# ===========================================================================


class TestModoApagado:
    def test_source_none_devuelve_dict_vacio(self) -> None:
        """R5.3: `enable_layer3=false` ⇒ source None ⇒ {} (modo solo-deterministas)."""
        assert resolve_threatintel(None, ["a", "b"], _cfg()) == {}

    def test_lote_vacio_devuelve_dict_vacio(self) -> None:
        """Sin nombres FOUND no se consulta nada: dict vacio, fuente nunca invocada."""
        source = _RecordingSource()
        assert resolve_threatintel(source, [], _cfg()) == {}
        assert source.calls == []  # ningun lote enviado

    def test_lote_solo_duplicados_vacios_no_consulta_de_mas(self) -> None:
        """Un lote de duplicados colapsa a una sola consulta (dedup)."""
        source = _RecordingSource()
        resolve_threatintel(source, ["a", "a", "a"], _cfg())
        assert source.calls == [["a"]]


# ===========================================================================
# 2. Dedup GLOBAL antes del chunking (R6.4/R6.6) + determinismo de orden (R3.5)
# ===========================================================================


class TestDedupGlobal:
    def test_dedup_preserva_orden_de_primera_aparicion(self) -> None:
        """`_dedup_preserving_order` colapsa duplicados conservando el primer orden."""
        assert rv._dedup_preserving_order(["c", "a", "c", "b", "a"]) == ["c", "a", "b"]

    def test_claves_resultantes_son_unicas_y_cubren_los_nombres(self) -> None:
        """Tras dedup, el dict tiene una clave por nombre UNICO (sin duplicar)."""
        source = _RecordingSource()
        result = resolve_threatintel(source, ["x", "y", "x", "z", "y"], _cfg())
        assert set(result) == {"x", "y", "z"}

    def test_una_sola_consulta_por_nombre_aunque_aparezca_repetido(self) -> None:
        """R6.6: <=1 consulta por nombre. Un nombre repetido N veces se consulta una vez."""
        source = _RecordingSource()
        resolve_threatintel(source, ["dup", "dup", "dup", "dup"], _cfg(osv_batch_max=1000))
        enviados = [n for batch in source.calls for n in batch]
        assert enviados == ["dup"]  # el nombre viaja exactamente una vez

    def test_dedup_global_evita_que_un_nombre_caiga_en_dos_chunks(self) -> None:
        """R6.4: con chunk_size=1 y un nombre repetido, NO debe aparecer en dos chunks.

        Si el dedup fuera por-chunk (en vez de global), 'a' caeria en dos lotes distintos.
        El dedup global garantiza claves disjuntas entre chunks por construccion.
        """
        source = _RecordingSource()
        resolve_threatintel(source, ["a", "b", "a", "c"], _cfg(osv_batch_max=1))
        # Cada lote tiene exactamente un nombre y los conjuntos son disjuntos.
        conjuntos = [set(batch) for batch in source.calls]
        union: set[str] = set()
        for c in conjuntos:
            assert union.isdisjoint(c), "un nombre cayo en dos chunks (dedup no global)"
            union |= c
        assert union == {"a", "b", "c"}


# ===========================================================================
# 3. Chunking <= osv_batch_max + frontera de chunk (R6.5)
# ===========================================================================


class TestChunking:
    def test_chunks_parte_en_bloques_contiguos(self) -> None:
        """`_chunks` parte la lista deduplicada en bloques <= chunk_size, en orden."""
        assert rv._chunks(["a", "b", "c", "d", "e"], 2) == [["a", "b"], ["c", "d"], ["e"]]

    def test_chunks_lista_vacia_es_vacio(self) -> None:
        assert rv._chunks([], 3) == []

    def test_safe_chunk_size_piso_uno(self) -> None:
        """Defensa en profundidad: un osv_batch_max <=0 (refactor erroneo) se acota a 1."""
        assert rv._safe_chunk_size(0) == 1
        assert rv._safe_chunk_size(-5) == 1
        assert rv._safe_chunk_size(1000) == 1000

    def test_menor_o_igual_al_max_es_un_solo_lote(self) -> None:
        """<= osv_batch_max ⇒ un unico lote."""
        source = _RecordingSource()
        names = [f"p{i}" for i in range(50)]
        resolve_threatintel(source, names, _cfg(osv_batch_max=50))
        assert len(source.calls) == 1
        assert source.calls[0] == names

    def test_mayor_al_max_se_parte_en_multiples_lotes(self) -> None:
        """R6.5: > osv_batch_max ⇒ multiples lotes, ninguno excediendo el limite."""
        source = _RecordingSource()
        names = [f"p{i}" for i in range(2500)]
        resolve_threatintel(source, names, _cfg(osv_batch_max=1000))
        assert [len(c) for c in source.calls] == [1000, 1000, 500]
        assert all(len(c) <= 1000 for c in source.calls)

    def test_frontera_de_chunk_reensambla_sin_perdida(self) -> None:
        """RISK-H2-3: nombres en la frontera (ultimo de un chunk / primero del siguiente)
        se reensamblan correctamente; cobertura total y estados intactos."""
        source = _RecordingSource(
            {
                "p999": _malicious("p999"),  # ultimo del chunk 0
                "p1000": _hallucination("p1000"),  # primero del chunk 1
            }
        )
        names = [f"p{i}" for i in range(2001)]
        result = resolve_threatintel(source, names, _cfg(osv_batch_max=1000))
        assert set(result) == set(names)  # cobertura total
        assert result["p999"].state is MaliceState.MALICIOUS
        assert result["p1000"].state is MaliceState.KNOWN_HALLUCINATION

    def test_chunking_preserva_estados_mezclados_por_lote(self) -> None:
        """Cada lote resuelve sus propios nombres; el reensamblado por nombre es correcto."""
        source = _RecordingSource(
            {"a": _malicious("a"), "c": _hallucination("c"), "d": _unverifiable("d")}
        )
        result = resolve_threatintel(source, ["a", "b", "c", "d"], _cfg(osv_batch_max=2))
        assert result["a"].state is MaliceState.MALICIOUS
        assert result["b"].state is MaliceState.CLEAN
        assert result["c"].state is MaliceState.KNOWN_HALLUCINATION
        assert result["d"].state is MaliceState.UNVERIFIABLE


# ===========================================================================
# 4. Cobertura total + keys subset de found (§3.2 punto 4, §4.1 tests 1-2)
# ===========================================================================


class TestCoberturaTotal:
    def test_todo_nombre_found_tiene_entrada(self) -> None:
        """Invariante 2: todo nombre unico de found_names tiene entrada (nunca ausente)."""
        source = _RecordingSource({"a": _malicious("a")})
        names = ["a", "b", "c", "d"]
        result = resolve_threatintel(source, names, _cfg())
        assert set(result) == set(names)

    def test_fuente_que_inventa_nombre_fuera_del_lote_se_descarta(self) -> None:
        """§4.1 test 1: `set(keys) ⊆ set(found)`. Una clave inventada por la fuente se ignora."""
        source = _InventingSource()
        names = ["a", "b"]
        result = resolve_threatintel(source, names, _cfg())
        assert set(result) == set(names)
        assert "nombre-inventado-fuera-del-lote" not in result

    def test_cobertura_parcial_de_la_fuente_rellena_unverifiable(self) -> None:
        """Una fuente con cobertura PARCIAL (omite nombres) ⇒ los faltantes UNVERIFIABLE."""
        source = _PartialSource(return_only={"a", "c"})
        result = resolve_threatintel(source, ["a", "b", "c"], _cfg())
        assert result["a"].state is MaliceState.CLEAN
        assert result["c"].state is MaliceState.CLEAN
        # 'b' fue omitido por la fuente ⇒ relleno conservador a UNVERIFIABLE (nunca CLEAN).
        assert result["b"].state is MaliceState.UNVERIFIABLE
        assert result["b"].unverifiable_reason  # razon saneada presente

    def test_valor_corrupto_no_threatintelresult_es_unverifiable(self) -> None:
        """Defensa en profundidad: un valor que no es `ThreatIntelResult` ⇒ UNVERIFIABLE."""
        source = _BadValueSource()
        result = resolve_threatintel(source, ["a", "b"], _cfg())
        assert result["a"].state is MaliceState.UNVERIFIABLE  # valor corrupto saneado
        assert result["b"].state is MaliceState.CLEAN


# ===========================================================================
# 5. Degradacion segura del lote (NFR-Degr.1 / R1.6) — corazon de RISK-H2-3
# ===========================================================================


class TestDegradacionSegura:
    def test_chunk_que_lanza_degrada_a_unverifiable_nunca_clean(self) -> None:
        """Una fuente que LANZA (feed hostil) degrada TODO el chunk a UNVERIFIABLE, no CLEAN."""
        source = _RaisingSource()
        result = resolve_threatintel(source, ["a", "b", "c"], _cfg())
        assert set(result) == {"a", "b", "c"}
        assert all(r.state is MaliceState.UNVERIFIABLE for r in result.values())
        assert all(r.unverifiable_reason for r in result.values())  # razon saneada

    def test_solo_el_chunk_caido_se_degrada_los_demas_siguen(self) -> None:
        """Un chunk caido no contamina a los demas: solo sus nombres son UNVERIFIABLE.

        Se intercepta la 2da llamada al stub para que lance; con chunk_size=1 cada nombre
        es su propio lote, asi que solo el 2do nombre cae.
        """
        source = _RecordingSource()
        original = source.query_batch
        state = {"n": 0}

        def flaky(names: Sequence[str]) -> dict[str, ThreatIntelResult]:
            state["n"] += 1
            if state["n"] == 2:
                raise RuntimeError("falla transitoria del 2do lote")
            return original(names)

        source.query_batch = flaky  # type: ignore[method-assign]
        result = resolve_threatintel(source, ["a", "b", "c"], _cfg(osv_batch_max=1))
        assert result["a"].state is MaliceState.CLEAN
        assert result["b"].state is MaliceState.UNVERIFIABLE  # el lote caido
        assert result["c"].state is MaliceState.CLEAN

    def test_feed_que_devuelve_unverifiable_no_se_convierte_en_clean(self) -> None:
        """Una fuente que reporta UNVERIFIABLE explicito se respeta (no se reescribe a CLEAN)."""
        source = _RecordingSource(default_state=MaliceState.UNVERIFIABLE)
        result = resolve_threatintel(source, ["a", "b"], _cfg())
        assert all(r.state is MaliceState.UNVERIFIABLE for r in result.values())

    def test_keyboard_interrupt_propaga_no_se_traga(self) -> None:
        """`KeyboardInterrupt` (no es Exception) propaga: Ctrl-C interrumpe el escaneo."""
        source = _RaisingSource(KeyboardInterrupt())
        with pytest.raises(KeyboardInterrupt):
            resolve_threatintel(source, ["a"], _cfg())

    def test_system_exit_propaga_no_se_traga(self) -> None:
        """`SystemExit` (no es Exception) propaga: una salida solicitada no se enmascara."""
        source = _RaisingSource(SystemExit(2))
        with pytest.raises(SystemExit):
            resolve_threatintel(source, ["a"], _cfg())

    def test_multiples_chunks_uno_cae_los_otros_ok(self) -> None:
        """Con 3 chunks y el del medio caido, los dos sanos resuelven y el caido degrada."""
        source = _RecordingSource()
        original = source.query_batch
        state = {"n": 0}

        def flaky(names: Sequence[str]) -> dict[str, ThreatIntelResult]:
            state["n"] += 1
            if state["n"] == 2:
                raise ConnectionError("red caida en el chunk del medio")
            return original(names)

        source.query_batch = flaky  # type: ignore[method-assign]
        names = ["a", "b", "c", "d", "e", "f"]
        result = resolve_threatintel(source, names, _cfg(osv_batch_max=2))
        # chunk0 [a,b] ok, chunk1 [c,d] cae, chunk2 [e,f] ok.
        assert result["a"].state is MaliceState.CLEAN
        assert result["b"].state is MaliceState.CLEAN
        assert result["c"].state is MaliceState.UNVERIFIABLE
        assert result["d"].state is MaliceState.UNVERIFIABLE
        assert result["e"].state is MaliceState.CLEAN
        assert result["f"].state is MaliceState.CLEAN


# ===========================================================================
# 6. Determinismo bajo permutacion del lote (R3.5)
# ===========================================================================


class TestDeterminismo:
    def test_resultado_igual_bajo_permutacion_de_entrada(self) -> None:
        """R3.5: permutar found_names no cambia los estados resueltos (determinismo)."""
        results = {"a": _malicious("a"), "b": _hallucination("b"), "c": _unverifiable("c")}
        base = resolve_threatintel(_RecordingSource(dict(results)), ["a", "b", "c", "d"], _cfg())
        perm = resolve_threatintel(_RecordingSource(dict(results)), ["d", "c", "a", "b"], _cfg())
        estados_base = {k: v.state for k, v in base.items()}
        estados_perm = {k: v.state for k, v in perm.items()}
        assert estados_base == estados_perm


# ===========================================================================
# 7. Camino REAL OSV(+watchlist) sobre servidor HTTP local (RISK-H2-2/3 e2e)
# ===========================================================================


class _ResolverHandler(BaseHTTPRequestHandler):
    """Sirve respuestas OSV (POST) y watchlist (GET) por ruta; registra el ultimo POST."""

    osv_responses: ClassVar[dict[str, Any]] = {}
    osv_raw: ClassVar[dict[str, bytes]] = {}
    osv_truncated: ClassVar[set[str]] = set()
    osv_status: ClassVar[dict[str, int]] = {}
    wl_responses: ClassVar[dict[str, Any]] = {}
    wl_status: ClassVar[dict[str, int]] = {}
    last_post_body: ClassVar[bytes] = b""
    last_get_path: ClassVar[str | None] = None

    def do_POST(self) -> None:  # firma impuesta por BaseHTTPRequestHandler
        """Sirve la respuesta OSV de la ruta; registra el body para el aserto de privacidad."""
        length = int(self.headers.get("Content-Length", "0") or "0")
        type(self).last_post_body = self.rfile.read(length) if length else b""
        path = self.path.split("?", 1)[0]
        if path in self.osv_status:
            self._send_status(self.osv_status[path])
        elif path in self.osv_truncated:
            self._send_truncated(self.osv_raw[path])
        elif path in self.osv_responses:
            self._send_json(self.osv_responses[path])
        else:
            self._send_status(404)

    def do_GET(self) -> None:  # firma impuesta por BaseHTTPRequestHandler
        """Sirve el corpus watchlist; registra el path para el aserto de privacidad."""
        type(self).last_get_path = self.path
        path = self.path.split("?", 1)[0]
        if path in self.wl_status:
            self._send_status(self.wl_status[path])
        elif path in self.wl_responses:
            self._send_json(self.wl_responses[path])
        else:
            self._send_status(404)

    def _send_json(self, payload: Any) -> None:
        self._send_raw(json.dumps(payload).encode())

    def _send_raw(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_truncated(self, body: bytes) -> None:
        # Declara mas bytes de los que envia: IncompleteRead ⇒ no-verificable.
        self.send_response(200)
        self.send_header("Content-Length", str(len(body) + 64))
        self.end_headers()
        self.wfile.write(body)

    def _send_status(self, code: int) -> None:
        body = b'{"error":"x"}'
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        """Silencia el log del servidor para no contaminar la salida de pytest."""


class _ResolverServer:
    """Levanta `_ResolverHandler` en 127.0.0.1 (puerto efimero) en un hilo daemon."""

    def __init__(self) -> None:
        _ResolverHandler.osv_responses = {}
        _ResolverHandler.osv_raw = {}
        _ResolverHandler.osv_truncated = set()
        _ResolverHandler.osv_status = {}
        _ResolverHandler.wl_responses = {}
        _ResolverHandler.wl_status = {}
        _ResolverHandler.last_post_body = b""
        _ResolverHandler.last_get_path = None
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _ResolverHandler)
        self._thread = threading.Thread(
            target=lambda: self._httpd.serve_forever(poll_interval=0.005), daemon=True
        )

    def __enter__(self) -> _ResolverServer:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def url(self, path: str) -> str:
        host, port = self._httpd.server_address[0], self._httpd.server_address[1]
        return f"http://{host!s}:{port!s}{path}"


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> Iterator[_ResolverServer]:
    """Servidor local + permisos de allowlist/puerto para http://127.0.0.1 SOLO en el test.

    El loopback usa puerto efimero (necesidad tecnica); se neutralizan `_is_allowed` y
    `_reject_port_and_userinfo` igual que el harness del Hito 1/H2, sin tocar el
    endurecimiento de produccion (TLS, allowlist real, parseo defensivo, charset/URL).
    """

    def allow_local(
        scheme: str, host: str, allowed_hosts: frozenset[str] | None = None
    ) -> bool:
        return scheme.lower() == "http" and host == "127.0.0.1"

    monkeypatch.setattr(hc, "_is_allowed", allow_local)
    monkeypatch.setattr(hc, "_reject_port_and_userinfo", lambda _parts: None)
    with _ResolverServer() as srv:
        yield srv


def _wired_osv(server: _ResolverServer, osv_path: str, tmp_path: Path, config: Config) -> OsvSource:
    """OsvSource genuino apuntado al loopback (HTTPHandler extra) con cache real en tmp."""
    source = OsvSource(config, use_cache=False)
    client = SecureHttpClient(extra_allowed_hosts=frozenset({"api.osv.dev"}))
    client._opener.add_handler(urllib.request.HTTPHandler())
    source._http = client
    source._query_url = server.url(osv_path)
    source._cache = DiskCache(tmp_path / "osv", config.osv_ttl_cache_horas, enabled=False)
    return source


def _wired_watchlist(
    server: _ResolverServer, wl_path: str, tmp_path: Path, config: Config
) -> WatchlistSource:
    """WatchlistSource genuino apuntado al loopback (HTTPHandler extra) con cache real en tmp."""
    source = WatchlistSource(config, use_cache=False)
    client = SecureHttpClient(extra_allowed_hosts=frozenset({"depscope.dev"}))
    client._opener.add_handler(urllib.request.HTTPHandler())
    source._http = client
    source._url = server.url(wl_path)
    source._cache = DiskCache(tmp_path / "wl", config.watchlist_ttl_cache_horas, enabled=False)
    return source


def _wired_both(server: _ResolverServer, tmp_path: Path, config: Config) -> CompositeSource:
    """CompositeSource con OSV (/osv) + watchlist (/wl) genuinos sobre el loopback."""
    return CompositeSource(
        (
            _wired_osv(server, "/osv", tmp_path, config),
            _wired_watchlist(server, "/wl", tmp_path, config),
        )
    )


class TestResolverRealOsv:
    """El resolver maneja un CompositeSource(OsvSource real) sobre el servidor local."""

    def test_mal_id_real_es_malicious(self, server: _ResolverServer, tmp_path: Path) -> None:
        """e2e: el resolver resuelve un MAL- real a MALICIOUS con advisory reconstruido."""
        _ResolverHandler.osv_responses["/osv"] = {
            "results": [{"vulns": [{"id": "MAL-2025-47868"}]}]
        }
        comp = CompositeSource((_wired_osv(server, "/osv", tmp_path, _cfg()),))
        result = resolve_threatintel(comp, ["bioql"], _cfg())
        assert result["bioql"].state is MaliceState.MALICIOUS
        assert result["bioql"].advisories[0].url == "https://osv.dev/vulnerability/MAL-2025-47868"

    def test_no_mal_ids_ignorados_es_clean(self, server: _ResolverServer, tmp_path: Path) -> None:
        """e2e: GHSA/CVE (no-MAL) se ignoran ⇒ CLEAN (R1.3/R1.4)."""
        _ResolverHandler.osv_responses["/osv"] = {
            "results": [{"vulns": [{"id": "GHSA-x"}, {"id": "CVE-2025-1"}]}]
        }
        comp = CompositeSource((_wired_osv(server, "/osv", tmp_path, _cfg()),))
        assert resolve_threatintel(comp, ["pkg"], _cfg())["pkg"].state is MaliceState.CLEAN

    def test_vacio_es_clean(self, server: _ResolverServer, tmp_path: Path) -> None:
        """e2e: results[i]={} ⇒ CLEAN (R1.4)."""
        _ResolverHandler.osv_responses["/osv"] = {"results": [{}]}
        comp = CompositeSource((_wired_osv(server, "/osv", tmp_path, _cfg()),))
        assert resolve_threatintel(comp, ["safe"], _cfg())["safe"].state is MaliceState.CLEAN

    def test_len_mismatch_real_es_unverifiable_nunca_clean(
        self, server: _ResolverServer, tmp_path: Path
    ) -> None:
        """RISK-H2-2 e2e: results mas corto que queries ⇒ lote UNVERIFIABLE, jamas CLEAN."""
        _ResolverHandler.osv_responses["/osv"] = {"results": [{}]}  # 1 result, 2 queries
        comp = CompositeSource((_wired_osv(server, "/osv", tmp_path, _cfg()),))
        result = resolve_threatintel(comp, ["a", "b"], _cfg())
        assert {r.state for r in result.values()} == {MaliceState.UNVERIFIABLE}
        assert set(result) == {"a", "b"}  # cobertura total preservada

    def test_truncada_real_es_unverifiable(self, server: _ResolverServer, tmp_path: Path) -> None:
        """RISK-H2-2 e2e: respuesta truncada (Content-Length miente) ⇒ UNVERIFIABLE, no CLEAN."""
        _ResolverHandler.osv_raw["/osv"] = b'{"results": ['
        _ResolverHandler.osv_truncated.add("/osv")
        comp = CompositeSource((_wired_osv(server, "/osv", tmp_path, _cfg()),))
        assert resolve_threatintel(comp, ["a"], _cfg())["a"].state is MaliceState.UNVERIFIABLE

    def test_osv_503_agotado_es_unverifiable(
        self, server: _ResolverServer, tmp_path: Path
    ) -> None:
        """R1.6 e2e: 5xx agotado ⇒ UNVERIFIABLE; el resolver no aborta el escaneo."""
        _ResolverHandler.osv_status["/osv"] = 503
        cfg = _cfg(osv_timeout_total_por_lote_s=0.2, osv_reintentos=0)
        comp = CompositeSource((_wired_osv(server, "/osv", tmp_path, cfg),))
        assert resolve_threatintel(comp, ["a"], cfg)["a"].state is MaliceState.UNVERIFIABLE

    def test_multilote_real_osv_batch_max_uno(
        self, server: _ResolverServer, tmp_path: Path
    ) -> None:
        """R6.5 e2e: con osv_batch_max=1, dos nombres ⇒ dos POST; reensamblado por nombre."""
        _ResolverHandler.osv_responses["/osv"] = {"results": [{"vulns": [{"id": "MAL-2025-1"}]}]}
        comp = CompositeSource((_wired_osv(server, "/osv", tmp_path, _cfg()),))
        result = resolve_threatintel(comp, ["a", "b"], _cfg(osv_batch_max=1))
        # Cada nombre se consulto en su propio POST y ambos resolvieron MALICIOUS (misma ruta).
        assert result["a"].state is MaliceState.MALICIOUS
        assert result["b"].state is MaliceState.MALICIOUS
        assert set(result) == {"a", "b"}

    def test_privacidad_body_solo_ecosystem_y_name(
        self, server: _ResolverServer, tmp_path: Path
    ) -> None:
        """NFR-Priv.1 e2e: el body OSV lleva SOLO {ecosystem, name}, jamas version/ruta."""
        _ResolverHandler.osv_responses["/osv"] = {"results": [{}]}
        comp = CompositeSource((_wired_osv(server, "/osv", tmp_path, _cfg()),))
        resolve_threatintel(comp, ["bioql"], _cfg())
        sent = json.loads(_ResolverHandler.last_post_body.decode("utf-8"))
        assert sent == {"queries": [{"package": {"ecosystem": "PyPI", "name": "bioql"}}]}


class TestResolverRealWatchlist:
    """El resolver maneja un CompositeSource(OSV + watchlist real) sobre el servidor local."""

    def test_match_exacto_es_known_hallucination(
        self, server: _ResolverServer, tmp_path: Path
    ) -> None:
        """e2e: OSV limpio + watchlist matchea ⇒ KNOWN_HALLUCINATION (R2.3)."""
        _ResolverHandler.osv_responses["/osv"] = {"results": [{}]}
        _ResolverHandler.wl_responses["/wl"] = {"names": ["reqe"], "corpus_date": "2026-06-20"}
        cfg = _cfg(enable_watchlist=True)
        comp = _wired_both(server, tmp_path, cfg)
        result = resolve_threatintel(comp, ["reqe"], cfg)["reqe"]
        assert result.state is MaliceState.KNOWN_HALLUCINATION
        assert result.watchlist_source == "depscope-hallucinations"

    def test_corpus_envenenado_no_inyecta_falso_match(
        self, server: _ResolverServer, tmp_path: Path
    ) -> None:
        """Anti-envenenamiento e2e: nombres con CRLF/ANSI en el corpus se descartan ⇒ CLEAN."""
        _ResolverHandler.osv_responses["/osv"] = {"results": [{}]}
        _ResolverHandler.wl_responses["/wl"] = {
            "names": ["safelib\r\nevil", "reqe\x1b[31m", "otro"]
        }
        cfg = _cfg(enable_watchlist=True)
        comp = _wired_both(server, tmp_path, cfg)
        # 'safelib' no esta en el corpus (la entrada envenenada se descarto) ⇒ CLEAN.
        assert resolve_threatintel(comp, ["safelib"], cfg)["safelib"].state is MaliceState.CLEAN

    def test_watchlist_caida_no_invalida_osv_malicious(
        self, server: _ResolverServer, tmp_path: Path
    ) -> None:
        """R2.5 e2e: watchlist 500 (UNVERIFIABLE) no invalida un MALICIOUS de OSV (domina)."""
        _ResolverHandler.osv_responses["/osv"] = {"results": [{"vulns": [{"id": "MAL-2025-8"}]}]}
        _ResolverHandler.wl_status["/wl"] = 500
        cfg = _cfg(enable_watchlist=True)
        comp = _wired_both(server, tmp_path, cfg)
        assert resolve_threatintel(comp, ["bioql"], cfg)["bioql"].state is MaliceState.MALICIOUS

    def test_ambas_fuentes_caidas_es_unverifiable_nunca_clean(
        self, server: _ResolverServer, tmp_path: Path
    ) -> None:
        """NFR-Degr.1 e2e: OSV 503 + watchlist 503 ⇒ UNVERIFIABLE, jamas un falso CLEAN."""
        _ResolverHandler.osv_status["/osv"] = 503
        _ResolverHandler.wl_status["/wl"] = 503
        cfg = _cfg(
            enable_watchlist=True, osv_timeout_total_por_lote_s=0.2, osv_reintentos=0,
            watchlist_timeout_total_s=0.2,
        )
        comp = _wired_both(server, tmp_path, cfg)
        assert resolve_threatintel(comp, ["x"], cfg)["x"].state is MaliceState.UNVERIFIABLE

    def test_privacidad_get_sin_query_string(
        self, server: _ResolverServer, tmp_path: Path
    ) -> None:
        """NFR-Priv.1 e2e: la peticion del corpus es un GET pelado, sin nombres en query string."""
        _ResolverHandler.osv_responses["/osv"] = {"results": [{}]}
        _ResolverHandler.wl_responses["/wl"] = {"names": ["reqe"]}
        cfg = _cfg(enable_watchlist=True)
        comp = _wired_both(server, tmp_path, cfg)
        resolve_threatintel(comp, ["secreto-del-usuario", "reqe"], cfg)
        assert _ResolverHandler.last_get_path == "/wl"
        assert "secreto-del-usuario" not in (_ResolverHandler.last_get_path or "")
