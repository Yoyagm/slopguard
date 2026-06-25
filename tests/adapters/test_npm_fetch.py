"""Tests de `NpmAdapter.fetch`/`fetch_attempt` + cap + URL anti-traversal (H4-T07).

Transporte mockeado (sin red): se sustituye `adapter._http` por un stub guionado que
mapea la URL pedida a un payload dict (FOUND) o a un `NetworkUnverifiableError` tipado
(404/4xx/5xx/timeout/cap). Cubre el alcance EARS de H4-T07:

- R4.1: 200->FOUND, 404->NOT_FOUND, 4xx!=404->UNVERIFIABLE permanente, 5xx/429/timeout
  ->UNVERIFIABLE transitorio (is_transient=True); `fetch` colapsa a UNVERIFIABLE.
- R4.3: cuerpo >cap (`npm_max_response_bytes`, ADR-2) -> UNVERIFIABLE fail-safe, nunca
  metadata parcial; packument no-objeto -> UNVERIFIABLE.
- R4.5: host `registry.npmjs.org` entra al allowlist EFECTIVO SOLO via la instancia del
  adapter, jamas en la constante base global; sin secretos en la ruta.
- §4.1: nombre invalido (`/` extra, `..`, CRLF) NO viaja a la red y cae a UNVERIFIABLE;
  un scoped legitimo `@scope/name` produce EXACTAMENTE `.../%40scope%2Fname`
  (`quote(name, safe='')`, un solo segmento opaco, anti path-traversal/SSRF).

No se ejercitan los reintentos/backoff (eso vive en `concurrent.py`, ya cubierto por
`test_adapter.py`): aqui solo el contrato del adapter por intento.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import pytest

from slopguard.core.adapters.base import FetchState
from slopguard.core.adapters.concurrent import RetryableAdapter
from slopguard.core.adapters.npm import NpmAdapter
from slopguard.core.config import Config
from slopguard.core.errors import NetworkUnverifiableError
from slopguard.core.net.http_client import ALLOWED_HOSTS

if TYPE_CHECKING:
    from collections.abc import Iterator

# Host del registry npm: debe entrar al allowlist SOLO via el adapter (R4.5).
_NPM_HOST = "registry.npmjs.org"

# Packument npm minimo bien formado para el camino FOUND (mapeo §3.2).
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
# Doble determinista del cliente HTTP (mismo patron que test_adapter.py)
# ---------------------------------------------------------------------------


class _StubHttp:
    """Doble de `SecureHttpClient`: mapea la URL pedida a un comportamiento guionado.

    Cada entrada del guion es un payload dict (FOUND) o una `NetworkUnverifiableError`
    tipada (404/4xx/5xx/timeout/cap). Una lista simula intentos sucesivos. Registra cada
    URL pedida para asertar el url-encode del nombre y 'cache antes de red'.
    """

    def __init__(self, scripts: dict[str, list[Any]]) -> None:
        self._scripts = {k: list(v) for k, v in scripts.items()}
        self.urls: list[str] = []
        self._lock = threading.Lock()

    def get_json(self, url: str, **_: Any) -> dict[str, Any]:
        """Devuelve el siguiente paso del guion para el nombre encodeado en `url`."""
        encoded = url.rsplit("/", maxsplit=1)[1]
        with self._lock:
            self.urls.append(url)
            count = sum(1 for u in self.urls if u.endswith(f"/{encoded}"))
        steps = self._scripts[encoded]
        step = steps[min(count - 1, len(steps) - 1)]
        if isinstance(step, BaseException):
            raise step
        assert isinstance(step, dict)
        return step


def _http_error(status_code: int, *, is_transient: bool) -> NetworkUnverifiableError:
    """Error tipado que `SecureHttpClient` elevaria ante un status HTTP concreto."""
    return NetworkUnverifiableError(
        f"respuesta HTTP {status_code} no verificable",
        status_code=status_code,
        is_transient=is_transient,
    )


def _timeout_error() -> NetworkUnverifiableError:
    """Error de transporte transitorio (timeout/conexion caida), sin status_code."""
    return NetworkUnverifiableError(
        "fallo de red no verificable: TimeoutError", is_transient=True
    )


def _cap_error() -> NetworkUnverifiableError:
    """Error del cap de streaming (ADR-2): el cuerpo excede `npm_max_response_bytes`.

    `_extend_capped` lo lanza SIN `status_code` ni `is_transient`, de modo que el adapter
    lo clasifica UNVERIFIABLE permanente fail-safe (nunca metadata parcial, R4.3).
    """
    return NetworkUnverifiableError("cuerpo de la respuesta excede el maximo permitido")


def _non_object_error() -> NetworkUnverifiableError:
    """Error que `get_json` eleva cuando el top-level JSON no es un objeto (§4.1)."""
    return NetworkUnverifiableError("la respuesta JSON no es un objeto")


def _make_adapter(
    scripts: dict[str, list[Any]], *, use_cache: bool = False
) -> NpmAdapter:
    """Crea un `NpmAdapter` real con el cliente HTTP sustituido por un stub guionado.

    El dataset top-N npm embebido se carga de verdad en `__init__` (camino real, ADR-02);
    solo se inyecta el doble del cliente HTTP para controlar las respuestas sin red.
    Las claves del guion son nombres YA url-encodeados (la forma con que viajan en la URL).
    """
    adapter = NpmAdapter(Config(), use_cache=use_cache)
    adapter._http = _StubHttp(scripts)  # type: ignore[assignment]
    return adapter


def _enc(name: str) -> str:
    """Forma url-encodeada del nombre tal como el adapter la interpola en la URL."""
    return quote(name, safe="")


# ---------------------------------------------------------------------------
# Clasificacion de estados (R4.1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("step", "expected_state", "expected_transient"),
    [
        (_GOOD_PACKUMENT, FetchState.FOUND, False),
        (_http_error(404, is_transient=False), FetchState.NOT_FOUND, False),
        (_http_error(403, is_transient=False), FetchState.UNVERIFIABLE, False),
        (_http_error(410, is_transient=False), FetchState.UNVERIFIABLE, False),
        (_http_error(500, is_transient=True), FetchState.UNVERIFIABLE, True),
        (_http_error(503, is_transient=True), FetchState.UNVERIFIABLE, True),
        (_http_error(429, is_transient=True), FetchState.UNVERIFIABLE, True),
        (_timeout_error(), FetchState.UNVERIFIABLE, True),
    ],
)
def test_fetch_attempt_clasifica_status(
    step: Any, expected_state: FetchState, expected_transient: bool
) -> None:
    """fetch_attempt mapea cada status al estado y la transitoriedad de §4.1 (R4.1).

    200->FOUND, 404->NOT_FOUND (permanente), 4xx!=404->UNVERIFIABLE permanente,
    5xx/429/timeout->UNVERIFIABLE transitorio. Una anomalia jamas arrastra metadata.
    """
    adapter = _make_adapter({_enc("lodash"): [step]})

    attempt = adapter.fetch_attempt("lodash")

    assert attempt.outcome.state is expected_state
    assert attempt.is_transient is expected_transient
    if expected_state is not FetchState.FOUND:
        assert attempt.outcome.metadata is None


def test_404_no_lanza_y_es_not_found() -> None:
    """Un 404 (paquete inexistente/alucinado) => NOT_FOUND sin lanzar (R4.1, override)."""
    adapter = _make_adapter({_enc("ghost-pkg"): [_http_error(404, is_transient=False)]})

    outcome = adapter.fetch("ghost-pkg")

    assert outcome.state is FetchState.NOT_FOUND
    assert outcome.metadata is None


def test_found_mapea_packument_campo_por_campo() -> None:
    """200 ok => FOUND con `PackageMetadata` normalizado (§3.2), jamas el payload crudo."""
    adapter = _make_adapter({_enc("lodash"): [_GOOD_PACKUMENT]})

    outcome = adapter.fetch("lodash")

    meta = outcome.metadata
    assert outcome.state is FetchState.FOUND
    assert meta is not None
    assert meta.name == "lodash"  # nombre CONSULTADO normalizado, no payload["name"]
    assert meta.releases_count == 2  # len(versions)
    assert meta.has_repo_url is True
    assert meta.has_description is True
    assert meta.has_author is True
    assert meta.has_license is True
    assert meta.has_classifiers is True  # keywords no vacio
    assert meta.first_release_epoch is not None  # time.created parseado


# ---------------------------------------------------------------------------
# Cap de streaming + packument anomalo (R4.3, fail-safe)
# ---------------------------------------------------------------------------


def test_cap_excedido_es_unverifiable_sin_metadata() -> None:
    """Cuerpo >cap (ADR-2) => UNVERIFIABLE fail-safe, nunca metadata parcial (R4.3).

    El error del cap llega SIN status_code ni is_transient; el adapter lo degrada a
    UNVERIFIABLE permanente: jamas NOT_FOUND, jamas FOUND con metadata a medias.
    """
    adapter = _make_adapter({_enc("huge-pkg"): [_cap_error()]})

    attempt = adapter.fetch_attempt("huge-pkg")

    assert attempt.outcome.state is FetchState.UNVERIFIABLE
    assert attempt.is_transient is False  # cap => permanente (no reintentar a ciegas)
    assert attempt.outcome.metadata is None


def test_packument_no_objeto_es_unverifiable() -> None:
    """Un top-level JSON no-objeto (lista/escalar) => UNVERIFIABLE (§4.1, fail-closed)."""
    adapter = _make_adapter({_enc("weird-pkg"): [_non_object_error()]})

    outcome = adapter.fetch("weird-pkg")

    assert outcome.state is FetchState.UNVERIFIABLE
    assert outcome.metadata is None


def test_packument_anomalo_degrada_flags_sin_inventar_senal() -> None:
    """Packument FOUND pero con `time` ausente y `versions` no-dict => flags False/None.

    El adapter NO inventa senal: sin `time` => first_release_epoch None; `versions` no-dict
    => releases_count 0; campos de metadata ausentes => False (R4.4, fail-closed).
    """
    anomalous: dict[str, Any] = {"versions": "not-a-dict"}
    adapter = _make_adapter({_enc("bare-pkg"): [anomalous]})

    outcome = adapter.fetch("bare-pkg")

    meta = outcome.metadata
    assert outcome.state is FetchState.FOUND
    assert meta is not None
    assert meta.first_release_epoch is None
    assert meta.releases_count == 0
    assert meta.has_repo_url is False
    assert meta.has_description is False
    assert meta.has_author is False
    assert meta.has_license is False
    assert meta.has_classifiers is False


def test_excepcion_inesperada_degrada_a_unverifiable() -> None:
    """Defensa en profundidad: una excepcion no-NetworkUnverifiable => UNVERIFIABLE (R4.4).

    Una regresion del cliente HTTP (p.ej. un TypeError crudo) jamas aborta el lote ni
    escapa como stacktrace: el adapter la degrada a UNVERIFIABLE permanente.
    """
    adapter = _make_adapter({_enc("poison"): [TypeError("regresion inesperada")]})

    attempt = adapter.fetch_attempt("poison")

    assert attempt.outcome.state is FetchState.UNVERIFIABLE
    assert attempt.is_transient is False


# ---------------------------------------------------------------------------
# Nombre invalido: fail-closed sin red (§4.1, R3.3/R4.5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_name",
    [
        "@scope/../evil",  # `/` extra + segmento `..` (traversal)
        "foo/bar",  # `/` fuera de la posicion del scope
        "..",  # segmento de traversal puro
        "re\nact",  # CRLF INTERNO (sobrevive al strip; bypass clasico de `^..$`)
        "re\ract",  # CR interno
        ".hidden",  # inicio por `.`
        "_private",  # inicio por `_`
        "pkg name",  # espacio
        "pkg%2e",  # `%` (encoding manual prohibido en el nombre)
        "café",  # unicode fuera del charset
        "a" * 215,  # > 214 (limite npm)
    ],
)
def test_nombre_invalido_es_unverifiable_sin_red(bad_name: str) -> None:
    """Un nombre estructuralmente invalido => UNVERIFIABLE SIN tocar la red (§4.1).

    El stub no tiene guion para ningun nombre: si el adapter intentara consultar la red,
    `get_json` lanzaria `KeyError` y el test fallaria. Que el guion vacio no se toque
    prueba que la validacion corta ANTES del transporte (fail-closed, R3.3/R4.5).

    Nota: un CRLF *terminal* (`"react\\n"`) NO se prueba aqui porque `normalize_name`
    hace `strip()` antes de validar y lo neutraliza a `"react"` (nombre legitimo que
    viaja limpio, igual que PyPI). Los casos peligrosos son los CRLF/control INTERNOS,
    que sobreviven al strip y deben caer a UNVERIFIABLE sin tocar la red.
    """
    adapter = _make_adapter({})  # guion VACIO: cualquier viaje a la red explota

    attempt = adapter.fetch_attempt(bad_name)

    assert attempt.outcome.state is FetchState.UNVERIFIABLE
    assert attempt.is_transient is False
    assert attempt.outcome.metadata is None
    assert adapter._http.urls == []  # type: ignore[attr-defined]  # nunca viajo a la red


# ---------------------------------------------------------------------------
# URL anti path-traversal: url-encode estricto (§4.1, R4.5)
# ---------------------------------------------------------------------------


def test_scoped_legitimo_se_url_encodea_a_un_solo_segmento() -> None:
    """`@scope/name` legitimo => URL `.../%40scope%2Fname` (un solo segmento opaco).

    `quote(name, safe='')` encodea `@`->%40 y `/`->%2F: el path resultante no tiene `/`
    ni `..` interpretables por el registry (anti path-traversal/SSRF, §4.1).
    """
    adapter = _make_adapter({_enc("@scope/util"): [_GOOD_PACKUMENT]})

    outcome = adapter.fetch("@scope/util")

    assert outcome.state is FetchState.FOUND
    urls = adapter._http.urls  # type: ignore[attr-defined]
    assert urls == ["https://registry.npmjs.org/%40scope%2Futil"]
    # El segmento del path no contiene `/` ni `@` crudos.
    segment = urls[0].rsplit("/", maxsplit=1)[1]
    assert "/" not in segment
    assert "@" not in segment
    assert segment == "%40scope%2Futil"


def test_nombre_simple_no_se_altera_en_la_url() -> None:
    """Un nombre simple sin chars especiales viaja tal cual (quote es no-op sobre `[a-z0-9-]`)."""
    adapter = _make_adapter({_enc("lodash"): [_GOOD_PACKUMENT]})

    adapter.fetch("lodash")

    urls = adapter._http.urls  # type: ignore[attr-defined]
    assert urls == ["https://registry.npmjs.org/lodash"]


# ---------------------------------------------------------------------------
# Cache antes de red + fetch colapsa transitorios (R4.1)
# ---------------------------------------------------------------------------


def test_fetch_colapsa_transitorio_a_unverifiable() -> None:
    """`fetch` (via `EcosystemAdapter`) colapsa un fallo transitorio a UNVERIFIABLE.

    `fetch` no reintenta: devuelve directamente el outcome del unico intento (el motor
    concurrente usa `fetch_attempt` para reintentar). Un transitorio => UNVERIFIABLE.
    """
    adapter = _make_adapter({_enc("flaky"): [_timeout_error()]})

    outcome = adapter.fetch("flaky")

    assert outcome.state is FetchState.UNVERIFIABLE
    assert outcome.metadata is None


def test_unverifiable_no_se_cachea_y_found_si(tmp_path_cache: None) -> None:
    """FOUND/NOT_FOUND se cachean; UNVERIFIABLE no (segunda llamada reconsulta la red).

    Con cache habilitada: un primer FOUND se sirve de cache en la segunda llamada (una
    sola URL pedida). Un UNVERIFIABLE no se cachea (dos URLs pedidas).
    """
    found_adapter = _make_adapter({_enc("lodash"): [_GOOD_PACKUMENT]}, use_cache=True)
    found_adapter.fetch("lodash")
    found_adapter.fetch("lodash")
    assert len(found_adapter._http.urls) == 1  # type: ignore[attr-defined]

    unv_adapter = _make_adapter(
        {_enc("flaky"): [_timeout_error(), _timeout_error()]}, use_cache=True
    )
    unv_adapter.fetch("flaky")
    unv_adapter.fetch("flaky")
    assert len(unv_adapter._http.urls) == 2  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Contratos de protocolo + hooks (R4.1/R4.4)
# ---------------------------------------------------------------------------


def test_npm_adapter_es_retryable() -> None:
    """`NpmAdapter` satisface `RetryableAdapter` => `fetch_many` reintenta sus transitorios."""
    adapter = _make_adapter({})
    assert isinstance(adapter, RetryableAdapter)
    assert adapter.ecosystem_id == "npm"


def test_get_downloads_es_un_hook_inocuo() -> None:
    """`get_downloads` es un hook reservado que retorna None y nunca lanza (R4.4).

    El tipo de retorno es `None` (verificable por mypy en la firma), asi que aqui solo
    se ejercita la rama para cobertura: la ausencia de descargas NO es senal de riesgo.
    """
    adapter = _make_adapter({})
    adapter.get_downloads("lodash")  # no lanza; valor de retorno tipado None en la firma


# ---------------------------------------------------------------------------
# Allowlist: host npm SOLO via la instancia del adapter (R4.5/NFR-Seg.1)
# ---------------------------------------------------------------------------


def test_host_npm_solo_en_la_instancia_del_adapter() -> None:
    """El host npm entra al allowlist EFECTIVO SOLO via la instancia del adapter (R4.5).

    La constante base global `ALLOWED_HOSTS` NO contiene `registry.npmjs.org`: solo la
    allowlist de ESTA instancia (base | extra) lo admite. Asi el host npm jamas se filtra
    a otras instancias del cliente HTTP (p.ej. la de PyPI).
    """
    assert _NPM_HOST not in ALLOWED_HOSTS  # nunca en la constante base global

    adapter = NpmAdapter(Config(), use_cache=False)
    effective = adapter._http._allowed_hosts
    assert _NPM_HOST in effective
    assert "pypi.org" in effective  # la base anclada se conserva


@pytest.fixture
def tmp_path_cache(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Apunta el root del DiskCache del adapter npm a un tmp aislado por test.

    Evita contaminar `~/.cache/slopguard` y garantiza que cada test arranque con cache
    limpia (el aislamiento entre tests no depende del estado del disco del usuario).
    """
    monkeypatch.setattr(
        "slopguard.core.adapters.npm.Path.home", lambda: tmp_path
    )
    yield
