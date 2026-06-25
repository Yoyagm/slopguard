"""Aislamiento L4 por ecosistema en el resolver de la Capa 4 (H4-T27, design §3.7, ADR-6 pto 5).

La garantia central de esta ola: ningun veredicto LLM cruza entre ecosistemas (NFR-Seg.3).
El aislamiento es por DOS capas (simetria con OSV, ADR-6):

1. **Por clave** (`_cache_key`): el `ecosystem_id` es el PRIMER componente => npm y PyPI del
   mismo nombre/contexto/modelo/prompt NUNCA colisionan en disco.
2. **Por validador** (`_to_blob` persiste `ecosystem`; `_validate_blob` lo exige al leer): un
   blob de ecosistema ajeno se rechaza (=> miss) AUNQUE la clave se malformara, y un blob
   pre-H4 sin `ecosystem` tambien.

Se prueban las funciones puras (clave/blob/validador) y el camino e2e de `resolve_layer4`
con `DiskCache` real en `tmp_path`: un blob npm cacheado no se sirve a una lectura pypi del
mismo nombre/contexto, ni viceversa. Espeja el patron de `test_h2_osv.py` para OSV.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from slopguard.core.cache.disk_cache import DiskCache
from slopguard.core.config import Config
from slopguard.core.llm.resolver import (
    _cache_key,
    _to_blob,
    _validate_blob,
    resolve_layer4,
)
from slopguard.core.models import Clasificacion, HallucinationContext, LlmAssessment

if TYPE_CHECKING:
    from pathlib import Path

_NAMESPACE = "llm"
_SCHEMA = "llm-1"
_TTL_SEGUNDOS = 168 * 3600


def _assessment(modelo: str = "claude-opus-4-8") -> LlmAssessment:
    return LlmAssessment(
        clasificacion=Clasificacion.FABRICACION,
        confianza=0.9,
        patron="p",
        rationale="r",
        modelo=modelo,
        prompt_version="h4-v1",
    )


def _context() -> HallucinationContext:
    return HallucinationContext(
        existe=True,
        edad_dias=10,
        typo_vecino=None,
        typo_distancia=None,
        tiene_repo=False,
        tiene_metadata=False,
        senales_blandas=(),
    )


class _CountingEvaluator:
    """Evaluador FALSO conforme al Protocol: registra (name, ecosystem_id) y cuenta llamadas.

    Contrato `evaluate` (design §3.7): NUNCA lanza; devuelve un `LlmAssessment` o `None`.
    """

    def __init__(self, assessment: LlmAssessment | None) -> None:
        self._assessment = assessment
        self.calls: list[tuple[str, str]] = []

    def evaluate(
        self, name: str, context: HallucinationContext, ecosystem_id: str = "pypi"
    ) -> LlmAssessment | None:
        self.calls.append((name, ecosystem_id))
        return self._assessment


# --------------------------------------------------------------------------- #
# Capa 1 del aislamiento: la clave incorpora el ecosistema (design §3.7).
# --------------------------------------------------------------------------- #


def test_cache_key_distinta_por_ecosistema() -> None:
    config = Config()
    context = _context()
    key_npm = _cache_key("lodash", context, config, "npm")
    key_pypi = _cache_key("lodash", context, config, "pypi")
    assert key_npm != key_pypi
    # El ecosistema es el PRIMER componente de la clave (separador '|').
    assert key_npm.split("|")[0] == "npm"
    assert key_pypi.split("|")[0] == "pypi"


def test_cache_key_estable_para_mismo_ecosistema() -> None:
    config = Config()
    context = _context()
    assert _cache_key("lodash", context, config, "npm") == _cache_key(
        "lodash", context, config, "npm"
    )


# --------------------------------------------------------------------------- #
# Capa 2 del aislamiento: blob persiste `ecosystem`; el validador lo exige.
# --------------------------------------------------------------------------- #


def test_to_blob_persiste_ecosystem() -> None:
    blob = _to_blob(_assessment(), "npm")
    assert blob["ecosystem"] == "npm"


def test_validate_blob_acepta_mismo_ecosistema() -> None:
    blob = _to_blob(_assessment(), "npm")
    result = _validate_blob(blob, "npm")
    assert result is not None
    assert result.clasificacion is Clasificacion.FABRICACION


def test_validate_blob_rechaza_ecosistema_ajeno() -> None:
    # Un blob npm leido como pypi (y viceversa) => None (miss): no hay cruce de veredictos.
    blob_npm = _to_blob(_assessment(), "npm")
    assert _validate_blob(blob_npm, "pypi") is None
    blob_pypi = _to_blob(_assessment(), "pypi")
    assert _validate_blob(blob_pypi, "npm") is None


def test_validate_blob_sin_ecosystem_pre_h4_es_miss() -> None:
    # Un blob pre-H4 (sin campo `ecosystem`) se rechaza => refetch (ADR-6 pto 5).
    blob = _to_blob(_assessment(), "npm")
    del blob["ecosystem"]
    assert _validate_blob(blob, "npm") is None


@pytest.mark.parametrize(
    ("campo", "valor"),
    [
        ("clasificacion", "inexistente"),  # no es un Clasificacion valido
        ("clasificacion", 123),  # no-string
        ("confianza", 1.5),  # fuera de [0, 1]
        ("confianza", -0.1),  # fuera de [0, 1]
        ("confianza", float("nan")),  # no finito
        ("confianza", True),  # bool: rechazado explicitamente
        ("confianza", "0.9"),  # no es numero
        ("patron", 1),  # campo de texto no-string
        ("rationale", None),  # campo de texto ausente/None
        ("modelo", 42),  # campo de texto no-string
        ("prompt_version", []),  # campo de texto no-string
    ],
)
def test_validate_blob_rechaza_campo_invalido(campo: str, valor: object) -> None:
    # Defensa del validador (entrada NO confiable del disco): cualquier desviacion de tipo/
    # rango => None (miss => refetch), la cache nunca inyecta un assessment invalido.
    blob = _to_blob(_assessment(), "npm")
    blob[campo] = valor
    assert _validate_blob(blob, "npm") is None


# --------------------------------------------------------------------------- #
# resolve_layer4 e2e con DiskCache real: aislamiento por construccion (NFR-Seg.3).
# --------------------------------------------------------------------------- #


def test_resolve_layer4_cachea_y_segunda_vez_no_llama_evaluador(tmp_path: Path) -> None:
    config = Config()
    cache = DiskCache(tmp_path, config.llm_ttl_cache_horas, enabled=True)
    evaluator = _CountingEvaluator(_assessment())
    items = [("lodash", _context())]

    first = resolve_layer4(evaluator, cache, items, config, "npm", now=1_700_000_000.0)
    assert first["lodash"] is not None
    assert evaluator.calls == [("lodash", "npm")]

    # Segunda corrida: HIT de cache, el evaluador NO se vuelve a invocar.
    second = resolve_layer4(evaluator, cache, items, config, "npm", now=1_700_000_000.0)
    assert second["lodash"] is not None
    assert evaluator.calls == [("lodash", "npm")]  # sin nueva llamada de red


def test_resolve_layer4_blob_npm_no_se_sirve_a_lectura_pypi(tmp_path: Path) -> None:
    # El nucleo del finding: un veredicto cacheado para npm NO se sirve a una corrida pypi
    # del MISMO nombre/contexto. Como la clave difiere por ecosistema, la lectura pypi es
    # un miss => el evaluador se invoca con ecosystem_id="pypi" (no se reusa el blob npm).
    config = Config()
    cache = DiskCache(tmp_path, config.llm_ttl_cache_horas, enabled=True)
    items = [("lodash", _context())]

    npm_eval = _CountingEvaluator(_assessment())
    resolve_layer4(npm_eval, cache, items, config, "npm", now=1_700_000_000.0)
    assert npm_eval.calls == [("lodash", "npm")]

    pypi_eval = _CountingEvaluator(_assessment())
    resolve_layer4(pypi_eval, cache, items, config, "pypi", now=1_700_000_000.0)
    # La corrida pypi NO reuso el blob npm: hubo una llamada de red propia (pypi).
    assert pypi_eval.calls == [("lodash", "pypi")]


def test_resolve_layer4_blob_pypi_corrompido_a_npm_no_cruza(tmp_path: Path) -> None:
    # Defensa por VALIDADOR: aunque un blob se persistiera bajo la clave de npm pero con
    # `ecosystem="pypi"` (clave malformada/manipulada), `_validate_blob` lo rechaza al leer
    # con ecosystem_id="npm" => miss => refetch. El aislamiento no depende solo de la clave.
    config = Config()
    cache = DiskCache(tmp_path, config.llm_ttl_cache_horas, enabled=True)
    context = _context()
    npm_key = _cache_key("lodash", context, config, "npm")
    cache.put_blob(
        _NAMESPACE, npm_key, _to_blob(_assessment(), "pypi"),
        schema_version=_SCHEMA, now=1_700_000_000.0,
    )

    evaluator = _CountingEvaluator(_assessment())
    result = resolve_layer4(
        evaluator, cache, [("lodash", context)], config, "npm", now=1_700_000_000.0
    )
    assert result["lodash"] is not None
    # El blob con ecosystem ajeno fue rechazado: el evaluador npm tuvo que ejecutarse.
    assert evaluator.calls == [("lodash", "npm")]


def test_resolve_layer4_abstencion_no_se_cachea(tmp_path: Path) -> None:
    # Una abstencion (evaluator => None) NUNCA se cachea: la segunda corrida vuelve a llamar.
    config = Config()
    cache = DiskCache(tmp_path, config.llm_ttl_cache_horas, enabled=True)
    evaluator = _CountingEvaluator(None)
    items = [("lodash", _context())]

    first = resolve_layer4(evaluator, cache, items, config, "npm", now=1_700_000_000.0)
    assert first["lodash"] is None
    second = resolve_layer4(evaluator, cache, items, config, "npm", now=1_700_000_000.0)
    assert second["lodash"] is None
    assert evaluator.calls == [("lodash", "npm"), ("lodash", "npm")]  # dos llamadas


def test_resolve_layer4_tope_de_llamadas_abstiene_sin_evaluar(tmp_path: Path) -> None:
    # Con presupuesto 0 de llamadas de red, todo MISS => abstencion (None) sin invocar
    # al evaluador (LLM_UNAVAILABLE), preservando la degradacion segura (R4).
    config = Config(llm_max_calls_por_corrida=0)
    cache = DiskCache(tmp_path, config.llm_ttl_cache_horas, enabled=True)
    evaluator = _CountingEvaluator(_assessment())
    result = resolve_layer4(
        evaluator, cache, [("lodash", _context())], config, "npm", now=1_700_000_000.0
    )
    assert result["lodash"] is None
    assert evaluator.calls == []  # el tope evita siquiera invocar al evaluador
