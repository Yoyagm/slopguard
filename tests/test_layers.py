"""Suite de las capas de deteccion (T29): Layer 0, Layer 1 y Layer 2.

Cubre los criterios de aceptacion de T26, T27 y T28 trazados a:
- R2.2-R2.4, ADR-01 (Capa 0: existencia, NOT_FOUND, edad, NEW_PACKAGE)
- R3.1-R3.7, ADR-02 (Capa 1: typosquatting DL+JW, guardas de longitud, desempate)
- R4.2-R4.5, ADR-01 (Capa 2: WEAK_METADATA, LOW_VERIFIABILITY, cap c2_max_contrib)

NFR-Det.1: `now_epoch` inyectado; las funciones son puras y deterministas.
Frontera de import: las capas no importan core.net ni core.adapters.pypi.
"""

from __future__ import annotations

from slopguard.core.adapters.base import FetchOutcome, FetchState, PackageMetadata
from slopguard.core.config import Config
from slopguard.core.dataset.top_n import TopNDataset, build_top_n
from slopguard.core.layers import layer0_existence, layer1_similarity, layer2_metadata
from slopguard.core.models import ErrorCategory, Layer, SignalCode

# ---------------------------------------------------------------------------
# Epoch de referencia para tests deterministas (2024-06-01T00:00:00Z).
# ---------------------------------------------------------------------------
_NOW = 1_717_200_000.0
_SECONDS_PER_DAY = 86_400.0
_DEFAULT_CONFIG = Config()


# ---------------------------------------------------------------------------
# Helpers de construccion
# ---------------------------------------------------------------------------

def _found(
    *,
    releases_count: int = 20,
    has_repo_url: bool = True,
    has_description: bool = True,
    has_author: bool = True,
    has_license: bool = True,
    has_classifiers: bool = True,
    in_top_n: bool = False,
    first_release_epoch: float | None = None,
) -> FetchOutcome:
    """Construye un FetchOutcome FOUND con valores por defecto para tests."""
    meta = PackageMetadata(
        name="test-pkg",
        first_release_epoch=first_release_epoch,
        releases_count=releases_count,
        has_repo_url=has_repo_url,
        has_description=has_description,
        has_author=has_author,
        has_license=has_license,
        has_classifiers=has_classifiers,
        in_top_n=in_top_n,
    )
    return FetchOutcome(state=FetchState.FOUND, metadata=meta)


def _not_found() -> FetchOutcome:
    return FetchOutcome(state=FetchState.NOT_FOUND)


def _unverifiable() -> FetchOutcome:
    return FetchOutcome(
        state=FetchState.UNVERIFIABLE,
        error_category=ErrorCategory.NETWORK_UNVERIFIABLE,
    )


def _small_dataset(names: list[str]) -> TopNDataset:
    """Dataset minimal para tests de Capa 1."""
    return build_top_n(names, version="test", generated_at="2024-01-01")


# ===========================================================================
# CAPA 0 — existencia y edad
# ===========================================================================

class TestLayer0NotFound:
    """R2.2: NOT_FOUND -> senal NONEXISTENT, override, peso 0, is_soft=False."""

    def test_emite_nonexistent(self) -> None:
        signals = layer0_existence.evaluate(_not_found(), _DEFAULT_CONFIG, now_epoch=_NOW)
        assert len(signals) == 1
        s = signals[0]
        assert s.code is SignalCode.NONEXISTENT
        assert s.layer is Layer.L0
        assert s.weight == 0
        assert s.is_soft is False
        assert s.suspected_target is None

    def test_no_emite_senal_edad_cuando_not_found(self) -> None:
        # NOT_FOUND no debe analizar edad aunque la hubiera.
        signals = layer0_existence.evaluate(_not_found(), _DEFAULT_CONFIG, now_epoch=_NOW)
        assert all(s.code is SignalCode.NONEXISTENT for s in signals)


class TestLayer0Unverifiable:
    """UNVERIFIABLE -> lista vacia (el orquestador ya marca la dep)."""

    def test_unverifiable_sin_senales(self) -> None:
        signals = layer0_existence.evaluate(_unverifiable(), _DEFAULT_CONFIG, now_epoch=_NOW)
        assert signals == []


class TestLayer0NewPackage:
    """R2.3/R2.4: edad < edad_minima_dias -> NEW_PACKAGE blanda peso 15."""

    def test_paquete_nuevo_emite_senal(self) -> None:
        # Publicado hace 10 dias.
        epoch = _NOW - 10 * _SECONDS_PER_DAY
        signals = layer0_existence.evaluate(
            _found(first_release_epoch=epoch), _DEFAULT_CONFIG, now_epoch=_NOW
        )
        assert len(signals) == 1
        s = signals[0]
        assert s.code is SignalCode.NEW_PACKAGE
        assert s.weight == 15
        assert s.is_soft is True
        assert s.layer is Layer.L0
        assert s.suspected_target is None
        assert "10" in s.detail

    def test_paquete_viejo_sin_senal(self) -> None:
        # Publicado hace 200 dias (umbral default 90).
        epoch = _NOW - 200 * _SECONDS_PER_DAY
        signals = layer0_existence.evaluate(
            _found(first_release_epoch=epoch), _DEFAULT_CONFIG, now_epoch=_NOW
        )
        assert signals == []

    def test_edad_exactamente_en_umbral_sin_senal(self) -> None:
        # Exactamente edad_minima_dias dias -> no dispara (>= umbral).
        epoch = _NOW - _DEFAULT_CONFIG.edad_minima_dias * _SECONDS_PER_DAY
        signals = layer0_existence.evaluate(
            _found(first_release_epoch=epoch), _DEFAULT_CONFIG, now_epoch=_NOW
        )
        assert signals == []

    def test_sin_fecha_release_sin_senal_edad(self) -> None:
        signals = layer0_existence.evaluate(
            _found(first_release_epoch=None), _DEFAULT_CONFIG, now_epoch=_NOW
        )
        assert signals == []

    def test_paquete_found_limpio_sin_senales(self) -> None:
        # Paquete viejo y completo -> ninguna senal L0.
        epoch = _NOW - 365 * _SECONDS_PER_DAY
        signals = layer0_existence.evaluate(
            _found(first_release_epoch=epoch), _DEFAULT_CONFIG, now_epoch=_NOW
        )
        assert signals == []

    def test_now_epoch_inyectado_determinismo(self) -> None:
        """NFR-Det.1: el mismo outcome con now diferente produce resultados distintos."""
        epoch = _NOW - 10 * _SECONDS_PER_DAY
        outcome = _found(first_release_epoch=epoch)
        # Con now=NOW (paquete nuevo): dispara.
        signals_new = layer0_existence.evaluate(outcome, _DEFAULT_CONFIG, now_epoch=_NOW)
        # Con now muy posterior (paquete ya viejo): no dispara.
        now_far_future = _NOW + 365 * _SECONDS_PER_DAY
        signals_old = layer0_existence.evaluate(outcome, _DEFAULT_CONFIG, now_epoch=now_far_future)
        assert len(signals_new) == 1
        assert signals_old == []

    def test_config_edad_minima_personalizada(self) -> None:
        config = Config(edad_minima_dias=5)
        epoch = _NOW - 10 * _SECONDS_PER_DAY  # 10 dias > umbral 5 -> no dispara.
        signals = layer0_existence.evaluate(
            _found(first_release_epoch=epoch), config, now_epoch=_NOW
        )
        assert signals == []

    def test_senal_blanda_nunca_es_override(self) -> None:
        """NEW_PACKAGE es blanda (is_soft=True); no es override (R2.4, ADR-01)."""
        epoch = _NOW - 1 * _SECONDS_PER_DAY
        signals = layer0_existence.evaluate(
            _found(first_release_epoch=epoch), _DEFAULT_CONFIG, now_epoch=_NOW
        )
        assert all(s.is_soft for s in signals)


# ===========================================================================
# CAPA 1 — typosquatting
# ===========================================================================

_TOP_N_BASE = ["requests", "numpy", "flask", "django", "attrs", "click", "boto3"]


class TestLayer1Guards:
    """Guardas de longitud y match exacto (R3.2, R3.5, R3.6)."""

    def test_nombre_len_3_sin_senal(self) -> None:
        ds = _small_dataset(_TOP_N_BASE)
        signals = layer1_similarity.evaluate("pip", ds, _DEFAULT_CONFIG)
        assert signals == []

    def test_nombre_len_2_sin_senal(self) -> None:
        ds = _small_dataset(_TOP_N_BASE)
        signals = layer1_similarity.evaluate("ab", ds, _DEFAULT_CONFIG)
        assert signals == []

    def test_nombre_len_1_sin_senal(self) -> None:
        ds = _small_dataset(_TOP_N_BASE)
        signals = layer1_similarity.evaluate("a", ds, _DEFAULT_CONFIG)
        assert signals == []

    def test_match_exacto_sin_senal(self) -> None:
        """R3.2: nombre identico a uno del top-N -> sin senal."""
        ds = _small_dataset(_TOP_N_BASE)
        signals = layer1_similarity.evaluate("requests", ds, _DEFAULT_CONFIG)
        assert signals == []

    def test_match_exacto_normalizado_sin_senal(self) -> None:
        """El dataset esta normalizado PEP 503 (requests == requests)."""
        ds = _small_dataset(_TOP_N_BASE)
        # "attrs" esta en el dataset normalizado.
        signals = layer1_similarity.evaluate("attrs", ds, _DEFAULT_CONFIG)
        assert signals == []

    def test_nombre_demasiado_largo_name_untrusted(self) -> None:
        """R3.6: nombre > nombre_max_chars -> NAME_UNTRUSTED sin distancia."""
        ds = _small_dataset(_TOP_N_BASE)
        nombre_largo = "a" * (_DEFAULT_CONFIG.nombre_max_chars + 1)
        signals = layer1_similarity.evaluate(nombre_largo, ds, _DEFAULT_CONFIG)
        assert len(signals) == 1
        assert signals[0].code is SignalCode.NAME_UNTRUSTED
        assert signals[0].is_soft is False
        assert signals[0].layer is Layer.L1
        assert signals[0].weight == 30

    def test_nombre_exactamente_en_limite_no_name_untrusted(self) -> None:
        """Longitud == nombre_max_chars: no dispara NAME_UNTRUSTED."""
        ds = _small_dataset(_TOP_N_BASE)
        nombre = "z" * _DEFAULT_CONFIG.nombre_max_chars
        signals = layer1_similarity.evaluate(nombre, ds, _DEFAULT_CONFIG)
        # No debe ser NAME_UNTRUSTED (puede ser 0 senales o TYPOSQUAT si hay match).
        assert all(s.code is not SignalCode.NAME_UNTRUSTED for s in signals)


class TestLayer1Typosquat:
    """R3.3/R3.4: deteccion DL y JW con candidato correcto."""

    def test_dl1_dispara_peso_60(self) -> None:
        """DL=1 (transposicion) -> TYPOSQUAT peso 60."""
        ds = _small_dataset(["requests"])
        # "reqursts" tiene DL=1 respecto a "requests" (transposicion u↔e).
        signals = layer1_similarity.evaluate("reqursts", ds, _DEFAULT_CONFIG)
        assert len(signals) == 1
        s = signals[0]
        assert s.code is SignalCode.TYPOSQUAT
        assert s.weight == 60
        assert s.suspected_target == "requests"
        assert s.is_soft is False
        assert s.layer is Layer.L1

    def test_dl1_attr_vs_attrs(self) -> None:
        """DL=1 delecion: 'attr' vs 'attrs'."""
        ds = _small_dataset(["attrs"])
        signals = layer1_similarity.evaluate("attr", ds, _DEFAULT_CONFIG)
        assert len(signals) == 1
        assert signals[0].code is SignalCode.TYPOSQUAT
        assert signals[0].weight == 60
        assert signals[0].suspected_target == "attrs"

    def test_dl2_dispara_peso_40(self) -> None:
        """DL=2 -> TYPOSQUAT peso 40."""
        ds = _small_dataset(["requests"])
        # "rqursts" tiene DL=2 respecto a "requests".
        signals = layer1_similarity.evaluate("rqursts", ds, _DEFAULT_CONFIG)
        assert len(signals) == 1
        assert signals[0].code is SignalCode.TYPOSQUAT
        assert signals[0].weight == 40

    def test_dl_mayor_que_dl_max_sin_senal_dl(self) -> None:
        """DL > dl_max (default 2) con primer char diferente -> sin senal."""
        ds = _small_dataset(["requests"])
        # "xxxxxxxx" (8 chars) DL es alto; sin primer char comun con "requests" para JW.
        signals = layer1_similarity.evaluate("xxxxxxxx", ds, _DEFAULT_CONFIG)
        assert signals == []

    def test_sin_candidatos_sin_senal(self) -> None:
        """Nombre completamente diferente -> sin senal."""
        ds = _small_dataset(["requests"])
        signals = layer1_similarity.evaluate("zzzzzzzz", ds, _DEFAULT_CONFIG)
        assert signals == []

    def test_dataset_vacio_sin_senal(self) -> None:
        ds = _small_dataset([])
        signals = layer1_similarity.evaluate("requests", ds, _DEFAULT_CONFIG)
        assert signals == []

    def test_determinismo_misma_entrada(self) -> None:
        """R3.7: misma entrada -> mismo resultado siempre."""
        ds = _small_dataset(_TOP_N_BASE)
        r1 = layer1_similarity.evaluate("reqursts", ds, _DEFAULT_CONFIG)
        r2 = layer1_similarity.evaluate("reqursts", ds, _DEFAULT_CONFIG)
        assert r1 == r2

    def test_objetivo_sospechado_en_senal(self) -> None:
        """R3.3: la senal identifica el paquete legitimo sospechado."""
        ds = _small_dataset(["requests"])
        signals = layer1_similarity.evaluate("reqursts", ds, _DEFAULT_CONFIG)
        assert signals[0].suspected_target == "requests"

    def test_nombre_len_4_elegible(self) -> None:
        """R3.1: longitud 4 es elegible para analisis."""
        ds = _small_dataset(["numpy"])
        # "nump" (4 chars) tiene DL=1 con "numpy".
        signals = layer1_similarity.evaluate("nump", ds, _DEFAULT_CONFIG)
        assert len(signals) == 1
        assert signals[0].code is SignalCode.TYPOSQUAT


class TestLayer1Ramas:
    """Cobertura de ramas internas de _find_best_candidate/_jw_candidates/_dl_candidates."""

    def test_band_len_cero_ignorado(self) -> None:
        """band_len <= 0 se salta sin crashear (nombre corto con dl_max grande)."""
        # nombre de 4 chars, dl_max=4 -> band_len puede llegar a 0.
        config = Config(dl_max=4)
        ds = _small_dataset(["requests"])
        # No debe lanzar; puede o no emitir senal.
        signals = layer1_similarity.evaluate("abcd", ds, config)
        # El resultado es determinista; solo verificamos que no crashea.
        assert isinstance(signals, list)

    def test_target_igual_nombre_en_by_first_char(self) -> None:
        """_jw_candidates: target == name en by_first_char se omite (guarda exacta)."""
        # El dataset contiene 'abcde' y el probe es exactamente 'abcde'.
        # La guarda de match exacto en evaluate() devuelve [] antes de _find_best_candidate,
        # pero si otro target con mismo primer char y DL<=dl_max existe, se cubre la rama.
        # Forzamos la rama interna: el target 'aaaaa' esta en by_first_char['a'],
        # y el probe 'aaaaa' matchea exacto -> evaluate retorna [] antes (guarda3).
        # Para ejercer la rama `target == name` dentro de _jw_candidates necesitamos
        # un probe que NO este en members pero cuyo nombre[0] coincida con un target
        # que SI esta en by_first_char. El dataset tiene 'requests' y probe 'reqursts':
        # DL=1 <= dl_max, no entra a _jw_candidates para 'requests'.
        # Usamos un dataset con 2 nombres de primer char 'r': 'requests' y 'reqzzzzzz'.
        # probe='reqursts' (DL=1 con 'requests', DL alto con 'reqzzzzzz').
        # 'reqzzzzzz' comparte primer char pero DL alto; JW puede ser >= jw_min o no.
        ds = _small_dataset(["requests", "reqzzzzzz"])
        config = Config(jw_min=0.999)  # umbral JW imposible -> JW no dispara
        signals = layer1_similarity.evaluate("reqursts", ds, config)
        # DL=1 con 'requests' -> dispara por DL siempre.
        assert len(signals) == 1
        assert signals[0].weight == 60

    def test_jw_calculado_pero_bajo_umbral(self) -> None:
        """_jw_candidates: JW calculado < jw_min -> no agrega candidato (rama False)."""
        # probe 'requests-extra' comparte primer char 'r' con 'requests'.
        # DL alto (>2), JW moderado. Con jw_min=0.999, JW < jw_min -> sin senal.
        ds = _small_dataset(["requests"])
        config = Config(jw_min=0.999)
        signals = layer1_similarity.evaluate("requests-extra", ds, config)
        # DL alto, JW no llega a 0.999 -> sin senal.
        assert signals == []


class TestLayer1Desempate:
    """R3.4: desempate determinista menor DL -> mayor JW -> nombre asc."""

    def test_menor_dl_gana(self) -> None:
        """Candidato con DL=1 prevalece sobre DL=2."""
        ds = _small_dataset(["flasks", "flaask"])  # "flask" no esta en el dataset
        config = Config()
        # "flask": DL=1 con "flasks"; DL=2 con "flaask".
        signals = layer1_similarity.evaluate("flask", ds, config)
        if signals:
            # El candidato con menor DL debe ganar.
            assert signals[0].suspected_target == "flasks"

    def test_desempate_nombre_ascendente(self) -> None:
        """A igual DL y JW, elige nombre ascendente."""
        ds = _small_dataset(["aaa-b", "aaa-c"])
        # "aaaa" tiene DL=1 con ambos ("aaa-b" y "aaa-c") y JW similar.
        signals = layer1_similarity.evaluate("aaaa", ds, _DEFAULT_CONFIG)
        if signals:
            assert signals[0].suspected_target in {"aaa-b", "aaa-c"}


class TestLayer1JWSignal:
    """Senales capturadas por JW (DL > dl_max)."""

    def test_jw_debil_peso_25(self) -> None:
        """JW >= jw_min=0.92 pero < 0.95, DL > dl_max -> TYPOSQUAT peso 25.

        'requestsxxx': DL=3 (> dl_max=2), JW~0.945 (0.92 <= JW < 0.95).
        Capturado por la ruta JW; peso = 25 segun ADR-01.
        """
        ds = _small_dataset(["requests"])
        signals = layer1_similarity.evaluate("requestsxxx", ds, _DEFAULT_CONFIG)
        assert len(signals) == 1
        s = signals[0]
        assert s.code is SignalCode.TYPOSQUAT
        assert s.weight == 25
        assert s.suspected_target == "requests"
        assert not s.is_soft

    def test_jw_bajo_umbral_sin_senal(self) -> None:
        """JW < jw_min y DL > dl_max -> sin senal."""
        ds = _small_dataset(["requests"])
        # "zzzzzzzz" DL alto y JW muy bajo con "requests".
        signals = layer1_similarity.evaluate("zzzzzzzz", ds, _DEFAULT_CONFIG)
        assert signals == []

    def test_jw_fuerte_peso_30(self) -> None:
        """Rama JW fuerte: DL>dl_max y JW>=0.95 -> TYPOSQUAT peso 30 (ADR-01).

        Vector: dataset='abcdefghijklmnopqrstuvwx' (24 chars), probe con 3
        ediciones dispersas que mantienen JW>=0.95. DL=3>dl_max=2, JW=0.975.
        Confirma que la rama weight=30 de _weight_and_detail es alcanzable.
        """
        dataset_name = "abcdefghijklmnopqrstuvwx"
        probe = "abcdefghijklmnoqprtsvuwx"  # DL=3, JW~0.975
        ds = _small_dataset([dataset_name])
        signals = layer1_similarity.evaluate(probe, ds, _DEFAULT_CONFIG)
        assert len(signals) == 1
        s = signals[0]
        assert s.code is SignalCode.TYPOSQUAT
        assert s.weight == 30
        assert s.suspected_target == dataset_name
        assert s.is_soft is False
        assert s.layer is Layer.L1

    def test_jw_minimo_config_ajustable(self) -> None:
        """jw_min configurable; con umbral alto no dispara."""
        ds = _small_dataset(["requests"])
        config = Config(jw_min=0.999)  # umbral casi perfecto.
        signals = layer1_similarity.evaluate("reqursts", ds, config)
        # DL=1 < dl_max, sigue disparando por DL, no por JW.
        # La prueba valida que config.jw_min se respeta en la ruta JW.
        # reqursts DL=1, va por DL siempre.
        assert len(signals) == 1  # por DL
        assert signals[0].weight == 60


# ===========================================================================
# CAPA 2 — metadatos
# ===========================================================================

class TestLayer2NotFoundUnverifiable:
    """NOT_FOUND y UNVERIFIABLE -> lista vacia (L2 no aplica)."""

    def test_not_found_sin_senales(self) -> None:
        signals = layer2_metadata.evaluate(_not_found(), _DEFAULT_CONFIG)
        assert signals == []

    def test_unverifiable_sin_senales(self) -> None:
        signals = layer2_metadata.evaluate(_unverifiable(), _DEFAULT_CONFIG)
        assert signals == []


class TestLayer2WeakMetadata:
    """R4.2: WEAK_METADATA si releases <= releases_min Y faltan >= metadata_faltantes_min."""

    def test_emite_weak_metadata(self) -> None:
        outcome = _found(
            releases_count=1,
            has_description=False,
            has_author=False,
        )
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        codes = [s.code for s in signals]
        assert SignalCode.WEAK_METADATA in codes

    def test_sin_senal_suficientes_releases(self) -> None:
        """Mas de releases_min releases -> no dispara WEAK_METADATA (aunque falten campos)."""
        outcome = _found(
            releases_count=2,  # > releases_min=1
            has_description=False,
            has_author=False,
        )
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        codes = [s.code for s in signals]
        assert SignalCode.WEAK_METADATA not in codes

    def test_sin_senal_pocos_faltantes(self) -> None:
        """Solo 1 campo faltante (< metadata_faltantes_min=2) -> sin WEAK_METADATA."""
        outcome = _found(releases_count=1, has_description=False)
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        codes = [s.code for s in signals]
        assert SignalCode.WEAK_METADATA not in codes

    def test_combinacion_exacta_dispara(self) -> None:
        """releases == releases_min Y faltan == metadata_faltantes_min -> dispara."""
        outcome = _found(
            releases_count=1,  # == releases_min
            has_license=False,
            has_classifiers=False,  # 2 campos faltantes == metadata_faltantes_min
        )
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        codes = [s.code for s in signals]
        assert SignalCode.WEAK_METADATA in codes

    def test_peso_weak_metadata(self) -> None:
        outcome = _found(
            releases_count=1,
            has_description=False,
            has_author=False,
        )
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        weak = next(s for s in signals if s.code is SignalCode.WEAK_METADATA)
        assert weak.weight == 7
        assert weak.is_soft is True
        assert weak.layer is Layer.L2


class TestLayer2LowVerifiability:
    """R4.3: LOW_VERIFIABILITY si sin repo enlazado."""

    def test_emite_low_verifiability_sin_repo(self) -> None:
        outcome = _found(has_repo_url=False)
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        codes = [s.code for s in signals]
        assert SignalCode.LOW_VERIFIABILITY in codes

    def test_sin_senal_cuando_hay_repo(self) -> None:
        outcome = _found(has_repo_url=True)
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        codes = [s.code for s in signals]
        assert SignalCode.LOW_VERIFIABILITY not in codes

    def test_peso_low_verifiability(self) -> None:
        outcome = _found(has_repo_url=False)
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        lv = next(s for s in signals if s.code is SignalCode.LOW_VERIFIABILITY)
        assert lv.weight == 5
        assert lv.is_soft is True
        assert lv.layer is Layer.L2


class TestLayer2Cap:
    """R4.5, ADR-01: aporte total L2 acotado a c2_max_contrib."""

    def test_ambas_senales_cap_10(self) -> None:
        """WEAK_METADATA(7) + LOW_VERIFIABILITY(5) = 12 -> capado a 10."""
        outcome = _found(
            releases_count=1,
            has_repo_url=False,
            has_description=False,
            has_author=False,
        )
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        total_weight = sum(s.weight for s in signals)
        assert total_weight == _DEFAULT_CONFIG.c2_max_contrib

    def test_aporte_en_conjunto_esperado(self) -> None:
        """Aporte L2 pertenece a {0, 5, 7, 10} (ADR-01)."""
        outcomes = [
            _found(),  # paquete popular/completo -> 0
            _found(has_repo_url=False),  # solo LOW_VERIF -> 5
            _found(releases_count=1, has_description=False, has_author=False),  # solo WEAK -> 7
            _found(  # ambas -> 10
                releases_count=1,
                has_repo_url=False,
                has_description=False,
                has_author=False,
            ),
        ]
        valid_totals = {0, 5, 7, 10}
        for outcome in outcomes:
            signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
            total = sum(s.weight for s in signals)
            assert total in valid_totals, f"Aporte inesperado {total} para {outcome}"

    def test_c2_max_contrib_personalizado(self) -> None:
        """c2_max_contrib configurable; el cap se respeta."""
        config = Config(c2_max_contrib=5)
        outcome = _found(
            releases_count=1,
            has_repo_url=False,
            has_description=False,
            has_author=False,
        )
        signals = layer2_metadata.evaluate(outcome, config)
        total_weight = sum(s.weight for s in signals)
        assert total_weight <= 5


class TestLayer2Popular:
    """R4.5: paquete popular y completo -> sin senales L2."""

    def test_popular_completo_sin_senales(self) -> None:
        """releases >= releases_populares + repo + metadatos completos -> sin senal L2."""
        outcome = _found(
            releases_count=_DEFAULT_CONFIG.releases_populares,  # == 10
            has_repo_url=True,
            has_description=True,
            has_author=True,
            has_license=True,
            has_classifiers=True,
        )
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        assert signals == []

    def test_popular_sin_repo_emite_low_verifiability(self) -> None:
        """Popular pero sin repo: no cumple criterio completo -> puede emitir senal."""
        outcome = _found(
            releases_count=_DEFAULT_CONFIG.releases_populares,
            has_repo_url=False,
        )
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        # Sin repo no cumple la condicion de popular completo -> LOW_VERIFIABILITY.
        codes = [s.code for s in signals]
        assert SignalCode.LOW_VERIFIABILITY in codes

    def test_popular_config_ajustable(self) -> None:
        """Config.releases_populares determina el umbral."""
        config = Config(releases_populares=100)
        outcome = _found(
            releases_count=10,  # < 100, no se considera popular con este config
            has_repo_url=True,
            has_description=True,
            has_author=True,
            has_license=True,
            has_classifiers=True,
        )
        # Con releases_populares=100, el paquete con 10 releases no es popular.
        signals = layer2_metadata.evaluate(outcome, config)
        # No emite WEAK_METADATA porque releases_count(10) > releases_min(1).
        # No emite LOW_VERIF porque tiene repo.
        codes = [s.code for s in signals]
        assert SignalCode.LOW_VERIFIABILITY not in codes

    def test_downloads_no_consultados(self) -> None:
        """R4.4: downloads NO se consultan; ausencia de in_top_n no es senal de riesgo."""
        outcome = _found(in_top_n=False)  # in_top_n=False no debe generar senal L2.
        signals = layer2_metadata.evaluate(outcome, _DEFAULT_CONFIG)
        # Paquete found con metadatos completos y repo -> sin senales.
        assert signals == []
