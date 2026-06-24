# Pre-registro de la evaluación de la Capa 4 (Hito 3, R10.5 / ADR-18)

Este documento **se fija ANTES** de leer las métricas sobre el split `test` y constituye
el contrato de éxito de la Capa 4. La evaluación (`eval/run_eval.py`) **puede FALLAR**: no
es tautológica. El umbral y el método se congelan aquí; el split `test` no se usa para
afinar prompt ni configuración (afinado solo en `dev`, R10.1).

## Dataset (`eval/run_eval.py::CASES`)
- **Positivos** (nombres alucinados/slopsquat): procedencia **independiente** del modelo
  evaluado (`claude-opus-4-8`) — curados según la taxonomía publicada (conflación / typo /
  fabricación) y/o observados en otros modelos. **No** se deriva del juicio del modelo
  evaluado (anti-circularidad, R10.2). **No** se redistribuye el corpus depscope (CC-BY-NC-SA):
  solo se consultaría online con atribución, fuera de este dataset versionado.
- **Negativos en dos estratos** (R10.3):
  - `easy_neg`: paquetes reales establecidos (top-N PyPI).
  - `hard_neg`: paquetes legítimos **jóvenes / de baja señal** (la banda gris). La garantía
    anti-FP se mide **principalmente** sobre este estrato.
- **Splits** `train` / `dev` / `test` (R10.1). Métricas reportadas sobre `test`.
- **Snapshot reproducible** (R10.7): el veredicto del LLM por caso (`llm`) es un snapshot
  versionado → la eval corre offline, sin clave, determinista (Opus 4.8 no admite
  `temperature`; el determinismo viene del snapshot, no de un sampling fijo). Regenerar el
  snapshot con una clave real actualiza ese campo; el hash del archivo versionado documenta
  la versión del snapshot.

## Métricas por nivel de veredicto (R10.4)
- **`block`**: predicción positiva = `verdict == BLOCK`. La Capa 4 **no** puede producir
  `block`; por tanto el **delta de la ablación (L4 ON vs OFF) en `block` DEBE ser 0**, lo que
  valida el aislamiento estructural del anti-block.
- **`warn-o-peor`**: predicción positiva = `verdict ∈ {WARN, BLOCK}`. Es donde la Capa 4
  contribuye (puede mover `allow → warn`).

## Piso pre-registrado (umbrales que hacen FALLAR la eval)
1. `precision(block)` **= 1.0** sobre `test` (`REQUIRED_BLOCK_PRECISION`).
2. **delta de la ablación en `recall(block)` = 0.0** (`REQUIRED_BLOCK_ABLATION_DELTA`): la
   Capa 4 jamás cambia un veredicto de/ hacia `block`.
3. `precision(warn-o-peor)` con Capa 4 activa **≥ 0.90** sobre `test`
   (`FLOOR_WARN_PRECISION`) — medido incluyendo el estrato `hard_neg` (anti-FP).

## Criterio de valor (no es piso, se reporta)
- Se espera que la Capa 4 **aumente** `recall(warn-o-peor)` (delta ON−OFF > 0): detecta
  fabricaciones/conflaciones que las capas deterministas no marcan, sin degradar la precisión.

## Verificación
- `python eval/run_eval.py` imprime la tabla y devuelve exit 1 si se viola el piso.
- `tests/test_h3_eval.py` ancla los tres puntos del piso y comprueba que el chequeo del piso
  **puede fallar** con métricas malas (no tautológico).
