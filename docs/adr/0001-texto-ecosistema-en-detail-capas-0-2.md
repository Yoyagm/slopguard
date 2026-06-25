# ADR-0001 · Texto "PyPI" hardcodeado en el campo `detail` de las Capas 0/2 (H4-T46)

- Estado: Aceptada
- Fecha: 2026-06-25
- Tarea: H4-T46 (Hito 4 — adaptador npm)
- Rol: architect
- Decisores: architect (SlopGuard)
- EARS relacionados: R10.1 (salida con ecosistema correcto); §6 §open_risks del diseño Hito 4
- Relacionados: ADR-5/ADR-6/ADR-8 (parametrización por ecosistema), principio rector §1.3

## Contexto

El motor de capas/scoring de SlopGuard es **puro y agnóstico de ecosistema** por diseño
(principio rector §1.3 del Hito 4): toda divergencia npm↔PyPI vive dentro del adapter o detrás
de una constante de ecosistema, nunca como `if ecosystem == "npm"` esparcido por las capas.

Dos señales heredadas del Hito 1 violan esa pureza en su **texto humano** (no en su semántica):

- `core/layers/layer0_existence.py` ~L56 — `_nonexistent_signal()` emite
  `detail="El paquete no existe en PyPI (posible alucinacion o slopsquatting)."`
- `core/layers/layer2_metadata.py` ~L112 — la señal `LOW_VERIFIABILITY` emite
  `detail="El paquete no tiene repositorio enlazado en PyPI."`

Ambos `detail` se construyen **dentro de la capa pura** y los renders (`cli/render_human.py`,
`cli/render_json.py`) solo los **sanean** (`sanitize_for_output`) antes de emitirlos: NO los
recomponen. Para una dependencia npm, la salida humana y el campo `signals[].detail` del JSON
dirían "PyPI" (incorrecto), en tensión con R10.1.

El campo **estructural** `ScanReport.ecosystem` ya se puebla con `adapter.ecosystem_id` (H4-T35)
y se sanea en render; la cabecera humana ("ecosistema: npm") y el JSON ya son correctos. El
defecto se limita al texto libre de dos `detail`.

El diseño (§6 trazabilidad, R7) cataloga esto como *"Texto 'PyPI' en detalle L2 = riesgo
cosmético (§open_risks)"*. H4-T46 existe para **decidir** la vía antes de implementar, sin
depender de que el critic (T43) lo atrape.

### Requisitos y restricciones que gobiernan la decisión

- **Funcional (R10.1):** la salida debe reflejar el ecosistema correcto. Criterio mínimo: el
  campo `ecosystem` del JSON/cabecera es correcto.
- **No-funcional / principio rector:** **prohibido** introducir cualquier `if ecosystem == "npm"`
  o literal de ecosistema condicionado dentro de `core.layers`/`core.scoring`.
- **Frontera import-linter (NFR-Arq.1):** `core.layers` no importa adapters concretos ni conoce
  el ecosistema; consume `FetchOutcome`/`PackageMetadata`, ninguno de los cuales lleva hoy una
  etiqueta de ecosistema legible.
- **Cero regresión PyPI (R11):** los tests existentes asertan literalmente los `detail` con
  "PyPI" (p. ej. `tests/test_h2_scoring.py` usa `"No existe en PyPI."`); cualquier cambio de
  texto los rompería y exigiría tocar su comportamiento esperado.
- **Alcance acotado de H4-T46:** es una decisión de diseño + criterio verificable, no una
  refactorización transversal de las capas.

## Decisión

Se elige la **vía (a): aceptar el texto "PyPI" en `detail` como deuda técnica documentada**, con
la siguiente Definition of Done (cumplida por esta tarea):

1. El campo **estructural** `ecosystem` del reporte (JSON y cabecera humana) es correcto para npm
   (`"npm"`) — ya garantizado por H4-T35; R10.1 se cumple en el campo estructural.
2. La deuda queda **registrada** en `CHANGELOG.md` (sección *Unreleased → Known issues / Deuda
   técnica*) y en Basic Memory (proyecto "equipo", categoría `[decision]`), con su rationale y la
   ruta de pago futura (este ADR).
3. **No** se introduce ninguna ramificación por ecosistema ni literal condicionado en
   `core.layers`/`core.scoring`: el texto sigue siendo un literal fijo, no parametrizado.

No se modifica el código de las capas en H4-T46. El literal "PyPI" permanece como está; el
defecto es exclusivamente cosmético en el texto libre, mientras el dato estructural es correcto.

## Alternativas consideradas

### Vía (b1) — Parametrizar el `detail` en la capa pura vía dato agnóstico en `FetchOutcome`/contexto

El nombre del ecosistema viajaría como atributo agnóstico (no `if`) que la capa interpola:
añadir una etiqueta de ecosistema a `FetchOutcome` (y/o al contexto de evaluación), propagar la
firma de `layer0.evaluate`/`layer2.evaluate`, y repoblar los `detail` con esa etiqueta.

- A favor: el `detail` quedaría correcto para npm de forma verificable por test ("npm" vs "PyPI").
- En contra: cambia un modelo de transporte puro (`FetchOutcome`) y las firmas de dos capas puras
  más sus call-sites en el engine; impacta los tests de Capas 0/2 de los Hitos 1-3 (riesgo de
  regresión amplio para un defecto cosmético); aumenta el acoplamiento del modelo puro con una
  preocupación de presentación. Desproporcionado frente al alcance de H4-T46 y al beneficio
  (texto humano, no decisión).

### Vía (b2) — Recomponer el `detail` en la capa de render desde `ScanReport.ecosystem`

El render sustituiría "PyPI" por el ecosistema saneado al emitir cada señal.

- A favor: no toca las capas puras; el ecosistema ya está saneado en `ScanReport`.
- En contra: hoy el render **solo sanea** el `detail`; recomponerlo exige **parsear/reemplazar
  substrings** ("PyPI"→ecosistema) sobre texto ya formado en la capa — frágil (acoplado al
  literal exacto de cada señal), mezcla presentación con un detalle de la capa, y se rompería en
  silencio si el texto de una señal cambia. Es una transformación de string por coincidencia, no
  un dato; viola el espíritu de "el dato correcto viaja estructurado".

### Vía (a) — Deuda técnica documentada (ELEGIDA)

Mantener el literal y documentar la deuda, apoyándose en que el campo estructural `ecosystem` ya
es correcto (R10.1 satisfecho donde importa para integración/CI: el JSON).

## Trade-offs

- **Lo que se gana:** se preserva intacto el principio rector (cero texto/lógica por-ecosistema
  en las capas puras); cero riesgo de regresión PyPI (los `detail` y sus tests no cambian);
  diff nulo en código de producción; decisión cerrada y trazable (§open_risks resuelto).
- **Lo que se sacrifica:** el texto humano/`signals[].detail` de dos señales sigue diciendo
  "PyPI" para dependencias npm. Es un defecto **cosmético** en texto explicativo libre; el
  veredicto, el score, los exit codes y el campo estructural `ecosystem` son correctos. Un
  usuario que lea el JSON o la cabecera ve el ecosistema correcto; solo el texto narrativo de
  esas dos señales está desalineado.
- **Por qué es aceptable:** la información que un consumidor (CI, integración) usa para decidir
  —`verdict`, `score`, `ecosystem`, `signals[].code`— es correcta. El literal afectado es prosa
  explicativa, no un campo contractual.

## Consecuencias

- El código de `core/layers/layer0_existence.py` y `core/layers/layer2_metadata.py` **no se
  modifica** en H4-T46. Los tests existentes que asertan el `detail` con "PyPI" (p. ej.
  `tests/test_h2_scoring.py`) permanecen verdes sin cambios (cero regresión).
- Se añade la deuda a `CHANGELOG.md` (Unreleased → Known issues) y a Basic Memory.
- §6 §open_risks queda **resuelto** (decidido, no abierto): es deuda aceptada, no riesgo pendiente.
- **Ruta de pago futura (no en este hito):** cuando la prosa por-ecosistema sea prioritaria, la
  forma correcta es la vía (b1) hecha bien — el ecosistema viaja como **dato agnóstico**
  estructurado (atributo de `FetchOutcome`/contexto que la capa interpola), nunca como
  `if ecosystem == "npm"` ni como reemplazo de substring en el render. Esa evolución requeriría su
  propia tarea (cambio de modelo + firmas + repoblado de tests de Capas 0/2) y queda fuera de H4-T46.

## Non-goals (lo que este diseño NO hará)

- **NO** parametriza el `detail` de las Capas 0/2 por ecosistema en este hito.
- **NO** introduce ninguna ramificación `if ecosystem == "npm"` ni literal condicionado de
  ecosistema en `core.layers`/`core.scoring` (prohibido por el principio rector).
- **NO** modifica `FetchOutcome`/`PackageMetadata` ni las firmas de `layer0.evaluate`/
  `layer2.evaluate`.
- **NO** recompone ni reemplaza substrings del `detail` en la capa de render.
- **NO** cambia `schema_version` (permanece 1.2): no hay campos nuevos de salida.
- **NO** altera ningún veredicto, score o exit code de PyPI ni de npm.
