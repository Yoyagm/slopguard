# Flujo del ecosistema hacia la salida (H4-T46)

Diagrama de apoyo al [ADR-0001](../adr/0001-texto-ecosistema-en-detail-capas-0-2.md). Muestra por
qué el campo **estructural** `ecosystem` llega correcto a la salida mientras el texto libre
`signals[].detail` de las Capas 0/2 mantiene el literal "PyPI" (deuda documentada, vía (a)).

`adapter.ecosystem_id` viaja a `ScanReport.ecosystem` (cabecera humana + JSON correctos). El
`detail` de las señales L0/L2 se **construye dentro de la capa pura** con el literal fijo "PyPI";
los renders solo lo **sanean**, no lo recomponen, así que ese texto no se reescribe por ecosistema.

```mermaid
graph TD
    ADP["NpmAdapter / PypiAdapter<br/>ecosystem_id"]

    subgraph PURE["core.layers (PURO, agnóstico — NO conoce el ecosistema)"]
        L0["layer0_existence<br/>_nonexistent_signal()<br/>detail = '...no existe en PyPI...'  (literal fijo)"]
        L2["layer2_metadata<br/>LOW_VERIFIABILITY<br/>detail = '...repositorio enlazado en PyPI.'  (literal fijo)"]
    end

    subgraph FACADE["core.engine (fachada)"]
        ENG["engine<br/>puebla ScanReport.ecosystem = adapter.ecosystem_id"]
    end

    subgraph OUT["cli.render_* (solo SANEA, no recompone)"]
        RH["render_human<br/>cabecera: 'ecosistema: {ecosystem}'  ✅ correcto<br/>señal: sanitize_for_output(detail)  ⚠️ 'PyPI' literal"]
        RJ["render_json<br/>report.ecosystem  ✅ correcto<br/>signals[].detail = sanitize(detail)  ⚠️ 'PyPI' literal"]
    end

    ADP -->|ecosystem_id agnóstico| ENG
    ENG -->|FetchOutcome / PackageMetadata<br/>SIN etiqueta de ecosistema| L0
    ENG -->|FetchOutcome / PackageMetadata<br/>SIN etiqueta de ecosistema| L2
    ENG -->|ScanReport.ecosystem ✅| RH
    ENG -->|ScanReport.ecosystem ✅| RJ
    L0 -->|LayerSignal.detail ⚠️ 'PyPI'| RH
    L2 -->|LayerSignal.detail ⚠️ 'PyPI'| RH
    L0 -->|LayerSignal.detail ⚠️ 'PyPI'| RJ
    L2 -->|LayerSignal.detail ⚠️ 'PyPI'| RJ

    classDef ok fill:#1b3a1b,stroke:#3fa34d,color:#e8ffe8;
    classDef debt fill:#3a2a1b,stroke:#c08a3e,color:#fff3e0;
    class ENG ok
    class L0,L2 debt
```

## Lectura

- **✅ Correcto (R10.1 en el campo estructural):** `ScanReport.ecosystem` se puebla con
  `adapter.ecosystem_id` en el engine y llega íntegro y saneado a la cabecera humana y al JSON.
- **⚠️ Deuda documentada (vía (a) del ADR-0001):** el `detail` de `NONEXISTENT` (L0) y
  `LOW_VERIFIABILITY` (L2) contiene "PyPI" como literal construido en la capa pura. Para una dep
  npm ese texto narrativo está desalineado, pero el dato estructural es correcto.

## Punto de pago futuro (fuera de H4-T46)

La forma correcta de saldar la deuda —si se prioriza— es la **vía (b1)**: que el nombre del
ecosistema viaje como **dato agnóstico** estructurado por la flecha
`ENG -->|FetchOutcome ...| L0/L2` (un atributo de `FetchOutcome`/contexto que la capa interpola),
**nunca** como `if ecosystem == "npm"` en la capa ni como reemplazo de substring en el render.
Requiere cambio de modelo + firmas de `evaluate` + repoblado de los tests de Capas 0/2, y por eso
es una tarea aparte, no parte de H4-T46.
