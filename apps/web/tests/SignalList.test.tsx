import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { SignalList } from "@/components/report/SignalList";
import { makeSignal } from "./factories";

/**
 * SignalList centra la EXPLICACIÓN humana (`detail`) y agrupa por capa. Probamos que el detalle
 * es visible, que las señales se agrupan bajo el encabezado de su capa, y el estado vacío.
 */

describe("SignalList", () => {
  it("renderiza el detalle humano de cada señal", () => {
    const signals = [
      makeSignal({ code: "L1_A", detail: "Nombre muy parecido a 'requests'." }),
      makeSignal({
        layer: 2,
        code: "L2_B",
        detail: "El paquete fue publicado hace menos de 24 horas.",
      }),
    ];
    render(<SignalList signals={signals} />);

    expect(
      screen.getByText("Nombre muy parecido a 'requests'."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("El paquete fue publicado hace menos de 24 horas."),
    ).toBeInTheDocument();
  });

  it("agrupa las señales por capa con su encabezado", () => {
    const signals = [
      makeSignal({ layer: 1, code: "L1_A", detail: "Señal de typosquatting." }),
      makeSignal({ layer: 3, code: "L3_C", detail: "Advisory de threat-intel." }),
    ];
    render(<SignalList signals={signals} />);

    // Cada grupo es una <section> con aria-label = etiqueta de capa.
    expect(
      screen.getByRole("region", { name: "Capa 1 · Typosquatting" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("region", { name: "Capa 3 · Threat-intel" }),
    ).toBeInTheDocument();
  });

  it("muestra mensaje claro cuando no hay señales", () => {
    render(<SignalList signals={[]} />);
    expect(
      screen.getByText(/Sin señales emitidas por las capas de detección/),
    ).toBeInTheDocument();
  });
});
