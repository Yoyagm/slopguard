import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { SummaryCounts } from "@/components/report/SummaryCounts";
import { makeSummary } from "./factories";

/**
 * SummaryCounts: conteos por veredicto con icono + número + aria-label (color no es el único
 * canal). Probamos los valores, la pluralización del aria-label y el ocultamiento de ceros.
 */

describe("SummaryCounts — densidad full", () => {
  it("muestra los cuatro conteos con su etiqueta y número", () => {
    const summary = makeSummary({
      total: 10,
      allow: 4,
      warn: 3,
      block: 2,
      unverifiable: 1,
    });
    render(<SummaryCounts summary={summary} density="full" hideZeros={false} />);

    expect(screen.getByText("Permitidos")).toBeInTheDocument();
    expect(screen.getByText("Advertencias")).toBeInTheDocument();
    expect(screen.getByText("Bloqueados")).toBeInTheDocument();
    expect(screen.getByText("No verificables")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("usa aria-label con pluralización correcta (1 vs N)", () => {
    const summary = makeSummary({
      allow: 1,
      warn: 3,
      block: 0,
      unverifiable: 0,
    });
    render(<SummaryCounts summary={summary} density="full" hideZeros={false} />);

    expect(screen.getByLabelText("1 permitido")).toBeInTheDocument();
    expect(screen.getByLabelText("3 advertencias")).toBeInTheDocument();
  });
});

describe("SummaryCounts — ocultamiento de ceros", () => {
  it("compacto oculta los conteos en cero por defecto", () => {
    const summary = makeSummary({
      allow: 2,
      warn: 0,
      block: 0,
      unverifiable: 0,
    });
    render(<SummaryCounts summary={summary} density="compact" />);

    expect(screen.getByLabelText("2 permitidos")).toBeInTheDocument();
    // Los ceros no se renderizan en modo compacto.
    expect(screen.queryByLabelText("0 advertencias")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("0 bloqueados")).not.toBeInTheDocument();
  });

  it("muestra un guion cuando todo es cero y se ocultan ceros", () => {
    const summary = makeSummary({
      total: 0,
      allow: 0,
      warn: 0,
      block: 0,
      unverifiable: 0,
    });
    render(<SummaryCounts summary={summary} density="compact" />);
    expect(screen.getByLabelText("Sin conteos")).toHaveTextContent("—");
  });
});
