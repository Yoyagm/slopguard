import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScanSummaryBar } from "@/components/report/ScanSummaryBar";
import { makeSummary } from "./factories";

/**
 * Barra de resumen: explica el exit_code (no solo el número) y muestra los conteos. También debe
 * declarar de forma transparente la degradación de la Capa 4 (LLM) sin ocultarla.
 */

describe("ScanSummaryBar", () => {
  it("muestra el exit_code explicado y el total", () => {
    const summary = makeSummary({
      total: 5,
      allow: 3,
      warn: 1,
      block: 1,
      unverifiable: 0,
      exit_code: 2,
    });
    render(<ScanSummaryBar summary={summary} />);

    // exit_code 2 ⇒ "Bloqueado" con el número crudo visible.
    expect(screen.getByText("Bloqueado")).toBeInTheDocument();
    expect(screen.getByText("exit 2")).toBeInTheDocument();
    // Total visible.
    expect(screen.getByText("Total")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
  });

  it("aria-label del veredicto global describe el resultado (a11y)", () => {
    render(<ScanSummaryBar summary={makeSummary({ exit_code: 0 })} />);
    expect(
      screen.getByLabelText(/Resultado global: Limpio/),
    ).toBeInTheDocument();
  });

  it("declara la degradación de la Capa 4 cuando llm_unavailable > 0", () => {
    render(
      <ScanSummaryBar
        summary={makeSummary({ total: 3, llm_unavailable: 2, exit_code: 0 })}
      />,
    );
    // El aviso es único por su frase; verificamos además que reporta el conteo (2).
    const note = screen.getByText(/no estuvo disponible/i);
    expect(note).toHaveTextContent("2");
  });

  it("no muestra el aviso de Capa 4 cuando llm_unavailable es 0", () => {
    render(<ScanSummaryBar summary={makeSummary({ llm_unavailable: 0 })} />);
    expect(screen.queryByText(/no estuvo disponible/i)).not.toBeInTheDocument();
  });
});
