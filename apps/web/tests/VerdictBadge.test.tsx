import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { VerdictBadge } from "@/components/verdict/VerdictBadge";

/**
 * VerdictBadge es la cara visible de la regla fail-closed. Probamos COMPORTAMIENTO observable:
 * etiqueta de texto + aria-label descriptivo (color NUNCA es el único portador de significado),
 * y la dominancia absoluta del advisory MAL-*.
 */

describe("VerdictBadge — fail-closed (CRÍTICO)", () => {
  it("status 'unverifiable' muestra 'No verificable' y NO usa el tono allow (no verde)", () => {
    render(
      <VerdictBadge
        result={{ verdict: null, status: "unverifiable", advisories: [] }}
      />,
    );

    const badge = screen.getByRole("img");
    expect(badge).toHaveTextContent("No verificable");
    // Fail-closed: jamás la clase/tono de allow.
    expect(badge.className).not.toContain("text-sg-allow");
    expect(badge).toHaveClass("text-sg-unverifiable");
  });

  it("verdict null (status ok) tampoco se trata como seguro", () => {
    render(
      <VerdictBadge result={{ verdict: null, status: "ok", advisories: [] }} />,
    );
    const badge = screen.getByRole("img");
    expect(badge).toHaveTextContent("No verificable");
    expect(badge.className).not.toContain("text-sg-allow");
  });

  it("advisory MAL-* fuerza 'Malicioso' aunque el verdict sea 'allow'", () => {
    render(
      <VerdictBadge
        result={{
          verdict: "allow",
          status: "ok",
          advisories: [
            {
              id: "MAL-2025-0001",
              kind: "malware",
              url: "https://osv.dev/x",
              source: "osv",
            },
          ],
        }}
      />,
    );

    const badge = screen.getByRole("img");
    expect(badge).toHaveTextContent("Malicioso");
    expect(badge).toHaveClass("text-sg-malicious");
    expect(badge.className).not.toContain("text-sg-allow");
  });
});

describe("VerdictBadge — accesibilidad (WCAG 1.4.1)", () => {
  it("expone aria-label descriptivo (no solo color)", () => {
    render(
      <VerdictBadge
        result={{ verdict: "block", status: "ok", advisories: [] }}
      />,
    );
    const badge = screen.getByRole("img");
    expect(badge).toHaveAttribute(
      "aria-label",
      expect.stringContaining("Veredicto: Bloqueado"),
    );
  });

  it("renderiza etiqueta de texto visible + icono SVG (color no es el único canal)", () => {
    const { container } = render(
      <VerdictBadge result={{ verdict: "warn", status: "ok", advisories: [] }} />,
    );
    expect(screen.getByRole("img")).toHaveTextContent("Advertencia");
    // El icono acompaña al texto.
    expect(container.querySelector("svg")).toBeInTheDocument();
  });

  it.each([
    ["allow", "Permitido"],
    ["warn", "Advertencia"],
    ["block", "Bloqueado"],
  ] as const)("verdict '%s' muestra la etiqueta '%s'", (verdict, label) => {
    render(
      <VerdictBadge result={{ verdict, status: "ok", advisories: [] }} />,
    );
    expect(screen.getByRole("img")).toHaveTextContent(label);
  });
});
