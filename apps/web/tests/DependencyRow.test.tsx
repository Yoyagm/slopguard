import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DependencyRow } from "@/components/report/DependencyRow";
import {
  makeDependency,
  makeMalAdvisory,
  makeSignal,
} from "./factories";

/**
 * DependencyRow: identidad del paquete + veredicto + score, con detalle expandible (señales y
 * advisories). Reglas probadas: score null = "—" (NUNCA 0), expansión accesible (aria-expanded),
 * enlaces MAL-* seguros (rel noopener noreferrer) y filas sin detalle NO expandibles.
 */

describe("DependencyRow — identidad y veredicto", () => {
  it("muestra nombre, version_pin y el VerdictBadge", () => {
    render(
      <DependencyRow
        result={makeDependency({
          name: "left-pad",
          version_pin: "1.3.0",
          verdict: "warn",
        })}
      />,
    );

    expect(screen.getByText("left-pad")).toBeInTheDocument();
    expect(screen.getByText("1.3.0")).toBeInTheDocument();
    expect(screen.getByRole("img")).toHaveTextContent("Advertencia");
  });

  it("muestra sospecha de typosquatting cuando hay suspected_target", () => {
    render(
      <DependencyRow
        result={makeDependency({ name: "reqeusts", suspected_target: "requests" })}
      />,
    );
    expect(screen.getByText(/¿typo de/)).toBeInTheDocument();
    expect(screen.getByText("requests")).toBeInTheDocument();
  });
});

describe("DependencyRow — score null nunca es 0", () => {
  it("score null se muestra como '—' / 'Sin score', no como 0", () => {
    render(
      <DependencyRow
        result={makeDependency({ score: null, verdict: null, status: "unverifiable" })}
      />,
    );

    const scoreCell = screen.getByLabelText("Sin score");
    expect(scoreCell).toHaveTextContent("—");
    expect(scoreCell).not.toHaveTextContent("0");
  });

  it("score numérico se muestra con su valor y aria-label de riesgo", () => {
    render(<DependencyRow result={makeDependency({ score: 87 })} />);
    expect(screen.getByLabelText("Score de riesgo 87")).toHaveTextContent("87");
  });
});

describe("DependencyRow — expansión accesible", () => {
  it("una fila sin detalle no es expandible (botón disabled, sin aria-expanded)", () => {
    render(
      <DependencyRow
        result={makeDependency({
          signals: [],
          advisories: [],
          llm_assessment: null,
          error_category: null,
        })}
      />,
    );

    const button = screen.getByRole("button");
    expect(button).toBeDisabled();
    expect(button).not.toHaveAttribute("aria-expanded");
  });

  it("al expandir aparecen las señales (SignalList) y aria-expanded pasa a true", async () => {
    const user = userEvent.setup();
    render(
      <DependencyRow
        result={makeDependency({
          verdict: "warn",
          score: 40,
          signals: [
            makeSignal({ detail: "Publicado hace pocas horas; baja reputación." }),
          ],
        })}
      />,
    );

    const button = screen.getByRole("button");
    expect(button).toHaveAttribute("aria-expanded", "false");
    // El detalle no está montado hasta abrir.
    expect(
      screen.queryByText("Publicado hace pocas horas; baja reputación."),
    ).not.toBeInTheDocument();

    await user.click(button);

    expect(button).toHaveAttribute("aria-expanded", "true");
    expect(
      screen.getByText("Publicado hace pocas horas; baja reputación."),
    ).toBeInTheDocument();

    // Colapsa de nuevo.
    await user.click(button);
    expect(button).toHaveAttribute("aria-expanded", "false");
  });
});

describe("DependencyRow — advisories MAL-* seguros", () => {
  it("muestra el advisory MAL-* con enlace externo rel='noopener noreferrer'", async () => {
    const user = userEvent.setup();
    render(
      <DependencyRow
        result={makeDependency({
          verdict: "allow",
          advisories: [
            makeMalAdvisory({
              id: "MAL-2025-0042",
              url: "https://osv.dev/vulnerability/MAL-2025-0042",
            }),
          ],
        })}
      />,
    );

    // El badge ya refleja la dominancia MAL-*.
    expect(screen.getByRole("img")).toHaveTextContent("Malicioso");

    await user.click(screen.getByRole("button"));

    const section = screen.getByRole("region", { name: "Advisories de seguridad" });
    expect(within(section).getByText("MAL-2025-0042")).toBeInTheDocument();

    const link = within(section).getByRole("link", {
      name: /Abrir advisory MAL-2025-0042/,
    });
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute(
      "href",
      "https://osv.dev/vulnerability/MAL-2025-0042",
    );
  });
});
