import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScanReport } from "@/components/report/ScanReport";
import { makeDependency, makeMalAdvisory, makeScan, makeSummary } from "./factories";

// RawJsonViewer (montado por ScanReport) importa endpoints; la carga es perezosa (no en mount),
// pero mockeamos el módulo para aislar el componente de la red por completo.
vi.mock("@/lib/api/endpoints", () => ({
  getScanRaw: vi.fn(),
}));

/**
 * ScanReport compone cabecera + resumen + filas ordenadas por severidad descendente (lo crítico
 * primero, para triaje). Probamos el ORDEN observable y la presencia de cabecera y resumen.
 */

describe("ScanReport — orden por severidad", () => {
  it("ordena malicious > block > unverifiable > warn > allow", () => {
    const scan = makeScan({
      results: [
        makeDependency({ name: "a-allow", verdict: "allow" }),
        makeDependency({
          name: "z-mal",
          verdict: "allow",
          advisories: [makeMalAdvisory()],
        }),
        makeDependency({ name: "u-unv", verdict: null, status: "unverifiable", score: null }),
        makeDependency({ name: "b-block", verdict: "block" }),
        makeDependency({ name: "w-warn", verdict: "warn" }),
      ],
      summary: makeSummary({ total: 5, allow: 1, warn: 1, block: 1, unverifiable: 1 }),
    });

    render(<ScanReport scan={scan} />);

    const badgeLabels = screen.getAllByRole("img").map((el) => el.textContent);
    expect(badgeLabels).toEqual([
      "Malicioso",
      "Bloqueado",
      "No verificable",
      "Advertencia",
      "Permitido",
    ]);
  });

  it("empates conservan el orden original (orden estable)", () => {
    const scan = makeScan({
      results: [
        makeDependency({ name: "first-warn", verdict: "warn" }),
        makeDependency({ name: "second-warn", verdict: "warn" }),
      ],
      summary: makeSummary({ total: 2, allow: 0, warn: 2 }),
    });

    render(<ScanReport scan={scan} />);

    const names = ["first-warn", "second-warn"].map(
      (n) => screen.getByText(n),
    );
    // first-warn aparece antes en el DOM que second-warn.
    expect(
      names[0].compareDocumentPosition(names[1]) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });
});

describe("ScanReport — cabecera y resumen", () => {
  it("renderiza la cabecera con ecosistema y el resumen con exit_code", () => {
    const scan = makeScan({
      ecosystem: "pypi",
      summary: makeSummary({ total: 1, allow: 1, exit_code: 0 }),
    });
    render(<ScanReport scan={scan} />);

    expect(screen.getByRole("article", { name: "Reporte de escaneo" })).toBeInTheDocument();
    expect(screen.getByText("PyPI")).toBeInTheDocument();
    expect(screen.getByText("exit 0")).toBeInTheDocument();
  });

  it("muestra alerta de error de escaneo cuando hay error_category", () => {
    const scan = makeScan({ error_category: "manifest_parse" });
    render(<ScanReport scan={scan} />);
    expect(screen.getByRole("alert")).toHaveTextContent(
      "No se pudo interpretar el manifiesto de dependencias.",
    );
  });

  it("muestra estado vacío cuando no hay dependencias", () => {
    const scan = makeScan({
      results: [],
      summary: makeSummary({ total: 0, allow: 0 }),
    });
    render(<ScanReport scan={scan} />);
    expect(
      screen.getByText("El escaneo no produjo resultados de dependencias."),
    ).toBeInTheDocument();
  });
});
