import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Aislamos la red: mockeamos los endpoints. ApiError (de client) se mantiene REAL para que el
// `err instanceof ApiError` de la página funcione con las instancias que lanzamos.
vi.mock("@/lib/api/endpoints", () => ({
  createScan: vi.fn(),
  listRepos: vi.fn(),
  getScanRaw: vi.fn(),
}));

import ScanPage from "@/app/(app)/scan/page";
import { createScan, listRepos } from "@/lib/api/endpoints";
import { ApiError } from "@/lib/api/client";
import { makeScan, makeSummary } from "./factories";

const createScanMock = vi.mocked(createScan);
const listReposMock = vi.mocked(listRepos);

beforeEach(() => {
  listReposMock.mockResolvedValue([]);
});

describe("ScanPage — estado inicial (idle)", () => {
  it("renderiza el formulario sin reporte ni error", () => {
    render(<ScanPage />);
    expect(
      screen.getByRole("heading", { name: "Escaneo on-demand" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Iniciar escaneo/ })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("article", { name: "Reporte de escaneo" }),
    ).not.toBeInTheDocument();
  });
});

describe("ScanPage — validación inline", () => {
  it("enviar con manifiesto vacío muestra error y NO llama a la API", async () => {
    const user = userEvent.setup();
    render(<ScanPage />);

    await user.click(screen.getByRole("button", { name: /Iniciar escaneo/ }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("El manifiesto no puede estar vacío.");
    expect(createScanMock).not.toHaveBeenCalled();
  });
});

describe("ScanPage — éxito", () => {
  it("escaneo exitoso renderiza el reporte con el resumen", async () => {
    const user = userEvent.setup();
    createScanMock.mockResolvedValue(
      makeScan({
        ecosystem: "pypi",
        summary: makeSummary({ total: 1, allow: 1, exit_code: 0 }),
      }),
    );
    render(<ScanPage />);

    await user.type(
      screen.getByLabelText(/Contenido del manifiesto/),
      "requests==2.31.0",
    );
    await user.click(screen.getByRole("button", { name: /Iniciar escaneo/ }));

    // Reporte visible (ancla en el summary / cabecera).
    expect(
      await screen.findByRole("article", { name: "Reporte de escaneo" }),
    ).toBeInTheDocument();
    expect(screen.getByText("exit 0")).toBeInTheDocument();

    // Se envió el contenido recortado por la fuente inline.
    expect(createScanMock).toHaveBeenCalledWith(
      expect.objectContaining({ source: "inline", content: "requests==2.31.0" }),
    );
  });
});

describe("ScanPage — error de API", () => {
  it("muestra el mensaje saneado del ApiError", async () => {
    const user = userEvent.setup();
    createScanMock.mockRejectedValue(
      new ApiError(400, "VALIDATION_ERROR", "El manifiesto no se pudo interpretar.", "req-123"),
    );
    render(<ScanPage />);

    await user.type(
      screen.getByLabelText(/Contenido del manifiesto/),
      "contenido-invalido",
    );
    await user.click(screen.getByRole("button", { name: /Iniciar escaneo/ }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("El manifiesto no se pudo interpretar.");
    // No se renderiza ningún reporte en estado de error.
    await waitFor(() =>
      expect(
        screen.queryByRole("article", { name: "Reporte de escaneo" }),
      ).not.toBeInTheDocument(),
    );
  });

  it("error inesperado (no ApiError) muestra mensaje genérico", async () => {
    const user = userEvent.setup();
    createScanMock.mockRejectedValue(new Error("boom interno"));
    render(<ScanPage />);

    await user.type(
      screen.getByLabelText(/Contenido del manifiesto/),
      "requests==2.31.0",
    );
    await user.click(screen.getByRole("button", { name: /Iniciar escaneo/ }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Error inesperado al lanzar el escaneo.");
    // El detalle interno del Error NO se filtra al usuario.
    expect(alert).not.toHaveTextContent("boom interno");
  });
});
