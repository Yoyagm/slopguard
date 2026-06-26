import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Router compartido (hoisted) para poder afirmar que el filtro sincroniza la query string.
const { replaceMock } = vi.hoisted(() => ({ replaceMock: vi.fn() }));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock, push: vi.fn() }),
  usePathname: () => "/history",
  useSearchParams: () => new URLSearchParams(),
}));

// next/link → ancla simple para no requerir el contexto de router de Next en jsdom.
vi.mock("next/link", () => ({
  default: ({
    children,
    href,
    ...props
  }: {
    children: React.ReactNode;
    href: string;
  }) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

vi.mock("@/lib/api/endpoints", () => ({
  listScans: vi.fn(),
  listRepos: vi.fn(),
}));

import { HistoryClient } from "@/app/(app)/history/HistoryClient";
import { listScans, listRepos } from "@/lib/api/endpoints";
import { ApiError } from "@/lib/api/client";
import { makeScanListItem, makeSummary } from "./factories";

const listScansMock = vi.mocked(listScans);
const listReposMock = vi.mocked(listRepos);

beforeEach(() => {
  listReposMock.mockResolvedValue([]);
});

describe("HistoryClient — lista con resultados", () => {
  it("renderiza filas y el conteo total cuando hay escaneos", async () => {
    listScansMock.mockResolvedValue({
      items: [
        makeScanListItem({
          scan_id: "s-1",
          ecosystem: "pypi",
          summary: makeSummary({ total: 3, allow: 3 }),
        }),
        makeScanListItem({
          scan_id: "s-2",
          ecosystem: "npm",
          summary: makeSummary({ total: 1, allow: 0, block: 1, exit_code: 2 }),
        }),
      ],
      total: 2,
      page: 1,
      page_size: 20,
    });

    render(<HistoryClient />);

    expect(await screen.findByText("2 escaneos en total")).toBeInTheDocument();
    // Hay enlaces "Ver reporte" hacia el detalle de cada escaneo.
    const links = screen.getAllByRole("link", {
      name: /Ver reporte del escaneo/,
    });
    expect(links.length).toBeGreaterThanOrEqual(2);
    // No se muestra el estado vacío.
    expect(screen.queryByText("Aún no tienes escaneos")).not.toBeInTheDocument();
  });
});

describe("HistoryClient — estado vacío", () => {
  it("muestra el empty state con CTA a /scan cuando no hay items", async () => {
    listScansMock.mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      page_size: 20,
    });

    render(<HistoryClient />);

    expect(await screen.findByText("Aún no tienes escaneos")).toBeInTheDocument();
    const cta = screen.getByRole("link", { name: /Iniciar escaneo/ });
    expect(cta).toHaveAttribute("href", "/scan");
  });
});

describe("HistoryClient — error", () => {
  it("muestra el mensaje saneado del ApiError", async () => {
    listScansMock.mockRejectedValue(
      new ApiError(500, "INTERNAL", "No se pudo cargar el historial ahora mismo.", "req-9"),
    );

    render(<HistoryClient />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("No se pudo cargar el historial ahora mismo.");
  });
});

describe("HistoryClient — filtros", () => {
  it("cambiar el ecosistema re-consulta con el filtro y sincroniza la query string", async () => {
    listScansMock.mockResolvedValue({
      items: [makeScanListItem({ scan_id: "s-1" })],
      total: 1,
      page: 1,
      page_size: 20,
    });

    const user = userEvent.setup();
    render(<HistoryClient />);

    // Espera a la carga inicial.
    await screen.findByText("1 escaneo en total");
    expect(listScansMock).toHaveBeenCalledWith(
      expect.objectContaining({ ecosystem: undefined }),
      expect.anything(),
    );

    await user.selectOptions(screen.getByLabelText("Ecosistema:"), "npm");

    await waitFor(() =>
      expect(listScansMock).toHaveBeenCalledWith(
        expect.objectContaining({ ecosystem: "npm", page: 1 }),
        expect.anything(),
      ),
    );
    // La query string se actualiza vía router.replace.
    expect(replaceMock).toHaveBeenCalledWith(
      "/history?ecosystem=npm",
      expect.anything(),
    );
  });
});
