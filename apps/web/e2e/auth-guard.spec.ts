import { expect, test } from "@playwright/test";

/**
 * Flujos de error/guard del flujo crítico (H5-T40). No requieren sesión: validan que la barrera
 * de autenticación es fail-closed (una ruta protegida sin sesión termina en /login) y que la
 * landing de login es accesible.
 */

test.describe("guard de autenticación (sin sesión)", () => {
  test("la página de login renderiza el CTA de GitHub y el skip-link a11y", async ({
    page,
  }) => {
    await page.goto("/login");

    await expect(
      page.getByRole("heading", { name: /protege tus dependencias/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /continuar con github/i }),
    ).toBeVisible();
    // Accesibilidad: salto al contenido principal (NFR-UX.2).
    await expect(
      page.getByRole("link", { name: /saltar al contenido principal/i }),
    ).toBeAttached();
  });

  test("una ruta protegida sin sesión redirige a /login", async ({ page }) => {
    await page.goto("/scan");

    // El guard de cliente resuelve la sesión vía GET /me; 401 ⇒ redirección a login.
    await page.waitForURL(/\/login(\?.*)?$/);
    await expect(
      page.getByRole("button", { name: /continuar con github/i }),
    ).toBeVisible();
  });

  test("el historial sin sesión también queda tras la barrera", async ({ page }) => {
    await page.goto("/history");
    await page.waitForURL(/\/login(\?.*)?$/);
  });
});
