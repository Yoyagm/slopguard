import { expect, test } from "@playwright/test";

/**
 * Flujo feliz autenticado del flujo crítico (H5-T40): escaneo on-demand → reporte de veredictos
 * → histórico. Usa la sesión sembrada (storageState); si no hay cookie, el bloque se salta.
 *
 * El manifiesto mezcla un paquete real (`requests`) y un typo (`reqeusts`) para verificar el
 * contraste de veredictos y la dominancia fail-closed (block ⇒ exit 2).
 */

const MANIFEST = "requests==2.31.0\nreqeusts==1.0.0\n";

test.describe("escaneo on-demand → histórico (con sesión)", () => {
  test.skip(
    !process.env.SG_E2E_SESSION_COOKIE,
    "Requiere SG_E2E_SESSION_COOKIE (ver apps/web/e2e/README.md)",
  );

  test("escanea un manifiesto inline y muestra el reporte", async ({ page }) => {
    await page.goto("/scan");

    // Sesión resuelta: la cabecera muestra al usuario, no redirige a /login.
    await expect(page).toHaveURL(/\/scan$/);
    await expect(
      page.getByRole("heading", { name: /escaneo on-demand/i }),
    ).toBeVisible();

    await page
      .getByRole("textbox", { name: /contenido del manifiesto/i })
      .fill(MANIFEST);
    await page.getByRole("button", { name: /iniciar escaneo/i }).click();

    // El motor golpea PyPI en vivo; damos margen.
    await expect(page.getByText(/escaneo completado/i)).toBeVisible({
      timeout: 60_000,
    });

    const report = page.getByRole("article", { name: /reporte de escaneo/i });
    await expect(report).toBeVisible();
    // Veredicto global bloqueado por fail-closed (exit 2).
    await expect(report.getByText(/exit\s*2/i)).toBeVisible();
    // Contraste por fila (nombre accesible anclado): el typo va Bloqueado y enlaza al objetivo
    // sospechado; el paquete real va Permitido. Anclar a "^requests 2.31.0" evita el solape con
    // "reqeusts" y con el texto "requests" de la señal de typosquat.
    await expect(
      page.getByRole("button", { name: /reqeusts 1\.0\.0.*bloqueado/is }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /^requests 2\.31\.0.*permitido/is }),
    ).toBeVisible();
  });

  test("el escaneo persiste y aparece en el histórico", async ({ page }) => {
    await page.goto("/history");

    await expect(
      page.getByRole("heading", { name: /historial de escaneos/i }),
    ).toBeVisible();
    // Al menos un escaneo previo con su enlace a reporte (persistencia + aislamiento por usuario).
    await expect(
      page.getByRole("link", { name: /ver reporte/i }).first(),
    ).toBeVisible();
  });

  test("cargar archivo por el <label> rellena el textarea (regresión botón inerte)", async ({
    page,
  }) => {
    await page.goto("/scan");
    const textarea = page.getByRole("textbox", { name: /contenido del manifiesto/i });
    await expect(textarea).toHaveValue("");

    // El <label> envuelve el input[type=file]: clicar el label abre el diálogo SIN un .click()
    // programático (que Safari bloquea). Se verifica que el contenido del archivo llega al textarea.
    const chooserPromise = page.waitForEvent("filechooser");
    await page.getByText("Cargar archivo").click();
    const chooser = await chooserPromise;
    await chooser.setFiles({
      name: "reqs.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("requests==2.31.0\n"),
    });

    await expect(textarea).toHaveValue(/requests==2\.31\.0/);
    await expect(page.getByText("reqs.txt")).toBeVisible();
  });
});
