import { defineConfig, devices } from "@playwright/test";

/**
 * Config de los E2E del flujo crítico (H5-T40), pensada para correr contra el stack de
 * docker-compose YA en marcha (self-host local), no para levantar el servidor.
 *
 * - `baseURL`: el front publicado por el compose (override con SG_E2E_BASE_URL).
 * - `globalSetup`: materializa la sesión sembrada (cookie) como storageState para el
 *   proyecto autenticado. Si no hay cookie, los specs autenticados se saltan (test.skip).
 *
 * No se añade `@playwright/test` al package.json (lockfile congelado del CI): se ejecuta con
 *   `pnpm dlx playwright test -c e2e/playwright.config.ts`
 * Ver e2e/README.md.
 */

const BASE_URL = process.env.SG_E2E_BASE_URL ?? "http://localhost:3000";

// storageState compartido que escribe global-setup con la cookie de sesión sembrada.
export const STORAGE_STATE = "e2e/.auth/state.json";

export default defineConfig({
  testDir: ".",
  // Sin servidor embebido: el stack lo levanta docker compose (ver runbook self-host).
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [["list"]],
  globalSetup: "./global-setup.ts",
  use: {
    baseURL: BASE_URL,
    trace: "on-first-retry",
  },
  projects: [
    // Flujos de error/guard: NO requieren sesión.
    {
      name: "guest",
      testMatch: /auth-guard\.spec\.ts/,
      use: { ...devices["Desktop Chrome"] },
    },
    // Flujo feliz autenticado: consume el storageState de la sesión sembrada.
    {
      name: "authed",
      testMatch: /scan-flow\.spec\.ts/,
      use: { ...devices["Desktop Chrome"], storageState: STORAGE_STATE },
    },
  ],
});
