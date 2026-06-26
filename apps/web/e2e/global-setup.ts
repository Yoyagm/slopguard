import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { STORAGE_STATE } from "./playwright.config";

/**
 * Materializa la sesión sembrada como storageState de Playwright (H5-T40).
 *
 * Toma la cookie firmada que emite `apps/api/scripts/seed_e2e_session.py` (vía
 * SG_E2E_SESSION_COOKIE) y la escribe como storageState para el proyecto autenticado. Así el
 * E2E ejercita el flujo on-demand SIN pasar por el OAuth real de GitHub.
 *
 * Sin la variable de entorno, escribe un estado vacío: los specs autenticados se saltan solos
 * (test.skip), de modo que el suite no falla por ausencia de credenciales.
 */
async function globalSetup(): Promise<void> {
  const cookieValue = process.env.SG_E2E_SESSION_COOKIE;
  const cookieName = process.env.SG_E2E_SESSION_COOKIE_NAME ?? "sg_session";

  mkdirSync(dirname(STORAGE_STATE), { recursive: true });

  // El dominio "localhost" (sin puerto) hace que la cookie viaje tanto al front (:3000) como al
  // API (:8000): mismo host ⇒ mismo "site", así que SameSite=Lax la envía en las llamadas del
  // cliente al API. httpOnly=false porque la inyectamos desde el test (el backend no distingue).
  const cookies = cookieValue
    ? [
        {
          name: cookieName,
          value: cookieValue,
          domain: "localhost",
          path: "/",
          expires: -1,
          httpOnly: false,
          secure: false,
          sameSite: "Lax" as const,
        },
      ]
    : [];

  writeFileSync(STORAGE_STATE, JSON.stringify({ cookies, origins: [] }, null, 2));
}

export default globalSetup;
