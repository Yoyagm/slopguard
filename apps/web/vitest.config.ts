import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

/**
 * Config de Vitest para el frontend (T38). Entorno jsdom + Testing Library para probar
 * COMPORTAMIENTO (roles, texto, estados, a11y), no estilos. Alias `@/` → `src/` igual que Next.
 * Los tests viven en `tests/` (rol tester). No se procesa CSS (los componentes no importan CSS).
 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    include: ["tests/**/*.test.{ts,tsx}"],
    css: false,
    clearMocks: true,
  },
});
