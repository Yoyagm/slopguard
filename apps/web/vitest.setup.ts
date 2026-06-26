// Extiende `expect` de Vitest con los matchers de jest-dom (toBeInTheDocument, etc.) y limpia el
// DOM tras cada test. Se carga vía `setupFiles` en vitest.config.ts.
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => {
  cleanup();
});
