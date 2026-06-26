import { describe, expect, it } from "vitest";
import {
  ecosystemLabel,
  errorCategoryLabel,
  exitCodeMeta,
  formatDateTime,
  formatScore,
  layerLabel,
  originLabel,
} from "@/components/report/report-format";

/**
 * Módulo PURO de presentación del reporte. Se prueba el COMPORTAMIENTO de copy y fallbacks,
 * con foco en la regla crítica "score null = sin score, NUNCA 0".
 */

describe("formatScore — null es 'sin score', nunca 0", () => {
  it("score null ⇒ '—' y isAbsent true (no se confunde con 0)", () => {
    const result = formatScore(null);
    expect(result.text).toBe("—");
    expect(result.isAbsent).toBe(true);
    expect(result.text).not.toBe("0");
  });

  it("score 0 ⇒ '0' y isAbsent false (distingue ausencia de cero real)", () => {
    const result = formatScore(0);
    expect(result.text).toBe("0");
    expect(result.isAbsent).toBe(false);
  });

  it("redondea el score numérico a entero estable", () => {
    expect(formatScore(72.6).text).toBe("73");
    expect(formatScore(42.2).text).toBe("42");
  });
});

describe("ecosystemLabel", () => {
  it("traduce ecosistemas conocidos", () => {
    expect(ecosystemLabel("pypi")).toBe("PyPI");
    expect(ecosystemLabel("npm")).toBe("npm");
  });

  it("cae al valor crudo si es desconocido", () => {
    expect(ecosystemLabel("cargo")).toBe("cargo");
  });
});

describe("originLabel", () => {
  it("traduce orígenes conocidos", () => {
    expect(originLabel("on_demand")).toBe("On-demand");
    expect(originLabel("pull_request")).toBe("Pull request");
  });

  it("cae al valor crudo si es desconocido", () => {
    expect(originLabel("webhook")).toBe("webhook");
  });
});

describe("layerLabel", () => {
  it("compone 'Capa N · Nombre' para capas conocidas", () => {
    expect(layerLabel(0)).toBe("Capa 0 · Existencia y edad");
    expect(layerLabel(1)).toBe("Capa 1 · Typosquatting");
    expect(layerLabel(3)).toBe("Capa 3 · Threat-intel");
  });

  it("degrada a 'Capa N' para capas desconocidas", () => {
    expect(layerLabel(9)).toBe("Capa 9");
  });
});

describe("errorCategoryLabel", () => {
  it("traduce categorías de error conocidas a español", () => {
    expect(errorCategoryLabel("manifest_parse")).toBe(
      "No se pudo interpretar el manifiesto de dependencias.",
    );
    expect(errorCategoryLabel("network")).toBe(
      "Fallo de red al contactar las fuentes de datos.",
    );
  });

  it("cae a un mensaje legible con la categoría cruda si es desconocida", () => {
    expect(errorCategoryLabel("quota_exceeded")).toBe("Error: quota_exceeded");
  });
});

describe("exitCodeMeta — precedencia R7.5", () => {
  it.each([
    [0, "Limpio", "allow"],
    [1, "Advertencias", "warn"],
    [2, "Bloqueado", "block"],
    [3, "No concluyente", "unverifiable"],
  ] as const)("exit %i ⇒ label '%s' / tone '%s'", (code, label, tone) => {
    const meta = exitCodeMeta(code);
    expect(meta.code).toBe(code);
    expect(meta.label).toBe(label);
    expect(meta.tone).toBe(tone);
  });

  it("código no estándar degrada a tono unverifiable (fail-closed)", () => {
    const meta = exitCodeMeta(99);
    expect(meta.tone).toBe("unverifiable");
    expect(meta.label).toContain("99");
  });
});

describe("formatDateTime", () => {
  it("devuelve el crudo si la fecha es inválida (no rompe la UI)", () => {
    expect(formatDateTime("no-es-fecha")).toBe("no-es-fecha");
  });

  it("formatea un ISO válido a una cadena distinta del crudo", () => {
    const iso = "2026-06-26T10:00:00Z";
    const formatted = formatDateTime(iso);
    expect(formatted).not.toBe(iso);
    expect(formatted.length).toBeGreaterThan(0);
    // No dependemos de la zona horaria del runner: solo verificamos que incluye el año.
    expect(formatted).toContain("2026");
  });
});
