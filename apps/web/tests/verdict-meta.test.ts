import { describe, expect, it } from "vitest";
import {
  getVerdictMeta,
  hasMalAdvisory,
} from "@/components/verdict/verdict-meta";

/**
 * Reglas DURAS de negocio del veredicto (fail-closed). Estos tests blindan la invariante de
 * seguridad visual: lo no verificable JAMÁS se trata como seguro, y un MAL-* domina.
 */
describe("getVerdictMeta — regla fail-closed", () => {
  it("status 'unverifiable' ⇒ tone unverifiable, nunca allow/verde", () => {
    const meta = getVerdictMeta({
      verdict: null,
      status: "unverifiable",
      hasMaliciousAdvisory: false,
    });
    expect(meta.tone).toBe("unverifiable");
    expect(meta.tone).not.toBe("allow");
    expect(meta.label).toBe("No verificable");
  });

  it("verdict null con status ok ⇒ también unverifiable (no se asume seguro)", () => {
    const meta = getVerdictMeta({
      verdict: null,
      status: "ok",
      hasMaliciousAdvisory: false,
    });
    expect(meta.tone).toBe("unverifiable");
  });

  it("advisory MAL-* tiene prioridad ABSOLUTA sobre cualquier verdict", () => {
    const meta = getVerdictMeta({
      verdict: "allow",
      status: "ok",
      hasMaliciousAdvisory: true,
    });
    expect(meta.tone).toBe("malicious");
    expect(meta.iconKey).toBe("skull");
  });

  it.each([
    ["allow", "allow"],
    ["warn", "warn"],
    ["block", "block"],
  ] as const)("verdict '%s' ⇒ tone '%s'", (verdict, tone) => {
    const meta = getVerdictMeta({
      verdict,
      status: "ok",
      hasMaliciousAdvisory: false,
    });
    expect(meta.tone).toBe(tone);
  });
});

describe("hasMalAdvisory", () => {
  it("detecta ids que empiezan por MAL-", () => {
    expect(hasMalAdvisory([{ id: "MAL-2025-1" }])).toBe(true);
    expect(hasMalAdvisory([{ id: "GHSA-xxxx" }])).toBe(false);
    expect(hasMalAdvisory([])).toBe(false);
  });
});
