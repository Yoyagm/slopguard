/**
 * Factories de datos de prueba conformes al contrato (`src/lib/api/types.ts`).
 *
 * Objetivo: construir objetos VÁLIDOS por defecto y permitir overrides puntuales con un único
 * argumento parcial. Evita repetir literales en cada test y mantiene los fixtures alineados con
 * los DTOs del API. Los defaults representan el "camino feliz" (allow limpio); cada test ajusta
 * solo lo relevante a su caso.
 */

import type {
  Advisory,
  DependencyResult,
  Repo,
  Scan,
  ScanListItem,
  ScanSummary,
  Signal,
} from "@/lib/api/types";

export function makeSignal(overrides: Partial<Signal> = {}): Signal {
  return {
    layer: 1,
    code: "L1_TYPO_NEAR",
    weight: 30,
    is_soft: false,
    is_llm_channel: false,
    detail: "El nombre se parece a un paquete popular existente.",
    suspected_target: null,
    ...overrides,
  };
}

export function makeAdvisory(overrides: Partial<Advisory> = {}): Advisory {
  return {
    id: "GHSA-aaaa-bbbb-cccc",
    kind: "vulnerability",
    url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
    source: "github",
    ...overrides,
  };
}

/** Advisory de malicia confirmada (MAL-*) — dispara el tono malicious dominante. */
export function makeMalAdvisory(overrides: Partial<Advisory> = {}): Advisory {
  return makeAdvisory({
    id: "MAL-2025-0001",
    kind: "malware",
    url: "https://osv.dev/vulnerability/MAL-2025-0001",
    source: "osv",
    ...overrides,
  });
}

export function makeDependency(
  overrides: Partial<DependencyResult> = {},
): DependencyResult {
  return {
    name: "requests",
    version_pin: "2.31.0",
    status: "ok",
    verdict: "allow",
    score: 5,
    suspected_target: null,
    error_category: null,
    signals: [],
    advisories: [],
    llm_assessment: null,
    ...overrides,
  };
}

export function makeSummary(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    total: 1,
    allow: 1,
    warn: 0,
    block: 0,
    unverifiable: 0,
    llm_unavailable: 0,
    exit_code: 0,
    ...overrides,
  };
}

export function makeScan(overrides: Partial<Scan> = {}): Scan {
  const results = overrides.results ?? [makeDependency()];
  return {
    scan_id: "11111111-1111-1111-1111-111111111111",
    origin: "on_demand",
    created_at: "2026-06-26T10:00:00Z",
    schema_version: "1.2",
    tool_version: "1.4.2",
    ecosystem: "pypi",
    error_category: null,
    summary: makeSummary(),
    ...overrides,
    results,
  };
}

export function makeScanListItem(
  overrides: Partial<ScanListItem> = {},
): ScanListItem {
  return {
    scan_id: "22222222-2222-2222-2222-222222222222",
    origin: "on_demand",
    created_at: "2026-06-26T09:30:00Z",
    ecosystem: "npm",
    schema_version: "1.2",
    tool_version: "1.4.2",
    error_category: null,
    summary: makeSummary(),
    ...overrides,
  };
}

export function makeRepo(overrides: Partial<Repo> = {}): Repo {
  return {
    id: "repo-1",
    installation_id: "inst-1",
    github_repo_id: 123456,
    full_name: "acme/widgets",
    private: false,
    ...overrides,
  };
}
