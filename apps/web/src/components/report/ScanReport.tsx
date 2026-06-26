/**
 * Visor de reporte de escaneo (T34) — la pieza central que EXPLICA el veredicto.
 *
 * Estructura:
 *   1. Cabecera: ecosistema, versión del motor, fecha y origen (+ error de escaneo si lo hubo).
 *   2. ScanSummaryBar: conteos por veredicto y exit_code explicado.
 *   3. Lista de DependencyRow ordenada por severidad descendente (lo crítico primero, para
 *      facilitar el triaje) y expandible con señales/advisories/LLM.
 *   4. RawJsonViewer: JSON crudo del motor bajo demanda.
 *
 * Sin estado propio: compone subcomponentes (algunos cliente) y recibe el `Scan` ya resuelto.
 */

import type { DependencyResult, Scan } from "@/lib/api/types";
import { getVerdictMeta, hasMalAdvisory, type VerdictTone } from "@/components/verdict/verdict-meta";
import { ScanSummaryBar } from "./ScanSummaryBar";
import { DependencyRow } from "./DependencyRow";
import { RawJsonViewer } from "./RawJsonViewer";
import {
  ecosystemLabel,
  errorCategoryLabel,
  formatDateTime,
  originLabel,
} from "./report-format";
import { PackageIcon, AlertCircleIcon } from "@/lib/icons";

interface ScanReportProps {
  scan: Scan;
}

/** Rango de severidad para ordenar (mayor = más crítico). Empates conservan el orden original. */
const SEVERITY_RANK: Record<VerdictTone, number> = {
  malicious: 4,
  block: 3,
  unverifiable: 2,
  warn: 1,
  allow: 0,
};

function severityOf(result: DependencyResult): number {
  const meta = getVerdictMeta({
    verdict: result.verdict,
    status: result.status,
    hasMaliciousAdvisory: hasMalAdvisory(result.advisories),
  });
  return SEVERITY_RANK[meta.tone];
}

/** Ordena por severidad descendente de forma ESTABLE (sin mutar el array original). */
function sortBySeverity(results: DependencyResult[]): DependencyResult[] {
  return results
    .map((result, index) => ({ result, index }))
    .sort((a, b) => severityOf(b.result) - severityOf(a.result) || a.index - b.index)
    .map(({ result }) => result);
}

function MetaItem({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs text-sg-faint uppercase tracking-wide">{label}</dt>
      <dd className="text-sm text-sg-text">{children}</dd>
    </div>
  );
}

export function ScanReport({ scan }: ScanReportProps) {
  const orderedResults = sortBySeverity(scan.results);

  return (
    <article className="space-y-5" aria-label="Reporte de escaneo">
      {/* Cabecera */}
      <header className="rounded-sg border border-sg-border bg-sg-surface p-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-sg bg-sg-accent/10 text-sg-accent flex items-center justify-center shrink-0">
            <PackageIcon className="w-5 h-5" />
          </div>
          <dl className="grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-3 flex-1">
            <MetaItem label="Ecosistema">
              <span className="font-mono">{ecosystemLabel(scan.ecosystem)}</span>
            </MetaItem>
            <MetaItem label="Origen">{originLabel(scan.origin)}</MetaItem>
            <MetaItem label="Motor">
              <span className="font-mono">{scan.tool_version}</span>
            </MetaItem>
            <MetaItem label="Fecha">
              <time dateTime={scan.created_at}>{formatDateTime(scan.created_at)}</time>
            </MetaItem>
          </dl>
        </div>

        {scan.error_category && (
          <div
            role="alert"
            className="mt-3 flex items-start gap-2 rounded-sg border border-sg-warn/30 bg-sg-warn/10 px-3 py-2 text-sm text-sg-warn"
          >
            <AlertCircleIcon className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{errorCategoryLabel(scan.error_category)}</span>
          </div>
        )}
      </header>

      {/* Resumen */}
      <ScanSummaryBar summary={scan.summary} />

      {/* Dependencias */}
      <section aria-labelledby="scan-deps-heading">
        <h2
          id="scan-deps-heading"
          className="mb-2 text-xs font-semibold uppercase tracking-widest text-sg-faint"
        >
          Dependencias analizadas
        </h2>
        {orderedResults.length > 0 ? (
          <div className="rounded-sg border border-sg-border bg-sg-surface overflow-hidden">
            <ul role="list">
              {orderedResults.map((result, index) => (
                <DependencyRow
                  key={`${result.name}@${result.version_pin ?? ""}#${index}`}
                  result={result}
                />
              ))}
            </ul>
          </div>
        ) : (
          <p className="rounded-sg border border-sg-border bg-sg-surface px-4 py-6 text-sm text-sg-muted text-center">
            El escaneo no produjo resultados de dependencias.
          </p>
        )}
      </section>

      {/* JSON crudo */}
      <RawJsonViewer scanId={scan.scan_id} />
    </article>
  );
}
