/**
 * Barra de resumen del escaneo (T34): total de dependencias, conteos por veredicto con
 * color+icono+etiqueta, y el `exit_code` EXPLICADO con su tono semántico. Si el LLM (Capa 4) no
 * estuvo disponible para alguna dependencia, se nota de forma visible (no se oculta el degradado).
 *
 * Componente presentacional puro.
 */

import type { ScanSummary } from "@/lib/api/types";
import { SummaryCounts } from "./SummaryCounts";
import { exitCodeMeta } from "./report-format";
import { cn } from "@/lib/utils";

interface ScanSummaryBarProps {
  summary: ScanSummary;
}

const EXIT_TONE_CLASSES: Record<string, string> = {
  allow: "text-sg-allow bg-sg-allow/15 border-sg-allow/30",
  warn: "text-sg-warn bg-sg-warn/15 border-sg-warn/30",
  block: "text-sg-block bg-sg-block/15 border-sg-block/30",
  unverifiable: "text-sg-unverifiable bg-sg-unverifiable/15 border-sg-unverifiable/30",
};

export function ScanSummaryBar({ summary }: ScanSummaryBarProps) {
  const exit = exitCodeMeta(summary.exit_code);

  return (
    <div className="rounded-sg border border-sg-border bg-sg-surface p-4 space-y-4">
      {/* Veredicto global (exit code) explicado */}
      <div className="flex flex-wrap items-center gap-3">
        <span
          className={cn(
            "inline-flex items-center gap-2 rounded-sg border px-3 py-1.5",
            "text-sm font-semibold",
            EXIT_TONE_CLASSES[exit.tone],
          )}
          aria-label={`Resultado global: ${exit.label}. ${exit.description}`}
        >
          {exit.label}
          <span className="font-mono text-xs font-normal opacity-80">
            exit {exit.code}
          </span>
        </span>
        <p className="text-sm text-sg-muted flex-1 min-w-[14rem]">{exit.description}</p>
      </div>

      {/* Conteos por veredicto + total */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-1 border-t border-sg-border">
        <div className="pt-3">
          <SummaryCounts summary={summary} density="full" hideZeros={false} />
        </div>
        <div className="pt-3 flex items-center gap-2 text-sm">
          <span className="text-sg-muted">Total</span>
          <span className="font-mono font-semibold text-sg-text tabular-nums">
            {summary.total}
          </span>
        </div>
      </div>

      {/* Degradación de la Capa 4 (LLM) — transparente, no se esconde */}
      {summary.llm_unavailable > 0 && (
        <p className="text-xs text-sg-faint border-t border-sg-border pt-3">
          La evaluación LLM (Capa 4) no estuvo disponible para{" "}
          <span className="font-mono text-sg-muted">{summary.llm_unavailable}</span>{" "}
          {summary.llm_unavailable === 1 ? "dependencia" : "dependencias"}; el veredicto se basa
          en las capas deterministas.
        </p>
      )}
    </div>
  );
}
