"use client";

/**
 * Fila de una dependencia en el reporte (T34) — pieza central de la explicación.
 *
 * Cabecera (siempre visible): nombre (mono), version_pin, VerdictBadge (icono+etiqueta+color,
 * fail-closed y MAL-* dominante ya resueltos dentro del badge), score (null ⇒ "—"/"sin score",
 * NUNCA 0) y sospecha de typosquatting ("¿typo de X?").
 *
 * Detalle expandible (aria-expanded/aria-controls): SignalList con la explicación humana como
 * protagonista, advisories MAL-* destacados con enlace externo seguro, y el veredicto del LLM
 * cuando existe. El detalle solo monta cuando se abre para no inflar el árbol con escaneos grandes.
 */

import { useId, useState } from "react";
import type { Advisory, DependencyResult, LlmAssessment } from "@/lib/api/types";
import { VerdictBadge } from "@/components/verdict/VerdictBadge";
import { SignalList } from "./SignalList";
import { formatScore } from "./report-format";
import {
  ChevronRightIcon,
  ExternalLinkIcon,
  SkullIcon,
  AlertCircleIcon,
} from "@/lib/icons";
import { cn } from "@/lib/utils";

interface DependencyRowProps {
  result: DependencyResult;
}

function ScoreCell({ score }: { score: number | null }) {
  const { text, isAbsent } = formatScore(score);
  return (
    <span
      className={cn(
        "font-mono text-sm tabular-nums whitespace-nowrap",
        isAbsent ? "text-sg-faint" : "text-sg-text",
      )}
      aria-label={isAbsent ? "Sin score" : `Score de riesgo ${text}`}
      title={
        isAbsent
          ? "Sin score (no verificable o bloqueo dominante)"
          : "Score de riesgo del motor (mayor = más sospechoso)"
      }
    >
      <span className="text-sg-faint text-xs mr-1">score</span>
      {text}
    </span>
  );
}

function AdvisoryItem({ advisory }: { advisory: Advisory }) {
  const isMalicious = advisory.id.startsWith("MAL-");
  return (
    <li
      className={cn(
        "flex items-start gap-2 rounded-sg border px-3 py-2 text-sm",
        isMalicious
          ? "border-sg-malicious/40 bg-sg-malicious/10"
          : "border-sg-border bg-sg-bg/40",
      )}
    >
      {isMalicious && (
        <SkullIcon className="w-4 h-4 shrink-0 mt-0.5 text-sg-malicious" />
      )}
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <code
            className={cn(
              "font-mono font-medium",
              isMalicious ? "text-sg-malicious" : "text-sg-text",
            )}
          >
            {advisory.id}
          </code>
          <span className="text-xs text-sg-faint">{advisory.kind}</span>
          <span className="text-xs text-sg-faint">· {advisory.source}</span>
        </div>
        <a
          href={advisory.url}
          target="_blank"
          rel="noopener noreferrer"
          className={cn(
            "mt-0.5 inline-flex items-center gap-1 text-xs",
            "text-sg-accent hover:text-sg-accent-strong underline underline-offset-2",
            "transition-colors duration-150 cursor-pointer break-all",
          )}
          aria-label={`Abrir advisory ${advisory.id} en una pestaña nueva`}
        >
          {advisory.url}
          <ExternalLinkIcon className="w-3 h-3 shrink-0" />
        </a>
      </div>
    </li>
  );
}

function LlmAssessmentPanel({ assessment }: { assessment: LlmAssessment }) {
  const confidencePct = Math.round(assessment.confianza * 100);
  return (
    <div className="rounded-sg border border-sg-border bg-sg-bg/40 px-3 py-2.5 space-y-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-sg-faint">
        <span className="font-semibold uppercase tracking-wide">Evaluación LLM</span>
        <span className="text-sg-muted">
          clasificación:{" "}
          <span className="font-mono text-sg-text">{assessment.clasificacion}</span>
        </span>
        <span className="text-sg-muted">
          confianza: <span className="font-mono text-sg-text">{confidencePct}%</span>
        </span>
        {assessment.patron && (
          <span className="text-sg-muted">
            patrón: <span className="font-mono text-sg-text">{assessment.patron}</span>
          </span>
        )}
      </div>
      <p className="text-sm text-sg-text leading-relaxed">{assessment.rationale}</p>
      <p className="text-xs text-sg-faint font-mono">
        {assessment.modelo} · {assessment.prompt_version}
      </p>
    </div>
  );
}

export function DependencyRow({ result }: DependencyRowProps) {
  const [open, setOpen] = useState(false);
  const panelId = useId();

  const hasDetail =
    result.signals.length > 0 ||
    result.advisories.length > 0 ||
    result.llm_assessment !== null ||
    result.error_category !== null;

  const maliciousAdvisories = result.advisories.filter((a) => a.id.startsWith("MAL-"));
  const otherAdvisories = result.advisories.filter((a) => !a.id.startsWith("MAL-"));
  const orderedAdvisories = [...maliciousAdvisories, ...otherAdvisories];

  return (
    <li className="border-b border-sg-border last:border-b-0">
      <button
        type="button"
        onClick={() => hasDetail && setOpen((v) => !v)}
        aria-expanded={hasDetail ? open : undefined}
        aria-controls={hasDetail ? panelId : undefined}
        disabled={!hasDetail}
        className={cn(
          "w-full flex items-center gap-3 px-4 py-3 text-left",
          "transition-colors duration-150 rounded-sg",
          hasDetail ? "cursor-pointer hover:bg-sg-raised" : "cursor-default",
        )}
      >
        <ChevronRightIcon
          className={cn(
            "w-4 h-4 shrink-0 text-sg-faint transition-transform duration-200",
            open && "rotate-90",
            !hasDetail && "opacity-0",
          )}
        />

        {/* Identidad del paquete */}
        <span className="min-w-0 flex-1 flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="font-mono text-sm text-sg-text font-medium break-all">
            {result.name}
          </span>
          {result.version_pin && (
            <span className="font-mono text-xs text-sg-faint">{result.version_pin}</span>
          )}
          {result.suspected_target && (
            <span className="text-xs text-sg-warn">
              ¿typo de{" "}
              <span className="font-mono">{result.suspected_target}</span>?
            </span>
          )}
        </span>

        {/* Veredicto + score */}
        <span className="flex items-center gap-3 shrink-0">
          <ScoreCell score={result.score} />
          <VerdictBadge result={result} size="sm" />
        </span>
      </button>

      {hasDetail && open && (
        <div id={panelId} className="px-4 pb-4 pt-1 space-y-4 bg-sg-bg/30">
          {result.error_category && (
            <div className="flex items-start gap-2 text-sm text-sg-warn">
              <AlertCircleIcon className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                Esta dependencia no pudo verificarse por completo (
                <code className="font-mono">{result.error_category}</code>).
              </span>
            </div>
          )}

          <SignalList signals={result.signals} />

          {orderedAdvisories.length > 0 && (
            <section aria-label="Advisories de seguridad">
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-sg-faint">
                Advisories
              </h3>
              <ul className="space-y-2" role="list">
                {orderedAdvisories.map((advisory) => (
                  <AdvisoryItem key={advisory.id} advisory={advisory} />
                ))}
              </ul>
            </section>
          )}

          {result.llm_assessment && (
            <LlmAssessmentPanel assessment={result.llm_assessment} />
          )}
        </div>
      )}
    </li>
  );
}
