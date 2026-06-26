/**
 * Conteos de veredicto con icono + color + etiqueta (T34 barra de resumen, T35 histórico).
 *
 * El color NUNCA es el único portador de significado (WCAG 1.4.1): cada conteo lleva icono y
 * un texto/`aria-label` explícito. Dos densidades:
 *   - "full":    chip con número + etiqueta visible (barra de resumen del reporte).
 *   - "compact": chip con número e icono, etiqueta solo para lectores (filas del histórico).
 *
 * Reutilizado en ambos sitios para que la semántica de color y orden sea idéntica en toda la app.
 */

import type { ReactElement } from "react";
import { cn } from "@/lib/utils";
import type { ScanSummary } from "@/lib/api/types";
import {
  CheckCircleIcon,
  AlertTriangleIcon,
  OctagonXIcon,
  HelpCircleIcon,
} from "@/lib/icons";

type CountTone = "allow" | "warn" | "block" | "unverifiable";

interface CountDef {
  key: keyof Pick<ScanSummary, "allow" | "warn" | "block" | "unverifiable">;
  tone: CountTone;
  label: string;
  /** Singular/plural para el aria-label ("1 permitido", "3 permitidos"). */
  noun: [singular: string, plural: string];
  Icon: (props: { className?: string }) => ReactElement;
}

/** Orden fijo de severidad ascendente: allow → warn → block → unverifiable. */
const COUNT_DEFS: CountDef[] = [
  {
    key: "allow",
    tone: "allow",
    label: "Permitidos",
    noun: ["permitido", "permitidos"],
    Icon: CheckCircleIcon,
  },
  {
    key: "warn",
    tone: "warn",
    label: "Advertencias",
    noun: ["advertencia", "advertencias"],
    Icon: AlertTriangleIcon,
  },
  {
    key: "block",
    tone: "block",
    label: "Bloqueados",
    noun: ["bloqueado", "bloqueados"],
    Icon: OctagonXIcon,
  },
  {
    key: "unverifiable",
    tone: "unverifiable",
    label: "No verificables",
    noun: ["no verificable", "no verificables"],
    Icon: HelpCircleIcon,
  },
];

const TONE_CLASSES: Record<CountTone, string> = {
  allow: "text-sg-allow bg-sg-allow/15",
  warn: "text-sg-warn bg-sg-warn/15",
  block: "text-sg-block bg-sg-block/15",
  unverifiable: "text-sg-unverifiable bg-sg-unverifiable/15",
};

interface SummaryCountsProps {
  summary: Pick<ScanSummary, "allow" | "warn" | "block" | "unverifiable">;
  density?: "full" | "compact";
  /** En "compact": si es true oculta los conteos en cero (filas densas). Default true. */
  hideZeros?: boolean;
  className?: string;
}

export function SummaryCounts({
  summary,
  density = "full",
  hideZeros,
  className,
}: SummaryCountsProps) {
  const compact = density === "compact";
  const shouldHideZeros = hideZeros ?? compact;

  const visible = COUNT_DEFS.filter((def) => !shouldHideZeros || summary[def.key] > 0);

  // Cuando todo es cero y ocultamos ceros (p.ej. escaneo con error), mostramos un guion.
  if (visible.length === 0) {
    return (
      <span className={cn("text-sm text-sg-faint", className)} aria-label="Sin conteos">
        —
      </span>
    );
  }

  return (
    <ul
      className={cn("flex flex-wrap items-center", compact ? "gap-1.5" : "gap-2", className)}
      role="list"
    >
      {visible.map(({ key, tone, label, noun, Icon }) => {
        const value = summary[key];
        const ariaLabel = `${value} ${value === 1 ? noun[0] : noun[1]}`;
        return (
          <li key={key}>
            <span
              className={cn(
                "inline-flex items-center rounded font-mono font-medium",
                TONE_CLASSES[tone],
                compact ? "gap-1 px-1.5 py-0.5 text-xs" : "gap-1.5 px-2.5 py-1 text-sm",
              )}
              aria-label={ariaLabel}
            >
              <Icon className={cn("shrink-0", compact ? "w-3 h-3" : "w-4 h-4")} />
              <span aria-hidden="true">{value}</span>
              {!compact && (
                <span aria-hidden="true" className="font-sans text-sg-muted">
                  {label}
                </span>
              )}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
