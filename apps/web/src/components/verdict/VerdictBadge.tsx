/**
 * Badge de veredicto de SlopGuard.
 *
 * Muestra ICONO + ETIQUETA DE TEXTO + color. El color NUNCA es el único portador
 * de significado (WCAG 1.4.1): siempre acompañamos con icono y etiqueta visible.
 *
 * aria-label descriptivo para lectores de pantalla.
 */

import type { ReactElement } from "react";
import { cn } from "@/lib/utils";
import {
  CheckCircleIcon,
  AlertTriangleIcon,
  OctagonXIcon,
  SkullIcon,
  HelpCircleIcon,
} from "@/lib/icons";
import {
  getVerdictMeta,
  hasMalAdvisory,
  type VerdictIconKey,
  type VerdictTone,
} from "./verdict-meta";
import type { DependencyResult } from "@/lib/api/types";

type BadgeSize = "sm" | "md";

interface VerdictBadgeProps {
  /** Resultado completo de la dependencia — se extrae lo necesario aquí. */
  result: Pick<DependencyResult, "verdict" | "status" | "advisories">;
  size?: BadgeSize;
  className?: string;
}

/** Mapa icono-key → componente SVG. */
const ICON_MAP: Record<VerdictIconKey, (p: { className: string }) => ReactElement> = {
  "check-circle": ({ className }) => <CheckCircleIcon className={className} />,
  "alert-triangle": ({ className }) => <AlertTriangleIcon className={className} />,
  "octagon-x": ({ className }) => <OctagonXIcon className={className} />,
  skull: ({ className }) => <SkullIcon className={className} />,
  "help-circle": ({ className }) => <HelpCircleIcon className={className} />,
};

/** Clases de texto/fondo por tono semántico. */
const TONE_CLASSES: Record<VerdictTone, { text: string; bg: string }> = {
  allow: { text: "text-sg-allow", bg: "bg-sg-allow/15" },
  warn: { text: "text-sg-warn", bg: "bg-sg-warn/15" },
  block: { text: "text-sg-block", bg: "bg-sg-block/15" },
  malicious: { text: "text-sg-malicious", bg: "bg-sg-malicious/15" },
  unverifiable: { text: "text-sg-unverifiable", bg: "bg-sg-unverifiable/15" },
};

const SIZE_CLASSES: Record<BadgeSize, { icon: string; text: string; gap: string; padding: string }> = {
  sm: { icon: "w-3.5 h-3.5", text: "text-xs", gap: "gap-1", padding: "px-2 py-0.5" },
  md: { icon: "w-4 h-4", text: "text-sm", gap: "gap-1.5", padding: "px-2.5 py-1" },
};

export function VerdictBadge({
  result,
  size = "md",
  className,
}: VerdictBadgeProps) {
  const meta = getVerdictMeta({
    verdict: result.verdict,
    status: result.status,
    hasMaliciousAdvisory: hasMalAdvisory(result.advisories),
  });

  const { text, bg } = TONE_CLASSES[meta.tone];
  const { icon, text: textSize, gap, padding } = SIZE_CLASSES[size];
  const IconComponent = ICON_MAP[meta.iconKey];

  return (
    <span
      role="img"
      aria-label={`Veredicto: ${meta.label}. ${meta.description}`}
      className={cn(
        "inline-flex items-center rounded font-medium font-mono",
        text,
        bg,
        gap,
        padding,
        textSize,
        className,
      )}
    >
      <IconComponent className={cn(icon, "shrink-0")} />
      <span>{meta.label}</span>
    </span>
  );
}
