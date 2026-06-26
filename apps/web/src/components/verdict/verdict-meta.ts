/**
 * Módulo PURO (sin JSX) de metadatos de veredicto para SlopGuard.
 *
 * Reglas DURAS de negocio:
 *  1. Advisory MAL-* confirmado → malicious, prioridad absoluta.
 *  2. status==='unverifiable' o verdict===null → unverifiable, JAMÁS verde.
 *     Es fail-closed visual: la ausencia de verificación NO implica seguridad.
 *  3. allow/warn/block según su veredicto.
 *
 * La función es pura y determinista: dado el mismo input, siempre produce el mismo output.
 * No lanza excepciones para inputs válidos del tipo; el `never` final previene fugas de tipo.
 */

import type { DependencyStatus, Verdict } from "@/lib/api/types";

/** Clave del icono que VerdictBadge mapea al componente SVG correspondiente. */
export type VerdictIconKey =
  | "check-circle"
  | "alert-triangle"
  | "octagon-x"
  | "skull"
  | "help-circle";

/** Tono semántico — corresponde a los tokens `text-sg-*` y `bg-sg-*` del sistema de diseño. */
export type VerdictTone =
  | "allow"
  | "warn"
  | "block"
  | "malicious"
  | "unverifiable";

/** Resultado normalizado de getVerdictMeta. */
export interface VerdictMeta {
  /** Identificador canónico del estado (para lógica de negocio, no para UI directa). */
  key: VerdictTone;
  /** Etiqueta en español para mostrar al usuario. */
  label: string;
  /** Tono semántico que mapea a los tokens de color del design system. */
  tone: VerdictTone;
  /** Icono a renderizar en VerdictBadge. */
  iconKey: VerdictIconKey;
  /** Descripción accesible larga (aria-label ampliado, tooltips). */
  description: string;
}

export interface VerdictInput {
  verdict: Verdict | null;
  status: DependencyStatus;
  /** `true` si el paquete tiene al menos un advisory con id que empieza por "MAL-". */
  hasMaliciousAdvisory: boolean;
}

/** Retorna los metadatos de veredicto normalizados para su presentación en la UI. */
export function getVerdictMeta({
  verdict,
  status,
  hasMaliciousAdvisory,
}: VerdictInput): VerdictMeta {
  // Prioridad 1: Advisory MAL-* confirmado — supera cualquier veredicto heurístico.
  if (hasMaliciousAdvisory) {
    return {
      key: "malicious",
      label: "Malicioso",
      tone: "malicious",
      iconKey: "skull",
      description:
        "Paquete con advisory de malicia confirmado (MAL-*). No usar bajo ninguna circunstancia.",
    };
  }

  // Prioridad 2: No verificable — fail-closed, NUNCA aparece en verde.
  if (status === "unverifiable" || verdict === null) {
    return {
      key: "unverifiable",
      label: "No verificable",
      tone: "unverifiable",
      iconKey: "help-circle",
      description:
        "No fue posible verificar este paquete. La ausencia de verificación no implica seguridad. Tratar con precaución.",
    };
  }

  // Prioridad 3: Veredictos del motor de detección.
  // En este punto, `verdict` es Verdict ('allow' | 'warn' | 'block') — el switch es exhaustivo.
  switch (verdict) {
    case "allow":
      return {
        key: "allow",
        label: "Permitido",
        tone: "allow",
        iconKey: "check-circle",
        description: "Paquete verificado y considerado seguro por el motor de detección.",
      };

    case "warn":
      return {
        key: "warn",
        label: "Advertencia",
        tone: "warn",
        iconKey: "alert-triangle",
        description:
          "Paquete con señales de riesgo. Revisar los detalles antes de incluirlo en producción.",
      };

    case "block":
      return {
        key: "block",
        label: "Bloqueado",
        tone: "block",
        iconKey: "octagon-x",
        description:
          "Paquete detectado como potencialmente peligroso por el motor de detección heurístico.",
      };

    default: {
      // Guarda de exhaustividad — TypeScript la usa para detectar ramas no cubiertas.
      const _exhaustive: never = verdict;
      throw new Error(`Veredicto inesperado: ${String(_exhaustive)}`);
    }
  }
}

/** Helper para derivar `hasMaliciousAdvisory` desde el array de advisories del contrato. */
export function hasMalAdvisory(
  advisories: { id: string }[],
): boolean {
  return advisories.some((a) => a.id.startsWith("MAL-"));
}
