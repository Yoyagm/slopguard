/**
 * Módulo PURO (sin JSX) de formato y etiquetas para el visor de reporte (T34).
 *
 * Centraliza las decisiones de presentación que comparten ScanReport, el histórico y los
 * subcomponentes: formateo de fechas, score, ecosistema, origen, capas de detección y la
 * explicación del exit_code. Mantenerlo puro lo hace testeable y evita divergencias de copy.
 *
 * Semántica autoritativa (design §R7.5 / docs/slopguard.tex):
 *   exit_code 0 = allow limpio · 1 = warn · 2 = block (dominante) · 3 = operacional/unverifiable.
 * Capas (docs §arquitectura): 0 existencia+edad · 1 typosquatting · 2 metadatos ·
 *   3 threat-intel (MAL-*) · 4 LLM (alucinación, opt-in).
 */

import type { Ecosystem, ScanOrigin } from "@/lib/api/types";

/** Formatea un ISO-8601 a fecha+hora local legible (es-CO). Devuelve el crudo si es inválido. */
export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return new Intl.DateTimeFormat("es-CO", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

/** Formatea un ISO-8601 a fecha+hora corta para tablas densas. */
export function formatDateTimeShort(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return new Intl.DateTimeFormat("es-CO", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(date);
}

/**
 * Presenta el score. `null` NO es 0: significa "sin score" (unverifiable o block-override).
 * Devuelve `{ text, isAbsent }` para que la UI pueda diferenciar el caso ausente del numérico.
 */
export function formatScore(score: number | null): { text: string; isAbsent: boolean } {
  if (score === null) return { text: "—", isAbsent: true };
  // El score del motor es 0..100; lo mostramos como entero estable.
  return { text: String(Math.round(score)), isAbsent: false };
}

const ECOSYSTEM_LABELS: Record<Ecosystem, string> = {
  pypi: "PyPI",
  npm: "npm",
};

/** Etiqueta humana del ecosistema; cae al valor crudo si llega uno no contemplado. */
export function ecosystemLabel(ecosystem: string): string {
  return ECOSYSTEM_LABELS[ecosystem as Ecosystem] ?? ecosystem;
}

const ORIGIN_LABELS: Record<ScanOrigin, string> = {
  on_demand: "On-demand",
  pull_request: "Pull request",
};

/** Etiqueta humana del origen del escaneo. */
export function originLabel(origin: string): string {
  return ORIGIN_LABELS[origin as ScanOrigin] ?? origin;
}

/** Nombre corto de cada capa de detección, para agrupar señales. */
const LAYER_NAMES: Record<number, string> = {
  0: "Existencia y edad",
  1: "Typosquatting",
  2: "Metadatos",
  3: "Threat-intel",
  4: "LLM (alucinación)",
};

/** Etiqueta de capa: "Capa N · Nombre". Capas desconocidas degradan a "Capa N". */
export function layerLabel(layer: number): string {
  const name = LAYER_NAMES[layer];
  return name ? `Capa ${layer} · ${name}` : `Capa ${layer}`;
}

/** Explicación del exit_code para mostrar junto al resumen, con su tono semántico. */
export interface ExitCodeMeta {
  code: number;
  label: string;
  description: string;
  tone: "allow" | "warn" | "block" | "unverifiable";
}

/** Mapea el exit_code a etiqueta + explicación + tono (precedencia R7.5). */
export function exitCodeMeta(code: number): ExitCodeMeta {
  switch (code) {
    case 0:
      return {
        code,
        label: "Limpio",
        description: "Todas las dependencias resultaron permitidas, sin riesgo detectado.",
        tone: "allow",
      };
    case 1:
      return {
        code,
        label: "Advertencias",
        description: "Hay señales de riesgo (warn). Revisa los detalles antes de continuar.",
        tone: "warn",
      };
    case 2:
      return {
        code,
        label: "Bloqueado",
        description:
          "Al menos una dependencia fue bloqueada o es maliciosa. Acción requerida antes de usar.",
        tone: "block",
      };
    case 3:
      return {
        code,
        label: "No concluyente",
        description:
          "Error operacional o dependencias no verificables. La ausencia de verificación no implica seguridad.",
        tone: "unverifiable",
      };
    default:
      return {
        code,
        label: `Código ${code}`,
        description: "Resultado de escaneo no estándar.",
        tone: "unverifiable",
      };
  }
}

/** Traduce un `error_category` técnico a una explicación corta en español. */
const ERROR_CATEGORY_LABELS: Record<string, string> = {
  manifest_parse: "No se pudo interpretar el manifiesto de dependencias.",
  invalid_config: "La configuración del escaneo es inválida.",
  dataset_integrity: "El dataset de referencia no está disponible o está corrupto.",
  not_found: "El recurso solicitado no existe.",
  network: "Fallo de red al contactar las fuentes de datos.",
  timeout: "El escaneo superó el tiempo máximo permitido.",
};

/** Explicación humana de un `error_category`; cae al crudo legible si no se conoce. */
export function errorCategoryLabel(category: string): string {
  return ERROR_CATEGORY_LABELS[category] ?? `Error: ${category}`;
}
