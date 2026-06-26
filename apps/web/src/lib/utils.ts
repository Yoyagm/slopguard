/**
 * Utilidades genéricas del frontend de SlopGuard.
 * `cn` concatena clases condicionalmente sin dependencia externa.
 */

/** Combina clases CSS filtrando valores falsy. Suficiente sin clsx/tailwind-merge. */
export function cn(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(" ");
}
