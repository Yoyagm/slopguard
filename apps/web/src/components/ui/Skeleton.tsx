/**
 * Bloque de contenido en estado de carga (skeleton screen).
 * Pulse sutil sobre bg-sg-raised — no disturba en prefers-reduced-motion.
 */

interface SkeletonProps {
  className?: string;
  /** Accesible: describe qué está cargando para SR. */
  "aria-label"?: string;
}

export function Skeleton({
  className = "h-4 w-full",
  "aria-label": ariaLabel,
}: SkeletonProps) {
  return (
    <div
      role="status"
      aria-label={ariaLabel ?? "Cargando…"}
      aria-busy="true"
      className={`animate-pulse bg-sg-raised rounded ${className}`}
    />
  );
}
