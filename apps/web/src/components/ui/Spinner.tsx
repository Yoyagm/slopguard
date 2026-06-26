/**
 * Indicador de carga accesible.
 * - role="status" + aria-label para lectores de pantalla.
 * - Tamaño controlable con className (por defecto w-5 h-5).
 */

interface SpinnerProps {
  className?: string;
  "aria-label"?: string;
}

export function Spinner({
  className = "w-5 h-5",
  "aria-label": ariaLabel = "Cargando…",
}: SpinnerProps) {
  return (
    <svg
      role="status"
      aria-label={ariaLabel}
      className={`animate-spin text-sg-accent ${className}`}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* Pista del spinner */}
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      {/* Arco animado */}
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}
