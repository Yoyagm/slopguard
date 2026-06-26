/**
 * Set de iconos SVG inline para SlopGuard.
 *
 * Props comunes:
 *  - `className`: clases Tailwind/CSS adicionales.
 *  - `aria-hidden` (por defecto true): cuando el icono es decorativo el texto circundante o
 *    el aria-label del padre provee el nombre accesible. Pasa `aria-hidden={false}` + `title`
 *    si el icono es el único portador de significado (caso raro en nuestra UI).
 *
 * ViewBox: 24×24. Trazo: stroke="currentColor" fill="none" salvo indicado. strokeWidth 2px.
 * Sin dependencias de iconos externas — requisito de bundle del proyecto.
 */

import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement>;

const defaultProps: IconProps = {
  width: 20,
  height: 20,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 2,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true,
};

/** Escudo — logo de marca / identidad de SlopGuard. */
export function ShieldIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

/** Check dentro de círculo — veredicto allow/permitido. */
export function CheckCircleIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <circle cx="12" cy="12" r="10" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

/** Triángulo con signo de exclamación — veredicto warn/advertencia. */
export function AlertTriangleIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

/** Octágono con X — veredicto block/bloqueado. */
export function OctagonXIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
      <line x1="15" y1="9" x2="9" y2="15" />
      <line x1="9" y1="9" x2="15" y2="15" />
    </svg>
  );
}

/** Signo de interrogación en círculo — veredicto unverifiable/no verificable. */
export function HelpCircleIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <circle cx="12" cy="12" r="10" />
      <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

/** Calavera — advisory MAL-* confirmado (malicioso). */
export function SkullIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <circle cx="12" cy="12" r="10" />
      <path d="M9 14v1M15 14v1" />
      <path d="M9 10h.01M15 10h.01" />
      <path d="M12 4a6 6 0 016 6v2H6v-2a6 6 0 016-6z" />
    </svg>
  );
}

/** Logo de GitHub (Octocat). fill="currentColor", sin stroke. */
export function GithubIcon({ className, ...props }: IconProps) {
  return (
    <svg
      {...defaultProps}
      fill="currentColor"
      stroke="none"
      className={className}
      {...props}
    >
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483
        0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608
        1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951
        0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004
        1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688
        0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019
        10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
      />
    </svg>
  );
}

/** Flecha izquierda con punto de salida — cerrar sesión. */
export function LogOutIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
      <polyline points="16 17 21 12 16 7" />
      <line x1="21" y1="12" x2="9" y2="12" />
    </svg>
  );
}

/** Radar/lupa — escanear dependencias. */
export function ScanIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
      <line x1="11" y1="8" x2="11" y2="14" />
      <line x1="8" y1="11" x2="14" y2="11" />
    </svg>
  );
}

/** Reloj — historial de escaneos. */
export function HistoryIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <polyline points="1 4 1 10 7 10" />
      <path d="M3.51 15a9 9 0 101.59-3.36L1 10" />
      <polyline points="12 6 12 12 16 14" />
    </svg>
  );
}

/** Chevron hacia abajo — menús/dropdowns. */
export function ChevronDownIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

/** Copiar al portapapeles. */
export function CopyIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
    </svg>
  );
}

/** Enlace externo / abrir en nueva pestaña. */
export function ExternalLinkIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6" />
      <polyline points="15 3 21 3 21 9" />
      <line x1="10" y1="14" x2="21" y2="3" />
    </svg>
  );
}

/** Hamburguesa — menú móvil. */
export function MenuIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <line x1="3" y1="12" x2="21" y2="12" />
      <line x1="3" y1="6" x2="21" y2="6" />
      <line x1="3" y1="18" x2="21" y2="18" />
    </svg>
  );
}

/** X — cerrar menú/modal. */
export function XIcon({ className, ...props }: IconProps) {
  return (
    <svg {...defaultProps} className={className} {...props}>
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}
