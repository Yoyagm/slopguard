"use client";

/**
 * Botón de acción de SlopGuard.
 *
 * Variantes: primary | secondary | ghost | danger.
 * Tamaños: sm | md.
 * Prop `loading`: deshabilita la interacción y muestra un Spinner inline.
 *
 * Accesibilidad:
 * - cursor-pointer siempre visible.
 * - Foco heredado del global :focus-visible.
 * - aria-disabled cuando loading para que SR anuncie el estado.
 * - Sin scale: el hover usa opacidad/color para no desplazar layout.
 */

import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { Spinner } from "./Spinner";
import { cn } from "@/lib/utils";

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
type ButtonSize = "sm" | "md";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  children?: ReactNode;
}

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    "bg-sg-accent text-sg-accent-contrast hover:bg-sg-accent-strong border border-transparent",
  secondary:
    "bg-sg-surface text-sg-text border border-sg-border hover:bg-sg-raised hover:border-sg-border-strong",
  ghost:
    "bg-transparent text-sg-muted border border-transparent hover:text-sg-text hover:bg-sg-raised",
  danger:
    "bg-sg-block/10 text-sg-block border border-sg-block/30 hover:bg-sg-block/20",
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: "px-3 py-1.5 text-xs gap-1.5",
  md: "px-4 py-2 text-sm gap-2",
};

/**
 * Clases de apariencia del botón, SIN el elemento `<button>`. Sirve para dar pinta de botón a
 * otro elemento interactivo (p.ej. un `<label>` que envuelve un input de archivo, donde no cabe un
 * `<button>`). Una sola fuente de verdad para variantes/tamaños.
 */
export function buttonClasses(options?: {
  variant?: ButtonVariant;
  size?: ButtonSize;
  className?: string;
}): string {
  const { variant = "primary", size = "md", className } = options ?? {};
  return cn(
    "inline-flex items-center justify-center rounded-sg font-medium",
    "transition-colors duration-200",
    "cursor-pointer",
    "focus-visible:outline-2 focus-visible:outline-sg-accent",
    variantClasses[variant],
    sizeClasses[size],
    className,
  );
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = "primary",
    size = "md",
    loading = false,
    disabled,
    className,
    children,
    ...props
  },
  ref,
) {
  const isDisabled = disabled ?? loading;

  return (
    <button
      ref={ref}
      type="button"
      disabled={isDisabled}
      aria-disabled={isDisabled}
      className={cn(
        buttonClasses({ variant, size }),
        // Estados deshabilitados
        isDisabled && "opacity-50 cursor-not-allowed pointer-events-none",
        className,
      )}
      {...props}
    >
      {loading && (
        <Spinner
          className="w-4 h-4 shrink-0"
          aria-label="Procesando…"
        />
      )}
      {children}
    </button>
  );
});
