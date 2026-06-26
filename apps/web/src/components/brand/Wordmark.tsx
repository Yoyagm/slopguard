/**
 * Wordmark de SlopGuard: ShieldIcon + logotipo de texto.
 * Componente servidor puro — sin estado ni eventos.
 */

import { ShieldIcon } from "@/lib/icons";
import { cn } from "@/lib/utils";

interface WordmarkProps {
  className?: string;
  /** Tamaño del icono y texto. */
  size?: "sm" | "md" | "lg";
}

const SIZE_CLASSES = {
  sm: { icon: "w-4 h-4", text: "text-base" },
  md: { icon: "w-5 h-5", text: "text-lg" },
  lg: { icon: "w-7 h-7", text: "text-2xl" },
};

export function Wordmark({ className, size = "md" }: WordmarkProps) {
  const { icon, text } = SIZE_CLASSES[size];

  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 font-semibold text-sg-text select-none",
        className,
      )}
      aria-label="SlopGuard"
    >
      <ShieldIcon
        className={cn(icon, "text-sg-accent shrink-0")}
        aria-hidden
      />
      <span className={cn("font-mono tracking-tight", text)}>
        Slop<span className="text-sg-accent">Guard</span>
      </span>
    </span>
  );
}
