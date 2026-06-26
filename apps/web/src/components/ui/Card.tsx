/**
 * Componente de tarjeta/panel para SlopGuard.
 *
 * Uso directo:  <Card className="p-6">…</Card>
 * Con partes:   <Card><Card.Header>…</Card.Header><Card.Body>…</Card.Body></Card>
 */

import { type HTMLAttributes, type ReactNode } from "react";
import { cn } from "@/lib/utils";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children?: ReactNode;
}

function CardRoot({ className, children, ...props }: CardProps) {
  return (
    <div
      className={cn(
        "bg-sg-surface border border-sg-border rounded-sg shadow-sg-panel",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}

function CardHeader({ className, children, ...props }: CardProps) {
  return (
    <div
      className={cn(
        "px-5 py-4 border-b border-sg-border",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}

function CardBody({ className, children, ...props }: CardProps) {
  return (
    <div className={cn("px-5 py-4", className)} {...props}>
      {children}
    </div>
  );
}

export const Card = Object.assign(CardRoot, {
  Header: CardHeader,
  Body: CardBody,
});
