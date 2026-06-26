"use client";

/**
 * Layout protegido para todas las rutas bajo /(app)/.
 *
 * Usa useRequireSession() para redirigir a /login si la sesión es inválida.
 * Muestra:
 *  - loading      → AppShell con skeletons (UX: no flash de contenido vacío)
 *  - authenticated → AppShell con children
 *  - unauthenticated → splash mínimo mientras ocurre la redirección
 */

import type { ReactNode } from "react";
import { useRequireSession } from "@/lib/api/session";
import { AppShell } from "@/components/shell/AppShell";
import { Skeleton } from "@/components/ui/Skeleton";
import { Wordmark } from "@/components/brand/Wordmark";
import { Spinner } from "@/components/ui/Spinner";

function LoadingShell() {
  return (
    <AppShell>
      <div className="space-y-6" aria-busy="true" aria-label="Cargando contenido…">
        {/* Encabezado de página */}
        <div className="space-y-2">
          <Skeleton className="h-7 w-48" aria-label="Cargando título…" />
          <Skeleton className="h-4 w-80" aria-label="Cargando descripción…" />
        </div>
        {/* Tarjetas */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Skeleton className="h-36 w-full rounded-sg" />
          <Skeleton className="h-36 w-full rounded-sg" />
        </div>
        {/* Lista/tabla */}
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-12 w-full rounded-sg" />
          ))}
        </div>
      </div>
    </AppShell>
  );
}

function UnauthenticatedSplash() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-sg-bg gap-6">
      <Wordmark size="lg" />
      <Spinner className="w-6 h-6" aria-label="Redirigiendo al login…" />
    </div>
  );
}

export default function AppLayout({ children }: { children: ReactNode }) {
  const { status } = useRequireSession();

  if (status === "loading") return <LoadingShell />;
  if (status === "unauthenticated") return <UnauthenticatedSplash />;

  return <AppShell>{children}</AppShell>;
}
