/**
 * Historial de escaneos (T35).
 *
 * Server Component que envuelve HistoryClient en <Suspense>.
 * Necesario porque HistoryClient usa useSearchParams() — Next.js exige que el
 * componente que llama useSearchParams esté dentro de un Suspense boundary.
 */

import { Suspense } from "react";
import { Skeleton } from "@/components/ui/Skeleton";
import { HistoryClient } from "./HistoryClient";

function HistoryFallback() {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-8 w-56" aria-label="Cargando título…" />
        <Skeleton className="h-4 w-32" />
      </div>
      <Skeleton className="h-16 w-full rounded-sg" aria-label="Cargando filtros…" />
      <div className="space-y-3">
        {[1, 2, 3, 4, 5].map((i) => (
          <Skeleton key={i} className="h-12 w-full rounded-sg" />
        ))}
      </div>
    </div>
  );
}

export default function HistoryPage() {
  return (
    <Suspense fallback={<HistoryFallback />}>
      <HistoryClient />
    </Suspense>
  );
}
