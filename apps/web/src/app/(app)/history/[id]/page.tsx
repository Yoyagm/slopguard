"use client";

/**
 * Detalle de un escaneo histórico (T35).
 *
 * Client Component obligatorio: getScan() usa cookies del navegador (credentials: "include").
 * Usa React.use(params) para desempaquetar el Promise de params en Next.js 15+/16.
 *
 * Maneja:
 *  - loading  → Skeleton
 *  - 404      → "Escaneo no encontrado" con volver atrás
 *  - error    → mensaje saneado de ApiError
 *  - success  → ScanReport completo
 */

import { use, useEffect, useState } from "react";
import Link from "next/link";
import type { Scan } from "@/lib/api/types";
import { getScan } from "@/lib/api/endpoints";
import { ApiError } from "@/lib/api/client";
import { ScanReport } from "@/components/report/ScanReport";
import { Skeleton } from "@/components/ui/Skeleton";
import { ArrowLeftIcon, AlertCircleIcon, HistoryIcon } from "@/lib/icons";
import { cn } from "@/lib/utils";

interface PageProps {
  params: Promise<{ id: string }>;
}

type FetchState =
  | { status: "loading" }
  | { status: "not_found" }
  | { status: "error"; message: string }
  | { status: "success"; scan: Scan };

function ScanDetailSkeleton() {
  return (
    <div className="space-y-4" aria-busy="true" aria-label="Cargando reporte…">
      {/* Back link */}
      <Skeleton className="h-4 w-24" />
      {/* Header */}
      <Skeleton className="h-20 w-full rounded-sg" />
      {/* Summary bar */}
      <Skeleton className="h-14 w-full rounded-sg" />
      {/* Rows */}
      {[1, 2, 3, 4].map((i) => (
        <Skeleton key={i} className="h-12 w-full rounded-sg" />
      ))}
    </div>
  );
}

export default function HistoryDetailPage({ params }: PageProps) {
  const { id } = use(params);

  const [state, setState] = useState<FetchState>({ status: "loading" });

  useEffect(() => {
    if (!id) return;
    let cancelled = false;

    getScan(id)
      .then((scan) => {
        if (!cancelled) setState({ status: "success", scan });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 404) {
          setState({ status: "not_found" });
        } else {
          const message =
            err instanceof ApiError ? err.message : "Error al cargar el escaneo.";
          setState({ status: "error", message });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [id]);

  if (state.status === "loading") {
    return <ScanDetailSkeleton />;
  }

  // ─── Back link — siempre presente en estados resueltos ──────────────────
  const backLink = (
    <Link
      href="/history"
      className={cn(
        "inline-flex items-center gap-1.5 text-sm text-sg-muted",
        "hover:text-sg-text transition-colors duration-150 cursor-pointer mb-4",
      )}
      aria-label="Volver al historial"
    >
      <ArrowLeftIcon className="w-4 h-4 shrink-0" />
      Historial
    </Link>
  );

  if (state.status === "not_found") {
    return (
      <div className="space-y-4">
        {backLink}
        <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
          <div className="w-14 h-14 rounded-full bg-sg-warn/10 text-sg-warn flex items-center justify-center">
            <HistoryIcon className="w-7 h-7" />
          </div>
          <div>
            <p className="text-base font-semibold text-sg-text">Escaneo no encontrado</p>
            <p className="text-sm text-sg-muted mt-1">
              No existe un escaneo con ese ID o no tienes acceso a él.
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (state.status === "error") {
    return (
      <div className="space-y-4">
        {backLink}
        <div
          role="alert"
          className="flex items-start gap-3 p-4 rounded-sg bg-sg-block/10
                     border border-sg-block/30 text-sm text-sg-block"
        >
          <AlertCircleIcon className="w-4 h-4 shrink-0 mt-0.5" />
          {state.message}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {backLink}
      <h1 className="text-2xl font-semibold text-sg-text">Reporte de escaneo</h1>
      <ScanReport scan={state.scan} />
    </div>
  );
}
