"use client";

/**
 * Contenido del histórico — Client Component separado para envolver en <Suspense>.
 * Usa useSearchParams() para filtros por query string.
 */

import { useState, useEffect, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import type { ScanListItem, Repo, Ecosystem } from "@/lib/api/types";
import { listScans, listRepos } from "@/lib/api/endpoints";
import { ApiError } from "@/lib/api/client";
import { Skeleton } from "@/components/ui/Skeleton";
import { Button } from "@/components/ui/Button";
import { SummaryCounts } from "@/components/report/SummaryCounts";
import {
  ecosystemLabel,
  formatDateTimeShort,
  originLabel,
} from "@/components/report/report-format";
import {
  HistoryIcon,
  ScanIcon,
  AlertCircleIcon,
  ArrowRightIcon,
  ArrowLeftIcon,
  FilterIcon,
} from "@/lib/icons";
import { cn } from "@/lib/utils";

const PAGE_SIZE = 20;

// ─── Fila de la tabla (escritorio, md+) ──────────────────────────────────────

function HistoryRow({ item }: { item: ScanListItem }) {
  return (
    <tr className="border-b border-sg-border last:border-b-0 hover:bg-sg-raised transition-colors duration-150">
      {/* Fecha */}
      <td className="px-4 py-3 text-sm text-sg-muted whitespace-nowrap">
        <time dateTime={item.created_at}>{formatDateTimeShort(item.created_at)}</time>
      </td>

      {/* Ecosistema */}
      <td className="px-4 py-3 text-sm text-sg-muted">
        {ecosystemLabel(item.ecosystem)}
      </td>

      {/* Origen */}
      <td className="px-4 py-3 text-xs text-sg-faint">{originLabel(item.origin)}</td>

      {/* Resumen mini (conteos compartidos, color+icono+aria-label) */}
      <td className="px-4 py-3">
        <SummaryCounts summary={item.summary} density="compact" />
      </td>

      {/* Total */}
      <td className="px-4 py-3 text-sm font-mono text-sg-muted text-right tabular-nums">
        {item.summary.total}
      </td>

      {/* Acción */}
      <td className="px-4 py-3 text-right">
        <Link
          href={`/history/${item.scan_id}`}
          className={cn(
            "inline-flex items-center gap-1 text-xs text-sg-accent",
            "hover:text-sg-accent-strong underline underline-offset-2",
            "transition-colors duration-150 cursor-pointer",
          )}
          aria-label={`Ver reporte del escaneo del ${formatDateTimeShort(item.created_at)}`}
        >
          Ver reporte
        </Link>
      </td>
    </tr>
  );
}

// ─── Tarjeta (móvil, < md): toda la tarjeta es el enlace al detalle ──────────

function HistoryCard({ item }: { item: ScanListItem }) {
  return (
    <li>
      <Link
        href={`/history/${item.scan_id}`}
        aria-label={`Ver reporte del escaneo del ${formatDateTimeShort(item.created_at)}`}
        className={cn(
          "block rounded-sg border border-sg-border bg-sg-surface p-4 space-y-3",
          "hover:border-sg-border-strong hover:bg-sg-raised",
          "transition-colors duration-150 cursor-pointer",
        )}
      >
        <div className="flex items-center justify-between gap-2">
          <time dateTime={item.created_at} className="text-sm text-sg-text">
            {formatDateTimeShort(item.created_at)}
          </time>
          <span className="text-xs font-mono text-sg-muted">
            {ecosystemLabel(item.ecosystem)}
          </span>
        </div>
        <div className="flex items-center justify-between gap-2">
          <SummaryCounts summary={item.summary} density="compact" />
          <span className="text-xs text-sg-faint shrink-0">
            {item.summary.total} total
          </span>
        </div>
        <p className="text-xs text-sg-faint">{originLabel(item.origin)}</p>
      </Link>
    </li>
  );
}

// ─── Componente principal ────────────────────────────────────────────────────

export function HistoryClient() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const [items, setItems] = useState<ScanListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [repos, setRepos] = useState<Repo[]>([]);

  // Filtros (desde query string o estado local)
  const [ecosystemFilter, setEcosystemFilter] = useState<"" | Ecosystem>(
    (searchParams.get("ecosystem") as Ecosystem | null) ?? "",
  );
  const [repoFilter, setRepoFilter] = useState(searchParams.get("repo_id") ?? "");
  const [page, setPage] = useState(Number(searchParams.get("page") ?? "1"));

  // Cargar repos para el filtro
  useEffect(() => {
    listRepos()
      .then(setRepos)
      .catch(() => {
        // El filtro de repo no es crítico; lo omitimos si falla
      });
  }, []);

  // Sincronizar query string
  const updateQueryString = useCallback(
    (newEco: string, newRepo: string, newPage: number) => {
      const params = new URLSearchParams();
      if (newEco) params.set("ecosystem", newEco);
      if (newRepo) params.set("repo_id", newRepo);
      if (newPage > 1) params.set("page", String(newPage));
      const qs = params.toString();
      router.replace(`/history${qs ? `?${qs}` : ""}`, { scroll: false });
    },
    [router],
  );

  // Cargar escaneos — fetch extraído en useCallback para que useEffect no llame setState directo.
  const fetchScans = useCallback(
    async (signal: AbortSignal) => {
      setLoading(true);
      setError(null);
      try {
        const data = await listScans(
          {
            ecosystem: ecosystemFilter || undefined,
            repo_id: repoFilter || undefined,
            page,
            page_size: PAGE_SIZE,
          },
          signal,
        );
        setItems(data.items);
        setTotal(data.total);
      } catch (err: unknown) {
        if (signal.aborted) return;
        const msg =
          err instanceof ApiError ? err.message : "Error al cargar el historial.";
        setError(msg);
      } finally {
        if (!signal.aborted) setLoading(false);
      }
    },
    [ecosystemFilter, repoFilter, page],
  );

  useEffect(() => {
    const controller = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void fetchScans(controller.signal);
    return () => controller.abort();
  }, [fetchScans]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const handleEcoChange = useCallback(
    (value: "" | Ecosystem) => {
      setEcosystemFilter(value);
      setPage(1);
      updateQueryString(value, repoFilter, 1);
    },
    [repoFilter, updateQueryString],
  );

  const handleRepoChange = useCallback(
    (value: string) => {
      setRepoFilter(value);
      setPage(1);
      updateQueryString(ecosystemFilter, value, 1);
    },
    [ecosystemFilter, updateQueryString],
  );

  const handlePageChange = useCallback(
    (newPage: number) => {
      setPage(newPage);
      updateQueryString(ecosystemFilter, repoFilter, newPage);
      window.scrollTo({ top: 0, behavior: "smooth" });
    },
    [ecosystemFilter, repoFilter, updateQueryString],
  );

  return (
    <div className="space-y-6">
      {/* Título */}
      <div>
        <h1 className="text-2xl font-semibold text-sg-text">Historial de escaneos</h1>
        <p className="text-sm text-sg-muted mt-1">
          {total > 0 ? `${total} escaneo${total !== 1 ? "s" : ""} en total` : ""}
        </p>
      </div>

      {/* Filtros */}
      <div
        role="search"
        aria-label="Filtros del historial"
        className="flex flex-wrap items-center gap-3 p-4 bg-sg-surface border border-sg-border rounded-sg"
      >
        <FilterIcon className="w-4 h-4 text-sg-faint shrink-0" />

        {/* Ecosistema */}
        <div className="flex items-center gap-2">
          <label htmlFor="eco-filter" className="text-xs text-sg-muted whitespace-nowrap">
            Ecosistema:
          </label>
          <select
            id="eco-filter"
            value={ecosystemFilter}
            onChange={(e) => handleEcoChange(e.target.value as "" | Ecosystem)}
            className={cn(
              "rounded bg-sg-bg border border-sg-border px-2 py-1.5 text-xs text-sg-text",
              "focus:outline-none focus:border-sg-accent cursor-pointer",
            )}
          >
            <option value="">Todos</option>
            <option value="pypi">PyPI</option>
            <option value="npm">npm</option>
          </select>
        </div>

        {/* Repo */}
        {repos.length > 0 && (
          <div className="flex items-center gap-2">
            <label htmlFor="repo-filter" className="text-xs text-sg-muted whitespace-nowrap">
              Repositorio:
            </label>
            <select
              id="repo-filter"
              value={repoFilter}
              onChange={(e) => handleRepoChange(e.target.value)}
              className={cn(
                "rounded bg-sg-bg border border-sg-border px-2 py-1.5 text-xs text-sg-text",
                "focus:outline-none focus:border-sg-accent cursor-pointer max-w-[200px]",
              )}
            >
              <option value="">Todos</option>
              {repos.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.full_name}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Estado: cargando */}
      {loading && (
        <div className="space-y-3" aria-busy="true" aria-label="Cargando historial…">
          {[1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} className="h-12 w-full rounded-sg" />
          ))}
        </div>
      )}

      {/* Estado: error */}
      {!loading && error && (
        <div
          role="alert"
          className="flex items-start gap-3 p-4 rounded-sg bg-sg-block/10
                     border border-sg-block/30 text-sm text-sg-block"
        >
          <AlertCircleIcon className="w-4 h-4 shrink-0 mt-0.5" />
          {error}
        </div>
      )}

      {/* Estado: vacío */}
      {!loading && !error && items.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
          <div className="w-14 h-14 rounded-full bg-sg-accent/10 text-sg-accent flex items-center justify-center">
            <HistoryIcon className="w-7 h-7" />
          </div>
          <div className="space-y-1">
            <p className="text-base font-semibold text-sg-text">Aún no tienes escaneos</p>
            <p className="text-sm text-sg-muted">
              {ecosystemFilter || repoFilter
                ? "No hay resultados con los filtros aplicados."
                : "Lanza tu primer escaneo para ver los resultados aquí."}
            </p>
          </div>
          <Link
            href="/scan"
            className={cn(
              "inline-flex items-center gap-2 px-4 py-2 rounded-sg text-sm font-medium",
              "bg-sg-accent text-sg-accent-contrast hover:bg-sg-accent-strong",
              "transition-colors duration-150 cursor-pointer",
            )}
          >
            <ScanIcon className="w-4 h-4" />
            Iniciar escaneo
          </Link>
        </div>
      )}

      {/* Resultados */}
      {!loading && !error && items.length > 0 && (
        <>
          {/* Escritorio (md+): tabla semántica */}
          <div className="hidden md:block rounded-sg border border-sg-border overflow-hidden">
            <table className="w-full text-left" aria-label="Historial de escaneos">
              <thead>
                <tr className="bg-sg-surface border-b border-sg-border">
                  <th scope="col" className="px-4 py-3 text-xs font-semibold text-sg-faint uppercase tracking-wide">
                    Fecha
                  </th>
                  <th scope="col" className="px-4 py-3 text-xs font-semibold text-sg-faint uppercase tracking-wide">
                    Ecosistema
                  </th>
                  <th scope="col" className="px-4 py-3 text-xs font-semibold text-sg-faint uppercase tracking-wide">
                    Origen
                  </th>
                  <th scope="col" className="px-4 py-3 text-xs font-semibold text-sg-faint uppercase tracking-wide">
                    Resumen
                  </th>
                  <th scope="col" className="px-4 py-3 text-xs font-semibold text-sg-faint uppercase tracking-wide text-right">
                    Total
                  </th>
                  <th scope="col" className="px-4 py-3 text-xs font-semibold text-sg-faint uppercase tracking-wide text-right">
                    <span className="sr-only">Acciones</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <HistoryRow key={item.scan_id} item={item} />
                ))}
              </tbody>
            </table>
          </div>

          {/* Móvil (< md): lista de tarjetas, sin scroll horizontal */}
          <ul className="md:hidden space-y-3" role="list" aria-label="Historial de escaneos">
            {items.map((item) => (
              <HistoryCard key={item.scan_id} item={item} />
            ))}
          </ul>

          {/* Paginación */}
          {totalPages > 1 && (
            <nav
              aria-label="Paginación del historial"
              className="flex items-center justify-between"
            >
              <Button
                variant="secondary"
                size="sm"
                onClick={() => handlePageChange(page - 1)}
                disabled={page <= 1}
                aria-label="Página anterior"
                className="gap-1.5"
              >
                <ArrowLeftIcon className="w-4 h-4" />
                Anterior
              </Button>

              <span className="text-sm text-sg-muted" aria-live="polite">
                Página <span className="font-semibold text-sg-text">{page}</span> de{" "}
                <span className="font-semibold text-sg-text">{totalPages}</span>
              </span>

              <Button
                variant="secondary"
                size="sm"
                onClick={() => handlePageChange(page + 1)}
                disabled={page >= totalPages}
                aria-label="Página siguiente"
                className="gap-1.5"
              >
                Siguiente
                <ArrowRightIcon className="w-4 h-4" />
              </Button>
            </nav>
          )}
        </>
      )}
    </div>
  );
}
