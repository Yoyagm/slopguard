/**
 * Endpoints tipados de la API de SlopGuard (Ola 6a/T36). Una función por ruta del contrato §4.1.
 * El login OAuth es una navegación top-level (no fetch): la cookie se fija en el dominio del API.
 */

import { apiFetch, apiUrl } from "./client";
import type {
  Installation,
  Me,
  RawReport,
  Repo,
  Scan,
  ScanListQuery,
  ScanPage,
  ScanRequest,
} from "./types";

/** URL de inicio del flujo OAuth con GitHub. Se navega con `window.location` (no fetch). */
export function loginUrl(): string {
  return apiUrl("/auth/login");
}

/** Cierra la sesión (borra la cookie en el servidor). `204` sin cuerpo. */
export function logout(signal?: AbortSignal): Promise<void> {
  return apiFetch<void>("/auth/logout", { method: "POST", signal });
}

/** Identidad del usuario autenticado. `401` si no hay sesión. */
export function getMe(signal?: AbortSignal): Promise<Me> {
  return apiFetch<Me>("/me", { signal });
}

/** Instalaciones de la GitHub App del usuario. */
export function listInstallations(signal?: AbortSignal): Promise<Installation[]> {
  return apiFetch<Installation[]>("/installations", { signal });
}

/** Repos accesibles; opcionalmente acotados a una instalación. */
export function listRepos(
  installationId?: number,
  signal?: AbortSignal,
): Promise<Repo[]> {
  return apiFetch<Repo[]>("/repos", {
    query: { installation_id: installationId },
    signal,
  });
}

/** Lanza un escaneo on-demand y devuelve el reporte. */
export function createScan(body: ScanRequest, signal?: AbortSignal): Promise<Scan> {
  return apiFetch<Scan>("/scans", { method: "POST", body, signal });
}

/** Histórico paginado del usuario, con filtros opcionales. */
export function listScans(
  query: ScanListQuery = {},
  signal?: AbortSignal,
): Promise<ScanPage> {
  // Cast explícito: los valores de ScanListQuery son compatibles con el tipo del cliente.
  return apiFetch<ScanPage>("/scans", {
    query: query as Record<string, string | number | undefined | null>,
    signal,
  });
}

/** Detalle completo de un escaneo propio. `404` si no existe o es de otro usuario. */
export function getScan(scanId: string, signal?: AbortSignal): Promise<Scan> {
  return apiFetch<Scan>(`/scans/${encodeURIComponent(scanId)}`, { signal });
}

/** JSON crudo (schema 1.2) de un escaneo propio. */
export function getScanRaw(scanId: string, signal?: AbortSignal): Promise<RawReport> {
  return apiFetch<RawReport>(`/scans/${encodeURIComponent(scanId)}/raw`, { signal });
}
