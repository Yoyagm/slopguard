/**
 * Tipos del contrato de la API de SlopGuard (design §4), espejo 1:1 de los DTOs Pydantic
 * (`apps/api/app/schemas/scan.py`). UUID y datetime se serializan como `string` sobre el cable.
 *
 * Regla: el front NO inventa campos de veredicto; solo consume lo que el motor produce vía el API.
 * `report_dict` se excluye de las respuestas de `/scans` y `/scans/{id}` (el JSON crudo schema 1.2
 * se obtiene aparte en `/scans/{id}/raw`).
 */

export type Ecosystem = "pypi" | "npm";
export type ScanOrigin = "on_demand" | "pull_request";
export type Verdict = "allow" | "warn" | "block";
export type DependencyStatus = "ok" | "unverifiable";

/** Identidad pública del usuario autenticado (`GET /me`). Sin secretos. */
export interface Me {
  id: string;
  login: string;
  avatar_url: string | null;
}

/** Instalación de la GitHub App (`GET /installations`). */
export interface Installation {
  id: string;
  installation_id: number;
  account_login: string;
  status: string;
}

/** Repo accesible vía una instalación activa (`GET /repos`). */
export interface Repo {
  id: string;
  installation_id: string;
  github_repo_id: number;
  full_name: string;
  private: boolean;
}

/** Señal emitida por una capa de detección, con su explicación saneada en español. */
export interface Signal {
  layer: number;
  code: string;
  weight: number;
  is_soft: boolean;
  is_llm_channel: boolean;
  detail: string;
  suspected_target: string | null;
}

/** Advisory de malicia normalizado (MAL-*) de la Capa 3. */
export interface Advisory {
  id: string;
  kind: string;
  url: string;
  source: string;
}

/** Veredicto del LLM (Capa 4). `null` cuando la Capa 4 está off (por defecto). */
export interface LlmAssessment {
  clasificacion: string;
  confianza: number;
  patron: string;
  rationale: string;
  modelo: string;
  prompt_version: string;
}

/** Resultado de una dependencia: estado, veredicto, score y señales por capa. */
export interface DependencyResult {
  name: string;
  version_pin: string | null;
  status: DependencyStatus;
  /** `null` cuando es unverifiable. */
  verdict: Verdict | null;
  /** `null` en unverifiable o block-override: tratar como "sin score", NO como 0. */
  score: number | null;
  suspected_target: string | null;
  error_category: string | null;
  signals: Signal[];
  advisories: Advisory[];
  llm_assessment: LlmAssessment | null;
}

/** Conteos del escaneo y exit code equivalente del CLI (0/1/2/3). */
export interface ScanSummary {
  total: number;
  allow: number;
  warn: number;
  block: number;
  unverifiable: number;
  llm_unavailable: number;
  exit_code: number;
}

/** DTO completo del reporte (`POST /scans`, `GET /scans/{id}`). Sin `report_dict`. */
export interface Scan {
  scan_id: string;
  origin: ScanOrigin;
  created_at: string;
  schema_version: string;
  tool_version: string;
  ecosystem: Ecosystem;
  error_category: string | null;
  summary: ScanSummary;
  results: DependencyResult[];
}

/** Fila del histórico (`GET /scans`): sin `results` ni raw. */
export interface ScanListItem {
  scan_id: string;
  origin: ScanOrigin;
  created_at: string;
  ecosystem: Ecosystem;
  schema_version: string;
  tool_version: string;
  error_category: string | null;
  summary: ScanSummary;
}

/** Respuesta paginada del histórico (`GET /scans`). */
export interface ScanPage {
  items: ScanListItem[];
  total: number;
  page: number;
  page_size: number;
}

/** Cuerpo del escaneo on-demand (`POST /scans`). */
export interface ScanRequest {
  source: "inline" | "repo";
  /** Requerido si source=inline. */
  content?: string;
  /** Opcional: ayuda a autodetectar el ecosistema. */
  filename?: string;
  /** Requerido si source=repo. */
  repo_id?: string;
  /** Requerido si source=repo. */
  path?: string;
  /** Override opcional; `null`/ausente = autodetección. */
  ecosystem?: Ecosystem | null;
}

/** Filtros del histórico (`GET /scans`). */
export interface ScanListQuery {
  repo_id?: string;
  ecosystem?: Ecosystem;
  page?: number;
  page_size?: number;
}

/** JSON crudo del motor (schema 1.2) de `GET /scans/{id}/raw`. Forma opaca: se muestra tal cual. */
export type RawReport = Record<string, unknown>;

/** Cuerpo de error estable de la API: `{ error: { code, message, request_id } }` (R9.2). */
export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    request_id: string;
  };
}
