/**
 * Cliente HTTP tipado de la API de SlopGuard (Ola 6a/T36).
 *
 * Sesión por cookie httpOnly puesta por el API: por eso TODA petición va con
 * `credentials: "include"` y el front NUNCA toca el token (no es legible desde JS, por diseño).
 * Los errores llegan con forma estable `{ error: { code, message, request_id } }` (R9.2) y se
 * normalizan a `ApiError`, con `message` ya saneado por el backend (sin stacktrace ni secretos).
 */

import type { ApiErrorBody } from "./types";

/** Base del API. En el navegador debe ser pública (`NEXT_PUBLIC_*`). Default: dev local. */
const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/+$/, "");

const API_V1 = "/api/v1";

/** Error normalizado de la API. Porta el código estable y el `request_id` para soporte. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;

  constructor(
    status: number,
    code: string,
    message: string,
    requestId: string | null,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }

  /** `true` si la sesión es inválida/ausente: el llamador debe redirigir al login. */
  get isUnauthorized(): boolean {
    return this.status === 401;
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  /** Cuerpo JSON; se serializa y se fija el Content-Type. */
  body?: unknown;
  /** Query params; los `undefined`/`null` se omiten. */
  query?: Record<string, string | number | undefined | null>;
  signal?: AbortSignal;
}

function buildUrl(
  path: string,
  query?: RequestOptions["query"],
): string {
  const url = new URL(`${API_BASE_URL}${API_V1}${path}`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url.toString();
}

async function toApiError(response: Response): Promise<ApiError> {
  // Intentamos leer el envelope estable; si el cuerpo no es el esperado, mensaje genérico.
  let code = "HTTP_ERROR";
  let message = `Error ${response.status}.`;
  let requestId: string | null = null;
  try {
    const data = (await response.json()) as Partial<ApiErrorBody>;
    if (data.error) {
      code = data.error.code ?? code;
      message = data.error.message ?? message;
      requestId = data.error.request_id ?? null;
    }
  } catch {
    // Respuesta sin JSON (p.ej. 502 de un proxy): conservamos el mensaje genérico.
  }
  return new ApiError(response.status, code, message, requestId);
}

/**
 * Realiza una petición al API y devuelve el JSON tipado. Lanza `ApiError` en respuestas ≥400.
 * `T = void` para respuestas sin cuerpo (204).
 */
export async function apiFetch<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const { method = "GET", body, query, signal } = options;
  const headers: HeadersInit = { Accept: "application/json" };
  let payload: string | undefined;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  let response: Response;
  try {
    response = await fetch(buildUrl(path, query), {
      method,
      headers,
      body: payload,
      credentials: "include",
      signal,
    });
  } catch {
    // Fallo de red/CORS: error accionable, sin filtrar detalles internos.
    throw new ApiError(0, "NETWORK_ERROR", "No se pudo contactar al servidor.", null);
  }

  if (!response.ok) {
    throw await toApiError(response);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

/** URL absoluta de un endpoint del API (para navegaciones top-level como el login OAuth). */
export function apiUrl(path: string): string {
  return `${API_BASE_URL}${API_V1}${path}`;
}
