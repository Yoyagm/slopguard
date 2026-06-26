"use client";

/**
 * Visor del JSON crudo del motor (schema 1.2) de un escaneo (T34).
 *
 * Carga PEREZOSA: `getScanRaw(id)` solo se dispara la primera vez que el usuario abre el panel,
 * y se cachea en estado para no re-pedirlo al alternar. Botón "Copiar" con `navigator.clipboard`
 * y feedback temporal. Maneja loading (Spinner) y error (mensaje saneado de ApiError).
 *
 * El JSON se muestra tal cual (forma opaca): font-mono, scroll contenido, sin reformatear su
 * semántica más allá de un `JSON.stringify` indentado.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { RawReport } from "@/lib/api/types";
import { getScanRaw } from "@/lib/api/endpoints";
import { ApiError } from "@/lib/api/client";
import { Spinner } from "@/components/ui/Spinner";
import {
  ChevronRightIcon,
  CodeIcon,
  CopyIcon,
  CheckIcon,
  AlertCircleIcon,
} from "@/lib/icons";
import { cn } from "@/lib/utils";

interface RawJsonViewerProps {
  scanId: string;
}

type RawState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; json: string };

export function RawJsonViewer({ scanId }: RawJsonViewerProps) {
  const [open, setOpen] = useState(false);
  const [state, setState] = useState<RawState>({ status: "idle" });
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const loadRaw = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setState({ status: "loading" });
    try {
      const raw: RawReport = await getScanRaw(scanId, controller.signal);
      if (controller.signal.aborted) return;
      setState({ status: "ready", json: JSON.stringify(raw, null, 2) });
    } catch (error: unknown) {
      if (controller.signal.aborted) return;
      const message =
        error instanceof ApiError ? error.message : "No se pudo cargar el JSON crudo.";
      setState({ status: "error", message });
    }
  }, [scanId]);

  const toggle = useCallback(() => {
    setOpen((prev) => {
      const next = !prev;
      // Carga perezosa: solo al abrir por primera vez (o tras un error, para reintentar).
      if (next && (state.status === "idle" || state.status === "error")) {
        void loadRaw();
      }
      return next;
    });
  }, [loadRaw, state.status]);

  const handleCopy = useCallback(async () => {
    if (state.status !== "ready") return;
    try {
      await navigator.clipboard.writeText(state.json);
      setCopied(true);
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      // El portapapeles puede estar bloqueado (permisos/contexto inseguro): no es crítico.
    }
  }, [state]);

  // Limpieza de timers y peticiones en vuelo al desmontar.
  useEffect(() => {
    return () => {
      if (copyTimer.current) clearTimeout(copyTimer.current);
      abortRef.current?.abort();
    };
  }, []);

  const panelId = `raw-json-${scanId}`;

  return (
    <div className="rounded-sg border border-sg-border bg-sg-surface">
      <h2>
        <button
          type="button"
          onClick={toggle}
          aria-expanded={open}
          aria-controls={panelId}
          className={cn(
            "w-full flex items-center gap-2 px-4 py-3 text-left",
            "text-sm font-medium text-sg-muted hover:text-sg-text",
            "transition-colors duration-150 cursor-pointer rounded-sg",
          )}
        >
          <ChevronRightIcon
            className={cn(
              "w-4 h-4 shrink-0 transition-transform duration-200",
              open && "rotate-90",
            )}
          />
          <CodeIcon className="w-4 h-4 shrink-0" />
          JSON crudo del motor
          <span className="font-mono text-xs text-sg-faint">(schema 1.2)</span>
        </button>
      </h2>

      {open && (
        <div id={panelId} className="border-t border-sg-border">
          {state.status === "loading" && (
            <div
              className="flex items-center gap-2 px-4 py-6 text-sm text-sg-muted"
              aria-live="polite"
            >
              <Spinner className="w-4 h-4" aria-label="Cargando JSON crudo…" />
              Cargando JSON crudo…
            </div>
          )}

          {state.status === "error" && (
            <div
              role="alert"
              className="flex items-start gap-2 px-4 py-4 text-sm text-sg-block"
            >
              <AlertCircleIcon className="w-4 h-4 shrink-0 mt-0.5" />
              {state.message}
            </div>
          )}

          {state.status === "ready" && (
            <div className="relative">
              <div className="flex items-center justify-end px-3 pt-3">
                <button
                  type="button"
                  onClick={() => void handleCopy()}
                  aria-label={copied ? "JSON copiado" : "Copiar JSON al portapapeles"}
                  className={cn(
                    "inline-flex items-center gap-1.5 px-2.5 py-1 rounded",
                    "text-xs font-medium border border-sg-border",
                    "text-sg-muted hover:text-sg-text hover:bg-sg-raised",
                    "transition-colors duration-150 cursor-pointer",
                  )}
                >
                  {copied ? (
                    <CheckIcon className="w-3.5 h-3.5 text-sg-allow" />
                  ) : (
                    <CopyIcon className="w-3.5 h-3.5" />
                  )}
                  {copied ? "Copiado" : "Copiar"}
                </button>
              </div>
              <pre
                className={cn(
                  "px-4 pb-4 pt-2 overflow-auto max-h-96",
                  "text-xs font-mono text-sg-text leading-relaxed",
                )}
                tabIndex={0}
                aria-label="JSON crudo del escaneo"
              >
                <code>{state.json}</code>
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
