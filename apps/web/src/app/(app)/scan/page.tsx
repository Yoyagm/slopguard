"use client";

/**
 * Dashboard de escaneo on-demand (T33).
 *
 * Fuentes: Inline (textarea + upload de archivo) | Repo (select + ruta).
 * Selector de ecosistema opcional.
 * Estados: idle → loading → error | success (ScanReport inline).
 */

import { useState, useRef, useCallback, useEffect, type KeyboardEvent } from "react";
import type { Scan, Repo, Ecosystem } from "@/lib/api/types";
import { createScan, listRepos } from "@/lib/api/endpoints";
import { ApiError } from "@/lib/api/client";
import { ScanReport } from "@/components/report/ScanReport";
import { Button, buttonClasses } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { Card } from "@/components/ui/Card";
import {
  FileTextIcon,
  GitBranchIcon,
  UploadIcon,
  ScanIcon,
  AlertCircleIcon,
  XIcon,
} from "@/lib/icons";
import { cn } from "@/lib/utils";

type SourceTab = "inline" | "repo";

interface TabDef {
  id: SourceTab;
  label: string;
  icon: (p: { className?: string }) => React.ReactElement;
}

/** Tabs de fuente del manifiesto, en orden de navegación con flechas. */
const SOURCE_TABS: TabDef[] = [
  { id: "inline", label: "Inline", icon: FileTextIcon },
  { id: "repo", label: "Repositorio", icon: GitBranchIcon },
];

/** id estable del botón de tab y de su panel, para enlazar aria-controls/aria-labelledby. */
const tabButtonId = (tab: SourceTab) => `scan-tab-${tab}`;
const tabPanelId = (tab: SourceTab) => `scan-panel-${tab}`;

type PageState =
  | { status: "idle" }
  | { status: "scanning" }
  | { status: "error"; message: string }
  | { status: "success"; scan: Scan };

const ECOSYSTEM_OPTIONS: { value: "" | Ecosystem; label: string }[] = [
  { value: "", label: "Auto-detectar" },
  { value: "pypi", label: "PyPI (Python)" },
  { value: "npm", label: "npm (Node.js)" },
];

// ─── Subcomponentes ─────────────────────────────────────────────────────────

/**
 * Tablist accesible (WAI-ARIA Tabs): roving tabindex + navegación con flechas/Home/End.
 * Solo la tab activa está en el orden de tabulación; las flechas mueven el foco y seleccionan.
 */
function SourceTabs({
  active,
  onSelect,
}: {
  active: SourceTab;
  onSelect: (tab: SourceTab) => void;
}) {
  const tabRefs = useRef<Record<SourceTab, HTMLButtonElement | null>>({
    inline: null,
    repo: null,
  });

  const handleKeyDown = useCallback(
    (event: KeyboardEvent<HTMLButtonElement>) => {
      const currentIndex = SOURCE_TABS.findIndex((t) => t.id === active);
      let nextIndex: number | null = null;

      switch (event.key) {
        case "ArrowRight":
        case "ArrowDown":
          nextIndex = (currentIndex + 1) % SOURCE_TABS.length;
          break;
        case "ArrowLeft":
        case "ArrowUp":
          nextIndex = (currentIndex - 1 + SOURCE_TABS.length) % SOURCE_TABS.length;
          break;
        case "Home":
          nextIndex = 0;
          break;
        case "End":
          nextIndex = SOURCE_TABS.length - 1;
          break;
        default:
          return;
      }

      event.preventDefault();
      const nextTab = SOURCE_TABS[nextIndex].id;
      onSelect(nextTab);
      tabRefs.current[nextTab]?.focus();
    },
    [active, onSelect],
  );

  return (
    <div role="tablist" aria-label="Fuente del manifiesto" className="flex gap-1 -mx-1">
      {SOURCE_TABS.map(({ id, label, icon: Icon }) => {
        const isActive = id === active;
        return (
          <button
            key={id}
            ref={(node) => {
              tabRefs.current[id] = node;
            }}
            type="button"
            role="tab"
            id={tabButtonId(id)}
            aria-selected={isActive}
            aria-controls={tabPanelId(id)}
            tabIndex={isActive ? 0 : -1}
            onClick={() => onSelect(id)}
            onKeyDown={handleKeyDown}
            className={cn(
              "flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-t-sg border-b-2",
              "transition-colors duration-150 cursor-pointer",
              isActive
                ? "text-sg-accent border-sg-accent bg-sg-raised"
                : "text-sg-muted border-transparent hover:text-sg-text hover:bg-sg-raised",
            )}
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </button>
        );
      })}
    </div>
  );
}

// ─── Panel Inline ────────────────────────────────────────────────────────────

interface InlinePanelProps {
  content: string;
  setContent: (v: string) => void;
  filename: string;
  setFilename: (v: string) => void;
}

function InlinePanel({ content, setContent, filename, setFilename }: InlinePanelProps) {
  const handleFileChange = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        setContent(text);
        setFilename(file.name);
      } catch {
        // El usuario puede pegar manualmente si falla la lectura
      }
      // Reset input para permitir re-subir el mismo archivo
      e.target.value = "";
    },
    [setContent, setFilename],
  );

  const clearFile = useCallback(() => {
    setFilename("");
    setContent("");
  }, [setFilename, setContent]);

  return (
    <div className="space-y-3">
      {/* Upload de archivo: un <label> nativo que envuelve el input ⇒ al clicarlo, el navegador
          abre el diálogo SIN un .click() programático. Esto funciona en TODOS los navegadores
          (incl. Safari, que bloquea el .click() programático sobre inputs ocultos). El input
          queda sr-only pero accesible por teclado (recibe foco vía el label → focus-within). */}
      <div className="flex items-center gap-3 flex-wrap">
        <label
          className={cn(
            buttonClasses({ variant: "secondary", size: "sm", className: "gap-2" }),
            "focus-within:outline-2 focus-within:outline-sg-accent",
          )}
        >
          <UploadIcon className="w-4 h-4" />
          Cargar archivo
          <input
            type="file"
            accept=".txt,.toml,.json,.lock"
            className="sr-only"
            onChange={(e) => void handleFileChange(e)}
          />
        </label>

        {filename && (
          <div className="flex items-center gap-2 text-xs text-sg-muted">
            <span className="font-mono">{filename}</span>
            <button
              type="button"
              onClick={clearFile}
              aria-label={`Eliminar archivo ${filename}`}
              className="text-sg-faint hover:text-sg-text transition-colors cursor-pointer"
            >
              <XIcon className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Textarea */}
      <div>
        <label
          htmlFor="manifest-content"
          className="block text-sm font-medium text-sg-muted mb-1.5"
        >
          Contenido del manifiesto
          <span className="text-sg-faint ml-1 font-normal">
            (requirements.txt, package.json, pyproject.toml…)
          </span>
        </label>
        <textarea
          id="manifest-content"
          name="manifest-content"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={10}
          placeholder={"# Pega aquí tu manifiesto de dependencias\nrequests==2.31.0\nnumpy>=1.24.0\n…"}
          className={cn(
            "w-full rounded-sg bg-sg-bg border border-sg-border",
            "px-3 py-2.5 text-sm font-mono text-sg-text",
            "placeholder:text-sg-faint resize-y",
            "focus:outline-none focus:border-sg-accent focus:ring-1 focus:ring-sg-accent",
            "transition-colors duration-150",
          )}
          aria-required="true"
          aria-describedby="manifest-hint"
        />
        <p id="manifest-hint" className="mt-1 text-xs text-sg-faint">
          Pega el contenido o carga un archivo. Formatos admitidos: <span className="font-mono">.txt .toml .json .lock</span>
        </p>
      </div>
    </div>
  );
}

// ─── Panel Repo ──────────────────────────────────────────────────────────────

interface RepoPanelProps {
  repoId: string;
  setRepoId: (v: string) => void;
  path: string;
  setPath: (v: string) => void;
}

function RepoPanel({ repoId, setRepoId, path, setPath }: RepoPanelProps) {
  const [repos, setRepos] = useState<Repo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRepos = useCallback(async (signal: AbortSignal) => {
    setLoading(true);
    setError(null);
    try {
      const data = await listRepos(undefined, signal);
      setRepos(data);
    } catch (err: unknown) {
      if (signal.aborted) return;
      const msg =
        err instanceof ApiError ? err.message : "No se pudieron cargar los repositorios.";
      setError(msg);
    } finally {
      if (!signal.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void fetchRepos(controller.signal);
    return () => controller.abort();
  }, [fetchRepos]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-4 text-sm text-sg-muted">
        <Spinner className="w-4 h-4" aria-label="Cargando repositorios…" />
        Cargando repositorios…
      </div>
    );
  }

  if (error) {
    return (
      <div role="alert" className="flex items-center gap-2 text-sm text-sg-block py-4">
        <AlertCircleIcon className="w-4 h-4 shrink-0" />
        {error}
      </div>
    );
  }

  if (repos.length === 0) {
    return (
      <div className="py-6 text-center space-y-2">
        <p className="text-sm text-sg-muted">No hay repositorios disponibles.</p>
        <p className="text-xs text-sg-faint">
          Instala la GitHub App en tu cuenta u organización para acceder a tus repos. Mientras
          tanto, puedes analizar un manifiesto pegándolo en la pestaña{" "}
          <span className="text-sg-text font-medium">Inline</span>.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Select de repo */}
      <div>
        <label
          htmlFor="repo-select"
          className="block text-sm font-medium text-sg-muted mb-1.5"
        >
          Repositorio
        </label>
        <select
          id="repo-select"
          value={repoId}
          onChange={(e) => setRepoId(e.target.value)}
          className={cn(
            "w-full rounded-sg bg-sg-bg border border-sg-border",
            "px-3 py-2.5 text-sm text-sg-text",
            "focus:outline-none focus:border-sg-accent focus:ring-1 focus:ring-sg-accent",
            "transition-colors duration-150 cursor-pointer",
          )}
          aria-required="true"
        >
          <option value="">Selecciona un repositorio…</option>
          {repos.map((repo) => (
            <option key={repo.id} value={repo.id}>
              {repo.full_name}
              {repo.private ? " (privado)" : ""}
            </option>
          ))}
        </select>
      </div>

      {/* Ruta del manifiesto */}
      <div>
        <label
          htmlFor="manifest-path"
          className="block text-sm font-medium text-sg-muted mb-1.5"
        >
          Ruta del manifiesto en el repo
        </label>
        <input
          id="manifest-path"
          type="text"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder="requirements.txt"
          className={cn(
            "w-full rounded-sg bg-sg-bg border border-sg-border",
            "px-3 py-2.5 text-sm font-mono text-sg-text",
            "placeholder:text-sg-faint",
            "focus:outline-none focus:border-sg-accent focus:ring-1 focus:ring-sg-accent",
            "transition-colors duration-150",
          )}
          aria-required="true"
          aria-describedby="path-hint"
        />
        <p id="path-hint" className="mt-1 text-xs text-sg-faint">
          Ruta relativa desde la raíz del repositorio, p.ej.{" "}
          <span className="font-mono">requirements.txt</span> o{" "}
          <span className="font-mono">app/package.json</span>
        </p>
      </div>
    </div>
  );
}

// ─── Página principal ────────────────────────────────────────────────────────

export default function ScanPage() {
  const [activeTab, setActiveTab] = useState<SourceTab>("inline");

  // Inline state
  const [content, setContent] = useState("");
  const [filename, setFilename] = useState("");

  // Repo state
  const [repoId, setRepoId] = useState("");
  const [manifestPath, setManifestPath] = useState("requirements.txt");

  // Ecosistema
  const [ecosystem, setEcosystem] = useState<"" | Ecosystem>("");

  // Estado de la petición
  const [pageState, setPageState] = useState<PageState>({ status: "idle" });

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setPageState({ status: "scanning" });

      try {
        let scan: Scan;

        if (activeTab === "inline") {
          if (!content.trim()) {
            setPageState({
              status: "error",
              message: "El manifiesto no puede estar vacío.",
            });
            return;
          }
          scan = await createScan({
            source: "inline",
            content: content.trim(),
            filename: filename || undefined,
            ecosystem: ecosystem || null,
          });
        } else {
          if (!repoId) {
            setPageState({
              status: "error",
              message: "Selecciona un repositorio.",
            });
            return;
          }
          if (!manifestPath.trim()) {
            setPageState({
              status: "error",
              message: "Introduce la ruta del manifiesto.",
            });
            return;
          }
          scan = await createScan({
            source: "repo",
            repo_id: repoId,
            path: manifestPath.trim(),
            ecosystem: ecosystem || null,
          });
        }

        setPageState({ status: "success", scan });
      } catch (err: unknown) {
        const message =
          err instanceof ApiError
            ? err.message
            : "Error inesperado al lanzar el escaneo.";
        setPageState({ status: "error", message });
      }
    },
    [activeTab, content, filename, repoId, manifestPath, ecosystem],
  );

  const isScanning = pageState.status === "scanning";

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      {/* Título */}
      <div>
        <h1 className="text-2xl font-semibold text-sg-text">Escaneo on-demand</h1>
        <p className="text-sm text-sg-muted mt-1">
          Analiza un manifiesto de dependencias y obtén un reporte de veredictos en segundos.
        </p>
      </div>

      {/* Formulario */}
      <Card>
        <form onSubmit={(e) => void handleSubmit(e)} noValidate>
          <Card.Header>
            {/* Tabs fuente */}
            <SourceTabs active={activeTab} onSelect={setActiveTab} />
          </Card.Header>

          <Card.Body className="space-y-5">
            {/* Panel de fuente: enlazado a su tab con aria-labelledby (WAI-ARIA Tabs) */}
            <div
              role="tabpanel"
              id={tabPanelId(activeTab)}
              aria-labelledby={tabButtonId(activeTab)}
              tabIndex={0}
            >
              {activeTab === "inline" ? (
                <InlinePanel
                  content={content}
                  setContent={setContent}
                  filename={filename}
                  setFilename={setFilename}
                />
              ) : (
                <RepoPanel
                  repoId={repoId}
                  setRepoId={setRepoId}
                  path={manifestPath}
                  setPath={setManifestPath}
                />
              )}
            </div>

            {/* Ecosistema */}
            <div>
              <label
                htmlFor="ecosystem-select"
                className="block text-sm font-medium text-sg-muted mb-1.5"
              >
                Ecosistema{" "}
                <span className="text-sg-faint font-normal">(opcional)</span>
              </label>
              <select
                id="ecosystem-select"
                value={ecosystem}
                onChange={(e) => setEcosystem(e.target.value as "" | Ecosystem)}
                className={cn(
                  "w-full sm:w-auto rounded-sg bg-sg-bg border border-sg-border",
                  "px-3 py-2 text-sm text-sg-text",
                  "focus:outline-none focus:border-sg-accent focus:ring-1 focus:ring-sg-accent",
                  "transition-colors duration-150 cursor-pointer",
                )}
              >
                {ECOSYSTEM_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Botón escanear */}
            <Button
              type="submit"
              variant="primary"
              loading={isScanning}
              disabled={isScanning}
              className="w-full sm:w-auto gap-2"
              aria-label={isScanning ? "Escaneando dependencias…" : "Iniciar escaneo"}
            >
              {!isScanning && <ScanIcon className="w-4 h-4 shrink-0" />}
              {isScanning ? "Escaneando…" : "Escanear"}
            </Button>
          </Card.Body>
        </form>
      </Card>

      {/*
        Región de estado SOLO con mensaje conciso (aria-live="polite"): anuncia el cambio
        async sin volcar el reporte entero al lector de pantalla. El reporte va aparte.
      */}
      <div aria-live="polite" className="sr-only">
        {pageState.status === "scanning" && "Escaneando dependencias…"}
        {pageState.status === "error" && `Error en el escaneo: ${pageState.message}`}
        {pageState.status === "success" &&
          `Escaneo completado: ${pageState.scan.summary.total} ${
            pageState.scan.summary.total === 1 ? "dependencia analizada" : "dependencias analizadas"
          }.`}
      </div>

      {/* Estado: escaneando (feedback visual) */}
      {pageState.status === "scanning" && (
        <div className="flex items-center justify-center gap-3 py-12 text-sg-muted text-sm">
          <Spinner className="w-5 h-5" aria-label="Escaneando dependencias…" />
          <span>Analizando dependencias, puede tomar unos segundos…</span>
        </div>
      )}

      {/* Estado: error */}
      {pageState.status === "error" && (
        <div
          role="alert"
          className="flex items-start gap-3 p-4 rounded-sg bg-sg-block/10
                     border border-sg-block/30 text-sm text-sg-block"
        >
          <AlertCircleIcon className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <span className="font-medium">Error en el escaneo: </span>
            {pageState.message}
          </div>
        </div>
      )}

      {/* Estado: éxito → reporte inline */}
      {pageState.status === "success" && (
        <section aria-labelledby="scan-result-heading">
          <div className="flex items-center justify-between mb-4">
            <h2 id="scan-result-heading" className="text-lg font-semibold text-sg-text">
              Resultado del escaneo
            </h2>
            <button
              type="button"
              onClick={() => setPageState({ status: "idle" })}
              className="text-xs text-sg-muted hover:text-sg-text underline underline-offset-2
                         transition-colors cursor-pointer"
            >
              Nuevo escaneo
            </button>
          </div>
          <ScanReport scan={pageState.scan} />
        </section>
      )}
    </div>
  );
}
