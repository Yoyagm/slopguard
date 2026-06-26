/**
 * Lista de señales de una dependencia, agrupadas por capa de detección (T34).
 *
 * Diseño centrado en la EXPLICACIÓN: el `detail` humano de cada señal es el protagonista; el
 * `code` técnico, el peso y los marcadores (soft / canal LLM) son metadatos secundarios. Las
 * señales se agrupan por capa para dar contexto del "por qué" del veredicto.
 *
 * Responsive: la fila de metadatos colapsa bajo el detalle en pantallas estrechas (sin scroll
 * horizontal). Componente presentacional puro, sin estado.
 */

import type { Signal } from "@/lib/api/types";
import { cn } from "@/lib/utils";
import { layerLabel } from "./report-format";
import { LayersIcon } from "@/lib/icons";

interface SignalListProps {
  signals: Signal[];
}

/** Agrupa señales por capa preservando el orden de aparición de cada capa. */
function groupByLayer(signals: Signal[]): { layer: number; items: Signal[] }[] {
  const order: number[] = [];
  const byLayer = new Map<number, Signal[]>();
  for (const signal of signals) {
    const bucket = byLayer.get(signal.layer);
    if (bucket) {
      bucket.push(signal);
    } else {
      byLayer.set(signal.layer, [signal]);
      order.push(signal.layer);
    }
  }
  return order.map((layer) => ({ layer, items: byLayer.get(layer) ?? [] }));
}

function SignalItem({ signal }: { signal: Signal }) {
  return (
    <li className="rounded-sg border border-sg-border bg-sg-bg/40 px-3 py-2.5">
      {/* El detalle humano es el protagonista. */}
      <p className="text-sm text-sg-text leading-relaxed">{signal.detail}</p>

      {/* Metadatos secundarios: colapsan en columna en móvil. */}
      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-sg-faint">
        <code className="font-mono text-sg-muted">{signal.code}</code>
        <span aria-label={`Peso ${signal.weight}`}>peso {signal.weight}</span>
        {signal.is_soft && (
          <span className="text-sg-faint" title="Señal blanda: contribuye sin ser determinante">
            soft
          </span>
        )}
        {signal.is_llm_channel && (
          <span className="text-sg-faint" title="Señal del canal LLM (no bloqueante)">
            canal LLM
          </span>
        )}
        {signal.suspected_target && (
          <span className="text-sg-muted">
            ¿typo de{" "}
            <span className="font-mono text-sg-warn">{signal.suspected_target}</span>?
          </span>
        )}
      </div>
    </li>
  );
}

export function SignalList({ signals }: SignalListProps) {
  if (signals.length === 0) {
    return (
      <p className="text-sm text-sg-muted">
        Sin señales emitidas por las capas de detección.
      </p>
    );
  }

  const groups = groupByLayer(signals);

  return (
    <div className="space-y-4">
      {groups.map(({ layer, items }) => (
        <section key={layer} aria-label={layerLabel(layer)}>
          <h3
            className={cn(
              "flex items-center gap-2 mb-2",
              "text-xs font-semibold uppercase tracking-wide text-sg-faint",
            )}
          >
            <LayersIcon className="w-3.5 h-3.5 shrink-0" />
            {layerLabel(layer)}
          </h3>
          <ul className="space-y-2" role="list">
            {items.map((signal, index) => (
              <SignalItem key={`${signal.code}-${index}`} signal={signal} />
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
