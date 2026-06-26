/**
 * Página de historial — placeholder Ola 6a.
 * La funcionalidad completa llega en Ola 6b.
 */

import Link from "next/link";
import { HistoryIcon } from "@/lib/icons";
import { Card } from "@/components/ui/Card";

export default function HistoryPage() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] py-16 px-4">
      <Card className="w-full max-w-md p-10 flex flex-col items-center gap-6 text-center">
        {/* Icono de empty state */}
        <div className="w-14 h-14 rounded-full bg-sg-accent/10 text-sg-accent flex items-center justify-center">
          <HistoryIcon className="w-7 h-7" />
        </div>

        {/* Texto */}
        <div className="space-y-2">
          <h1 className="text-xl font-semibold text-sg-text">En construcción</h1>
          <p className="text-sm text-sg-muted leading-relaxed">
            El historial paginado de escaneos estará disponible en la{" "}
            <strong className="text-sg-text font-medium">Ola 6b</strong>.
            Podrás filtrar por ecosistema, ver el resumen de veredictos y
            descargar el reporte JSON completo de cada escaneo.
          </p>
        </div>

        {/* CTA alternativa */}
        <Link
          href="/dashboard"
          className="text-sm text-sg-accent hover:text-sg-accent-strong underline underline-offset-2 transition-colors duration-150 cursor-pointer"
        >
          Volver al dashboard
        </Link>
      </Card>
    </div>
  );
}
