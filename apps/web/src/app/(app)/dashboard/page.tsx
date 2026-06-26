/**
 * Dashboard — overview de la aplicación.
 *
 * Server Component: no necesita hooks. El contexto de usuario viene del
 * layout protegido via AppShell → TopBar → useSession.
 * Para mostrar el saludo con el nombre de usuario usamos un client component
 * pequeño encapsulado aquí mismo.
 */

"use client";

import Link from "next/link";
import { useSession } from "@/lib/api/session";
import { Card } from "@/components/ui/Card";
import { ScanIcon, HistoryIcon, ShieldIcon } from "@/lib/icons";

function WelcomeHeading() {
  const { user } = useSession();
  const name = user?.login ?? "usuario";

  return (
    <div>
      <h1 className="text-2xl font-semibold text-sg-text">
        Hola,{" "}
        <span className="font-mono text-sg-accent">{name}</span>
      </h1>
      <p className="mt-1 text-sm text-sg-muted">
        ¿Qué quieres hacer hoy?
      </p>
    </div>
  );
}

interface ActionCardProps {
  href: string;
  icon: React.ReactElement;
  title: string;
  description: string;
}

function ActionCard({ href, icon, title, description }: ActionCardProps) {
  return (
    <Link
      href={href}
      className="group block rounded-sg focus-visible:outline-2 focus-visible:outline-sg-accent cursor-pointer"
    >
      <Card className="p-6 flex flex-col gap-4 transition-colors duration-200 group-hover:border-sg-border-strong group-hover:bg-sg-raised h-full">
        <div className="w-10 h-10 rounded-sg bg-sg-accent/10 text-sg-accent flex items-center justify-center">
          {icon}
        </div>
        <div className="space-y-1">
          <h2 className="font-semibold text-sg-text group-hover:text-sg-accent transition-colors duration-150">
            {title}
          </h2>
          <p className="text-sm text-sg-muted leading-relaxed">{description}</p>
        </div>
      </Card>
    </Link>
  );
}

export default function DashboardPage() {
  return (
    <div className="space-y-8">
      {/* Saludo */}
      <WelcomeHeading />

      {/* Acciones principales */}
      <section aria-labelledby="actions-heading">
        <h2
          id="actions-heading"
          className="text-xs font-semibold text-sg-faint uppercase tracking-widest mb-4"
        >
          Acciones rápidas
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <ActionCard
            href="/scan"
            icon={<ScanIcon className="w-5 h-5" />}
            title="Nuevo escaneo"
            description="Analiza un requirements.txt o package.json y detecta paquetes sospechosos en segundos."
          />
          <ActionCard
            href="/history"
            icon={<HistoryIcon className="w-5 h-5" />}
            title="Historial"
            description="Revisa todos tus escaneos anteriores, filtra por ecosistema y consulta los reportes completos."
          />
        </div>
      </section>

      {/* ¿Qué es SlopGuard? */}
      <section
        aria-labelledby="about-heading"
        className="border border-sg-border rounded-sg p-6 bg-sg-surface"
      >
        <div className="flex items-start gap-4">
          <div className="w-9 h-9 rounded-sg bg-sg-accent/10 text-sg-accent flex items-center justify-center shrink-0">
            <ShieldIcon className="w-5 h-5" />
          </div>
          <div className="space-y-2">
            <h2
              id="about-heading"
              className="font-semibold text-sg-text"
            >
              ¿Qué hace SlopGuard?
            </h2>
            <p className="text-sm text-sg-muted leading-relaxed">
              Los LLMs de código alucinan nombres de paquetes que no existen —{" "}
              <strong className="text-sg-text font-medium">slopsquatting</strong>. Actores
              maliciosos registran esos nombres para comprometer cadenas de suministro.
              SlopGuard analiza tus manifiestos de dependencias en{" "}
              <span className="font-mono text-sg-accent">PyPI</span> y{" "}
              <span className="font-mono text-sg-accent">npm</span> y asigna un veredicto
              a cada paquete:{" "}
              <span className="text-sg-allow font-medium">allow</span>,{" "}
              <span className="text-sg-warn font-medium">warn</span>,{" "}
              <span className="text-sg-block font-medium">block</span> o{" "}
              <span className="text-sg-unverifiable font-medium">no verificable</span>.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
