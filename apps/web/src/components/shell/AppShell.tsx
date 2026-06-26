/**
 * Shell de la aplicación autenticada.
 *
 * Estructura:
 *   <header> → TopBar (sticky, cliente)
 *   <main>   → {children} centrado con max-w-6xl y padding
 *
 * AppShell en sí es un Server Component: no tiene estado ni eventos.
 * TopBar importa como Client Component de forma transparente.
 */

import type { ReactNode } from "react";
import { TopBar } from "./TopBar";

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="min-h-screen flex flex-col bg-sg-bg">
      <TopBar />
      <main
        id="main-content"
        className="flex-1 mx-auto w-full max-w-6xl px-4 sm:px-6 py-8"
      >
        {children}
      </main>
    </div>
  );
}
