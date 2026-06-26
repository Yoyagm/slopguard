"use client";

/**
 * Providers raíz del cliente.
 * Permite que layout.tsx siga siendo un Server Component mientras inyecta
 * el contexto de sesión (y cualquier provider futuro) a todo el árbol.
 */

import type { ReactNode } from "react";
import { SessionProvider } from "@/lib/api/session";

interface ProvidersProps {
  children: ReactNode;
}

export function Providers({ children }: ProvidersProps) {
  return <SessionProvider>{children}</SessionProvider>;
}
