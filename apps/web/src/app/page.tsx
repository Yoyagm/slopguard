"use client";

/**
 * Página raíz ("/").
 * Redirige según el estado de sesión:
 *  - authenticated   → /dashboard
 *  - unauthenticated → /login
 *  - loading         → splash de marca centrado
 */

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useSession } from "@/lib/api/session";
import { Wordmark } from "@/components/brand/Wordmark";
import { Spinner } from "@/components/ui/Spinner";

export default function RootPage() {
  const { status } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (status === "authenticated") router.replace("/dashboard");
    if (status === "unauthenticated") router.replace("/login");
  }, [status, router]);

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-sg-bg gap-6">
      <Wordmark size="lg" />
      <Spinner className="w-6 h-6" aria-label="Verificando sesión…" />
    </div>
  );
}
