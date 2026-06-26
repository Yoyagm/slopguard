"use client";

/**
 * Estado de sesión del cliente (Ola 6a/T32). La cookie de sesión es httpOnly y cross-origin, así
 * que el navegador NO puede leerla ni un middleware del edge inspeccionarla: la fuente de verdad
 * es `GET /me`. El provider la resuelve una vez al montar y la expone a toda la app.
 *
 * Patrón de protección de rutas: las páginas privadas usan `useRequireSession()`, que redirige al
 * login cuando el estado resuelve a `unauthenticated`.
 */

import { useRouter } from "next/navigation";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { ApiError } from "./client";
import { getMe, logout } from "./endpoints";
import type { Me } from "./types";

type SessionStatus = "loading" | "authenticated" | "unauthenticated";

interface SessionValue {
  status: SessionStatus;
  user: Me | null;
  /** Re-consulta `/me` (p.ej. tras volver del callback OAuth). */
  refresh: () => Promise<void>;
  /** Cierra sesión y deja el estado en `unauthenticated`. */
  signOut: () => Promise<void>;
}

const SessionContext = createContext<SessionValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<SessionStatus>("loading");
  const [user, setUser] = useState<Me | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const refresh = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const me = await getMe(controller.signal);
      setUser(me);
      setStatus("authenticated");
    } catch (error) {
      if (controller.signal.aborted) return;
      // 401 ⇒ sin sesión; cualquier otro error también deja al usuario fuera (fail-safe de UI).
      if (error instanceof ApiError && !error.isUnauthorized) {
        // Error de red/servidor: lo tratamos como no autenticado para no bloquear la UI,
        // el usuario podrá reintentar el login.
      }
      setUser(null);
      setStatus("unauthenticated");
    }
  }, []);

  const signOut = useCallback(async () => {
    try {
      await logout();
    } catch {
      // Aunque el logout del servidor falle, limpiamos el estado local del cliente.
    }
    setUser(null);
    setStatus("unauthenticated");
  }, []);

  useEffect(() => {
    // La sesión se resuelve una vez al montar; `refresh` es estable (useCallback).
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
    return () => abortRef.current?.abort();
  }, [refresh]);

  return (
    <SessionContext.Provider value={{ status, user, refresh, signOut }}>
      {children}
    </SessionContext.Provider>
  );
}

/** Acceso al estado de sesión. Debe usarse dentro de `<SessionProvider>`. */
export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (value === null) {
    throw new Error("useSession debe usarse dentro de <SessionProvider>.");
  }
  return value;
}

/**
 * Exige sesión activa en una página privada: redirige a `/login` cuando resuelve a no autenticado.
 * Devuelve el estado para que la página muestre el esqueleto mientras `status === "loading"`.
 */
export function useRequireSession(): SessionValue {
  const session = useSession();
  const router = useRouter();
  useEffect(() => {
    if (session.status === "unauthenticated") {
      router.replace("/login");
    }
  }, [session.status, router]);
  return session;
}
