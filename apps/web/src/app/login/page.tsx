"use client";

/**
 * Pantalla de login de SlopGuard.
 *
 * Estructura:
 *  - LoginPage (default export): Server-compatible wrapper, provee <Suspense> para useSearchParams.
 *  - LoginContent: Client component que lee ?error= del query y lanza el flujo OAuth.
 *
 * Accesibilidad:
 *  - Región main con h1 visible.
 *  - Error anunciado con role="alert".
 *  - Botón con GithubIcon + texto + aria-label descriptivo.
 *  - Foco visible heredado del global.
 */

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { loginUrl } from "@/lib/api/endpoints";
import { Wordmark } from "@/components/brand/Wordmark";
import { Button } from "@/components/ui/Button";
import { GithubIcon } from "@/lib/icons";
import { Spinner } from "@/components/ui/Spinner";

/** Mapa de códigos de error OAuth → mensajes en español. */
const ERROR_MESSAGES: Record<string, string> = {
  access_denied: "Acceso denegado. Autoriza la aplicación en GitHub e inténtalo de nuevo.",
  oauth_failed: "Error durante la autenticación con GitHub. Inténtalo de nuevo.",
  session_expired: "Tu sesión expiró. Inicia sesión nuevamente.",
  callback_error: "Error al procesar la respuesta de GitHub. Inténtalo de nuevo.",
};

function getErrorMessage(code: string): string {
  return ERROR_MESSAGES[code] ?? "Error de autenticación. Inténtalo de nuevo.";
}

function LoginFallback() {
  return (
    <main className="min-h-screen flex flex-col items-center justify-center bg-sg-bg px-4">
      <div className="flex flex-col items-center gap-6">
        <Wordmark size="lg" />
        <Spinner className="w-5 h-5" aria-label="Cargando…" />
      </div>
    </main>
  );
}

function LoginContent() {
  const searchParams = useSearchParams();
  const errorCode = searchParams.get("error");
  const errorMessage = errorCode ? getErrorMessage(errorCode) : null;

  function handleLogin() {
    window.location.href = loginUrl();
  }

  return (
    <main className="min-h-screen flex flex-col items-center justify-center bg-sg-bg px-4">
      {/* Skip to main content — accesibilidad teclado */}
      <a
        href="#login-card"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-sg-accent focus:text-sg-accent-contrast focus:rounded"
      >
        Saltar al contenido principal
      </a>

      <div
        id="login-card"
        className="w-full max-w-sm bg-sg-surface border border-sg-border rounded-sg shadow-sg-panel p-8 flex flex-col items-center gap-6"
      >
        {/* Marca */}
        <Wordmark size="lg" />

        {/* Claim */}
        <div className="text-center space-y-2">
          <h1 className="text-lg font-semibold text-sg-text">
            Protege tus dependencias
          </h1>
          <p className="text-sm text-sg-muted leading-relaxed">
            SlopGuard detecta paquetes alucinados y typosquatting en tus
            manifiestos de PyPI y npm antes de que lleguen a producción.
          </p>
        </div>

        {/* Error OAuth (si viene de callback) */}
        {errorMessage && (
          <div
            role="alert"
            className="w-full px-3 py-2.5 rounded bg-sg-block/10 border border-sg-block/30 text-sg-block text-sm"
          >
            {errorMessage}
          </div>
        )}

        {/* Botón OAuth */}
        <Button
          variant="primary"
          size="md"
          className="w-full justify-center"
          aria-label="Continuar con GitHub para iniciar sesión en SlopGuard"
          onClick={handleLogin}
        >
          <GithubIcon className="w-4 h-4" aria-hidden />
          Continuar con GitHub
        </Button>

        {/* Nota de privacidad */}
        <p className="text-xs text-sg-faint text-center leading-relaxed">
          Solo solicitamos permisos de lectura de repositorios.
          No almacenamos tu código.
        </p>
      </div>
    </main>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<LoginFallback />}>
      <LoginContent />
    </Suspense>
  );
}
