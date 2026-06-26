"use client";

/**
 * Barra superior de navegación de SlopGuard.
 *
 * Contiene:
 *  - Wordmark (izquierda)
 *  - Nav principal: Escaneo + Historial (centro/izquierda, activo con usePathname)
 *  - Avatar + menú de sesión (derecha)
 *  - En móvil: hamburger que despliega nav apilado
 *
 * Accesibilidad:
 *  - <header> semántico con <nav> y <ul>/<li>.
 *  - aria-current="page" en el enlace activo.
 *  - Botones solo-icono con aria-label.
 *  - Foco visible heredado del global.
 */

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useCallback } from "react";
import { Wordmark } from "@/components/brand/Wordmark";
import { useSession } from "@/lib/api/session";
import { ScanIcon, HistoryIcon, LogOutIcon, MenuIcon, XIcon } from "@/lib/icons";
import { cn } from "@/lib/utils";

interface NavItem {
  href: string;
  label: string;
  Icon: (props: { className?: string }) => React.ReactElement;
}

const NAV_ITEMS: NavItem[] = [
  { href: "/scan", label: "Escaneo", Icon: ScanIcon },
  { href: "/history", label: "Historial", Icon: HistoryIcon },
];

function UserAvatar({ login, avatarUrl }: { login: string; avatarUrl: string | null }) {
  if (avatarUrl) {
    return (
      // eslint-disable-next-line @next/next/no-img-element
      <img
        src={avatarUrl}
        alt={login}
        width={28}
        height={28}
        className="w-7 h-7 rounded-full ring-1 ring-sg-border object-cover"
      />
    );
  }

  // Fallback: inicial del login en un círculo
  const initial = login[0]?.toUpperCase() ?? "U";
  return (
    <span
      aria-label={login}
      className="w-7 h-7 rounded-full bg-sg-accent/20 text-sg-accent text-xs font-bold flex items-center justify-center select-none ring-1 ring-sg-border"
    >
      {initial}
    </span>
  );
}

function NavLinks({
  pathname,
  onNavigate,
  className,
}: {
  pathname: string;
  onNavigate?: () => void;
  className?: string;
}) {
  return (
    <ul className={cn("flex", className)} role="list">
      {NAV_ITEMS.map(({ href, label, Icon }) => {
        const isActive = pathname.startsWith(href);
        return (
          <li key={href}>
            <Link
              href={href}
              onClick={onNavigate}
              aria-current={isActive ? "page" : undefined}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded text-sm font-medium",
                "transition-colors duration-150",
                "cursor-pointer",
                isActive
                  ? "text-sg-text bg-sg-raised"
                  : "text-sg-muted hover:text-sg-text hover:bg-sg-raised",
              )}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {label}
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

export function TopBar() {
  const { user, signOut } = useSession();
  const pathname = usePathname();
  const [menuOpen, setMenuOpen] = useState(false);

  const closeMenu = useCallback(() => setMenuOpen(false), []);
  const toggleMenu = useCallback(() => setMenuOpen((v) => !v), []);

  const handleSignOut = useCallback(async () => {
    await signOut();
  }, [signOut]);

  return (
    <header className="sticky top-0 z-40 w-full border-b border-sg-border bg-sg-bg/90 backdrop-blur-sm">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="flex h-14 items-center justify-between gap-4">
          {/* Wordmark */}
          <Link
            href="/dashboard"
            className="flex-shrink-0 rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sg-accent"
            aria-label="SlopGuard — inicio"
          >
            <Wordmark size="sm" />
          </Link>

          {/* Nav desktop */}
          <nav aria-label="Navegación principal" className="hidden sm:flex">
            <NavLinks pathname={pathname} />
          </nav>

          {/* Zona derecha: usuario + logout + hamburguesa */}
          <div className="flex items-center gap-2">
            {/* Usuario (desktop) */}
            {user && (
              <div className="hidden sm:flex items-center gap-2">
                <UserAvatar login={user.login} avatarUrl={user.avatar_url} />
                <span className="text-sm text-sg-muted font-mono hidden md:inline">
                  {user.login}
                </span>
              </div>
            )}

            {/* Botón cerrar sesión (desktop) */}
            <button
              type="button"
              onClick={() => void handleSignOut()}
              aria-label="Cerrar sesión"
              className={cn(
                "hidden sm:flex items-center gap-1.5 px-2.5 py-1.5",
                "rounded text-sm text-sg-muted hover:text-sg-text hover:bg-sg-raised",
                "transition-colors duration-150 cursor-pointer",
              )}
            >
              <LogOutIcon className="w-4 h-4" />
              <span className="hidden md:inline">Salir</span>
            </button>

            {/* Hamburguesa (móvil) */}
            <button
              type="button"
              onClick={toggleMenu}
              aria-label={menuOpen ? "Cerrar menú" : "Abrir menú"}
              aria-expanded={menuOpen}
              aria-controls="mobile-nav"
              className={cn(
                "sm:hidden flex items-center justify-center w-9 h-9 rounded",
                "text-sg-muted hover:text-sg-text hover:bg-sg-raised",
                "transition-colors duration-150 cursor-pointer",
              )}
            >
              {menuOpen ? (
                <XIcon className="w-5 h-5" />
              ) : (
                <MenuIcon className="w-5 h-5" />
              )}
            </button>
          </div>
        </div>

        {/* Menú móvil desplegable */}
        {menuOpen && (
          <div
            id="mobile-nav"
            className="sm:hidden border-t border-sg-border py-3"
          >
            <nav aria-label="Navegación móvil">
              <NavLinks
                pathname={pathname}
                onNavigate={closeMenu}
                className="flex-col gap-1"
              />
            </nav>

            {/* Usuario + logout en móvil */}
            {user && (
              <div className="mt-3 pt-3 border-t border-sg-border flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <UserAvatar login={user.login} avatarUrl={user.avatar_url} />
                  <span className="text-sm text-sg-muted font-mono">{user.login}</span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    closeMenu();
                    void handleSignOut();
                  }}
                  aria-label="Cerrar sesión"
                  className={cn(
                    "flex items-center gap-1.5 px-2.5 py-1.5",
                    "rounded text-sm text-sg-muted hover:text-sg-text hover:bg-sg-raised",
                    "transition-colors duration-150 cursor-pointer",
                  )}
                >
                  <LogOutIcon className="w-4 h-4" />
                  Salir
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  );
}
