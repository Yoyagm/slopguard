# SlopGuard — Web Frontend

Frontend del SaaS de SlopGuard. Detecta *slopsquatting* (paquetes alucinados/typosquatting) en manifiestos de dependencias de **PyPI** y **npm** y presenta veredictos por paquete: `allow`, `warn`, `block` o `no verificable`.

## Stack

- **Next.js 16** (App Router) + **React 19** + **TypeScript strict**
- **Tailwind CSS v4** con design system `sg-*` definido en `globals.css`
- Autenticación via OAuth GitHub — sesión por cookie httpOnly (sin tokens en JS)

## Variables de entorno

Copia `.env.example` a `.env.local` y ajusta:

```
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

## Scripts

```bash
pnpm dev        # Servidor de desarrollo en http://localhost:3000
pnpm build      # Build de producción
pnpm start      # Sirve el build de producción
pnpm lint       # ESLint (Next.js + TypeScript)
pnpm typecheck  # TypeScript sin emit
```

## Estructura relevante

```
src/
├── app/
│   ├── (app)/          # Rutas protegidas (requieren sesión)
│   │   ├── dashboard/
│   │   ├── scan/
│   │   └── history/
│   ├── login/          # Pantalla OAuth
│   ├── layout.tsx      # Root layout con Providers
│   └── page.tsx        # Redirector raíz
├── components/
│   ├── brand/          # Wordmark
│   ├── shell/          # TopBar, AppShell
│   ├── ui/             # Button, Card, Spinner, Skeleton
│   └── verdict/        # VerdictBadge, verdict-meta
└── lib/
    ├── api/            # client, endpoints, session, types
    ├── icons.tsx       # Iconos SVG inline
    └── utils.ts        # cn()
```
