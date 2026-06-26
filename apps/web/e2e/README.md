# E2E del flujo crítico (Playwright) — H5-T40

Tests end-to-end del flujo crítico **login → escaneo on-demand → histórico** y de los flujos de
**error/guard**, contra el stack de **docker-compose en marcha** (self-host local, sin cloud
externo).

> El OAuth real de GitHub exige `github.com` y queda fuera del self-host local. Por eso el flujo
> autenticado se ejercita con una **sesión sembrada** (cookie de servidor firmada, indistinguible
> de una real para el backend), no automatizando la UI de GitHub. Los flujos de error/guard no
> necesitan sesión.

`@playwright/test` **no** está en el `package.json` (lockfile congelado del CI de unidad). El
suite se ejecuta con `pnpm dlx`, así que no afecta a `pnpm install --frozen-lockfile`. La carpeta
`e2e/` está excluida de `tsc`, ESLint y Vitest.

## Requisitos

1. El stack levantado y sano (ver `docs/self-host.md`):
   ```bash
   docker compose up --build -d
   curl -s http://localhost:8000/api/v1/health   # {"status":"ok","db":"ok","redis":"ok"}
   ```

## Correr los flujos de error/guard (sin sesión)

```bash
cd apps/web
pnpm dlx playwright install chromium      # una vez
pnpm dlx playwright test -c e2e/playwright.config.ts --project=guest
```

## Correr el flujo feliz autenticado (con sesión sembrada)

1. Siembra el usuario de prueba y obtén la cookie firmada:
   ```bash
   docker compose exec -T api python - < apps/api/scripts/seed_e2e_session.py
   # → COOKIE_NAME=sg_session
   #   COOKIE_VALUE=<id>.<firma>
   #   USER_ID=<uuid>
   ```
2. Exporta la cookie y corre el proyecto autenticado:
   ```bash
   cd apps/web
   export SG_E2E_SESSION_COOKIE='<pega aquí COOKIE_VALUE>'
   pnpm dlx playwright test -c e2e/playwright.config.ts --project=authed
   ```

Sin `SG_E2E_SESSION_COOKIE`, el proyecto `authed` se salta solo (no falla).

## Variables de entorno

| Variable | Default | Uso |
|---|---|---|
| `SG_E2E_BASE_URL` | `http://localhost:3000` | URL del front publicado por el compose. |
| `SG_E2E_SESSION_COOKIE` | — | Valor de cookie firmado (`COOKIE_VALUE` del seed). |
| `SG_E2E_SESSION_COOKIE_NAME` | `sg_session` | Nombre de la cookie (dev). |
