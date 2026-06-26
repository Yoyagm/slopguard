# Dockerfile multi-stage del frontend Next.js de SlopGuard (H5-T43, self-host).
#
# El contexto de build DEBE ser la raíz del monorepo (ver docker-compose.yml: context: .)
# porque apps/web es miembro del workspace pnpm de la raíz (lockfile y pnpm-workspace.yaml
# viven allí). Usa el output "standalone" de Next para una imagen de runtime mínima.

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM node:22-slim AS builder
WORKDIR /repo

ENV NEXT_TELEMETRY_DISABLED=1
# pnpm 11 vía corepack (casa el lockfileVersion generado localmente).
RUN corepack enable && corepack prepare pnpm@11.9.0 --activate

# 1. Instala dependencias del workspace con el lockfile congelado (capa cacheable).
COPY pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json apps/web/package.json
RUN pnpm install --frozen-lockfile

# 2. Copia el código del front y construye (genera apps/web/.next/standalone).
COPY apps/web apps/web
# La URL pública del API se hornea en el bundle del cliente en build-time.
ARG NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL}
RUN pnpm --filter @slopguard/web build

# ── Stage 2: runner ──────────────────────────────────────────────────────────
FROM node:22-slim AS runner
WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# Usuario no-root (reduce superficie de ataque).
RUN groupadd --system --gid 1001 nodejs \
    && useradd --system --uid 1001 --gid nodejs nextjs

# El output standalone conserva la ruta del monorepo: apps/web/server.js + node_modules en la raíz.
COPY --from=builder --chown=nextjs:nodejs /repo/apps/web/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /repo/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder --chown=nextjs:nodejs /repo/apps/web/public ./apps/web/public

USER nextjs
EXPOSE 3000

CMD ["node", "apps/web/server.js"]
