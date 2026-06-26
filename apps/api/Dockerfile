# Dockerfile multi-stage para el API + Worker de SlopGuard SaaS (H5-T07).
#
# Stage 1 (builder): instala dependencias en una copia aislada del venv.
# Stage 2 (runtime): imagen mínima que copia el venv construido y el código fuente.
#
# Entrypoint:
#   CMD api    → arranca uvicorn (por defecto)
#   CMD worker → arranca el worker Arq (placeholder hasta Ola 5)
#
# El motor zero-deps (src/slopguard) se instala editable desde el contexto raíz
# del monorepo. El contexto Docker DEBE apuntar a la raíz del repo (no a apps/api).
# Ver docker-compose.yml: context: .

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

# Directorio de trabajo temporal para construir el entorno virtual.
WORKDIR /build

# Variables que evitan generar bytecode innecesario durante el build.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # pip: no guarda caché en la imagen
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Instala build tools mínimos (solo lo necesario para compilar psycopg binary).
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Crea el venv en una ruta predecible para copiarlo al stage de runtime.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 1. Copia e instala el motor zero-deps de forma editable (src/slopguard).
#    Al ser zero-deps, no tiene dependencias transitivas que resolver.
#    El README.md raíz es OBLIGATORIO: pyproject.toml lo declara `readme = "README.md"`
#    y setuptools lo lee al construir la metadata (sin él, `pip install` aborta).
COPY src/ /build/src/
COPY pyproject.toml /build/pyproject.toml
COPY README.md /build/README.md
RUN pip install -e /build

# 2. Copia e instala el paquete API (apps/api).
#    Se instala después del motor para que `slopguard` ya esté disponible.
#    `apps/api/README.md` también es requerido por su pyproject (mismo motivo).
COPY apps/api/ /build/apps/api/
RUN pip install /build/apps/api

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Usuario no-root para reducir superficie de ataque (NFR-Seg).
RUN useradd --no-create-home --shell /bin/false slopguard

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Copia el venv construido en el stage builder.
COPY --from=builder /opt/venv /opt/venv

# Copia el código fuente del motor (necesario para el install editable).
COPY --from=builder /build/src /app/src

# Copia el código fuente del API.
COPY --from=builder /build/apps/api/app /app/app

# Migraciones Alembic: config + scripts de versión. Necesarios para el servicio one-shot
# `migrate` del compose (entrypoint `migrate` → `alembic upgrade head`). `alembic.ini` usa
# `script_location = alembic` relativo, por eso ambos cuelgan de WORKDIR /app.
COPY --from=builder /build/apps/api/alembic.ini /app/alembic.ini
COPY --from=builder /build/apps/api/alembic /app/alembic

# Copia el entrypoint antes de cambiar al usuario no-root.
COPY apps/api/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

USER slopguard

# Puerto que expone uvicorn (configurable por variable de entorno).
EXPOSE 8000

# Por defecto arranca el API; override con "worker" para el proceso Arq.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["api"]
