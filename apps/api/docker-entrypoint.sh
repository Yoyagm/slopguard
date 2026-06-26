#!/bin/sh
# Entrypoint del contenedor API/Worker de SlopGuard SaaS (H5-T07).
#
# Uso:
#   docker run ... api     → inicia uvicorn (modo API)
#   docker run ... worker  → inicia el worker Arq (escaneo de PR en segundo plano)
#   docker run ... migrate → aplica las migraciones Alembic y sale (servicio one-shot)
#
# La distinción permite que api y worker compartan la misma imagen Docker
# y se lancen como procesos separados según el comando pasado en compose.
set -e

case "${1}" in
  api)
    # Arranca uvicorn apuntando al factory create_app().
    # --host 0.0.0.0 obligatorio para ser accesible dentro de la red de Docker.
    exec uvicorn app.main:app \
      --host 0.0.0.0 \
      --port "${PORT:-8000}" \
      --workers "${UVICORN_WORKERS:-1}" \
      --log-level "${LOG_LEVEL:-info}"
    ;;
  worker)
    # Worker Arq real (H5-T27, Ola 5): consume jobs de escaneo de PR desde Redis y
    # publica Check Run + comentario. `arq` descubre la cola y la tarea vía WorkerSettings.
    exec arq app.worker.main.WorkerSettings
    ;;
  migrate)
    # Migraciones one-shot: aplica el esquema (`alembic upgrade head`) y sale 0. Lo usa el
    # servicio `migrate` del compose; api y worker dependen de él vía
    # `service_completed_successfully`, así arrancan ya con el esquema al día.
    # WORKDIR es /app, donde viven alembic.ini y alembic/ (copiados en el Dockerfile).
    exec alembic upgrade head
    ;;
  *)
    echo "Uso: docker run <imagen> [api|worker]"
    echo "  api    → uvicorn (FastAPI)"
    echo "  worker → Arq worker (escaneo de PR en segundo plano)"
    exit 1
    ;;
esac
