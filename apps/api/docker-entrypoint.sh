#!/bin/sh
# Entrypoint del contenedor API/Worker de SlopGuard SaaS (H5-T07).
#
# Uso:
#   docker run ... api     → inicia uvicorn (modo API)
#   docker run ... worker  → inicia el worker Arq (placeholder hasta Ola 5)
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
    # Placeholder hasta Ola 5 (H5-T27): el worker Arq real se conecta a Redis
    # y procesa jobs de escaneo de PR. Por ahora solo valida que el entorno está
    # configurado e informa claramente que el worker aún no está implementado.
    echo "[worker] SlopGuard Arq worker — placeholder (Ola 5)."
    echo "[worker] REDIS_URL = ${REDIS_URL:-<no configurado>}"
    echo "[worker] El worker real se implementa en H5-T27. Proceso terminado."
    exit 0
    ;;
  *)
    echo "Uso: docker run <imagen> [api|worker]"
    echo "  api    → uvicorn (FastAPI)"
    echo "  worker → Arq worker (placeholder hasta Ola 5)"
    exit 1
    ;;
esac
