# Runbook — Self-host de SlopGuard SaaS (Docker Compose)

Levanta el stack completo del SaaS en local/self-host con `docker compose`, sin depender de ningún
cloud gestionado. Cubre el flujo de escaneo on-demand (login → escaneo → histórico) y el del
webhook de PR (worker Arq).

> Estado: **verificado en vivo**. `docker compose up --build` levanta los 5 servicios sanos, las
> migraciones se aplican solas (servicio `migrate`), el flujo on-demand funciona end-to-end y el
> E2E Playwright (H5-T40) pasa contra el stack. Ver §7.

## 1. Arquitectura del stack

| Servicio | Imagen / build | Rol | Puerto (host) |
|---|---|---|---|
| `postgres` | `postgres:16-alpine` | Persistencia (usuarios, instalaciones, repos, escaneos). | `127.0.0.1:5432` |
| `redis` | `redis:7-alpine` | Cola Arq + `state` OAuth + rate limiting. | `127.0.0.1:6379` |
| `migrate` | `apps/api/Dockerfile` (alembic) | One-shot: aplica el esquema (`alembic upgrade head`) y sale. | — |
| `api` | `apps/api/Dockerfile` (uvicorn) | FastAPI: OAuth, REST, webhooks, motor in-process. | `8000` |
| `worker` | `apps/api/Dockerfile` (arq) | Escaneo de PR en segundo plano (Check Run + comentario). | — |
| `web` | `apps/web/Dockerfile` (Next.js standalone) | Dashboard: login, escaneo, reportes, histórico. | `3000` |

Postgres y Redis solo se publican en `127.0.0.1` (herramientas locales); `api` y `web` se exponen
para el navegador. Los secretos entran **solo** por env (nunca en el YAML versionado).

## 2. Prerrequisitos

- Docker Desktop (o Docker Engine) + Docker Compose v2.
- Espacio de disco libre suficiente para construir las imágenes (varios GB).

## 3. Arranque rápido (modo desarrollo, sin configurar nada)

Sin `apps/api/.env`, el API arranca en modo `development` con defaults (no exige secretos fuertes
ni `encryption_key`, que solo se validan en `production`). El flujo OAuth/GitHub requiere
configuración (paso 5); el resto del stack levanta out-of-the-box.

```bash
# Construye e inicia todo el stack con un solo comando. El servicio one-shot `migrate` aplica
# las migraciones Alembic ANTES de que api y worker arranquen (depends_on: migrate →
# service_completed_successfully), así que no hay paso manual de base de datos.
docker compose up --build -d
```

> Migraciones: viven dentro de la imagen (`/app/alembic`) y las ejecuta el servicio `migrate`.
> Para correrlas a mano contra el Postgres publicado (p.ej. tras editar un modelo):
> `docker compose run --rm migrate` (vuelve a aplicar `upgrade head`, idempotente).

Comprueba salud y accede:

```bash
curl -s http://localhost:8000/api/v1/health    # {"status":"ok","db":"ok","redis":"ok"}
open http://localhost:3000                       # dashboard (redirige a /login)
```

## 4. Logs y observabilidad

- **Logs JSON** estructurados a stdout (un objeto por línea), con `request_id` de correlación y
  **redacción** de secretos. Síguelos con:
  ```bash
  docker compose logs -f api worker
  ```
- **Request-id**: cada respuesta del API lleva `X-Request-ID`; mándalo tú (cabecera del mismo
  nombre) para correlacionar tus peticiones con los logs.
- **Health**: `GET /api/v1/health` hace ping real a Postgres y Redis; si una está caída → `503`.
- **Rate limiting**: los endpoints públicos (login/callback, webhook) están limitados por IP vía
  Redis (cabeceras `X-RateLimit-*`, `429` + `Retry-After` al exceder). Es **fail-open**: si Redis
  no está, no se bloquea el tráfico.

## 5. Configuración completa (OAuth + GitHub App + LLM)

Para el login con GitHub, el escaneo de repos y el webhook de PR, crea `apps/api/.env`:

```bash
cp apps/api/.env.example apps/api/.env
# Edita apps/api/.env y rellena:
#   SESSION_SECRET           (aleatorio fuerte, p.ej. `python -c "import secrets;print(secrets.token_urlsafe(32))"`)
#   ENCRYPTION_KEY           (clave AEAD base64 de 32 bytes, p.ej. `python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"`)
#   GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET     (OAuth App)
#   GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY      (GitHub App)
#   GITHUB_WEBHOOK_SECRET                       (secreto del webhook)
#   ANTHROPIC_API_KEY        (opcional; activa la Capa 4 LLM)
#   WEB_BASE_URL             (opcional; URL pública del front, default http://localhost:3000)
```

> `WEB_BASE_URL` es la URL a la que el API redirige tras el login (al dashboard) y donde muestra
> los errores de OAuth (`/login?error=…`). En self-host con el API y el web en puertos distintos
> DEBE ser la URL del **web** (no del API), o el redirect post-login caería en el host del API.

`docker-compose.yml` carga `apps/api/.env` de forma **opcional** (`required: false`) y sobreescribe
`DATABASE_URL`/`REDIS_URL` para apuntar a los servicios de la red Docker. Reinicia tras editar:

```bash
docker compose up -d --force-recreate api worker
```

Registra la GitHub App con el perfil de **mínimo privilegio** de `docs/github-app-permissions.md`
y apunta el webhook a `http://<host>/api/v1/webhooks/github` (en local, expón el puerto con un túnel
tipo `cloudflared`/`ngrok` para recibir eventos de GitHub).

## 6. Operación

```bash
docker compose ps                 # estado y healthchecks
docker compose logs -f web        # logs de un servicio
docker compose restart worker     # reiniciar un servicio
docker compose down               # parar (conserva volúmenes/datos)
docker compose down -v            # parar y BORRAR datos (postgres_data, redis_data)
```

## 7. Verificación en vivo (completada)

`docker compose up --build` levantado y verificado en self-host local:

- **Servicios**: `postgres`, `redis`, `api`, `worker` y `web` en `healthy`; `migrate` one-shot
  aplica el esquema y sale 0 antes de que arranquen `api`/`worker`.
- **Salud**: `GET /api/v1/health` → `{"status":"ok","db":"ok","redis":"ok"}`.
- **Flujo on-demand** end-to-end: escaneo inline (`reqeusts`→block por nonexistent+typosquat,
  `requests`→allow), histórico, detalle y raw; aislamiento por usuario (scan ajeno → 404).
- **Fail-closed**: guard sin sesión → 401; webhook sin secreto → 503; firma HMAC inválida → 204.
- **E2E Playwright (H5-T40)**: ver `apps/web/e2e/README.md` (proyecto `guest` 3/3 + `authed` 2/2).

Lo único que requiere GitHub real (fuera del self-host local): el login OAuth y el posteo del
Check Run del webhook (`pull_request`). El resto del webhook (HMAC, dispatch, encolado) es local.

### Operación: smoke rápido tras un arranque

```bash
docker compose up --build -d
curl -s http://localhost:8000/api/v1/health            # {"status":"ok","db":"ok","redis":"ok"}
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/login   # 200
```
