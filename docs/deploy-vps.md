# Runbook — Despliegue en producción (VPS + dominio + TLS)

Pone SlopGuard SaaS en internet sobre **tu propio VPS y dominio**, con HTTPS automático. A
diferencia del self-host local (`docs/self-host.md`, todo en `localhost`), aquí un reverse proxy
**Caddy** unifica el front (Next.js) y el API (FastAPI) bajo **un solo origen HTTPS** y gestiona
los certificados de Let's Encrypt solo.

> Resultado: `https://tu-dominio` sirve la UI; `https://tu-dominio/api/*` va al API. Mismo origen ⇒
> login OAuth con callback `same-origin`, sin trucos de CORS entre puertos.

## 1. Arquitectura de producción

```mermaid
flowchart LR
  U[Navegador] -- HTTPS 443 --> C[Caddy<br/>TLS auto]
  C -- "/api/*" --> A[api:8000<br/>FastAPI]
  C -- "resto" --> W[web:3000<br/>Next.js]
  A --> P[(postgres)]
  A --> R[(redis)]
  WK[worker Arq] --> P
  WK --> R
```

| Componente | Rol | Expuesto a internet |
|---|---|---|
| `caddy` | Reverse proxy + TLS (Let's Encrypt). Único punto de entrada. | **Sí** (80/443) |
| `api` | FastAPI: OAuth, REST, webhooks, motor in-process. | No (solo vía Caddy) |
| `web` | Dashboard Next.js. | No (solo vía Caddy) |
| `worker` | Escaneo de PR en segundo plano. | No |
| `postgres` / `redis` | Persistencia y cola. | No (loopback del VPS) |

Frente al base (`docker-compose.yml`), el overlay `docker-compose.prod.yml`:
- añade **Caddy** (publica 80/443 + 443/udp para HTTP/3);
- **deja de publicar** `api`/`web`/`postgres`/`redis` al host (`ports: !reset []`) — solo Caddy expuesto;
- pone `api`/`worker` en `ENVIRONMENT=production` (validación estricta de secretos, fail-closed);
- fija `CORS_ORIGINS=["https://${DOMAIN}"]` y `WEB_BASE_URL=https://${DOMAIN}` (un solo origen);
- hornea `NEXT_PUBLIC_API_BASE_URL=https://${DOMAIN}` en el build del front;
- activa `RATE_LIMIT_TRUST_FORWARDED_FOR=true` para que el rate-limit sea **por IP real**.

> **Rate-limit detrás del proxy:** el API limita por IP (`60/min` auth, `120/min` webhooks). Tras el
> proxy, la IP del socket es la de Caddy, así que el límite leería un único cubo global (un atacante
> tumbaría el login de todos). Por eso Caddy **reescribe `X-Forwarded-For` con la IP real del peer**
> (`Caddyfile`, `header_up X-Forwarded-For {remote_host}`, descartando cualquier XFF que el cliente
> inyecte) y el API confía en él. Esto **asume que Caddy es el borde directo** (DNS → VPS, sin
> CDN/otro proxy delante). Si antepones un CDN (p.ej. Cloudflare), ajusta la cadena de confianza.

## 2. Prerrequisitos

- **VPS** con Ubuntu 22.04+ (o Debian 12+), 2 GB RAM mínimo (4 GB recomendado para el `build`),
  ~10 GB de disco. IP pública.
- **Dominio** o subdominio que controles (para crear el registro DNS).
- Cuenta de **GitHub** para crear la OAuth App (login) y la GitHub App (escaneo de PR).
- `ANTHROPIC_API_KEY` (opcional; activa la Capa 4 LLM).

## 3. Provisionar el VPS

SSH al servidor como root (o un usuario con sudo) y prepara Docker + firewall.

```bash
# Docker Engine + Compose plugin (script oficial)
curl -fsSL https://get.docker.com | sh

# Verifica Compose v2.24+ (necesario para el tag `!reset` del overlay)
docker compose version

# Firewall: permite SSH + HTTP + HTTPS, deniega el resto
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp        # HTTP/3 (QUIC)
ufw --force enable
```

> Si tu `docker compose version` es < 2.24, actualiza el plugin (`apt-get install docker-compose-plugin`)
> o el `!reset []` del overlay fallará al parsear.

## 4. DNS

En tu proveedor de DNS, crea un registro **A** que apunte tu dominio a la IP del VPS:

```
Tipo: A    Nombre: slopguard (o @)    Valor: <IP_DEL_VPS>    TTL: 300
```

Verifica la propagación antes de seguir (Caddy necesita resolver el dominio para emitir el cert):

```bash
dig +short slopguard.tudominio.com    # debe devolver la IP del VPS
```

## 5. Clonar el repo

```bash
git clone <URL_DEL_REPO> slopguard && cd slopguard
```

## 6. Crear las apps de GitHub (con las URLs de tu dominio)

Sustituye `tu-dominio` por tu dominio real en todas las URLs.

### 6.1. OAuth App (login)
GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**
(`https://github.com/settings/developers`):

| Campo | Valor |
|---|---|
| Application name | `SlopGuard` |
| Homepage URL | `https://tu-dominio` |
| Authorization callback URL | `https://tu-dominio/api/v1/auth/callback` |

Genera un **client secret**. Anota `Client ID` y `Client secret`.

### 6.2. GitHub App (escaneo de PR)
GitHub → **Settings → Developer settings → GitHub Apps → New GitHub App**.
Permisos de **mínimo privilegio** (detalle en `docs/github-app-permissions.md`):

| Campo | Valor |
|---|---|
| Homepage URL | `https://tu-dominio` |
| Webhook URL | `https://tu-dominio/api/v1/webhooks/github` |
| Webhook secret | una cadena aleatoria fuerte (la usarás como `GITHUB_WEBHOOK_SECRET`) |
| Permisos | Contents: RO · Metadata: RO · Pull requests: R&W · Checks: R&W · resto: No access |
| Suscripción a eventos | Installation, Installation repositories, Pull request |

Anota el **App ID**, genera y descarga la **private key** (`.pem`), y configura el webhook secret.

## 7. Configurar los secretos en el VPS

Dos archivos de entorno (ambos en `.gitignore`, nunca se commitean):

### 7.1. `.env` de la raíz — solo el dominio

```bash
cp .env.prod.example .env
# Edita .env y pon tu dominio real:
#   DOMAIN=slopguard.tudominio.com
```

### 7.2. `apps/api/.env` — los secretos

```bash
cp apps/api/.env.example apps/api/.env
```

Genera valores fuertes (en el VPS; `openssl` viene de fábrica):

```bash
openssl rand -hex 32        # → SESSION_SECRET
openssl rand -base64 32     # → ENCRYPTION_KEY  (32 bytes en base64, lo exige la validación AEAD)
```

Edita `apps/api/.env` y rellena:

```ini
ENVIRONMENT=production
SESSION_SECRET=<salida de `openssl rand -hex 32`>
ENCRYPTION_KEY=<salida de `openssl rand -base64 32`>

# OAuth App (paso 6.1)
GITHUB_CLIENT_ID=<client id>
GITHUB_CLIENT_SECRET=<client secret>

# GitHub App (paso 6.2)
GITHUB_APP_ID=<app id>
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n"
GITHUB_WEBHOOK_SECRET=<webhook secret>

# Opcional: Capa 4 LLM
ANTHROPIC_API_KEY=<tu key>
```

> **No** pongas `CORS_ORIGINS` ni `WEB_BASE_URL` aquí: el overlay de producción los fija a partir
> de `DOMAIN` y `environment` gana sobre `env_file`. `DATABASE_URL`/`REDIS_URL` también los inyecta
> el compose (apuntan a los servicios internos). La private key debe ir en **una sola línea** con
> los saltos como `\n` literales, entre comillas.

## 8. Levantar el stack

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d
```

Esto construye las imágenes (el front se hornea con `NEXT_PUBLIC_API_BASE_URL=https://tu-dominio`),
aplica las migraciones (servicio one-shot `migrate`), arranca todo y Caddy emite el certificado TLS
en el primer arranque (puede tardar unos segundos).

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps        # estado/healthchecks
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f caddy   # ver emisión del cert
```

> Tip: exporta `COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml` en tu shell para no repetir
> los `-f` en cada comando.

## 9. Verificación

```bash
curl -s https://tu-dominio/api/v1/health          # {"status":"ok","db":"ok","redis":"ok"}
curl -s -o /dev/null -w "%{http_code}\n" https://tu-dominio/login    # 200
```

Luego en el navegador:
1. Abre `https://tu-dominio` → redirige a `/login` (candado TLS válido).
2. **Continuar con GitHub** → autoriza la OAuth App → vuelve a `https://tu-dominio/dashboard`.
3. Instala la GitHub App en un repo de prueba y abre un PR que toque un manifiesto
   (`requirements.txt`, `package.json`, …) → el worker postea un **Check Run** con el veredicto.

## 10. Operación

```bash
export COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml   # evita repetir los -f

docker compose logs -f api worker         # logs (JSON, con redacción de secretos)
docker compose restart worker             # reiniciar un servicio
docker compose down                       # parar (conserva datos y certificados)

# Actualizar a una versión nueva del código:
git pull
docker compose up --build -d              # reconstruye e reinicia sin downtime apreciable

# Backup de la base de datos (el volumen postgres_data es la fuente de verdad):
docker compose exec -T postgres pg_dump -U slopguard slopguard | gzip > backup-$(date +%F).sql.gz
```

Los certificados de Caddy persisten en el volumen `caddy_data` (no se re-emiten en cada deploy, lo
que evita topar con los rate limits de Let's Encrypt).

## 11. Hardening (recomendado)

- **Contraseña de Postgres**: el base usa `slopguard/slopguard`. En producción el overlay ya **no
  publica** Postgres/Redis al host (solo viven en la red interna de Docker), así que no son
  alcanzables ni desde el loopback del VPS. Para endurecer aún más, sobreescribe `POSTGRES_PASSWORD`
  y los tres `DATABASE_URL` con un secreto propio en un overlay/`.env` adicional.
- **SSH**: deshabilita login por password y root directo; usa solo claves.
- **Actualizaciones**: `unattended-upgrades` para parches de seguridad del SO.
- **Avisos de cert**: añade un bloque global con tu email al `Caddyfile`
  (`{ email tu-email@example.com }`) para recibir avisos de Let's Encrypt.
- **Backups**: automatiza el `pg_dump` del paso 10 (cron) y guárdalo fuera del VPS.

## 12. Troubleshooting

| Síntoma | Causa probable | Solución |
|---|---|---|
| Caddy no emite el cert | DNS no propagado o 80/443 cerrados | `dig +short tu-dominio` debe dar la IP; revisa `ufw status` |
| `services.api.ports: invalid type for !reset` | Compose < 2.24 | Actualiza el plugin de Compose |
| Login muestra "no está configurado" | Falta `GITHUB_CLIENT_ID/SECRET` en `apps/api/.env` | Rellénalos y `up -d --force-recreate api` |
| OAuth: redirect URI mismatch | Callback de la OAuth App ≠ `https://tu-dominio/api/v1/auth/callback` | Corrígelo en la OAuth App |
| `api` no arranca en producción | `SESSION_SECRET` débil o `ENCRYPTION_KEY` inválida | Regenera con los `openssl` del paso 7.2 |
| Webhook no llega | URL ≠ `https://tu-dominio/api/v1/webhooks/github` o secreto distinto | Alinéalos en la GitHub App |

> El front hornea la URL del API en **build-time**. Si cambias `DOMAIN`, reconstruye:
> `docker compose up --build -d web`.
