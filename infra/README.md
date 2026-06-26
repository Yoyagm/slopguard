# Infraestructura — SlopGuard SaaS (Hito 5)

Infraestructura como código (IaC) del SaaS. Implementa **ADR-1** del diseño
(`specs/slopguard-hito5-saas/design.md`): front en Vercel, API + Worker en un
runtime de contenedor persistente (Render), Postgres y Redis gestionados.

> **Esta tarea (H5-T08) NO ejecuta `terraform apply` ni despliega.** Solo define
> la IaC de forma idiomática y segura. El despliegue real es H5-T43.

## Reparto de responsabilidades

| Plano | Herramienta | Qué gobierna | Archivo(s) |
|---|---|---|---|
| Almacenes gestionados + front | **Terraform** | Postgres (Neon), Redis (Upstash), proyecto Vercel | `infra/terraform/*.tf` |
| Runtime de larga vida | **Render Blueprint** | web service (API) + background worker | `render.yaml` (raíz) |

Por qué dos planos: el runtime (API/worker) es un **proceso de larga vida con
disco** (ADR-1) que Render modela de forma nativa con `render.yaml`; reescribirlo
en Terraform añadiría un provider más sin ganancia. Terraform se reserva para los
recursos que sí conviene declarar declarativamente y versionar (las dos bases de
datos gestionadas y el proyecto del front).

```
infra/
├── README.md                 # este documento
└── terraform/
    ├── versions.tf           # versiones de Terraform y providers (pinned)
    ├── variables.tf          # entradas parametrizadas (secretos = sensitive)
    ├── providers.tf          # config de providers desde variables
    ├── neon.tf               # Postgres gestionado (Neon)
    ├── upstash.tf            # Redis gestionado (Upstash)
    ├── vercel.tf             # proyecto del front (Vercel)
    ├── outputs.tf            # outputs (connection strings/tokens = sensitive)
    ├── terraform.tfvars.example   # plantilla SOLO de valores no secretos
    └── .gitignore            # excluye estado y tfvars reales (anti-fuga)
render.yaml                   # (raíz) Blueprint de Render: API + worker
```

## Inyección de secretos (nunca en el repo)

Regla dura (NFR-Seg-3): **ningún secreto vive en el repositorio**. Se distinguen
dos clases de secreto y cada una entra por un canal distinto.

### 1. Credenciales de los providers (para que Terraform pueda crear recursos)

Se inyectan por entorno con el prefijo `TF_VAR_` (Terraform las mapea a variables
`sensitive`). Nunca se ponen en `terraform.tfvars` ni en `*.tf`:

```bash
export TF_VAR_neon_api_key="..."        # API key de Neon
export TF_VAR_upstash_email="..."       # cuenta de Upstash
export TF_VAR_upstash_api_key="..."     # API key de Upstash
export TF_VAR_vercel_api_token="..."    # token de Vercel
```

En CI/CD se proveen desde el **secret store** del runner (GitHub Actions secrets,
etc.), nunca como texto plano en el workflow.

Los valores **no secretos** (región, nombres, versión de Postgres) sí pueden ir
en un `terraform.tfvars` local copiado de `terraform.tfvars.example` (ese
`terraform.tfvars` está gitignored por precaución).

### 2. Secretos de runtime (los que consume el API/Worker)

`DATABASE_URL`, `REDIS_URL`, `SESSION_SECRET`, `ENCRYPTION_KEY` y las credenciales
de GitHub se declaran en `render.yaml` con **`sync: false`**: Render pide su valor
manualmente (o vía API de Render) y lo guarda **cifrado**, fuera del repo.

Los dos primeros provienen de los outputs de Terraform:

```bash
cd infra/terraform
terraform output -raw database_url    # → pegar en Render como DATABASE_URL
terraform output -raw redis_url       # → pegar en Render como REDIS_URL
```

`SESSION_SECRET` y `ENCRYPTION_KEY` se generan con entropía fuerte por entorno
(p.ej. `python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"`
para la clave AEAD de 32 bytes, H5-T06) y se introducen directamente en Render.

## Estado y secretos (importante)

El `terraform.tfstate` almacena **en claro** todos los valores sensibles que
devuelven los providers (connection strings con contraseña, tokens). Marcar un
output como `sensitive` solo evita que se **imprima** en `plan`/`apply`; **no** lo
elimina del estado. Por eso:

- `terraform.tfstate*` está en `.gitignore`: **nunca** se versiona.
- En producción real se usa un **backend remoto cifrado** (Terraform Cloud, o S3
  con SSE-KMS + lock en DynamoDB). El bloque está documentado y comentado en
  `versions.tf`; se deja sin activar para no acoplar el demo a una cuenta concreta.
- Para extraer un secreto deliberadamente: `terraform output -raw <nombre>`.

## Flujo de trabajo (sin aplicar en H5-T08)

```bash
cd infra/terraform

# 1. Inyectar credenciales de provider por entorno (ver arriba).
export TF_VAR_neon_api_key=...   # etc.

# 2. (Opcional) parámetros no secretos:
cp terraform.tfvars.example terraform.tfvars   # editar región/nombres si hace falta

# 3. Inicializar y validar (esto NO crea nada):
terraform init
terraform fmt -check
terraform validate

# 4. Ver el plan (H5-T08 llega hasta aquí; NO se ejecuta apply):
terraform plan

# 5. (H5-T43, despliegue) aplicar y volcar outputs a Render:
# terraform apply
# terraform output -raw database_url   # → Render (sync:false)
# terraform output -raw redis_url      # → Render (sync:false)
```

### Render (runtime)

`render.yaml` es un **Blueprint**: en el dashboard de Render se conecta el repo y
Render detecta el archivo. Crea dos servicios desde el mismo `apps/api/Dockerfile`
(contexto raíz del monorepo):

- **slopguard-api** (`web`): `dockerCommand: api` → uvicorn. Healthcheck en
  `/api/v1/health`. Disco persistente montado en `/var/cache/slopguard` para la
  caché en disco del motor (ADR-1, NFR-Rendimiento-1); `HOME` apunta ahí para que
  `Path.home()/.cache/slopguard` (donde el motor escribe) caiga en el disco.
- **slopguard-worker** (`worker`): `dockerCommand: worker` → worker Arq
  (placeholder hasta Ola 5, H5-T27).

Postgres y Redis **no** son recursos de Render: son Neon/Upstash (gestionados por
Terraform). Sus URLs entran como secretos `sync: false`.

## Mínimo privilegio y postura de seguridad

- **Cifrado en tránsito:** Postgres con `sslmode=require`; Redis con `rediss://`
  (TLS forzado, `upstash_redis_tls = true`).
- **Least-privilege en Postgres:** el runtime se conecta con el rol de aplicación
  `slopguard_app`, no con el rol owner de la nube.
- **Sin puertos abiertos a 0.0.0.0:** Neon/Upstash exponen endpoints gestionados
  con TLS y autenticación; no hay security groups propios que endurecer (a
  diferencia de un self-host). No se define ninguna regla de red permisiva.
- **Redacción:** ni `render.yaml` ni los `.tf` contienen secretos; los outputs
  sensibles no se imprimen; el estado se mantiene fuera del repo.
