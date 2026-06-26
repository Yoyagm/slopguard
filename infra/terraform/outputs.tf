# outputs.tf — Salidas de la IaC (H5-T08).
#
# CONTRATO DE SEGURIDAD:
#   - Todo output que contenga una credencial (connection string, contraseña,
#     token) lleva `sensitive = true`. Esto evita imprimirlos en `plan`/`apply`.
#   - ADVERTENCIA (ver infra/README.md): `sensitive` NO los elimina del
#     `terraform.tfstate`. El estado debe tratarse como secreto (backend cifrado,
#     nunca commitear). Para extraer un valor de forma deliberada:
#         terraform output -raw database_url
#   - Los outputs no sensibles (ids, hosts, URL del proyecto Vercel) son
#     información pública y se dejan visibles para operar.

# ── Neon / Postgres ──────────────────────────────────────────────────────────

output "neon_project_id" {
  description = "ID del proyecto Neon (no sensible)."
  value       = neon_project.slopguard.id
}

output "database_url" {
  description = <<-EOT
    Connection string de Postgres para el API/Worker, con el driver que espera
    SQLAlchemy/psycopg (`postgresql+psycopg://`). SECRETO: inyectar en Render como
    DATABASE_URL (sync: false). Extraer con `terraform output -raw database_url`.
  EOT
  # El provider emite el URI estándar `postgres://...`. Se reescribe el esquema al
  # driver `postgresql+psycopg` que usa el API (ver apps/api/.env.example) sin
  # tocar las credenciales embebidas. `sslmode=require` fuerza TLS en tránsito.
  value = format(
    "postgresql+psycopg://%s",
    replace(
      replace(neon_project.slopguard.connection_uri, "postgresql://", ""),
      "postgres://", ""
    )
  )
  sensitive = true
}

# ── Upstash / Redis ──────────────────────────────────────────────────────────

output "redis_endpoint" {
  description = "Host del Redis de Upstash (no sensible por sí solo)."
  value       = upstash_redis_database.slopguard.endpoint
}

output "redis_url" {
  description = <<-EOT
    Connection string de Redis con TLS (`rediss://`) para Arq/rate-limit/state.
    SECRETO (incluye la contraseña). Inyectar en Render como REDIS_URL
    (sync: false). Extraer con `terraform output -raw redis_url`.
  EOT
  # rediss:// = Redis sobre TLS (cifrado en tránsito, NFR-Seg). Usuario "default".
  value = format(
    "rediss://default:%s@%s:%d",
    upstash_redis_database.slopguard.password,
    upstash_redis_database.slopguard.endpoint,
    upstash_redis_database.slopguard.port,
  )
  sensitive = true
}

# ── Vercel ───────────────────────────────────────────────────────────────────

output "vercel_project_id" {
  description = "ID del proyecto Vercel (no sensible)."
  value       = vercel_project.web.id
}
