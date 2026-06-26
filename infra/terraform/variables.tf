# variables.tf — Entradas parametrizadas de la IaC (H5-T08).
#
# Regla dura de seguridad (cloud-security skill, NFR-Seg-3):
#   - NINGÚN secreto tiene valor por defecto. Las credenciales de provider entran
#     SOLO por entorno (`TF_VAR_<nombre>`) o un `.tfvars` NO versionado.
#   - Toda variable que transporta una credencial lleva `sensitive = true` para
#     que no se imprima en `plan`/`apply` ni en errores.
#   - Las variables no sensibles (nombres, región) tienen defaults razonables y
#     se sobrescriben por entorno.

# ── Parámetros de despliegue (no sensibles) ──────────────────────────────────

variable "environment" {
  description = "Nombre lógico del entorno (etiqueta los recursos). Demo single-tenant: un solo entorno."
  type        = string
  default     = "production"

  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "environment debe ser production, staging o development."
  }
}

variable "project_name" {
  description = "Prefijo de nombres de recursos gestionados."
  type        = string
  default     = "slopguard-saas"
}

# ── Neon (Postgres gestionado) ───────────────────────────────────────────────

variable "neon_api_key" {
  description = "API key de la cuenta de Neon. Inyectar por TF_VAR_neon_api_key; nunca commitear."
  type        = string
  sensitive   = true
}

variable "neon_region_id" {
  description = "Región de Neon (p.ej. aws-us-east-1). Cercana al runtime de Render para minimizar latencia SQL."
  type        = string
  default     = "aws-us-east-1"
}

variable "neon_pg_version" {
  description = "Versión mayor de Postgres en Neon."
  type        = number
  default     = 16
}

variable "neon_database_name" {
  description = "Nombre de la base de datos de la aplicación."
  type        = string
  default     = "slopguard"
}

variable "neon_role_name" {
  description = "Rol de aplicación (least-privilege; no es el rol owner de la nube)."
  type        = string
  default     = "slopguard_app"
}

# ── Upstash (Redis gestionado) ───────────────────────────────────────────────

variable "upstash_email" {
  description = "Email de la cuenta de Upstash para la API de gestión. Inyectar por TF_VAR_upstash_email."
  type        = string
  sensitive   = true
}

variable "upstash_api_key" {
  description = "API key de gestión de Upstash. Inyectar por TF_VAR_upstash_api_key; nunca commitear."
  type        = string
  sensitive   = true
}

variable "upstash_redis_region" {
  description = "Región primaria del Redis de Upstash (global=replicado; aquí región única para el demo)."
  type        = string
  default     = "us-east-1"
}

variable "upstash_redis_tls" {
  description = "Forzar TLS en las conexiones a Redis (NFR-Seg: cifrado en tránsito). Siempre true."
  type        = bool
  default     = true
}

variable "upstash_redis_eviction" {
  description = "Permitir evicción (Redis se usa como cola Arq + state OAuth + rate-limit; efímero, no fuente de verdad)."
  type        = bool
  default     = true
}

# ── Vercel (proyecto del front) ──────────────────────────────────────────────

variable "vercel_api_token" {
  description = "Token de la API de Vercel. Inyectar por TF_VAR_vercel_api_token; nunca commitear."
  type        = string
  sensitive   = true
}

variable "vercel_team_id" {
  description = "ID del team de Vercel (vacío = cuenta personal/hobby)."
  type        = string
  default     = ""
}

variable "vercel_git_repo" {
  description = "Repositorio Git conectado al proyecto Vercel, en formato owner/repo."
  type        = string
  default     = "Yoyagm/slopguard"
}

variable "vercel_root_directory" {
  description = "Subdirectorio del monorepo que contiene el front Next.js."
  type        = string
  default     = "apps/web"
}

variable "api_public_url" {
  description = "URL pública del API en Render que el front consume (se conoce tras desplegar Render)."
  type        = string
  default     = ""
}
