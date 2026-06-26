# providers.tf — Configuración de providers desde variables sensibles (H5-T08).
#
# Cada credencial proviene de una variable `sensitive`; no se hardcodea nada.
# Los providers leen estas variables, que a su vez se rellenan por entorno
# (TF_VAR_*). Ver infra/README.md para el flujo de inyección.

provider "neon" {
  # API key de Neon. Solo entra por TF_VAR_neon_api_key (sensible).
  api_key = var.neon_api_key
}

provider "upstash" {
  # Credenciales de gestión de Upstash (sensibles).
  email   = var.upstash_email
  api_key = var.upstash_api_key
}

provider "vercel" {
  # Token de la API de Vercel (sensible). team_id vacío = cuenta personal.
  api_token = var.vercel_api_token
  team      = var.vercel_team_id != "" ? var.vercel_team_id : null
}
