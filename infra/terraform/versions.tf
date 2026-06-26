# versions.tf — Requisitos de Terraform y providers (H5-T08, ADR-1).
#
# Fija versiones de Terraform y de cada provider gestionado para que `init`/`plan`
# sean reproducibles entre máquinas. SlopGuard SaaS usa tres providers:
#   - Neon    (Postgres gestionado, ADR-1)
#   - Upstash (Redis gestionado, ADR-1 / ADR-2)
#   - Vercel  (proyecto del front, ADR-1)
#
# El runtime del API/Worker NO se gestiona aquí: vive en `render.yaml` (Blueprint
# nativo de Render) en la raíz del repo. Esta separación es intencional (ver
# infra/README.md): Terraform gobierna los almacenes gestionados y el proyecto
# del front; Render gobierna el contenedor de larga vida (web + worker).

terraform {
  required_version = ">= 1.6, < 2.0"

  required_providers {
    neon = {
      # Provider comunitario de referencia para Neon (Postgres serverless).
      source  = "kislerdm/neon"
      version = "~> 0.6"
    }
    upstash = {
      source  = "upstash/upstash"
      version = "~> 1.5"
    }
    vercel = {
      source  = "vercel/vercel"
      version = "~> 2.0"
    }
  }

  # NOTA DE SEGURIDAD (ver infra/README.md §"Estado y secretos"):
  # el `terraform.tfstate` almacena en claro los valores sensibles que devuelven
  # los providers (connection strings, tokens). Marcar outputs como `sensitive`
  # evita imprimirlos en consola, pero NO los elimina del estado. En un entorno
  # real, configurar aquí un backend remoto cifrado (p.ej. Terraform Cloud, S3 +
  # SSE-KMS + DynamoDB lock) en lugar del backend local por defecto. Se deja el
  # bloque documentado y comentado para no acoplar el demo a una cuenta concreta.
  #
  # backend "s3" {
  #   bucket         = "slopguard-tfstate"
  #   key            = "saas/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true            # SSE en reposo
  #   kms_key_id     = "alias/slopguard-tfstate"
  #   dynamodb_table = "slopguard-tflock"
  # }
}
