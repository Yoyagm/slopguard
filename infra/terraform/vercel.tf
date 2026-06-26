# vercel.tf — Proyecto del front Next.js en Vercel (ADR-1).
#
# El front (apps/web) solo habla con el API por HTTPS con cookie de sesión
# httpOnly (design §1.1): NO custodia secretos. La única configuración de entorno
# es la URL pública del API en Render, que es información pública (no sensible).
#
# Vercel construye desde el subdirectorio `apps/web` del monorepo conectado a Git.

resource "vercel_project" "web" {
  name      = "${var.project_name}-web"
  framework = "nextjs"

  # Subdirectorio del monorepo con el front (design ADR-5 layout).
  root_directory = var.vercel_root_directory

  git_repository = {
    type = "github"
    repo = var.vercel_git_repo
  }
}

# URL pública del API (no secreta): el front la usa para llamar al backend.
# Se crea solo si se conoce la URL de Render (api_public_url); de lo contrario
# se omite y se configura tras el primer despliegue de Render.
resource "vercel_project_environment_variable" "api_url" {
  count = var.api_public_url != "" ? 1 : 0

  project_id = vercel_project.web.id
  key        = "NEXT_PUBLIC_API_URL"
  value      = var.api_public_url
  target     = ["production", "preview"]
  # `sensitive` se deja en false a propósito: NEXT_PUBLIC_* se incrusta en el
  # bundle del cliente, por construcción no es un secreto.
  sensitive = false
}
