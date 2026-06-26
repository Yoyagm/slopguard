# neon.tf — Postgres gestionado en Neon (ADR-1, modelo de datos design §3).
#
# Crea un proyecto Neon con su branch primaria por defecto, y sobre ella una
# base de datos y un rol de aplicación dedicados (least-privilege: el runtime
# se conecta con `slopguard_app`, no con el rol owner de la nube).
#
# El connection string lo emite Neon e incluye la contraseña del rol: es un
# SECRETO. Se expone solo como output `sensitive` (ver outputs.tf) y se inyecta
# en Render como `DATABASE_URL` con `sync: false` (nunca se versiona).

resource "neon_project" "slopguard" {
  name                      = "${var.project_name}-${var.environment}"
  region_id                 = var.neon_region_id
  pg_version                = var.neon_pg_version
  history_retention_seconds = 86400 # 1 día de PITR; suficiente para un demo single-tenant.

  # La branch primaria ya provisiona la base de datos de la aplicación y su rol
  # owner (least-privilege: el runtime se conecta con `slopguard_app`, no con el
  # rol owner de la nube). NO se crea un `neon_database` separado con el mismo
  # nombre: colisionaría en `apply` con la database que esta branch ya crea.
  branch {
    name          = "main"
    database_name = var.neon_database_name
    role_name     = var.neon_role_name
  }
}
