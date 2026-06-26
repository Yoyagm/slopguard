# upstash.tf — Redis gestionado en Upstash (ADR-1, ADR-2).
#
# Redis cubre tres usos del SaaS (design §1.1): cola de jobs Arq del worker,
# store del `state` OAuth de un solo uso (TTL), y rate limiting de endpoints
# públicos. Es EFÍMERO (no fuente de verdad), por eso se permite evicción.
#
# La contraseña / endpoint / tokens REST son SECRETOS: se exponen solo como
# outputs `sensitive` y se inyectan en Render como `REDIS_URL` (sync: false).

resource "upstash_redis_database" "slopguard" {
  database_name = "${var.project_name}-${var.environment}"
  region        = var.upstash_redis_region

  # TLS obligatorio: cifrado en tránsito hacia el runtime (NFR-Seg).
  tls = var.upstash_redis_tls

  # Permite evicción porque el contenido es efímero (cola/state/rate-limit);
  # si se llena, descartar lo viejo es preferible a rechazar escrituras.
  eviction = var.upstash_redis_eviction
}
