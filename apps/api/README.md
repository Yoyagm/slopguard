# slopguard-api

Backend **FastAPI** del SaaS de SlopGuard (Hito 5). Envuelve el motor `slopguard`
(`src/slopguard`, zero-deps) **como librería in-process** y expone el dashboard + la
GitHub App. Ver `specs/slopguard-hito5-saas/design.md`.

## Desarrollo

```bash
# desde la raíz del repo (monorepo): crear venv del API e instalar el motor editable + el API
python -m venv apps/api/.venv
apps/api/.venv/bin/pip install -U pip
apps/api/.venv/bin/pip install -e .            # instala `slopguard` (motor) editable
apps/api/.venv/bin/pip install -e "apps/api[dev]"

# gate del API
apps/api/.venv/bin/ruff check apps/api
apps/api/.venv/bin/mypy apps/api
apps/api/.venv/bin/pytest apps/api
```

## Estructura

- `app/main.py` — app factory (`create_app`).
- `app/settings.py` — configuración por entorno (pydantic-settings).
- `app/db/` — base SQLAlchemy + modelos (Postgres).
- `app/api/` — routers (health, auth, scans, repos, webhooks — se añaden por olas).
- `alembic/` — migraciones versionadas.
