"""Entorno Alembic. Lee la URL de `app.settings`; soporta modo offline (`--sql`) sin DB.

Importa los modelos para que `Base.metadata` conozca todas las tablas (target para
autogenerate/comparación). En CI/offline sin `DATABASE_URL` usa un placeholder para renderizar
el SQL (`alembic upgrade head --sql`), sin abrir conexión.
"""

from __future__ import annotations

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context
from app.db import models
from app.db.base import Base
from app.settings import get_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

_OFFLINE_PLACEHOLDER = "postgresql+psycopg://user:pass@localhost:5432/slopguard"


def _database_url() -> str:
    return get_settings().database_url or _OFFLINE_PLACEHOLDER


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
