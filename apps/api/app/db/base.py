"""Base declarativa SQLAlchemy 2.0 + fábrica de engine/sesión.

Convención de nombres explícita para constraints e índices → migraciones Alembic
**deterministas** (R8.3, mismo esquema ⇒ mismo SQL). El engine se construye perezosamente
desde `DATABASE_URL`; en contextos sin DB (p.ej. tests de import) los modelos se definen sin
abrir conexión.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, MetaData, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from ..settings import get_settings

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base de todos los modelos ORM."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


@lru_cache
def get_engine() -> Engine:
    """Engine síncrono (una vez). Lanza si `DATABASE_URL` no está configurada (fail-closed)."""
    settings = get_settings()
    if not settings.database_url:
        raise RuntimeError("DATABASE_URL no configurada: no se puede crear el engine de Postgres.")
    return create_engine(settings.database_url, pool_pre_ping=True, future=True)


def get_sessionmaker() -> sessionmaker[Session]:
    """Fábrica de sesiones ligada al engine."""
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


def get_db() -> Iterator[Session]:
    """Dependencia FastAPI: una sesión por request, cerrada al terminar."""
    maker = get_sessionmaker()
    with maker() as session:
        yield session
