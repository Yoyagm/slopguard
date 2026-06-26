"""Repositorio de `users`: upsert de identidad GitHub + token cifrado (R1.2/R1.5, design §3.1).

El token OAuth se cifra con AEAD (`app.security.crypto`) ANTES de tocar la DB y se persiste como
`BYTEA` en `users.access_token_enc`; jamás en claro (R8.2). La AAD liga el ciphertext a la columna
y al usuario (`users.access_token_enc:<github_user_id>`): defensa contra reubicar un blob de una
fila/columna a otra (recomendación de deuda diferida de la Ola 0).

El motor SQLAlchemy del proyecto es **síncrono** (design/db/base.py). Para no bloquear el event
loop de FastAPI, el upsert se ejecuta en un threadpool (`anyio.to_thread.run_sync`), igual que el
patrón de ADR-3 para el motor.

Contrato `UserRepository` (Protocol) inyectable: en tests se dobla en memoria, sin Postgres.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from anyio import to_thread
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, sessionmaker

from ..db.models import User
from ..security.crypto import encrypt_str
from ..services.github import GitHubIdentity

# Prefijo de la AAD: liga el blob cifrado a esta columna y usuario concretos.
_AAD_COLUMN = "users.access_token_enc"


def _token_aad(github_user_id: int) -> bytes:
    """AAD estable por usuario: el blob solo descifra en su contexto (columna + identidad)."""
    return f"{_AAD_COLUMN}:{github_user_id}".encode()


class UserRepository(Protocol):
    """Contrato del repositorio de usuarios para el flujo de login y resolución de sesión."""

    async def upsert_from_oauth(self, identity: GitHubIdentity, access_token: str) -> uuid.UUID:
        """Crea o actualiza el usuario y guarda su token CIFRADO. Devuelve el `users.id` interno."""
        ...

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        """Busca el usuario por PK interna. Devuelve None si no existe."""
        ...


class SqlUserRepository:
    """Implementación SQLAlchemy. Cumple `UserRepository`.

    Usa `INSERT ... ON CONFLICT (github_user_id) DO UPDATE` (upsert atómico de Postgres): si el
    usuario ya existe, refresca `login`, `avatar_url` y el token cifrado (re-login rota el token).
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    async def upsert_from_oauth(self, identity: GitHubIdentity, access_token: str) -> uuid.UUID:
        # El cifrado es CPU-bound y trivial; el I/O de DB es lo que bloquea. Hacemos ambos dentro
        # del thread para mantener el handler async no-bloqueante y la transacción en un solo hilo.
        return await to_thread.run_sync(self._upsert_sync, identity, access_token)

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        """SELECT por PK en threadpool para no bloquear el event loop."""
        return await to_thread.run_sync(self._get_by_id_sync, user_id)

    def _get_by_id_sync(self, user_id: uuid.UUID) -> User | None:
        stmt = select(User).where(User.id == user_id)
        with self._session_factory() as session:
            return session.execute(stmt).scalar_one_or_none()

    def _upsert_sync(self, identity: GitHubIdentity, access_token: str) -> uuid.UUID:
        # Cifra el token ligándolo a la columna+usuario (AAD). Nunca se persiste en claro.
        token_enc = encrypt_str(
            access_token, associated_data=_token_aad(identity.github_user_id)
        )

        stmt = (
            insert(User)
            .values(
                github_user_id=identity.github_user_id,
                login=identity.login,
                avatar_url=identity.avatar_url,
                access_token_enc=token_enc,
            )
            .on_conflict_do_update(
                index_elements=[User.github_user_id],
                set_={
                    "login": identity.login,
                    "avatar_url": identity.avatar_url,
                    "access_token_enc": token_enc,
                },
            )
            .returning(User.id)
        )

        with self._session_factory() as session:
            user_id = session.execute(stmt).scalar_one()
            session.commit()
        return user_id
