"""Repositorio de instalaciones de la GitHub App (R2.1/R2.2/R2.4, design §3.1).

Espejo del patrón de `user_repo.py`/`scan_repo.py`: un `Protocol` inyectable + una implementación
SQLAlchemy (síncrona, ejecutada en threadpool para no bloquear el event loop) + un doble en memoria
para tests sin Postgres.

Responsabilidades acotadas a la Ola 4:
  - `upsert_installation`: alta/actualización idempotente de `github_installations` + sincronización
    de la lista de `repos` accesibles (R2.2). Idempotente porque GitHub reentrega webhooks.
  - `sync_repos`: añade/quita repos de una instalación ya existente (`installation_repositories`).
  - `set_status`: marca `active`/`revoked`/`suspended` SIN borrar el histórico de `scans` (R2.4).

Invariante R2.4 (NUNCA borrar histórico): desinstalar/suspender solo cambia `status`. Al quitar
repos (`removed`) se borran SOLO las filas de `repos` que no tengan `scans` asociados; un repo con
histórico se conserva para no romper la FK `scans.repo_id` ni perder escaneos pasados.
"""

from __future__ import annotations

import dataclasses
import uuid
from dataclasses import dataclass
from typing import Protocol

from anyio import to_thread
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, sessionmaker

from ..db.models import GithubInstallation, Repo, Scan, User

# ---------------------------------------------------------------------------
# Value objects de lectura (consultas H5-T23)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InstallationSummary:
    """Resumen de una instalación para el endpoint GET /installations."""

    id: uuid.UUID  # PK interna
    installation_id: int  # ID de GitHub App
    account_login: str
    status: str


@dataclass(frozen=True, slots=True)
class RepoSummary:
    """Resumen de un repo accesible para el endpoint GET /repos."""

    id: uuid.UUID  # PK interna
    installation_id: uuid.UUID  # FK → github_installations.id
    github_repo_id: int
    full_name: str
    private: bool


@dataclass(frozen=True, slots=True)
class RepoWithInstallation:
    """Repo + ID de instalación de GitHub (entero) para obtener el installation token (T24)."""

    repo: RepoSummary
    # ID de GitHub App (entero), necesario para llamar a get_installation_token.
    github_installation_id: int
    # owner/name del repo, p.ej. "acme/my-app" — usado en la contents API.
    full_name: str


# Estados válidos de una instalación. `active` es operativa; los otros dos la desactivan SIN
# borrar histórico (R2.4). Se mapean desde las `action` del webhook en el router.
STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"  # action=deleted (desinstalada)
STATUS_SUSPENDED = "suspended"  # action=suspend
_VALID_STATUSES = frozenset({STATUS_ACTIVE, STATUS_REVOKED, STATUS_SUSPENDED})


@dataclass(frozen=True, slots=True)
class RepoData:
    """Datos mínimos de un repo accesible (de `repositories[]` del webhook, design §3.1)."""

    github_repo_id: int
    full_name: str
    private: bool


@dataclass(frozen=True, slots=True)
class InstallationData:
    """Datos de una instalación de la GitHub App (de `installation` del webhook, design §3.1)."""

    installation_id: int
    account_login: str
    repos: tuple[RepoData, ...]


class InstallationRepository(Protocol):
    """Contrato del repositorio de instalaciones. Inyectable; se dobla en tests sin Postgres."""

    async def resolve_owner(self, github_user_id: int) -> uuid.UUID | None:
        """Resuelve el `users.id` interno del instalador; None si es desconocido.

        Una instalación de un GitHub user que nunca inició sesión (no está en `users`) no se puede
        asociar a un dueño: el router la descarta (fail-closed, demo single-tenant).
        """
        ...

    async def upsert_installation(
        self, data: InstallationData, *, user_id: uuid.UUID
    ) -> uuid.UUID:
        """Crea/actualiza la instalación y sincroniza repos. Devuelve `github_installations.id`."""
        ...

    async def sync_repos(
        self,
        *,
        installation_id: int,
        added: tuple[RepoData, ...],
        removed_repo_ids: tuple[int, ...],
    ) -> bool:
        """Aplica el delta `added`/`removed`. False si la instalación no existe."""
        ...

    async def set_status(self, *, installation_id: int, status: str) -> bool:
        """Cambia el `status` (no borra histórico, R2.4). False si la instalación no existe."""
        ...

    async def list_for_user(self, user_id: uuid.UUID) -> list[InstallationSummary]:
        """Lista las instalaciones del usuario (R2.3), ordenadas por `created_at` DESC."""
        ...

    async def list_repos_for_user(
        self,
        user_id: uuid.UUID,
        *,
        installation_id: int | None = None,
    ) -> list[RepoSummary]:
        """Lista los repos accesibles del usuario, opcionalmente filtrados por instalación.

        Solo devuelve repos de instalaciones `active` (una instalación revocada no da acceso).
        Si `installation_id` se pasa, filtra además por esa instalación concreta.
        """
        ...

    async def get_repo_with_installation_id(
        self,
        repo_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> RepoWithInstallation | None:
        """Devuelve el repo + ID de instalación de GitHub para el scan desde repo (T24).

        Devuelve None si:
        - El repo no existe.
        - El repo no pertenece al usuario (aislamiento R5.3).
        - La instalación asociada no está `active` (R2.4: instalación revocada ⇒ sin acceso).
        El caller debe responder 422 "repo no disponible" en todos estos casos (no distinguir
        la causa concreta evita enumerar repos de otros usuarios).
        """
        ...


def _validate_status(status: str) -> None:
    """Rechaza un status fuera del conjunto cerrado (fail-closed: no escribimos basura en DB)."""
    if status not in _VALID_STATUSES:
        raise ValueError(f"status de instalación no válido: {status!r}")


class SqlInstallationRepository:
    """Implementación SQLAlchemy. Cumple `InstallationRepository`.

    El motor del proyecto es síncrono; los métodos se exponen async vía threadpool (igual que
    `user_repo`/`scan_repo`) para no bloquear el event loop del handler del webhook.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    async def resolve_owner(self, github_user_id: int) -> uuid.UUID | None:
        return await to_thread.run_sync(self._resolve_owner_sync, github_user_id)

    async def upsert_installation(
        self, data: InstallationData, *, user_id: uuid.UUID
    ) -> uuid.UUID:
        return await to_thread.run_sync(self._upsert_installation_sync, data, user_id)

    def _resolve_owner_sync(self, github_user_id: int) -> uuid.UUID | None:
        with self._session_factory() as session:
            return session.execute(
                select(User.id).where(User.github_user_id == github_user_id)
            ).scalar_one_or_none()

    async def sync_repos(
        self,
        *,
        installation_id: int,
        added: tuple[RepoData, ...],
        removed_repo_ids: tuple[int, ...],
    ) -> bool:
        return await to_thread.run_sync(
            self._sync_repos_sync, installation_id, added, removed_repo_ids
        )

    async def set_status(self, *, installation_id: int, status: str) -> bool:
        _validate_status(status)
        return await to_thread.run_sync(self._set_status_sync, installation_id, status)

    async def list_for_user(self, user_id: uuid.UUID) -> list[InstallationSummary]:
        return await to_thread.run_sync(self._list_for_user_sync, user_id)

    async def list_repos_for_user(
        self,
        user_id: uuid.UUID,
        *,
        installation_id: int | None = None,
    ) -> list[RepoSummary]:
        return await to_thread.run_sync(
            self._list_repos_for_user_sync, user_id, installation_id
        )

    async def get_repo_with_installation_id(
        self,
        repo_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> RepoWithInstallation | None:
        return await to_thread.run_sync(
            self._get_repo_with_installation_id_sync, repo_id, user_id
        )

    def _get_repo_with_installation_id_sync(
        self,
        repo_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> RepoWithInstallation | None:
        """Busca repo + instalación activa del usuario para el scan desde repo (T24, R5.3)."""
        with self._session_factory() as session:
            row = session.execute(
                select(
                    Repo.id,
                    Repo.installation_id,
                    Repo.github_repo_id,
                    Repo.full_name,
                    Repo.private,
                    GithubInstallation.installation_id.label("gh_installation_id"),
                )
                .join(GithubInstallation, Repo.installation_id == GithubInstallation.id)
                .where(
                    Repo.id == repo_id,
                    GithubInstallation.user_id == user_id,
                    GithubInstallation.status == STATUS_ACTIVE,
                )
            ).one_or_none()

        if row is None:
            return None

        repo_summary = RepoSummary(
            id=row.id,
            installation_id=row.installation_id,
            github_repo_id=row.github_repo_id,
            full_name=row.full_name,
            private=row.private,
        )
        return RepoWithInstallation(
            repo=repo_summary,
            github_installation_id=row.gh_installation_id,
            full_name=row.full_name,
        )

    def _list_for_user_sync(self, user_id: uuid.UUID) -> list[InstallationSummary]:
        with self._session_factory() as session:
            rows = session.execute(
                select(
                    GithubInstallation.id,
                    GithubInstallation.installation_id,
                    GithubInstallation.account_login,
                    GithubInstallation.status,
                )
                .where(GithubInstallation.user_id == user_id)
                .order_by(GithubInstallation.created_at.desc())
            ).all()
        return [
            InstallationSummary(
                id=row.id,
                installation_id=row.installation_id,
                account_login=row.account_login,
                status=row.status,
            )
            for row in rows
        ]

    def _list_repos_for_user_sync(
        self,
        user_id: uuid.UUID,
        installation_id_gh: int | None,
    ) -> list[RepoSummary]:
        """Lista repos accesibles del usuario filtrando por instalación activa."""
        with self._session_factory() as session:
            stmt = (
                select(
                    Repo.id,
                    Repo.installation_id,
                    Repo.github_repo_id,
                    Repo.full_name,
                    Repo.private,
                )
                .join(GithubInstallation, Repo.installation_id == GithubInstallation.id)
                .where(
                    GithubInstallation.user_id == user_id,
                    GithubInstallation.status == STATUS_ACTIVE,
                )
                .order_by(Repo.full_name)
            )
            if installation_id_gh is not None:
                stmt = stmt.where(
                    GithubInstallation.installation_id == installation_id_gh
                )
            rows = session.execute(stmt).all()
        return [
            RepoSummary(
                id=row.id,
                installation_id=row.installation_id,
                github_repo_id=row.github_repo_id,
                full_name=row.full_name,
                private=row.private,
            )
            for row in rows
        ]

    def _upsert_installation_sync(
        self, data: InstallationData, user_id: uuid.UUID
    ) -> uuid.UUID:
        with self._session_factory() as session:
            # Dueño existente (si la instalación ya estaba registrada): lo necesitamos para NO
            # reasignarlo en una re-entrega. Una instalación pertenece a quien la creó.
            existing_owner = session.execute(
                select(GithubInstallation.user_id).where(
                    GithubInstallation.installation_id == data.installation_id
                )
            ).scalar_one_or_none()

            # SEC: un evento (HMAC-válido) con `sender` distinto al dueño NO debe reasignar la
            # instalación a otro usuario — eso le daría visibilidad del histórico ajeno. Detectamos
            # y logueamos la anomalía SIN secretos (solo ids internos), y conservamos el dueño.
            if existing_owner is not None and existing_owner != user_id:
                import logging as _log

                _log.getLogger(__name__).warning(
                    "installation %d re-entregada con un sender distinto del dueño original; "
                    "se conserva el dueño (no se reasigna).",
                    data.installation_id,
                )

            # Upsert atómico por `installation_id` de GitHub. Reactiva `status=active` (una re-
            # instalación tras revocar vuelve a operativa) y refresca metadata, pero el `set_`
            # EXCLUYE `user_id`: el dueño de una instalación existente jamás se reasigna (SEC).
            # `user_id` solo se fija en `values(...)`, que aplica únicamente al INSERT inicial.
            stmt = (
                insert(GithubInstallation)
                .values(
                    installation_id=data.installation_id,
                    user_id=user_id,
                    account_login=data.account_login,
                    status=STATUS_ACTIVE,
                )
                .on_conflict_do_update(
                    index_elements=[GithubInstallation.installation_id],
                    set_={
                        "account_login": data.account_login,
                        "status": STATUS_ACTIVE,
                    },
                )
                .returning(GithubInstallation.id)
            )
            internal_id: uuid.UUID = session.execute(stmt).scalar_one()
            self._upsert_repos(session, internal_id, data.repos)
            session.commit()
            return internal_id

    def _sync_repos_sync(
        self,
        installation_id: int,
        added: tuple[RepoData, ...],
        removed_repo_ids: tuple[int, ...],
    ) -> bool:
        with self._session_factory() as session:
            internal_id = session.execute(
                select(GithubInstallation.id).where(
                    GithubInstallation.installation_id == installation_id
                )
            ).scalar_one_or_none()
            if internal_id is None:
                # Webhook de repos para una instalación que nunca persistimos: descartar (no
                # inventamos una instalación sin su evento `created`).
                return False

            self._upsert_repos(session, internal_id, added)
            self._remove_repos(session, internal_id, removed_repo_ids)
            session.commit()
            return True

    def _set_status_sync(self, installation_id: int, status: str) -> bool:
        with self._session_factory() as session:
            installation = session.execute(
                select(GithubInstallation).where(
                    GithubInstallation.installation_id == installation_id
                )
            ).scalar_one_or_none()
            if installation is None:
                return False
            # R2.4: SOLO cambiamos el status; los `scans` y `repos` permanecen intactos.
            installation.status = status
            session.commit()
            return True

    @staticmethod
    def _upsert_repos(
        session: Session, internal_installation_id: uuid.UUID, repos: tuple[RepoData, ...]
    ) -> None:
        """Upsert idempotente de repos por (installation_id, github_repo_id)."""
        for repo in repos:
            stmt = (
                insert(Repo)
                .values(
                    installation_id=internal_installation_id,
                    github_repo_id=repo.github_repo_id,
                    full_name=repo.full_name,
                    private=repo.private,
                )
                .on_conflict_do_update(
                    # Nombre del constraint declarado en el modelo (design §3.1).
                    constraint="uq_repos_installation_repo",
                    set_={"full_name": repo.full_name, "private": repo.private},
                )
            )
            session.execute(stmt)

    @staticmethod
    def _remove_repos(
        session: Session, internal_installation_id: uuid.UUID, removed_repo_ids: tuple[int, ...]
    ) -> None:
        """Borra repos quitados que NO tengan histórico de scans (R2.4: nunca borrar histórico).

        Un repo con `scans` asociados se conserva (de lo contrario rompería la FK `scans.repo_id`
        y perdería escaneos pasados). El listado de `/repos` (T23) filtrará por instalación activa,
        así que un repo huérfano conservado no se muestra como accesible.
        """
        if not removed_repo_ids:
            return

        # Subconjunto de los repos a quitar que SÍ tienen scans: esos se conservan.
        repos_to_remove = session.execute(
            select(Repo.id, Repo.github_repo_id).where(
                Repo.installation_id == internal_installation_id,
                Repo.github_repo_id.in_(removed_repo_ids),
            )
        ).all()

        for repo_internal_id, _github_repo_id in repos_to_remove:
            has_scans = session.execute(
                select(func.count()).select_from(Scan).where(Scan.repo_id == repo_internal_id)
            ).scalar_one()
            if has_scans:
                # Conservado por histórico (R2.4); no se borra.
                continue
            session.execute(delete(Repo).where(Repo.id == repo_internal_id))


class FakeInstallationRepository:
    """Doble en memoria para tests sin Postgres. Paridad con `SqlInstallationRepository`.

    Modela las propiedades observables que importan a los tests de aceptación:
      - upsert idempotente por `installation_id` (re-entregar el webhook no duplica).
      - `set_status` cambia el status sin tocar la lista de repos ni histórico (R2.4).
      - `sync_repos` añade/quita repos (sin la regla de FK del SQL, irrelevante en memoria).
    """

    def __init__(self) -> None:
        # installation_id (GitHub) → (internal_id, user_id, account_login, status, repos por id)
        self._installations: dict[int, _FakeInstallationState] = {}
        # github_user_id → users.id interno (dueños conocidos, sembrados por el test).
        self._owners: dict[int, uuid.UUID] = {}
        self.status_changes: list[tuple[int, str]] = []

    def seed_owner(self, github_user_id: int, user_id: uuid.UUID) -> None:
        """Registra un dueño conocido (atajo para tests: simula un usuario ya logueado)."""
        self._owners[github_user_id] = user_id

    async def resolve_owner(self, github_user_id: int) -> uuid.UUID | None:
        return self._owners.get(github_user_id)

    async def upsert_installation(
        self, data: InstallationData, *, user_id: uuid.UUID
    ) -> uuid.UUID:
        existing = self._installations.get(data.installation_id)
        internal_id = existing.internal_id if existing else uuid.uuid4()
        # Preservar los UUIDs internos de repos ya existentes (idempotencia).
        existing_repo_ids = existing.repo_internal_ids if existing else {}
        repo_internal_ids = {
            r.github_repo_id: existing_repo_ids.get(r.github_repo_id, uuid.uuid4())
            for r in data.repos
        }
        state = _FakeInstallationState(
            internal_id=internal_id,
            user_id=user_id,
            account_login=data.account_login,
            status=STATUS_ACTIVE,
            repos={r.github_repo_id: r for r in data.repos},
            repo_internal_ids=repo_internal_ids,
        )
        self._installations[data.installation_id] = state
        return internal_id

    async def sync_repos(
        self,
        *,
        installation_id: int,
        added: tuple[RepoData, ...],
        removed_repo_ids: tuple[int, ...],
    ) -> bool:
        state = self._installations.get(installation_id)
        if state is None:
            return False
        for repo in added:
            state.repos[repo.github_repo_id] = repo
            # Asignar UUID interno estable si es un repo nuevo.
            if repo.github_repo_id not in state.repo_internal_ids:
                state.repo_internal_ids[repo.github_repo_id] = uuid.uuid4()
        for repo_id in removed_repo_ids:
            state.repos.pop(repo_id, None)
            state.repo_internal_ids.pop(repo_id, None)
        return True

    async def set_status(self, *, installation_id: int, status: str) -> bool:
        _validate_status(status)
        state = self._installations.get(installation_id)
        if state is None:
            return False
        state.status = status
        self.status_changes.append((installation_id, status))
        return True

    async def list_for_user(self, user_id: uuid.UUID) -> list[InstallationSummary]:
        return [
            InstallationSummary(
                id=state.internal_id,
                installation_id=iid,
                account_login=state.account_login,
                status=state.status,
            )
            for iid, state in self._installations.items()
            if state.user_id == user_id
        ]

    async def list_repos_for_user(
        self,
        user_id: uuid.UUID,
        *,
        installation_id: int | None = None,
    ) -> list[RepoSummary]:
        results: list[RepoSummary] = []
        for iid, state in self._installations.items():
            if state.user_id != user_id:
                continue
            if state.status != STATUS_ACTIVE:
                continue
            if installation_id is not None and iid != installation_id:
                continue
            for repo in state.repos.values():
                # Usamos el UUID interno estable (generado al upsert/sync).
                internal_id = state.repo_internal_ids.get(
                    repo.github_repo_id, uuid.uuid4()
                )
                results.append(
                    RepoSummary(
                        id=internal_id,
                        installation_id=state.internal_id,
                        github_repo_id=repo.github_repo_id,
                        full_name=repo.full_name,
                        private=repo.private,
                    )
                )
        results.sort(key=lambda r: r.full_name)
        return results

    async def get_repo_with_installation_id(
        self,
        repo_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> RepoWithInstallation | None:
        """Busca repo por UUID interno para el scan desde repo (T24, aislamiento R5.3)."""
        for gh_iid, state in self._installations.items():
            if state.user_id != user_id:
                continue
            if state.status != STATUS_ACTIVE:
                continue
            for gh_repo_id, repo in state.repos.items():
                if state.repo_internal_ids.get(gh_repo_id) == repo_id:
                    repo_summary = RepoSummary(
                        id=repo_id,
                        installation_id=state.internal_id,
                        github_repo_id=repo.github_repo_id,
                        full_name=repo.full_name,
                        private=repo.private,
                    )
                    return RepoWithInstallation(
                        repo=repo_summary,
                        github_installation_id=gh_iid,
                        full_name=repo.full_name,
                    )
        return None

    def get_state(self, installation_id: int) -> _FakeInstallationState | None:
        """Atajo para que los tests inspeccionen el estado persistido."""
        return self._installations.get(installation_id)


@dataclass
class _FakeInstallationState:
    """Estado interno del doble en memoria (no público)."""

    internal_id: uuid.UUID
    user_id: uuid.UUID
    account_login: str
    status: str
    repos: dict[int, RepoData]
    # github_repo_id → UUID interno estable (se genera al añadir el repo).
    repo_internal_ids: dict[int, uuid.UUID] = dataclasses.field(default_factory=dict)
