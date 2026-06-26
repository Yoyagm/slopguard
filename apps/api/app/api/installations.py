"""Endpoints de instalaciones y repos de la GitHub App (H5-T23, R2.3/R2.5, design §4.1).

GET /api/v1/installations  — lista las instalaciones del usuario con su status (R2.3).
GET /api/v1/repos          — repos accesibles del usuario; opcional: filtrar por
                             `installation_id` (query param, ID de GitHub App).

Ambos requieren sesión activa (cookie httpOnly, `require_user`). La información devuelta
es metadata pública de GitHub (account_login, full_name), no secretos.

El installation token NO se devuelve aquí ni en ningún endpoint de cliente (ADR-4).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict

from ..auth.guard import require_user
from ..db.models import User
from ..github_app.deps import get_installation_repository
from ..github_app.installation_repo import InstallationRepository

router = APIRouter(tags=["installations"])

# Alias del usuario autenticado (reutiliza el guard de sesión).
CurrentUser = Annotated[User, Depends(require_user)]
InstallationRepoDep = Annotated[InstallationRepository, Depends(get_installation_repository)]


# ---------------------------------------------------------------------------
# Schemas de respuesta
# ---------------------------------------------------------------------------


class InstallationResponse(BaseModel):
    """Resumen de una instalación de la GitHub App para el dashboard (R2.3)."""

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    installation_id: int
    account_login: str
    status: str


class RepoResponse(BaseModel):
    """Repo accesible a través de una instalación activa (R2.3)."""

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    installation_id: uuid.UUID  # PK interna de github_installations
    github_repo_id: int
    full_name: str
    private: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/installations", response_model=list[InstallationResponse])
async def list_installations(
    current_user: CurrentUser,
    repo: InstallationRepoDep,
) -> list[InstallationResponse]:
    """Lista las instalaciones de la GitHub App del usuario autenticado (R2.3).

    Incluye instalaciones en cualquier estado (`active`, `revoked`, `suspended`) para que
    el dashboard pueda mostrar el historial completo al usuario, no solo las operativas.
    """
    installations = await repo.list_for_user(current_user.id)
    return [
        InstallationResponse(
            id=inst.id,
            installation_id=inst.installation_id,
            account_login=inst.account_login,
            status=inst.status,
        )
        for inst in installations
    ]


@router.get("/repos", response_model=list[RepoResponse])
async def list_repos(
    current_user: CurrentUser,
    repo: InstallationRepoDep,
    installation_id: Annotated[
        int | None,
        Query(
            description=(
                "ID de la GitHub App installation (número de GitHub, no UUID interno). "
                "Si se omite, devuelve repos de todas las instalaciones activas del usuario."
            )
        ),
    ] = None,
) -> list[RepoResponse]:
    """Lista los repos accesibles del usuario autenticado (R2.3).

    Solo devuelve repos de instalaciones `active`. Si se pasa `installation_id`, filtra
    a esa instalación concreta (útil para el selector de repo del escaneo on-demand).

    El installation token NO se usa ni se devuelve aquí: esta ruta lee la DB local.
    La sincronización de repos llega vía webhook `installation_repositories`.
    """
    repos = await repo.list_repos_for_user(
        current_user.id,
        installation_id=installation_id,
    )
    return [
        RepoResponse(
            id=r.id,
            installation_id=r.installation_id,
            github_repo_id=r.github_repo_id,
            full_name=r.full_name,
            private=r.private,
        )
        for r in repos
    ]
