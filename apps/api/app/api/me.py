"""Endpoint protegido `GET /me` — ejercita el guard de sesión (H5-T12, ADR-4).

Devuelve la identidad pública del usuario autenticado (login + id). Nunca expone el token
de GitHub ni ningún secreto; `access_token_enc` queda dentro del ORM pero no se serializa.

Este endpoint sirve también como punto de validación de sesión para el front: si la cookie
expiró o es inválida, `require_user` lanza 401 antes de llegar al handler.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..auth.guard import require_user
from ..db.models import User

router = APIRouter(tags=["me"])

# Tipo anotado de la dependencia de usuario autenticado — reutilizable en otros routers.
CurrentUser = Annotated[User, Depends(require_user)]


class MeResponse(BaseModel):
    """Identidad pública del usuario autenticado. Sin secretos."""

    id: uuid.UUID
    login: str
    avatar_url: str | None


@router.get("/me", response_model=MeResponse)
async def get_me(current_user: CurrentUser) -> MeResponse:
    """Devuelve la identidad pública del usuario con sesión activa (R1, ADR-4).

    Sin sesión válida en cookie → `require_user` lanza 401 antes de llegar aquí.
    """
    return MeResponse(
        id=current_user.id,
        login=current_user.login,
        avatar_url=current_user.avatar_url,
    )
