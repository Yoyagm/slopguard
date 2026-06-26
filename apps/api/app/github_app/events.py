"""Parseo defensivo de eventos de webhook de GitHub (R2.2/R2.4, design §2.3).

Funciones PURAS que transforman un payload JSON (ya autenticado por HMAC en el borde) en value
objects tipados. Aunque la firma garantiza que el cuerpo viene de GitHub, el payload sigue siendo
una estructura externa: validamos forma y tipos campo a campo y fallamos cerrado ante cualquier
desviación (`MalformedEventError`), en lugar de asumir claves o tipos.

Este módulo NO toca DB ni red: solo extrae datos. El router decide qué hacer con cada evento.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .installation_repo import InstallationData, RepoData

# Cabecera que GitHub usa para nombrar el tipo de evento (independiente del `action` del body).
EVENT_HEADER = "X-GitHub-Event"

# `full_name` legítimo de GitHub = "owner/repo" (dos segmentos con caracteres seguros). Validar
# aquí, en el BORDE del webhook, evita persistir un full_name anómalo ('..', '%2F', '@host', '?')
# que luego podría reescribir host/path en la GitHub Contents API (SSRF / path injection). Es la
# primera barrera; `contents_client` revalida como defensa en profundidad (NFR-Seg-3, ADR-4).
# Anclada con \A...\Z (no ^...$): `$` matchearía antes de un '\n' terminal y dejaría pasar
# "owner/repo\n" (CRLF injection); \Z exige el fin absoluto de la cadena.
_FULL_NAME_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")

# Acciones de `installation` que activan/desactivan la instalación. `suspend`/`unsuspend` y
# `deleted` NUNCA borran histórico (R2.4): el router las traduce a un cambio de `status`.
INSTALL_ACTION_DELETED = "deleted"
INSTALL_ACTION_SUSPEND = "suspend"
INSTALL_ACTION_UNSUSPEND = "unsuspend"


class MalformedEventError(ValueError):
    """El payload no tiene la forma esperada para el evento. Mensaje saneado (sin datos crudos)."""


@dataclass(frozen=True, slots=True)
class InstallationRepositoriesChange:
    """Delta de repos de una instalación (`installation_repositories`)."""

    installation_id: int
    added: tuple[RepoData, ...]
    removed_repo_ids: tuple[int, ...]


def _require_dict(value: object, field: str) -> dict[str, object]:
    """Devuelve `value` como dict o falla con un mensaje saneado (no incluye el valor crudo)."""
    if not isinstance(value, dict):
        raise MalformedEventError(f"campo {field!r} ausente o con forma inesperada")
    return value


def _require_int(value: object, field: str) -> int:
    """Extrae un entero estricto (un `bool` es int en Python; lo rechazamos explícitamente)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedEventError(f"campo {field!r} ausente o no es entero")
    return value


def _require_str(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise MalformedEventError(f"campo {field!r} ausente o no es texto")
    return value


def _require_full_name(value: object, field: str) -> str:
    """Exige un `full_name` con forma estricta "owner/repo" (anti SSRF / path injection).

    Aunque la firma HMAC autentica que el payload viene de GitHub, `full_name` se persiste y luego
    se interpola al llamar a la Contents API: un valor anómalo lo rechazamos en el borde (fail-
    closed) con `MalformedEventError`. El mensaje NO incluye el valor crudo (no eco de input).
    """
    text = _require_str(value, field)
    if not _FULL_NAME_RE.match(text):
        raise MalformedEventError(f"campo {field!r} con formato de repo inválido")
    owner, repo = text.split("/", 1)
    if owner in (".", "..") or repo in (".", ".."):
        raise MalformedEventError(f"campo {field!r} con segmento de traversal no permitido")
    return text


def _parse_repo(raw: object) -> RepoData:
    """Parsea una entrada de `repositories[]` (id, full_name, private)."""
    repo = _require_dict(raw, "repository")
    return RepoData(
        github_repo_id=_require_int(repo.get("id"), "repository.id"),
        full_name=_require_full_name(repo.get("full_name"), "repository.full_name"),
        # `private` puede faltar en algunos payloads; por defecto lo tratamos como público (False)
        # solo si está ausente. Si viene con un tipo no-bool, fallamos (no adivinamos).
        private=_parse_optional_bool(repo.get("private"), "repository.private"),
    )


def _parse_optional_bool(value: object, field: str) -> bool:
    """Bool con default False si ausente; tipo inválido ⇒ fallo (no inventamos)."""
    if value is None:
        return False
    if not isinstance(value, bool):
        raise MalformedEventError(f"campo {field!r} no es booleano")
    return value


def _parse_repo_list(raw: object, field: str) -> tuple[RepoData, ...]:
    """Parsea una lista de repos; lista ausente ⇒ vacía; entrada inválida ⇒ fallo."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise MalformedEventError(f"campo {field!r} no es una lista")
    return tuple(_parse_repo(item) for item in raw)


def parse_installation_event(payload: dict[str, object]) -> tuple[str, InstallationData]:
    """Parsea un evento `installation`. Devuelve `(action, InstallationData)`.

    `repositories` solo viene en `created`; en `deleted`/`suspend` puede faltar (lista vacía).
    El `account_login` sale de `installation.account.login` (cuenta donde se instaló).
    """
    action = _require_str(payload.get("action"), "action")
    installation = _require_dict(payload.get("installation"), "installation")
    account = _require_dict(installation.get("account"), "installation.account")

    data = InstallationData(
        installation_id=_require_int(installation.get("id"), "installation.id"),
        account_login=_require_str(account.get("login"), "installation.account.login"),
        repos=_parse_repo_list(payload.get("repositories"), "repositories"),
    )
    return action, data


def parse_installation_repositories_event(
    payload: dict[str, object],
) -> InstallationRepositoriesChange:
    """Parsea un evento `installation_repositories` (delta de repos `added`/`removed`)."""
    installation = _require_dict(payload.get("installation"), "installation")
    installation_id = _require_int(installation.get("id"), "installation.id")

    added = _parse_repo_list(payload.get("repositories_added"), "repositories_added")
    removed = _parse_repo_list(payload.get("repositories_removed"), "repositories_removed")
    removed_ids = tuple(repo.github_repo_id for repo in removed)

    return InstallationRepositoriesChange(
        installation_id=installation_id, added=added, removed_repo_ids=removed_ids
    )
