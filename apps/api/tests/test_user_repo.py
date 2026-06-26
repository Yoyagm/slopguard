"""Unit test del upsert de `users` con token cifrado y AAD ligada (H5-T11, R1.5/R8.2).

No abre Postgres: dobla el `sessionmaker`/`Session` para capturar el `INSERT` y verifica la
invariante de seguridad — el token se persiste CIFRADO (no en claro) y la AAD liga el blob a la
columna+usuario, de modo que solo descifra en su contexto.
"""

from __future__ import annotations

import base64
import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from app.auth.user_repo import SqlUserRepository, _token_aad
from app.security import crypto
from app.security.crypto import DecryptionError, decrypt_str
from app.services.github import GitHubIdentity

_TOKEN = "gho_secreto_que_debe_cifrarse"


@pytest.fixture(autouse=True)
def _aead_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Inyecta una clave AES-256 válida para que el cifrado AEAD opere en el test."""
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    from app.settings import Settings

    monkeypatch.setattr(crypto, "get_settings", lambda: Settings(encryption_key=key_b64))
    crypto.reset_cipher_cache()
    yield
    crypto.reset_cipher_cache()


class _CaptureSession:
    """Session doble: captura los valores del INSERT y devuelve un UUID de `returning`."""

    def __init__(self, captured: dict[str, Any], user_id: uuid.UUID) -> None:
        self._captured = captured
        self._user_id = user_id

    def __enter__(self) -> _CaptureSession:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, stmt: Any) -> _CaptureSession:
        # Extrae los valores del INSERT compilado (sin tocar la DB).
        compiled = stmt.compile()
        self._captured.update(compiled.params)
        return self

    def scalar_one(self) -> uuid.UUID:
        return self._user_id

    def commit(self) -> None:
        return None


def _fake_session_factory(captured: dict[str, Any], user_id: uuid.UUID) -> Any:
    def factory() -> _CaptureSession:
        return _CaptureSession(captured, user_id)

    return factory


async def test_upsert_cifra_el_token_y_no_lo_persiste_en_claro() -> None:
    captured: dict[str, Any] = {}
    user_id = uuid.uuid4()
    repo = SqlUserRepository(_fake_session_factory(captured, user_id))
    identity = GitHubIdentity(github_user_id=4242, login="octocat", avatar_url=None)

    returned = await repo.upsert_from_oauth(identity, _TOKEN)

    assert returned == user_id
    token_blob = captured["access_token_enc"]
    assert isinstance(token_blob, bytes)
    # El token NO aparece en claro dentro del blob persistido (cifrado en reposo).
    assert _TOKEN.encode() not in token_blob

    # Descifra con la AAD correcta (columna+usuario) ⇒ recupera el token.
    aad = _token_aad(identity.github_user_id)
    assert decrypt_str(token_blob, associated_data=aad) == _TOKEN


async def test_upsert_aad_ligada_a_usuario_impide_descifrar_en_otro_contexto() -> None:
    captured: dict[str, Any] = {}
    repo = SqlUserRepository(_fake_session_factory(captured, uuid.uuid4()))
    identity = GitHubIdentity(github_user_id=1, login="a", avatar_url=None)

    await repo.upsert_from_oauth(identity, _TOKEN)
    token_blob = captured["access_token_enc"]

    # Intentar descifrar con la AAD de OTRO usuario falla (defensa contra swap entre filas).
    with pytest.raises(DecryptionError):
        decrypt_str(token_blob, associated_data=_token_aad(999))
