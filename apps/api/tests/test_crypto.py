"""Custodia de secretos AEAD (H5-T06, R8.2): round-trip, fail-closed y no-fuga.

Verifica: cifrado/descifrado autenticado de bytes y str; clave inválida ⇒ error claro (fail-closed);
nonce aleatorio (mismo plaintext ⇒ ciphertext distinto); detección de manipulación; redacción.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterator

import pytest

from app.security import crypto
from app.security.crypto import (
    CryptoKeyError,
    DecryptionError,
    decrypt_bytes,
    decrypt_str,
    encrypt_bytes,
    encrypt_str,
    redact,
)
from app.settings import Settings


def _settings_with_key(key_b64: str | None) -> Settings:
    """Construye `Settings` con una `encryption_key` concreta, sin tocar el entorno real."""
    return Settings(encryption_key=key_b64)


@pytest.fixture(autouse=True)
def _clean_cipher_cache() -> Iterator[None]:
    """Aísla cada test: limpia el cifrador cacheado antes y después."""
    crypto.reset_cipher_cache()
    yield
    crypto.reset_cipher_cache()


@pytest.fixture
def valid_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """Inyecta una clave AES-256 válida (32 bytes base64) vía `get_settings`."""
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    monkeypatch.setattr(crypto, "get_settings", lambda: _settings_with_key(key_b64))
    crypto.reset_cipher_cache()
    return key_b64


@pytest.mark.usefixtures("valid_key")
def test_round_trip_bytes() -> None:
    plaintext = b"github-oauth-token-\x00\xff-binario"
    blob = encrypt_bytes(plaintext)
    assert decrypt_bytes(blob) == plaintext


@pytest.mark.usefixtures("valid_key")
def test_round_trip_str() -> None:
    secret = "gho_tokenConAcentosÁÉÍ_y_emoji_🔐"
    blob = encrypt_str(secret)
    assert decrypt_str(blob) == secret


@pytest.mark.usefixtures("valid_key")
def test_round_trip_empty() -> None:
    # Plaintext vacío sigue siendo cifrable/autenticable (blob = nonce + tag).
    assert decrypt_bytes(encrypt_bytes(b"")) == b""
    assert decrypt_str(encrypt_str("")) == ""


@pytest.mark.usefixtures("valid_key")
def test_nonce_aleatorio_da_ciphertext_distinto() -> None:
    plaintext = b"mismo-secreto-cada-vez"
    blob_a = encrypt_bytes(plaintext)
    blob_b = encrypt_bytes(plaintext)
    # Dos cifrados del mismo texto NUNCA coinciden (nonce aleatorio por mensaje).
    assert blob_a != blob_b
    # Pero ambos descifran al mismo plaintext.
    assert decrypt_bytes(blob_a) == decrypt_bytes(blob_b) == plaintext


@pytest.mark.usefixtures("valid_key")
def test_ciphertext_no_contiene_plaintext() -> None:
    plaintext = b"SUPER_SECRETO_BUSCABLE"
    blob = encrypt_bytes(plaintext)
    # El secreto no aparece en claro dentro del blob cifrado (no-fuga en reposo).
    assert plaintext not in blob


@pytest.mark.usefixtures("valid_key")
def test_associated_data_debe_coincidir() -> None:
    plaintext = b"token-ligado-a-columna"
    blob = encrypt_bytes(plaintext, associated_data=b"users.access_token_enc")
    assert decrypt_bytes(blob, associated_data=b"users.access_token_enc") == plaintext
    # AAD distinta (o ausente) ⇒ fallo de autenticación, no descifrado silencioso.
    with pytest.raises(DecryptionError):
        decrypt_bytes(blob, associated_data=b"otra.columna")
    with pytest.raises(DecryptionError):
        decrypt_bytes(blob)


@pytest.mark.usefixtures("valid_key")
def test_blob_manipulado_falla_autenticacion() -> None:
    blob = bytearray(encrypt_bytes(b"intacto"))
    blob[-1] ^= 0x01  # corrompe el último byte (parte del tag)
    with pytest.raises(DecryptionError):
        decrypt_bytes(bytes(blob))


@pytest.mark.usefixtures("valid_key")
def test_blob_demasiado_corto_falla() -> None:
    with pytest.raises(DecryptionError):
        decrypt_bytes(b"corto")


@pytest.mark.parametrize(
    "key_value",
    [
        None,  # clave ausente
        "",  # cadena vacía
        "no-es-base64-válido-%%%",  # caracteres fuera del alfabeto base64
        base64.b64encode(os.urandom(16)).decode("ascii"),  # 16 bytes (AES-128, no permitido)
        base64.b64encode(os.urandom(31)).decode("ascii"),  # longitud incorrecta
    ],
)
def test_clave_invalida_es_fail_closed(
    monkeypatch: pytest.MonkeyPatch, key_value: str | None
) -> None:
    monkeypatch.setattr(crypto, "get_settings", lambda: _settings_with_key(key_value))
    crypto.reset_cipher_cache()
    # Cualquier clave inválida/ausente ⇒ error claro ANTES de cifrar (no se cifra con clave débil).
    with pytest.raises(CryptoKeyError):
        encrypt_bytes(b"no-debe-cifrarse")


def test_error_de_clave_no_filtra_la_clave(monkeypatch: pytest.MonkeyPatch) -> None:
    leaky = base64.b64encode(os.urandom(16)).decode("ascii")  # longitud inválida pero base64 ok
    monkeypatch.setattr(crypto, "get_settings", lambda: _settings_with_key(leaky))
    crypto.reset_cipher_cache()
    with pytest.raises(CryptoKeyError) as exc_info:
        encrypt_bytes(b"x")
    # El mensaje de error JAMÁS debe contener el material de la clave (NFR-Seg-3).
    assert leaky not in str(exc_info.value)


def test_redact_no_revela_el_secreto() -> None:
    secret = "gho_supersecretvalue1234567890"
    label = redact(secret)
    assert secret not in label
    assert "redacted" in label
    # Por defecto no muestra ningún carácter del secreto.
    assert "1234567890" not in label


def test_redact_visible_limita_a_la_mitad() -> None:
    secret = "abcdef"
    # Pedir 5 visibles sobre un secreto de 6 se acota a la mitad (3).
    label = redact(secret, visible=5)
    assert label.endswith("def>")
    assert "abc" not in label


def test_redact_vacio_y_none() -> None:
    assert redact(None) == "<empty>"
    assert redact("") == "<empty>"
    assert redact(b"") == "<empty>"


def test_redact_bytes() -> None:
    label = redact(b"\x00\x01\x02\x03")
    assert "redacted" in label
