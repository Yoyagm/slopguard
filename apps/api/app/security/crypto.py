"""Custodia de secretos: cifrado AEAD en reposo (ADR-4, R8.2, NFR-Seg-3).

Cifra/descifra bytes y strings con **AES-256-GCM** (AEAD autenticado) usando la librería
`cryptography`. La clave maestra entra SOLO por entorno (`Settings.encryption_key`, base64 de
32 bytes); si falta o es inválida se aplica **fail-closed** (nunca se cifra con clave débil).

Formato del blob persistido (compatible con `BYTEA` de `users.access_token_enc`, design §3.1):

    nonce(12 bytes) || ciphertext || tag(16 bytes)

`AESGCM.encrypt()` ya devuelve `ciphertext || tag` concatenados, así que el blob es simplemente
`nonce || encrypt(...)`. El nonce es aleatorio por mensaje (CSPRNG): reutilizarlo con la misma
clave rompe GCM de forma catastrófica, por eso JAMÁS es determinista ni se reutiliza.

Invariante de NO-FUGA: ni la clave ni los secretos en claro aparecen en excepciones, `repr` o logs.
Para registrar referencias a secretos use `redact()`.
"""

from __future__ import annotations

import base64
import binascii
import os
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..settings import Settings, get_settings

# AES-256 ⇒ clave de 32 bytes. Nonce GCM de 96 bits (12 bytes), el recomendado por NIST SP 800-38D.
_KEY_BYTES = 32
_NONCE_BYTES = 12
_TAG_BYTES = 16
# Blob mínimo legible: nonce + tag (ciphertext puede ser vacío para plaintext vacío).
_MIN_BLOB_BYTES = _NONCE_BYTES + _TAG_BYTES


class CryptoError(Exception):
    """Error base de la custodia de secretos. Nunca incluye material secreto en su mensaje."""


class CryptoKeyError(CryptoError):
    """La clave maestra falta o es inválida (fail-closed: no se cifra con clave débil)."""


class DecryptionError(CryptoError):
    """El descifrado/autenticación falló: blob corrupto, manipulado o clave incorrecta."""


def _load_key(settings: Settings) -> bytes:
    """Decodifica y valida la clave maestra desde `Settings.encryption_key` (fail-closed).

    Reglas (cualquier incumplimiento ⇒ `CryptoKeyError`, sin filtrar el valor de la clave):
    - debe estar presente (no `None`/vacía);
    - debe ser base64 estándar válido;
    - debe decodificar a EXACTAMENTE 32 bytes (AES-256).
    """
    secret = settings.encryption_key
    if secret is None:
        raise CryptoKeyError(
            "encryption_key no configurada: el cifrado en reposo no puede operar (fail-closed)."
        )
    # SecretStr: el valor solo se desempaqueta aquí, en el borde que lo decodifica.
    raw = secret.get_secret_value()
    if not raw:
        raise CryptoKeyError(
            "encryption_key no configurada: el cifrado en reposo no puede operar (fail-closed)."
        )

    try:
        # `validate=True` rechaza caracteres fuera del alfabeto base64 (no silencia basura).
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        # No se incluye `raw` en el mensaje: es material sensible.
        raise CryptoKeyError("encryption_key no es base64 válido (fail-closed).") from exc

    if len(key) != _KEY_BYTES:
        raise CryptoKeyError(
            f"encryption_key debe decodificar a {_KEY_BYTES} bytes (AES-256); "
            f"se obtuvieron {len(key)} (fail-closed)."
        )
    return key


@lru_cache(maxsize=1)
def _get_cipher() -> AESGCM:
    """Cifrador AEAD ligado a la clave de entorno (cacheado: la clave no cambia en runtime).

    Se construye perezosamente para no exigir la clave en contextos que no cifran (p.ej. tests
    de import). Si la clave es inválida, falla aquí en lugar de degradar silenciosamente.
    """
    key = _load_key(get_settings())
    return AESGCM(key)


def reset_cipher_cache() -> None:
    """Invalida el cifrador cacheado. Solo para tests que cambian `encryption_key` en runtime."""
    _get_cipher.cache_clear()


def encrypt_bytes(plaintext: bytes, *, associated_data: bytes | None = None) -> bytes:
    """Cifra bytes con AES-256-GCM y devuelve `nonce || ciphertext || tag`.

    `associated_data` (AAD) se autentica pero no se cifra; úsela para ligar el blob a un contexto
    (p.ej. el nombre de columna) y evitar reutilizar un ciphertext en otro lugar. Debe coincidir
    bit a bit en el descifrado.
    """
    cipher = _get_cipher()
    # Nonce aleatorio por mensaje: imprescindible para no reutilizar (nonce, clave) en GCM.
    nonce = os.urandom(_NONCE_BYTES)
    sealed = cipher.encrypt(nonce, plaintext, associated_data)
    return nonce + sealed


def decrypt_bytes(blob: bytes, *, associated_data: bytes | None = None) -> bytes:
    """Descifra y AUTENTICA un blob `nonce || ciphertext || tag`. Devuelve el plaintext.

    Lanza `DecryptionError` si el blob es demasiado corto, está corrupto/manipulado, o la clave
    (o la AAD) no corresponde. Nunca devuelve datos parciales ni sin verificar la integridad.
    """
    if len(blob) < _MIN_BLOB_BYTES:
        raise DecryptionError(
            f"blob cifrado demasiado corto: {len(blob)} bytes < mínimo {_MIN_BLOB_BYTES}."
        )

    cipher = _get_cipher()
    nonce, sealed = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    try:
        return cipher.decrypt(nonce, sealed, associated_data)
    except InvalidTag as exc:
        # Falla de autenticación: datos manipulados, AAD distinta o clave incorrecta.
        # No se expone el blob ni el nonce; el detalle criptográfico no aporta y es ruido.
        raise DecryptionError(
            "fallo de autenticación AEAD: el secreto está corrupto o la clave no corresponde."
        ) from exc


def encrypt_str(plaintext: str, *, associated_data: bytes | None = None) -> bytes:
    """Cifra un string (UTF-8) y devuelve el blob AEAD. Útil para tokens OAuth (R8.2)."""
    return encrypt_bytes(plaintext.encode("utf-8"), associated_data=associated_data)


def decrypt_str(blob: bytes, *, associated_data: bytes | None = None) -> str:
    """Descifra un blob AEAD a string (UTF-8). Inverso exacto de `encrypt_str`."""
    plaintext = decrypt_bytes(blob, associated_data=associated_data)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        # El plaintext autenticado no es UTF-8: se cifró como bytes, no como str.
        raise DecryptionError("el secreto descifrado no es texto UTF-8 válido.") from exc


def assert_no_token_leak(token: str, *haystacks: str) -> None:
    """Verifica que `token` NO aparece en ninguno de los `haystacks` (respuestas / logs).

    Lanza `AssertionError` con mensaje saneado (sin el token en claro) si hay fuga.
    Uso exclusivo en tests: permite que el equipo añada esta verificación a cualquier
    respuesta HTTP donde el token de GitHub no deba estar presente (R1.5, NFR-Seg-3).

    Ejemplo::

        assert_no_token_leak(raw_token, resp.text, *resp.headers.values())
    """
    for idx, haystack in enumerate(haystacks):
        if token in haystack:
            raise AssertionError(
                f"Fuga de token detectada en haystack[{idx}]: "
                f"token {redact(token)} aparece en la cadena. "
                "El token NUNCA debe viajar al cliente ni a logs (R1.5, NFR-Seg-3)."
            )


def redact(secret: str | bytes | None) -> str:
    """Devuelve una etiqueta SEGURA para logs que NO revela el secreto (NFR-Seg-3).

    Cero-revelación por construcción: NUNCA expone caracteres del secreto, solo su longitud
    (suficiente para correlacionar logs sin filtrar material). Para `None` o vacío devuelve
    `"<empty>"`. No admite un parámetro `visible`: cualquier carácter revelado de un token/secreto
    es una fuga, y no existe un caso de uso real que lo justifique (se eliminó a propósito).
    """
    if secret is None:
        return "<empty>"

    text = secret.decode("utf-8", errors="replace") if isinstance(secret, bytes) else secret
    length = len(text)
    if length == 0:
        return "<empty>"

    return f"<redacted:{length}>"
