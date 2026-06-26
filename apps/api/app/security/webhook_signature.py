"""Verificación HMAC de webhooks de GitHub (ADR-4, R6.1, NFR-Seg-2).

Esta es la frontera de confianza del receptor de webhooks: GitHub es un actor EXTERNO no
confiable hasta que la firma valida. La función `verify_signature` calcula el HMAC-SHA256 del
**cuerpo crudo** (los bytes exactos que GitHub firmó) y lo compara con la cabecera
``X-Hub-Signature-256`` en **tiempo constante** (`hmac.compare_digest`).

Invariantes de seguridad (intencionadamente estrictas):
  1. Se opera SIEMPRE sobre `bytes` crudos del cuerpo, JAMÁS sobre el JSON ya parseado: al
     re-serializar cambiarían los bytes y, peor, se expondría el parser a entrada no autenticada
     (superficie de RCE/DoS). El caller DEBE invocar esto ANTES de parsear el evento.
  2. La comparación es de tiempo constante: un `==` filtraría la firma byte a byte por timing.
  3. Fail-closed: cabecera ausente/malformada o secreto vacío ⇒ `False` (descartar), nunca `True`.
  4. No-fuga: ni el secreto ni la firma esperada aparecen en excepciones ni en logs.
"""

from __future__ import annotations

import hashlib
import hmac

# GitHub firma con HMAC-SHA256 y prefija la cabecera con el nombre del algoritmo.
_SIGNATURE_HEADER = "X-Hub-Signature-256"
_SIGNATURE_PREFIX = "sha256="
# Longitud en hex de un digest SHA-256 (32 bytes ⇒ 64 chars). Una firma con otra longitud es
# inválida por construcción y se descarta sin computar nada (defensa barata previa).
_SHA256_HEX_LEN = 64


def expected_signature(secret: str, raw_body: bytes) -> str:
    """Calcula la firma `sha256=<hex>` esperada para `raw_body` con `secret`.

    Expuesta para los tests (que firman cuerpos sintéticos); el receptor usa `verify_signature`.
    """
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"{_SIGNATURE_PREFIX}{digest}"


def verify_signature(*, secret: str, raw_body: bytes, signature_header: str | None) -> bool:
    """Devuelve True solo si `signature_header` es un HMAC-SHA256 válido de `raw_body`.

    Fail-closed en todos los caminos de error: secreto vacío, cabecera ausente, prefijo
    incorrecto o longitud anómala ⇒ False. La comparación final es de tiempo constante.

    El secreto se recibe ya desempaquetado (str) en el borde que lo consume; nunca se loguea.
    """
    # 1) Sin secreto configurado no podemos verificar nada: descartar (no autenticar a ciegas).
    if not secret:
        return False

    # 2) Cabecera ausente o con tipo inesperado: descartar.
    if not signature_header or not signature_header.startswith(_SIGNATURE_PREFIX):
        return False

    # 3) Longitud anómala del hex: descartar antes de gastar un HMAC (la firma legítima es fija).
    provided_hex = signature_header[len(_SIGNATURE_PREFIX) :]
    if len(provided_hex) != _SHA256_HEX_LEN:
        return False

    # 4) Comparación en tiempo constante sobre la cadena completa `sha256=<hex>`. compare_digest
    #    tolera longitudes distintas sin ramificar de forma observable, pero ya las acotamos arriba.
    expected = expected_signature(secret, raw_body)
    return hmac.compare_digest(expected, signature_header)
