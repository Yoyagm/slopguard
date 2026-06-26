"""Verificación HMAC del webhook (H5-T22, R6.1, ADR-4): unidad pura de `webhook_signature`.

La función `verify_signature` es la frontera de confianza del receptor. Estos tests fijan su
contrato fail-closed sin levantar FastAPI: firma correcta ⇒ True; cualquier desviación (secreto
vacío, cabecera ausente/mal prefijo/longitud anómala, cuerpo alterado, secreto incorrecto) ⇒ False.
"""

from __future__ import annotations

import pytest

from app.security.webhook_signature import expected_signature, verify_signature

_SECRET = "webhook-shared-secret"  # valor de prueba, no un secreto real
_BODY = b'{"action":"created","installation":{"id":1}}'


def test_firma_correcta_es_valida() -> None:
    sig = expected_signature(_SECRET, _BODY)
    assert verify_signature(secret=_SECRET, raw_body=_BODY, signature_header=sig) is True


def test_cuerpo_alterado_invalida_la_firma() -> None:
    """Un solo byte cambiado en el cuerpo rompe el HMAC (integridad, anti-tampering)."""
    sig = expected_signature(_SECRET, _BODY)
    tampered = _BODY + b" "
    assert verify_signature(secret=_SECRET, raw_body=tampered, signature_header=sig) is False


def test_secreto_incorrecto_invalida_la_firma() -> None:
    sig = expected_signature("otro-secreto", _BODY)
    assert verify_signature(secret=_SECRET, raw_body=_BODY, signature_header=sig) is False


@pytest.mark.parametrize(
    ("header", "case"),
    [
        (None, "cabecera ausente"),
        ("", "cabecera vacía"),
        ("sha1=deadbeef", "prefijo equivocado (sha1)"),
        ("deadbeef", "sin prefijo"),
        ("sha256=tooshort", "longitud hex anómala"),
        ("sha256=" + "z" * 64, "hex no hexadecimal pero longitud correcta"),
    ],
)
def test_cabeceras_malformadas_se_descartan(header: str | None, case: str) -> None:
    assert (
        verify_signature(secret=_SECRET, raw_body=_BODY, signature_header=header) is False
    ), f"caso: {case}"


def test_secreto_vacio_nunca_autentica() -> None:
    """Sin secreto configurado, NINGUNA firma es válida (fail-closed)."""
    # Aunque el atacante envíe la 'firma' que calcularía con secreto vacío, se descarta.
    sig = expected_signature("", _BODY)
    assert verify_signature(secret="", raw_body=_BODY, signature_header=sig) is False
