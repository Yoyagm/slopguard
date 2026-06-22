"""Pruebas de normalizacion PEP 503, acotado y saneo anti-inyeccion (T08, R1.1/R3.6/R6.5)."""

from __future__ import annotations

import pytest

from slopguard.core.normalize import bound_name, normalize_name, sanitize_for_output


@pytest.mark.parametrize(
    ("raw", "esperado"),
    [
        ("Requests", "requests"),
        ("Flask_Cors", "flask-cors"),
        ("ZOPE.interface", "zope-interface"),
        ("a__b--c..d", "a-b-c-d"),
        ("  spaced  ", "spaced"),
        ("Django", "django"),
    ],
)
def test_normalize_name_pep503(raw: str, esperado: str) -> None:
    assert normalize_name(raw) == esperado


def test_bound_name_supera_limite() -> None:
    assert bound_name("x" * 101, 100) is True
    assert bound_name("x" * 100, 100) is False
    assert bound_name("requests", 100) is False


@pytest.mark.parametrize(
    ("entrada", "esperado"),
    [
        ("\x1b[31mrojo\x1b[0m", "rojo"),  # CSI/SGR
        ("linea1\r\nlinea2", "linea1linea2"),  # CRLF
        ("nul\x00byte", "nulbyte"),  # C0
        ("c1\x9bcontrol", "c1control"),  # C1 (CSI byte)
        ("bell\x07end", "bellend"),  # BEL
        ("\x1b]0;titulo\x07texto", "texto"),  # OSC
        ("limpio", "limpio"),  # passthrough
    ],
)
def test_sanitize_for_output_neutraliza_controles(entrada: str, esperado: str) -> None:
    assert sanitize_for_output(entrada) == esperado


def test_sanitize_preserva_unicode_imprimible() -> None:
    assert sanitize_for_output("café—ñ") == "café—ñ"
