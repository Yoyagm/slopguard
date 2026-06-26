"""Unit tests de los helpers de configuración de auth (`app.auth.deps`).

Cubre el contrato fail-closed de `callback_redirect_uri` (SEC): el redirect_uri de OAuth DEBE
ser una URI absoluta. Si `cors_origins` está vacío o su primer origen no es una URL absoluta
(sin esquema/host), construir el redirect_uri produciría una URI relativa que GitHub rechaza —
un fallo silencioso de login. El helper lanza `AuthConfigError` en su lugar.

`Settings` se construye en development (cors_origins arbitrarios) para aislar el helper del
validador de boot de producción; la validación https en producción ya la cubre test_settings.
"""

from __future__ import annotations

import pytest

from app.auth.deps import AuthConfigError, callback_redirect_uri
from app.settings import Settings


def _settings(cors_origins: list[str]) -> Settings:
    """Settings de development con los `cors_origins` indicados (sin tocar el entorno real)."""
    return Settings(environment="development", cors_origins=cors_origins)


def test_redirect_uri_absoluto_con_origen_valido() -> None:
    # Caso feliz: origen absoluto → redirect_uri absoluto que cuelga del prefijo del API.
    settings = _settings(["https://app.example.com"])
    assert callback_redirect_uri(settings) == "https://app.example.com/api/v1/auth/callback"


def test_redirect_uri_normaliza_barra_final_del_origen() -> None:
    # La barra final del origen no debe duplicarse en el redirect_uri.
    settings = _settings(["https://app.example.com/"])
    assert callback_redirect_uri(settings) == "https://app.example.com/api/v1/auth/callback"


def test_redirect_uri_usa_el_primer_origen_cors() -> None:
    settings = _settings(["https://primary.example.com", "https://other.example.com"])
    assert callback_redirect_uri(settings).startswith("https://primary.example.com/")


def test_redirect_uri_localhost_http_en_dev_es_absoluto() -> None:
    # En desarrollo el origen http://localhost es absoluto y válido (flujo local sin TLS).
    settings = _settings(["http://localhost:3000"])
    assert callback_redirect_uri(settings) == "http://localhost:3000/api/v1/auth/callback"


def test_redirect_uri_falla_si_cors_origins_vacio() -> None:
    # Fail-closed (SEC): sin origen base no se construye un redirect_uri relativo silencioso.
    settings = _settings([])
    with pytest.raises(AuthConfigError, match="cors_origins"):
        callback_redirect_uri(settings)


@pytest.mark.parametrize(
    "bad_origin",
    [
        "/api/v1",  # path relativo: sin esquema ni host
        "app.example.com",  # host sin esquema (urlparse no lo trata como netloc)
        "",  # cadena vacía
    ],
)
def test_redirect_uri_falla_si_origen_no_es_absoluto(bad_origin: str) -> None:
    # Un origen no absoluto haría que el redirect_uri quedara relativo → fail-closed.
    settings = _settings([bad_origin])
    with pytest.raises(AuthConfigError):
        callback_redirect_uri(settings)
