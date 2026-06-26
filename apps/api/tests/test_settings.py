"""Configuración por entorno (H5-T02): defaults seguros y `is_production` por entorno.

Comportamiento observable de `Settings` (pydantic-settings). Cada test se aísla del entorno
real: la fixture autouse limpia las variables relevantes y cambia el cwd a un directorio
temporal, de modo que ningún `.env` del proyecto contamine los defaults (test no flaky).
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.settings import Settings

# Clave AEAD válida (32 bytes base64) para construir Settings de producción correctos.
_VALID_KEY_B64 = base64.b64encode(os.urandom(32)).decode("ascii")
# Secreto de sesión fuerte de ejemplo (>= 32 chars), claramente no el default de dev.
_STRONG_SESSION_SECRET = "x" * 48


def _prod_kwargs(**overrides: object) -> dict[str, object]:
    """Kwargs base para un Settings de producción VÁLIDO; los tests sobrescriben un campo."""
    base: dict[str, object] = {
        "environment": "production",
        "session_secret": _STRONG_SESSION_SECRET,
        "encryption_key": _VALID_KEY_B64,
        "cors_origins": ["https://app.example.com"],
    }
    base.update(overrides)
    return base

# Variables de entorno que pydantic-settings mapearía sobre los campos bajo prueba.
# Se limpian para que los defaults del código sean los que se verifican (no el shell de CI).
_RELEVANT_ENV_VARS = (
    "ENVIRONMENT",
    "API_V1_PREFIX",
    "SESSION_SECRET",
    "ENCRYPTION_KEY",
    "CORS_ORIGINS",
)


@pytest.fixture(autouse=True)
def _isolated_config_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[None]:
    """Aísla de entorno y de cualquier `.env`: limpia vars y opera desde un dir vacío."""
    for name in _RELEVANT_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    # El cwd vacío garantiza que `env_file=".env"` no encuentre un fichero que altere defaults.
    monkeypatch.chdir(tmp_path)
    yield


def test_environment_default_es_development() -> None:
    assert Settings().environment == "development"


def test_api_v1_prefix_default() -> None:
    assert Settings().api_v1_prefix == "/api/v1"


def test_default_no_es_production() -> None:
    # El default seguro NO es producción: evita activar rutas/políticas estrictas por accidente.
    assert Settings().is_production is False


def test_is_production_true_cuando_environment_es_production() -> None:
    # Producción exige secretos válidos (fail-closed en boot): se inyectan para aislar la
    # propiedad `is_production` del resto de la validación.
    assert Settings(**_prod_kwargs()).is_production is True  # type: ignore[arg-type]


def test_is_production_ignora_mayusculas() -> None:
    # `is_production` normaliza con .lower(): "Production"/"PRODUCTION" cuentan como producción.
    assert Settings(**_prod_kwargs(environment="Production")).is_production is True  # type: ignore[arg-type]
    assert Settings(**_prod_kwargs(environment="PRODUCTION")).is_production is True  # type: ignore[arg-type]


@pytest.mark.parametrize("environment", ["development", "staging", "test", ""])
def test_is_production_false_para_otros_entornos(environment: str) -> None:
    # Cualquier entorno que no sea exactamente 'production' (case-insensitive) no es producción.
    assert Settings(environment=environment).is_production is False


def test_environment_se_lee_de_variable_de_entorno(monkeypatch: pytest.MonkeyPatch) -> None:
    # 12-factor: el entorno manda. Una var exportada sobrescribe el default del código.
    monkeypatch.setenv("ENVIRONMENT", "production")
    # En producción los defaults inseguros NO arrancan: se inyectan secretos válidos por entorno.
    monkeypatch.setenv("SESSION_SECRET", _STRONG_SESSION_SECRET)
    monkeypatch.setenv("ENCRYPTION_KEY", _VALID_KEY_B64)
    monkeypatch.setenv("CORS_ORIGINS", '["https://app.example.com"]')
    settings = Settings()
    assert settings.environment == "production"
    assert settings.is_production is True


# --- Fail-closed en boot (SEC: producción no arranca con config insegura) -------------------


def test_development_arranca_con_defaults_inseguros() -> None:
    # En desarrollo el validador es no-op: los defaults locales deben seguir siendo válidos.
    settings = Settings()
    assert settings.session_secret == "dev-insecure-change-me"
    assert settings.encryption_key is None
    assert settings.cors_origins == ["http://localhost:3000"]


def test_produccion_valida_arranca() -> None:
    # Config de producción completa y endurecida: debe construirse sin error.
    settings = Settings(**_prod_kwargs())  # type: ignore[arg-type]
    assert settings.is_production is True


def test_produccion_rechaza_session_secret_default() -> None:
    # El default de dev en producción es fail-closed: no arranca.
    with pytest.raises(ValidationError, match="session_secret"):
        Settings(**_prod_kwargs(session_secret="dev-insecure-change-me"))  # type: ignore[arg-type]


def test_produccion_rechaza_session_secret_corto() -> None:
    with pytest.raises(ValidationError, match="session_secret"):
        Settings(**_prod_kwargs(session_secret="corto"))  # type: ignore[arg-type]


def test_produccion_rechaza_encryption_key_ausente() -> None:
    with pytest.raises(ValidationError, match="encryption_key"):
        Settings(**_prod_kwargs(encryption_key=None))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_key",
    [
        "no-es-base64-%%%",  # fuera del alfabeto base64
        base64.b64encode(os.urandom(16)).decode("ascii"),  # 16 bytes (AES-128, no permitido)
    ],
)
def test_produccion_rechaza_encryption_key_invalida(bad_key: str) -> None:
    with pytest.raises(ValidationError, match="encryption_key"):
        Settings(**_prod_kwargs(encryption_key=bad_key))  # type: ignore[arg-type]


def test_produccion_error_de_clave_no_filtra_la_clave() -> None:
    # El mensaje de validación JAMÁS debe contener el material de la clave (NFR-Seg-3).
    leaky = base64.b64encode(os.urandom(16)).decode("ascii")
    with pytest.raises(ValidationError) as exc_info:
        Settings(**_prod_kwargs(encryption_key=leaky))  # type: ignore[arg-type]
    assert leaky not in str(exc_info.value)


def test_produccion_rechaza_cors_comodin() -> None:
    with pytest.raises(ValidationError, match="cors_origins"):
        Settings(**_prod_kwargs(cors_origins=["*"]))  # type: ignore[arg-type]


def test_produccion_rechaza_cors_no_https() -> None:
    with pytest.raises(ValidationError, match="https"):
        Settings(**_prod_kwargs(cors_origins=["http://app.example.com"]))  # type: ignore[arg-type]


def test_produccion_rechaza_cors_vacio() -> None:
    # Fail-closed (SEC): sin orígenes no hay base https para el redirect_uri de OAuth.
    with pytest.raises(ValidationError, match="cors_origins"):
        Settings(**_prod_kwargs(cors_origins=[]))  # type: ignore[arg-type]


def test_desarrollo_permite_cors_localhost_http() -> None:
    # En development el CORS http://localhost no se valida (flujo local sin TLS).
    settings = Settings(environment="development", cors_origins=["http://localhost:3000"])
    assert settings.cors_origins == ["http://localhost:3000"]
