"""Configuración por entorno (12-factor) con pydantic-settings.

Los secretos (claves, tokens, webhook secret) entran SOLO por variables de entorno; nunca
se hardcodean ni se loguean. Los campos opcionales se completan ola a ola (auth, GitHub App,
webhooks). `get_settings()` cachea una única instancia.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración del servicio. Lee de entorno y, en dev, de un `.env`."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    environment: str = "development"
    api_v1_prefix: str = "/api/v1"

    # Infra (Ola 0): inyectadas por IaC en despliegue.
    database_url: str | None = None
    redis_url: str | None = None

    # Sesión y cifrado (Olas 0-1).
    session_secret: str = "dev-insecure-change-me"  # noqa: S105 (default solo de desarrollo)
    encryption_key: str | None = None  # clave AEAD base64 para cifrado en reposo (H5-T06)

    # Front (CORS).
    cors_origins: list[str] = ["http://localhost:3000"]

    # GitHub OAuth + App + webhooks (Olas 1/4/5).
    github_client_id: str | None = None
    github_client_secret: str | None = None
    github_app_id: str | None = None
    github_app_private_key: str | None = None
    github_webhook_secret: str | None = None

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    """Instancia única de configuración (cacheada)."""
    return Settings()
