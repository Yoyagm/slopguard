"""Configuración por entorno (12-factor) con pydantic-settings.

Los secretos (claves, tokens, webhook secret) entran SOLO por variables de entorno; nunca
se hardcodean ni se loguean. Los campos opcionales se completan ola a ola (auth, GitHub App,
webhooks). `get_settings()` cachea una única instancia.

Fail-closed en boot (NFR-Seg / ADR-4): con ENVIRONMENT=production, un `model_validator`
rechaza el arranque si el `session_secret` sigue siendo el default de dev o es demasiado corto,
si falta/es inválida la `encryption_key`, o si `cors_origins` contiene comodines u orígenes
no-HTTPS. En desarrollo los defaults siguen siendo válidos (no se rompe el flujo local).
"""

from __future__ import annotations

from functools import lru_cache
from urllib.parse import urlparse

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Default de desarrollo del secreto de sesión: JAMÁS debe usarse en producción.
_INSECURE_SESSION_SECRET = "dev-insecure-change-me"  # noqa: S105 (no es un secreto real)
# Longitud mínima razonable para un secreto de sesión en producción (>= 256 bits de entropía
# si se genera con `secrets.token_urlsafe(32)`, que produce ~43 chars).
_MIN_SESSION_SECRET_LEN = 32


class Settings(BaseSettings):
    """Configuración del servicio. Lee de entorno y, en dev, de un `.env`."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    environment: str = "development"
    api_v1_prefix: str = "/api/v1"

    # Infra (Ola 0): inyectadas por IaC en despliegue.
    database_url: str | None = None
    redis_url: str | None = None

    # Sesión y cifrado (Olas 0-1). SecretStr: enmascara el valor en repr/str/logs por
    # construcción (NFR-Seg-3, defensa en profundidad). El valor solo se desempaqueta en el
    # borde que lo consume vía `.get_secret_value()`.
    session_secret: SecretStr = SecretStr(_INSECURE_SESSION_SECRET)
    encryption_key: SecretStr | None = None  # clave AEAD base64 para cifrado en reposo (H5-T06)

    # Front (CORS).
    cors_origins: list[str] = ["http://localhost:3000"]

    # Scan Service (Ola 2, ADR-3): frontera in-process con el motor.
    # Timeout de envoltura (segundos): red de seguridad de PROCESO sobre `engine.scan_*`,
    # NO un reemplazo del fail-closed del motor. Si salta → error saneado (502/504),
    # nunca un reporte limpio sintético (R3.5/R9.1). Debe ser holgadamente mayor que el
    # `timeout_total_por_dep_s` (30s) del motor para no cortar escaneos legítimos: solo
    # ataja casos patológicamente largos.
    scan_wrapper_timeout_s: float = 120.0
    # Límites de entrada (H5-T17, R3.3): el SaaS rechaza con 422 ANTES del parseo completo.
    # Los defaults coinciden con los del motor (`Config.max_manifest_bytes` / `Config.max_deps`),
    # pero son configurables por entorno para poder endurecerlos en producción sin tocar el core.
    scan_max_manifest_bytes: int = 5_000_000
    scan_max_deps: int = 5000
    # Conmutador server-side de Capa 4 (R7.2): la Capa 4 (LLM) se activa SOLO si hay clave.
    # Sin clave, el motor devuelve `llm_assessment=null` por construcción. El valor NUNCA
    # se loguea ni viaja al cliente (NFR-Seg-3).
    anthropic_api_key: SecretStr | None = None

    # GitHub OAuth + App + webhooks (Olas 1/4/5). Los IDs públicos quedan como str; los
    # secretos van como SecretStr (enmascarados en repr/str/logs, NFR-Seg-3).
    github_client_id: str | None = None
    github_client_secret: SecretStr | None = None
    github_app_id: str | None = None
    github_app_private_key: SecretStr | None = None
    github_webhook_secret: SecretStr | None = None
    # Tope del cuerpo del webhook público (DoS): rechazamos cuerpos sobre este límite ANTES de
    # leerlos enteros en memoria o verificar el HMAC. Los payloads de GitHub son pequeños; 1 MiB
    # es holgado. Configurable por entorno para endurecerlo (NFR-Seg, R6.1, ADR-4).
    webhook_max_body_bytes: int = 1_048_576

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @model_validator(mode="after")
    def _fail_closed_in_production(self) -> Settings:
        """Rechaza configuraciones inseguras en producción (fail-closed en boot).

        En desarrollo es un no-op: preserva los defaults locales. En producción exige
        secretos fuertes y un CORS endurecido. Los mensajes NUNCA exponen el valor de
        ningún secreto, solo el nombre del campo y el motivo (NFR-Seg-3).
        """
        if not self.is_production:
            return self

        self._require_strong_session_secret()
        self._require_valid_encryption_key()
        self._require_hardened_cors()
        return self

    def _require_strong_session_secret(self) -> None:
        """`session_secret` no puede ser el default de dev ni demasiado corto en producción."""
        secret = self.session_secret.get_secret_value()
        if secret == _INSECURE_SESSION_SECRET:
            raise ValueError(
                "session_secret usa el default de desarrollo en producción: "
                "configure un secreto propio (fail-closed)."
            )
        if len(secret) < _MIN_SESSION_SECRET_LEN:
            raise ValueError(
                f"session_secret es demasiado corto en producción: exige "
                f">= {_MIN_SESSION_SECRET_LEN} caracteres (fail-closed)."
            )

    def _require_valid_encryption_key(self) -> None:
        """Valida `encryption_key` reusando la lógica AEAD de `crypto._load_key` (sin duplicar).

        Import diferido: `app.security.crypto` importa `Settings`, así que importarlo a nivel de
        módulo crearía un ciclo. Se traduce `CryptoKeyError` a un `ValueError` de configuración
        para que pydantic lo reporte como fallo de validación de `Settings`.
        """
        # Import local: rompe el ciclo settings <-> crypto.
        from .security.crypto import CryptoKeyError, _load_key

        try:
            _load_key(self)
        except CryptoKeyError as exc:
            # `_load_key` ya garantiza no filtrar el material de la clave en su mensaje.
            raise ValueError(f"encryption_key inválida en producción: {exc}") from exc

    def _require_hardened_cors(self) -> None:
        """En producción, `cors_origins` no admite vacío, comodines ni orígenes no-HTTPS.

        Con `allow_credentials=True` un origen comodín o un esquema sin TLS abriría el flujo a
        robo de cookies de sesión; se rechaza en boot en lugar de degradar en runtime. Además,
        una lista vacía dejaría sin origen base al `redirect_uri` de OAuth (callback relativo,
        login roto): se exige al menos un origen https (fail-closed, refuerza SEC del redirect).
        """
        if not self.cors_origins:
            raise ValueError(
                "cors_origins no puede estar vacío en producción: el login OAuth necesita un "
                "origen base https para el redirect_uri (fail-closed)."
            )
        for origin in self.cors_origins:
            if origin == "*":
                raise ValueError(
                    "cors_origins no puede contener '*' en producción con credenciales "
                    "habilitadas (fail-closed)."
                )
            scheme = urlparse(origin).scheme.lower()
            if scheme != "https":
                raise ValueError(
                    f"cors_origins en producción exige esquema https; origen rechazado: "
                    f"{origin!r} (fail-closed)."
                )


@lru_cache
def get_settings() -> Settings:
    """Instancia única de configuración (cacheada)."""
    return Settings()
