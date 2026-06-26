"""Configuración de logging estructurado del servicio (H5-T42, NFR-Seg-3).

Logs JSON a stdout (apto para contenedor / agregadores: un objeto por línea). Campos base:
`timestamp, level, logger, message` + el `request_id` de correlación + cualquier `extra`.

Defensa en profundidad contra fuga de secretos: aunque la convención del repo es NO pasar
secretos a los logs (los `SecretStr` ya se enmascaran en repr/str), el formatter aplica una
**redacción** adicional sobre los `extra`: si una clave parece sensible (`authorization`,
`token`, `secret`, `password`, `cookie`, ...) o un valor parece un token conocido, se reemplaza
por `***`. Es una red de seguridad, no una excusa para loguear secretos a propósito.

Mantiene la API pública `configure_logging(level=...)`.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

from .request_context import get_request_id

# Marcador de redacción. No revela longitud ni forma del valor original.
_REDACTED = "***"

# Claves de `extra` (o de dicts anidados) cuyo VALOR se enmascara siempre, sin mirar su contenido.
# Coincidencia por subcadena, case-insensitive: cubre `authorization`, `x-hub-signature`,
# `access_token`, `github_webhook_secret`, etc. Conservador: ante la duda, redacta.
_SENSITIVE_KEY_RE = re.compile(
    r"(authorization|api[_-]?key|secret|token|password|passwd|cookie|"
    r"set-cookie|private[_-]?key|signature|session)",
    re.IGNORECASE,
)

# Valores que "parecen" un secreto aunque la clave no lo delate (p.ej. si se concatena en el
# message). Cubre prefijos de tokens de GitHub/Anthropic y JWTs. Es heurístico y defensivo:
# prefiere falsos positivos (redactar de más) a filtrar material sensible.
_TOKEN_VALUE_RE = re.compile(
    r"\b(gh[posu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-ant-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)"
)

# Atributos estándar de `logging.LogRecord`: lo que NO esté aquí es un `extra` del call-site.
_RESERVED_RECORD_ATTRS = frozenset(
    logging.makeLogRecord({}).__dict__.keys()
) | {"message", "asctime", "taskName"}


def _redact(key: str, value: Any) -> Any:
    """Enmascara `value` si la `key` es sensible o el valor parece un token. Recurre en dicts."""
    if _SENSITIVE_KEY_RE.search(key):
        return _REDACTED
    if isinstance(value, dict):
        return {k: _redact(str(k), v) for k, v in value.items()}
    if isinstance(value, str):
        return _TOKEN_VALUE_RE.sub(_REDACTED, value)
    return value


class JsonLogFormatter(logging.Formatter):
    """Formatter que emite un objeto JSON por línea, con redacción defensiva de secretos."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": _redact("message", record.getMessage()),
            "request_id": get_request_id(),
        }
        if record.exc_info:
            # `formatException` no incluye secretos por sí mismo; aun así pasa por redacción.
            payload["exc_info"] = _redact("exc_info", self.formatException(record.exc_info))
        self._merge_extras(record, payload)
        # `default=str`: serializa lo no-JSON (uuid, datetime) sin lanzar y sin romper la línea.
        return json.dumps(payload, default=str, ensure_ascii=False)

    @staticmethod
    def _merge_extras(record: logging.LogRecord, payload: dict[str, Any]) -> None:
        """Vuelca los `extra` del record (no reservados) redactados, sin pisar los campos base."""
        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_ATTRS or key in payload:
                continue
            payload[key] = _redact(key, value)


def configure_logging(level: str = "INFO") -> None:
    """Configura el root logger a stdout con formato JSON estructurado y sin secretos."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
