"""Contexto de correlación por request (request-id) vía `contextvars` (H5-T42).

El `request_id` se fija en un `ContextVar` por el middleware de correlación y lo lee el
formatter de logging para estampar CADA línea de log con el id de la petición en curso. Usamos
`contextvars` (no un global) porque aísla el valor por tarea async: dos requests concurrentes no
se pisan el id. NUNCA transporta datos sensibles: es un uuid opaco de correlación.
"""

from __future__ import annotations

from contextvars import ContextVar, Token

# Valor por defecto fuera de un request (arranque, jobs del worker): "-" en vez de None para que
# el formatter siempre tenga un str y no haya que ramificar en el hot-path del logging.
_REQUEST_ID_DEFAULT = "-"

_request_id_var: ContextVar[str] = ContextVar("request_id", default=_REQUEST_ID_DEFAULT)


def get_request_id() -> str:
    """Devuelve el request-id de la petición en curso, o `"-"` si no hay ninguno."""
    return _request_id_var.get()


def set_request_id(request_id: str) -> Token[str]:
    """Fija el request-id del contexto actual y devuelve el `Token` para restaurarlo luego."""
    return _request_id_var.set(request_id)


def reset_request_id(token: Token[str]) -> None:
    """Restaura el valor previo del contexto (evita fugas de id entre requests reciclados)."""
    _request_id_var.reset(token)
