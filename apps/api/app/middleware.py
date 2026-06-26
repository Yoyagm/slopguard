"""Middleware de correlación request-id (H5-T42, NFR-Obs).

Middleware ASGI **puro** (no `BaseHTTPMiddleware`): fija el `request_id` en el `ContextVar`
en la MISMA tarea que ejecuta el endpoint, de modo que las líneas de log emitidas durante la
petición lo incluyen. `BaseHTTPMiddleware` ejecuta el downstream en otra tarea anyio y NO
propagaría el contextvar — por eso aquí se implementa a mano sobre el protocolo ASGI.

Reglas:
- Si el cliente envía `X-Request-ID` y es "seguro" (longitud y alfabeto acotados), se reutiliza
  para enlazar logs cliente↔servidor; si no, se genera un uuid4. Acotar el valor evita inyección
  de basura en los logs y abuso de memoria.
- El `request_id` se expone en la respuesta (`X-Request-ID`) para que el cliente lo correlacione.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from starlette.datastructures import Headers, MutableHeaders

from .request_context import reset_request_id, set_request_id

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_REQUEST_ID_HEADER = "x-request-id"
# Alfabeto seguro y longitud máxima del id entrante: uuid/ULID/hex caben de sobra. Cualquier
# cosa fuera de esto se descarta y se genera uno propio (anti log-injection / DoS de memoria).
_SAFE_REQUEST_ID_RE = re.compile(r"\A[A-Za-z0-9_-]{8,64}\Z")


def _resolve_request_id(headers: Headers) -> str:
    """Reutiliza el `X-Request-ID` del cliente si es seguro; si no, genera un uuid4."""
    incoming = headers.get(_REQUEST_ID_HEADER)
    if incoming and _SAFE_REQUEST_ID_RE.match(incoming):
        return incoming
    return uuid.uuid4().hex


class RequestIdMiddleware:
    """Genera/propaga el request-id y lo refleja en la respuesta."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            # Lifespan / websocket: no aplica correlación HTTP.
            await self._app(scope, receive, send)
            return

        request_id = _resolve_request_id(Headers(scope=scope))
        token = set_request_id(request_id)

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers[_REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self._app(scope, receive, send_with_request_id)
        finally:
            # Restaura el contexto SIEMPRE: evita que el id se filtre a la siguiente tarea que
            # reutilice este worker (los contextvars se heredan por copia, pero reseteamos por
            # higiene y para que fuera del request vuelva a "-").
            reset_request_id(token)
