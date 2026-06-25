"""Anti-CRLF: los validadores full-match anclan con ``\\A..\\Z``, no ``^..$``.

En Python ``$`` casa tambien ANTES de un ``\\n`` terminal, asi que un predicado
``^..$`` deja pasar ``name\\n`` (bypass CRLF de libro). Los validadores de NOMBRE
pre-red que NO hacen ``strip`` (npm fetch, npm/PyPI OSV) anclan con ``\\A..\\Z``
y rechazan el nombre envenenado en vez de saltar a la red con un CRLF. Este test
bloquea cualquier regresion a ``^..$`` en esos canales (Hito 4, Ola 1 —
endurecimiento uniforme del nucleo anti-CRLF).

Nota: ``_is_valid_https_host`` NO entra aqui porque su modelo es ``strip``+validar
(sanea el ``\\n`` y valida el host limpio), no rechazar; su anclaje ``\\A..\\Z`` es
defensa en profundidad cubierta por los tests de ``http_client``.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from slopguard.core.adapters.npm import _is_valid_npm_name, _is_valid_npm_osv_name
from slopguard.core.threatintel.osv import _is_valid_osv_name


@pytest.mark.parametrize(
    ("validator", "valido"),
    [
        (_is_valid_osv_name, "react"),
        (_is_valid_npm_osv_name, "react"),
        (_is_valid_npm_name, "react"),
        (_is_valid_npm_name, "@scope/name"),
    ],
)
def test_salto_de_linea_terminal_o_inicial_nunca_pasa(
    validator: Callable[[str], bool], valido: str
) -> None:
    assert validator(valido) is True
    for envenenado in (f"{valido}\n", f"{valido}\r\n", f"{valido}\r", f"\n{valido}"):
        assert validator(envenenado) is False, (
            f"{validator.__name__} dejo pasar {envenenado!r} (bypass CRLF: usar \\A..\\Z)"
        )
