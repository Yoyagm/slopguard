"""Normalizacion PEP 503, acotado de longitud y saneo de salida.

Funciones puras y deterministas. `sanitize_for_output` es critica de seguridad:
neutraliza secuencias ANSI y controles para impedir inyeccion de terminal/log/JSON
(R6.5). Se aplica a TODO string externo mostrado (TTY, logs y JSON).
"""

from __future__ import annotations

import re

# Runs de separadores PEP 503 (`.`, `-`, `_`) colapsan a un unico `-`.
_PEP503_SEPARATORS = re.compile(r"[-_.]+")

# Secuencias de escape ANSI a eliminar ANTES de barrer controles sueltos, para
# que su payload (p.ej. "[31m") no quede como texto visible.
_ANSI_CSI = re.compile(r"\x1b\[[0-9;:<=>?]*[ -/]*[@-~]")  # CSI ... final
_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")  # OSC ... BEL/ST
_ANSI_OTHER = re.compile(r"\x1b[@-_]")  # otros ESC Fe de un caracter
# C0 (incl. CR/LF/ESC residual), DEL y C1: se eliminan por completo.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def normalize_name(raw: str) -> str:
    """Normaliza un nombre de paquete segun PEP 503 (lowercase, runs `._-`→`-`)."""
    return _PEP503_SEPARATORS.sub("-", raw.strip()).lower()


def bound_name(name: str, max_chars: int) -> bool:
    """True si el nombre supera `max_chars` (entrada no confiable).

    Cuando es True NO deben ejecutarse algoritmos de distancia sobre el nombre
    (coste cuadratico no acotado); se emite NAME_UNTRUSTED (R3.6, NFR-Seg.5).
    """
    return len(name) > max_chars


def sanitize_for_output(text: str) -> str:
    """Neutraliza ANSI (CSI/OSC/Fe), controles C0/C1, DEL y CR/LF (R6.5).

    Anti inyeccion de terminal/log/JSON: ningun nombre de paquete ni dato externo
    puede arrastrar secuencias de control a la salida.
    """
    text = _ANSI_CSI.sub("", text)
    text = _ANSI_OSC.sub("", text)
    text = _ANSI_OTHER.sub("", text)
    return _CONTROL_CHARS.sub("", text)


# Marcador de truncado visible en salida TTY, logs y JSON.
_TRUNCADO_MARKER: str = "...[truncado]"


def sanitize_and_truncate(text: str, max_chars: int) -> str:
    """Sanea PRIMERO (ANSI/C0-C1/CRLF) y trunca DESPUES con marcador (ADR-19).

    El orden es critico: sanar antes de truncar evita dejar fragmentos de
    secuencias de control huerfanos al cortar en mitad de una secuencia ANSI.

    Args:
        text: Texto externo (p.ej. patron o rationale del LLM).
        max_chars: Longitud maxima del resultado, incluyendo el marcador si aplica.
            Debe ser > len(_TRUNCADO_MARKER) para que el marcador quepa; si
            max_chars <= len(_TRUNCADO_MARKER) se devuelve solo el marcador.

    Returns:
        Texto saneado y, si superaba max_chars, truncado con '...[truncado]'.
    """
    saneado = sanitize_for_output(text)
    if len(saneado) <= max_chars:
        return saneado
    marker_len = len(_TRUNCADO_MARKER)
    corte = max(0, max_chars - marker_len)
    return saneado[:corte] + _TRUNCADO_MARKER
