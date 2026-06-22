"""Parseo JSON endurecido contra JSON-bombs (anidamiento patologico).

`safe_json_loads` rechaza cualquier estructura cuya profundidad de anidamiento
supere `max_depth` ANTES de materializar el arbol (NFR-Seg.4): primero recorre los
bytes una sola vez contando la profundidad estructural (respetando strings y
escapes) y solo si pasa esa cota delega en `json.loads`. Es funcion pura,
determinista, sin `eval` ni deserializacion insegura (NFR-Seg.2).

El escaneo opera a nivel de byte: JSON es UTF-8 y los caracteres estructurales
(`{ } [ ]`), la comilla (`"`) y la barra de escape (`\\`) son ASCII de un solo
byte; en UTF-8 los bytes de continuacion (0x80-0xBF) nunca colisionan con ASCII,
de modo que contar bytes es seguro sin decodificar primero.
"""

from __future__ import annotations

import json

from ..errors import NetworkUnverifiableError

# Codigos de byte de los tokens estructurales y de string (ASCII de un byte).
_OPEN = frozenset({0x7B, 0x5B})  # '{', '['
_CLOSE = frozenset({0x7D, 0x5D})  # '}', ']'
_QUOTE = 0x22  # '"'
_BACKSLASH = 0x5C  # '\'


def safe_json_loads(data: bytes, max_depth: int) -> object:
    """Parsea `data` (UTF-8) rechazando anidamiento > `max_depth` antes de materializar.

    Lanza `NetworkUnverifiableError` si la profundidad estructural excede la cota,
    si `max_depth` es invalido o si el contenido no es JSON valido. Nunca expone el
    payload completo ni un stacktrace crudo (NFR-Seg.3-4).
    """
    if max_depth < 1:
        raise NetworkUnverifiableError("max_depth de JSON debe ser >= 1")
    _reject_excessive_depth(data, max_depth)
    try:
        return json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise NetworkUnverifiableError(f"respuesta JSON malformada: {type(exc).__name__}") from exc


def _reject_excessive_depth(data: bytes, max_depth: int) -> None:
    """Recorre los bytes una vez contando profundidad; aborta si supera `max_depth`.

    Mantiene estado dentro/fuera de string para no contar caracteres estructurales
    que aparezcan literalmente dentro de una cadena JSON (anti falso conteo).
    """
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            in_string, escaped = _step_in_string(byte, escaped)
            continue
        if byte == _QUOTE:
            in_string = True
        elif byte in _OPEN:
            depth += 1
            if depth > max_depth:
                raise NetworkUnverifiableError(
                    f"profundidad JSON {depth} supera el maximo permitido ({max_depth})"
                )
        elif byte in _CLOSE:
            depth -= 1


def _step_in_string(byte: int, escaped: bool) -> tuple[bool, bool]:
    """Avanza el estado dentro de una string JSON; devuelve (sigue_en_string, escaped).

    Un `\\` activa el modo escape (el siguiente byte es literal); una `"` no
    escapada cierra la string. Cualquier otro byte se ignora estructuralmente.
    """
    if escaped:
        return True, False
    if byte == _BACKSLASH:
        return True, True
    if byte == _QUOTE:
        return False, False
    return True, False
