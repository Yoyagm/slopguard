"""Adapter npm: nucleo de charset compartido + predicados de validez (C1, §3.4).

Este modulo aloja el `NpmAdapter` (ecosystem_id "npm"). El Hito 4 lo construye por
piezas: H4-T01 fija el **nucleo de charset npm** y los dos predicados de validez que
de el derivan; tareas posteriores (normalize_name, fetch, mapeo de packument) lo
amplian sin tocar este nucleo de seguridad.

Nucleo de charset (un solo punto de endurecimiento, §3.4). Dos predicados deben
rechazar EXACTAMENTE la misma estructura peligrosa y solo diferir en el tope de
longitud (clasico foco de divergencia entre validadores):

- `_is_valid_npm_name`     (pre-fetch al registry):   <= 214 chars (limite npm).
- `_is_valid_npm_osv_name` (pre-POST al querybatch):  <= 100 chars (cota del cuerpo
  OSV, igual que `_OSV_NAME_RE` de PyPI).

Ambos comparten `_NPM_NAME_RE` (misma estructura/charset) y solo cambian el limite de
longitud, de modo que un endurecimiento futuro del charset toca UN nucleo y se aplica
a los dos canales a la vez, sin bypass por un canal si y otro no (NFR-Seg.4, §7.3).

Fail-closed (R3.3/R8.3): un nombre que cualquiera de los predicados rechace queda
UNVERIFIABLE, **nunca** CLEAN, y no viaja a la red (ni al GET del registry ni al POST
de OSV). El nombre validado ademas se url-encodea (`quote(name, safe='')`) antes de
construir la URL del registry (anti path-traversal/SSRF, §4.1, H4-T07).

Frontera de arquitectura (R10.1): este modulo SI puede usar net/cache/dataset; las
capas y el scoring importan SOLO de `adapters.base`, nunca de aqui (import-linter).
"""

from __future__ import annotations

import re
from typing import Final

# Nucleo de charset npm: caracteres permitidos en UN segmento del nombre (§3.4). Solo
# minusculas/digitos y `._~-`; ningun CRLF/ANSI/C0-C1/espacio/`%`/unicode/`:`/`/` puede
# aparecer aqui, asi que la sola pertenencia a la clase ya excluye esos vectores.
_NPM_SEGMENT_CHARS: Final[str] = "a-z0-9._~-"

# Un segmento valido: 1+ chars del nucleo que NO empieza por `.` ni `_` (regla npm).
# El lookahead `(?![._])` ademas descarta los segmentos `.` y `..` (ambos empiezan por
# `.`), cerrando el traversal por segmento de ruta.
_NPM_SEGMENT_RE: Final[re.Pattern[str]] = re.compile(rf"(?![._])[{_NPM_SEGMENT_CHARS}]+")

# Nombre = segmento simple `name`  O  scoped `@<scope-seg>/<name-seg>` con EXACTAMENTE
# un `/` (y solo en la posicion del scope; `/` no pertenece al charset de segmento, asi
# que un `/` extra rompe el match). Anclado con `\A...\Z` —NO `^...$`— a proposito: en
# Python `$` tambien casa antes de un `\n` terminal, lo que dejaria pasar `"react\n"`
# (bypass CRLF). `\Z` casa solo el fin absoluto del string y cierra ese vector.
_NPM_NAME_RE: Final[re.Pattern[str]] = re.compile(
    rf"\A(@{_NPM_SEGMENT_RE.pattern}/)?{_NPM_SEGMENT_RE.pattern}\Z"
)

# Topes de longitud: unica diferencia entre los dos predicados (§3.4).
_NPM_NAME_MAX_LEN: Final[int] = 214  # limite de nombre publicable del registry npm.
_NPM_OSV_NAME_MAX_LEN: Final[int] = 100  # cota del cuerpo OSV (igual que PyPI).


def _is_valid_npm_structure(name: str, *, max_len: int) -> bool:
    """True si `name` es estructuralmente valido para npm dentro de `max_len` (nucleo unico).

    Guard de longitud ANTES del match: acota el tope exacto del canal y evita medir un
    string gigante (defensa en profundidad). Vacio ⇒ False (el guard `not name` corta
    antes de tocar el regex). El resto del contrato (charset por segmento, scoped con un
    solo `/`, sin segmentos `.`/`..`, sin inicio por `.`/`_`, sin CRLF/ANSI/unicode) lo
    impone `_NPM_NAME_RE`, compartido por ambos predicados.
    """
    if not name or len(name) > max_len:
        return False
    return _NPM_NAME_RE.match(name) is not None


def _is_valid_npm_name(name: str) -> bool:
    """True si `name` es seguro para consultar el registry npm (pre-fetch, <= 214).

    Defensa en profundidad (§3.4/§4.1): `normalize_name` baja a minusculas y recorta,
    pero NO valida charset/estructura; un nombre con CRLF/ANSI/unicode, un `/` extra o
    un segmento `..` que esquivara la normalizacion sobreviviria. Solo un nombre que
    pase este predicado se url-encodea y viaja al GET del registry; cualquier otro queda
    UNVERIFIABLE (nunca CLEAN) sin tocar la red (R3.3, fail-closed).
    """
    return _is_valid_npm_structure(name, max_len=_NPM_NAME_MAX_LEN)


def _is_valid_npm_osv_name(name: str) -> bool:
    """True si `name` es seguro para el cuerpo del POST a OSV (pre-POST, <= 100).

    Mismo nucleo de charset/estructura que `_is_valid_npm_name`; solo difiere el tope de
    longitud (cota del querybatch OSV, analogo a `_is_valid_osv_name` de PyPI). Un nombre
    que no pase se excluye del POST y queda UNVERIFIABLE, nunca CLEAN, sin viajar a la red
    (R8.3, defensa en profundidad anti-reflejo).
    """
    return _is_valid_npm_structure(name, max_len=_NPM_OSV_NAME_MAX_LEN)
