"""Adapter npm: nucleo de charset compartido + predicados de validez + mapeo packument.

Este modulo aloja el `NpmAdapter` (ecosystem_id "npm"). El Hito 4 lo construye por
piezas:
- H4-T01: nucleo de charset npm + predicados de validez.
- H4-T02: normalize_name.
- H4-T06: `_extract_metadata` (mapeo packument→PackageMetadata, ADR-1/§3.2).
- H4-T07: fetch, fetch_attempt, cap de streaming, URL anti-traversal.
- H4-T11: load_top_n_npm, integridad SHA-256 al arranque.

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

Mapeo packument (H4-T06, ADR-1, §3.2): se solicita el packument completo
(`Accept: application/json`), nunca el abreviado `install-v1` (omite time/repository/
description/author/license/keywords y dejaria inertes las Capas 0/2). Toda la
entrada del packument es NO confiable: campo ausente/tipo inesperado => flag False/None,
nunca senal inventada (R4.4, fail-closed).

Frontera de arquitectura (R10.1): este modulo SI puede usar net/cache/dataset; las
capas y el scoring importan SOLO de `adapters.base`, nunca de aqui (import-linter).
"""

from __future__ import annotations

import datetime
import re
from typing import TYPE_CHECKING, Final

from .base import PackageMetadata

if TYPE_CHECKING:
    from ..dataset.top_n import TopNDataset

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


def _normalize_npm_name(raw: str) -> str:
    """Normaliza un nombre npm: strip+lower, preservando la estructura scoped (§3.4).

    Para nombres simples: `strip().lower()`.
    Para nombres scoped `@scope/name`: normaliza cada segmento por separado y los
    reune con `/`, preservando el `@` inicial y sin colapsar el separador de scope.
    NO aplica colapso PEP 503 de `._-` (eso es PyPI, R3.4).
    Idempotente: `normalize(normalize(x)) == normalize(x)` (R3.2).
    """
    stripped = raw.strip()
    if stripped.startswith("@") and "/" in stripped:
        # Scoped: dividir en "@scope" y "name", normalizar cada parte.
        scope_part, _, name_part = stripped.partition("/")
        return f"{scope_part.strip().lower()}/{name_part.strip().lower()}"
    return stripped.lower()


# ---------------------------------------------------------------------------
# H4-T06: mapeo packument npm -> PackageMetadata (ADR-1, §3.2, R4.2/R4.4)
# ---------------------------------------------------------------------------


def _extract_first_release_epoch(payload: dict[str, object]) -> float | None:
    """Deriva el epoch UTC de first_release via `time.created` (§3.2, R4.4).

    `time` ausente o no-dict => None. `created` ausente o invalido => None.
    Nunca inventa fecha (sin NEW_PACKAGE espurio).
    """
    time_block = payload.get("time")
    if not isinstance(time_block, dict):
        return None
    return _parse_iso_to_epoch(time_block.get("created"))


def _extract_metadata(
    payload: dict[str, object],
    name: str,
    top_n: TopNDataset,
) -> PackageMetadata:
    """Mapea un packument npm a PackageMetadata normalizado (§3.2, ADR-1, R4.2/R4.4).

    Toda la entrada es NO confiable: campo ausente/tipo inesperado => flag False/None,
    nunca senal inventada. Se usa el nombre CONSULTADO (normalizado), NO `payload["name"]`
    (que podria diferir o estar ausente). Packument completo obligatorio (ADR-1).
    """
    normalized = _normalize_npm_name(name)
    first_release_epoch = _extract_first_release_epoch(payload)
    versions = payload.get("versions")
    releases_count = len(versions) if isinstance(versions, dict) else 0
    keywords = payload.get("keywords")
    return PackageMetadata(
        name=normalized,
        first_release_epoch=first_release_epoch,
        releases_count=releases_count,
        has_repo_url=_extract_repo_url(payload.get("repository")),
        has_description=bool(_truthy_npm_str(payload.get("description"))),
        has_author=_extract_author(payload.get("author")),
        has_license=_extract_license(payload.get("license")),
        has_classifiers=isinstance(keywords, list) and len(keywords) > 0,
        in_top_n=normalized in top_n.members,
    )


def _parse_iso_to_epoch(raw: object) -> float | None:
    """Parsea una fecha ISO-8601 (str) a epoch UTC. None si ausente o invalido.

    Acepta sufijo 'Z' (UTC) y offsets '+HH:MM'. fromisoformat cubre Python 3.11+
    con el reemplazo de 'Z'. Devuelve None ante cualquier ValueError/OverflowError
    (campo ausente o malformado => no se inventa fecha, R4.4).
    """
    if not isinstance(raw, str) or not raw:
        return None
    try:
        ts = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return ts.timestamp()
    except (ValueError, OverflowError):
        return None


def _truthy_npm_str(value: object) -> str:
    """Devuelve el string si no esta vacio, de lo contrario ''.

    Mas simple que la variante de PyPI (que filtra 'UNKNOWN'): npm no tiene ese
    convenio; cualquier string no vacio se acepta como senal de presencia.
    """
    if not isinstance(value, str):
        return ""
    return value.strip()


def _extract_repo_url(repository: object) -> bool:
    """True si el campo `repository` del packument indica una URL http(s) (§3.2).

    Dos formas validas segun la especificacion npm:
    - dict con clave `url` cuyo valor es str que empieza por 'http'.
    - string directo que empieza por 'http'.
    Campo ausente/tipo inesperado/url no-http => False (fail-closed, R4.4).
    """
    if isinstance(repository, dict):
        url = repository.get("url")
        return isinstance(url, str) and url.startswith("http")
    if isinstance(repository, str):
        return repository.startswith("http")
    return False


def _extract_author(author: object) -> bool:
    """True si el packument indica un autor no vacio (§3.2).

    Dos formas validas segun la especificacion npm:
    - str no vacio (forma corta: "Author Name <email>").
    - dict con clave `name` cuyo valor es str no vacio (forma objeto).
    Campo ausente/tipo inesperado/vacio => False (fail-closed, R4.4).
    """
    if isinstance(author, str):
        return bool(author.strip())
    if isinstance(author, dict):
        name_val = author.get("name")
        return isinstance(name_val, str) and bool(name_val.strip())
    return False


def _extract_license(license_field: object) -> bool:
    """True si el packument indica una licencia (§3.2).

    Dos formas validas segun la especificacion npm:
    - str no vacio (SPDX directo: "MIT", "Apache-2.0", etc.).
    - dict con clave `type` cuyo valor es str (forma objeto SPDX legacy).
    Campo ausente/tipo inesperado/vacio => False (fail-closed, R4.4).
    """
    if isinstance(license_field, str):
        return bool(license_field.strip())
    if isinstance(license_field, dict):
        type_val = license_field.get("type")
        return isinstance(type_val, str) and bool(type_val.strip())
    return False


class NpmAdapter:
    """Adapter del ecosistema npm: normalize_name (H4-T02) + mapeo packument (H4-T06).

    H4-T02 implementa `normalize_name` (§3.4, R3.1/R3.2/R3.4).
    H4-T06 introduce `_extract_metadata` (§3.2, ADR-1, R4.2/R4.4).
    Los metodos `fetch`/`fetch_attempt`/`load_top_n`/`get_downloads` se implementan en
    tareas posteriores (H4-T07, H4-T11) que amplian esta clase sin tocar el nucleo
    de charset ni el mapeo de packument.

    Frontera de arquitectura (R10.1): este modulo SI puede usar net/cache/dataset;
    las capas y el scoring importan SOLO de `adapters.base`, nunca de aqui (import-linter).
    """

    ecosystem_id: str = "npm"

    def normalize_name(self, raw: str) -> str:
        """Normaliza un nombre npm segun las reglas del ecosistema (§3.4, R3.1/R3.2).

        Aplica strip()+lower(); para nombres scoped `@scope/name` normaliza cada
        segmento por separado preservando el `/` (sin colapsar) y el `@` inicial.
        No aplica colapso PEP 503 de `._-` (eso es PyPI, R3.4).
        Idempotente: normalize(normalize(x)) == normalize(x).
        """
        return _normalize_npm_name(raw)
