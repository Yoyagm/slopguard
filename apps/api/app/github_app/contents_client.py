"""Cliente de la GitHub Contents API para el scan desde repo (H5-T24, R2.5).

Responsabilidad única: dado un installation token y la ruta de un archivo en un repo,
obtener el contenido decodificado como texto UTF-8.

Invariantes de seguridad (NFR-Seg-3, ADR-4):
  - El installation token NUNCA se loguea ni aparece en mensajes de error.
  - La ruta del archivo se confina (path traversal guard) antes de enviarla a GitHub.
  - Los errores de red/acceso se sanean a `RepoUnavailableError` con mensaje accionable.
  - Los bytes del contenido no se loguean.

Protocolo inyectable: en tests se sustituye por `FakeGitHubContentsClient` sin red real.
"""

from __future__ import annotations

import base64
import logging
import posixpath
import re
from typing import Protocol

import httpx

logger = logging.getLogger(__name__)

# Base de la GitHub REST API v3.
_GH_API_BASE = "https://api.github.com"
# Timeout para llamadas a la contents API (ajustado para repos privados grandes).
_HTTP_TIMEOUT_S = 15.0
# Tamaño máximo del contenido decodificado que aceptamos (5 MB). Defensa en profundidad
# antes de pasarlo al Scan Service (que tiene su propio límite en scan_max_manifest_bytes).
_MAX_CONTENT_BYTES = 5_000_000

# `full_name` legítimo de GitHub = "owner/repo": exactamente dos segmentos con caracteres
# seguros (alfanumérico, '_', '.', '-'). Anclada con \A...\Z (NO ^...$): en Python `$` matchea
# también ANTES de un '\n' terminal, lo que dejaría pasar "owner/repo\n" (CRLF injection). \Z
# ancla el fin ABSOLUTO de la cadena. Rechaza host injection / path traversal (p.ej. "..",
# "%2F", "@evil.host", "?q=", "a/b/c"): un full_name anómalo podría reescribir host o path al
# interpolarse en la URL de la contents API (SSRF, NFR-Seg-3, ADR-4).
_FULL_NAME_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class RepoUnavailableError(Exception):
    """El manifiesto del repo no está disponible o el acceso fue denegado.

    El mensaje es accionable y NO incluye el installation token ni detalles internos
    de GitHub (cuerpo de respuesta crudo) que podrían filtrar información sensible.
    """


def validate_full_name(full_name: str) -> tuple[str, str]:
    """Valida y descompone `owner/repo` con una regex estricta (anti SSRF / path injection).

    Devuelve `(owner, repo)` si `full_name` es exactamente dos segmentos seguros. Rechaza con
    `RepoUnavailableError` (mensaje saneado, sin exponer el valor) cualquier desviación: host
    injection (`@`, `:`), traversal (`..`, `.`), encoding (`%2F`), query/fragment (`?`, `#`),
    o un número de segmentos distinto de dos. Es la defensa en profundidad antes de construir la
    URL: aunque el webhook ya valida `full_name` al parsear, NO confiamos en una única barrera.
    """
    if not _FULL_NAME_RE.match(full_name):
        logger.warning("full_name de repo rechazado por formato inválido (saneado, sin exponer).")
        raise RepoUnavailableError("El identificador del repo no tiene un formato válido.")
    owner, repo = full_name.split("/", 1)
    # Defensa final: ningún segmento puede ser "." o ".." (traversal aunque pase la regex).
    if owner in (".", "..") or repo in (".", ".."):
        logger.warning("full_name de repo rechazado: segmento de traversal (saneado).")
        raise RepoUnavailableError("El identificador del repo no tiene un formato válido.")
    return owner, repo


def confine_path(raw_path: str) -> str:
    """Normaliza y confina la ruta del manifiesto para evitar path traversal.

    Reglas:
    - Se normalizan separadores (backslash → slash).
    - Componentes ".." se colapsan con `posixpath.normpath`.
    - La ruta resultante no puede empezar por "/" ni contener "..".
    - Componentes vacíos se eliminan.

    Si la ruta no pasa la validación se lanza `RepoUnavailableError` con mensaje genérico
    (no se expone cuál fue la ruta original en el mensaje de error del cliente, solo en el log).
    """
    # Normalizar separadores de Windows a POSIX.
    normalized = raw_path.replace("\\", "/")
    # Colapsar ".." con normpath (p.ej. "foo/../bar" → "bar").
    collapsed = posixpath.normpath(normalized)
    # Eliminar barra inicial (normpath la preserva si el input empieza con /).
    confined = collapsed.lstrip("/")
    # Defensa final: ningún segmento debe ser "..".
    if any(part == ".." for part in confined.split("/")):
        logger.warning("Ruta rechazada por path traversal (sanitizada, sin exponer raw).")
        raise RepoUnavailableError(
            "La ruta del manifiesto no es válida. Usa una ruta relativa al raíz del repo."
        )
    if not confined:
        raise RepoUnavailableError(
            "La ruta del manifiesto no puede estar vacía."
        )
    return confined


class GitHubContentsClient(Protocol):
    """Contrato inyectable: permite sustituirlo en tests sin red."""

    async def fetch_manifest(
        self,
        *,
        token: str,
        full_name: str,
        path: str,
        ref: str | None = None,
    ) -> str:
        """Obtiene el contenido de `path` en el repo `full_name` usando `token`.

        `full_name` es el nombre completo del repo, p.ej. "acme/my-app".
        `path` es la ruta relativa al raíz del repo (sin "/" inicial).
        `ref` es la rama, tag o SHA; None = rama por defecto del repo.

        Devuelve el contenido decodificado como str UTF-8.
        Lanza `RepoUnavailableError` si el archivo no existe, el acceso es denegado,
        hay error de red o el contenido no se puede decodificar.
        """
        ...


class HttpxGitHubContentsClient:
    """Implementación real: llama a la GitHub Contents API con httpx."""

    async def fetch_manifest(
        self,
        *,
        token: str,
        full_name: str,
        path: str,
        ref: str | None = None,
    ) -> str:
        """Descarga y decodifica el archivo del repo via GitHub Contents API."""
        # Defensa en profundidad: validar `full_name` (anti SSRF / host-path injection) ANTES de
        # construir cualquier URL, además de la validación en el borde del webhook.
        validate_full_name(full_name)
        # Confinamiento de ruta antes de salir al exterior.
        safe_path = confine_path(path)

        # Fijamos el host/scheme con httpx.URL y solo sustituimos el PATH (copy_with): la autoridad
        # queda anclada a api.github.com y ni full_name ni safe_path pueden reescribir el host.
        # full_name está validado (regex estricta) y safe_path confinado, por lo que el path es
        # seguro de componer.
        url = httpx.URL(_GH_API_BASE).copy_with(
            path=f"/repos/{full_name}/contents/{safe_path}"
        )
        params: dict[str, str] = {}
        if ref is not None:
            params["ref"] = ref

        headers = {
            # El token NUNCA debe aparecer en logs; solo se incluye en el header.
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S) as client:
                response = await client.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:
            raise RepoUnavailableError(
                f"No se pudo contactar a GitHub para leer el manifiesto del repo '{full_name}'."
            ) from exc

        if response.status_code == 404:
            raise RepoUnavailableError(
                f"El archivo '{safe_path}' no existe en el repo '{full_name}' "
                f"(o el repo no es accesible con las credenciales actuales)."
            )
        if response.status_code == 403:
            raise RepoUnavailableError(
                f"Acceso denegado al archivo '{safe_path}' en el repo '{full_name}'. "
                "Verifica que la GitHub App tiene permiso de lectura de contenidos."
            )
        if response.status_code not in (200, 201):
            # No incluimos el cuerpo crudo: puede contener info diagnóstica sensible.
            raise RepoUnavailableError(
                f"GitHub respondió {response.status_code} al leer el manifiesto "
                f"'{safe_path}' en '{full_name}'."
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise RepoUnavailableError(
                "GitHub devolvió una respuesta no-JSON al leer el manifiesto."
            ) from exc

        if not isinstance(body, dict):
            raise RepoUnavailableError(
                "GitHub devolvió un JSON con forma inesperada al leer el manifiesto."
            )

        # La contents API puede devolver un directorio (lista) en vez de un archivo.
        if body.get("type") != "file":
            raise RepoUnavailableError(
                f"'{safe_path}' es un directorio, no un archivo. "
                "Especifica la ruta completa del manifiesto."
            )

        # Contenido siempre en base64 para archivos (GitHub REST docs).
        raw_content = body.get("content", "")
        if not isinstance(raw_content, str):
            raise RepoUnavailableError(
                "GitHub devolvió un campo 'content' con tipo inesperado."
            )

        # GitHub incluye saltos de línea en el base64; hay que limpiarlos.
        b64_clean = raw_content.replace("\n", "")
        try:
            decoded_bytes = base64.b64decode(b64_clean)
        except Exception as exc:
            raise RepoUnavailableError(
                "No se pudo decodificar el contenido del manifiesto (base64 inválido)."
            ) from exc

        if len(decoded_bytes) > _MAX_CONTENT_BYTES:
            raise RepoUnavailableError(
                f"El manifiesto del repo '{full_name}' supera el tamaño máximo permitido "
                f"({_MAX_CONTENT_BYTES} bytes)."
            )

        try:
            return decoded_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RepoUnavailableError(
                f"El manifiesto del repo '{full_name}' no es texto UTF-8 válido."
            ) from exc


class FakeGitHubContentsClient:
    """Doble en memoria para tests sin red.

    Por defecto devuelve un contenido fijo. Se puede configurar para lanzar
    `RepoUnavailableError` con `fail=True`.
    """

    def __init__(
        self,
        *,
        content: str = "requests==2.28.0\n",
        fail: bool = False,
        fail_message: str = "repo no disponible (doble de prueba)",
    ) -> None:
        self._content = content
        self._fail = fail
        self._fail_message = fail_message
        self.fetch_calls: list[dict[str, str | None]] = []

    async def fetch_manifest(
        self,
        *,
        token: str,
        full_name: str,
        path: str,
        ref: str | None = None,
    ) -> str:
        # Paridad con el cliente real: validar full_name y confinar la ruta ANTES de registrar
        # la llamada, para que un input malicioso se rechace igual que en producción (sin red).
        validate_full_name(full_name)
        safe_path = confine_path(path)
        # Registrar la llamada (sin el token: no lo guardamos ni logueamos).
        self.fetch_calls.append({"full_name": full_name, "path": safe_path, "ref": ref})
        if self._fail:
            raise RepoUnavailableError(self._fail_message)
        return self._content
