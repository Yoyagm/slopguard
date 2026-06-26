"""Cliente de la GitHub PR API del worker: diff del PR + Check Run + comentario (R6).

`GitHubPrClient` es un `Protocol` inyectable. La impl real (`HttpxGitHubPrClient`) habla con la API
de GitHub con el installation token; en tests se usa `FakeGitHubPrClient` (sin red), que registra
las llamadas para verificar idempotencia y no-bloqueo. El Check Run se publica SIEMPRE como
informativo (`status=completed` + `conclusion`), NUNCA como required (R6.3, "solo informar").
"""

from __future__ import annotations

from typing import Protocol

import httpx

from ..github_app.contents_client import validate_full_name

_GH_API_BASE = "https://api.github.com"
_HTTP_TIMEOUT_S = 15.0

# Topes de paginación del diff: acotan trabajo y cuota de API ante un PR anómalamente grande
# (defensa anti-DoS). 50 paginas x 100 = hasta 5000 archivos inspeccionados; suficiente para
# cualquier PR legítimo, y `supported_manifests` filtra luego a los pocos manifiestos relevantes.
_MAX_PAGES = 50
_PER_PAGE = 100
_MAX_FILES = _MAX_PAGES * _PER_PAGE

# Nombre del Check Run y marca oculta del comentario: permiten el upsert idempotente (R6.6).
CHECK_RUN_NAME = "SlopGuard"
COMMENT_MARKER = "<!-- slopguard:pr-scan -->"

# Conclusiones válidas de un Check Run informativo (subconjunto del enum de GitHub que usamos).
CONCLUSION_SUCCESS = "success"
CONCLUSION_NEUTRAL = "neutral"
CONCLUSION_FAILURE = "failure"


class PrApiError(Exception):
    """Error saneado al hablar con la GitHub PR API (sin filtrar el token ni el cuerpo crudo)."""


class GitHubPrClient(Protocol):
    """Contrato inyectable del worker para leer el diff y publicar check + comentario."""

    async def list_pr_files(self, *, token: str, full_name: str, pr_number: int) -> list[str]:
        """Devuelve las rutas de los archivos cambiados en el PR (todas las páginas)."""
        ...

    async def upsert_check_run(
        self, *, token: str, full_name: str, head_sha: str, conclusion: str,
        title: str, summary: str,
    ) -> None:
        """Crea o actualiza (por nombre+head_sha) el Check Run informativo. Nunca bloqueante."""
        ...

    async def upsert_comment(
        self, *, token: str, full_name: str, pr_number: int, body: str
    ) -> None:
        """Crea o edita (por la marca oculta) el comentario resumen del PR (no duplica, R6.6)."""
        ...


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


class HttpxGitHubPrClient:
    """Implementación real contra la GitHub REST API con el installation token."""

    async def list_pr_files(self, *, token: str, full_name: str, pr_number: int) -> list[str]:
        # Defensa en profundidad: revalidamos el full_name aunque el borde del webhook ya lo filtró,
        # porque aquí se interpola directo en la URL de la API (anti SSRF / path injection).
        validate_full_name(full_name)
        paths: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S) as client:
                for page in range(1, _MAX_PAGES + 1):
                    resp = await client.get(
                        f"{_GH_API_BASE}/repos/{full_name}/pulls/{pr_number}/files",
                        headers=_headers(token),
                        params={"per_page": _PER_PAGE, "page": page},
                    )
                    if resp.status_code != httpx.codes.OK:
                        raise PrApiError("No se pudo leer el diff del PR.")
                    batch = resp.json()
                    if not isinstance(batch, list) or not batch:
                        break
                    paths.extend(str(item["filename"]) for item in batch if "filename" in item)
                    if len(batch) < _PER_PAGE or len(paths) >= _MAX_FILES:
                        break
        except httpx.HTTPError as exc:
            raise PrApiError("Error de red leyendo el diff del PR.") from exc
        return paths[:_MAX_FILES]

    async def upsert_check_run(
        self, *, token: str, full_name: str, head_sha: str, conclusion: str,
        title: str, summary: str,
    ) -> None:
        validate_full_name(full_name)  # defensa en profundidad (se interpola en la URL de la API).
        body = {
            "name": CHECK_RUN_NAME,
            "head_sha": head_sha,
            "status": "completed",
            # success | neutral | failure — informativo, NUNCA marca el PR como required (R6.3).
            "conclusion": conclusion,
            "output": {"title": title, "summary": summary},
        }
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S) as client:
                existing_id = await self._find_check_run_id(client, token, full_name, head_sha)
                if existing_id is None:
                    resp = await client.post(
                        f"{_GH_API_BASE}/repos/{full_name}/check-runs",
                        headers=_headers(token),
                        json=body,
                    )
                else:
                    resp = await client.patch(
                        f"{_GH_API_BASE}/repos/{full_name}/check-runs/{existing_id}",
                        headers=_headers(token),
                        json=body,
                    )
                if resp.status_code >= httpx.codes.BAD_REQUEST:
                    raise PrApiError("No se pudo publicar el Check Run.")
        except httpx.HTTPError as exc:
            raise PrApiError("Error de red publicando el Check Run.") from exc

    async def _find_check_run_id(
        self, client: httpx.AsyncClient, token: str, full_name: str, head_sha: str
    ) -> int | None:
        resp = await client.get(
            f"{_GH_API_BASE}/repos/{full_name}/commits/{head_sha}/check-runs",
            headers=_headers(token),
            params={"check_name": CHECK_RUN_NAME},
        )
        if resp.status_code != httpx.codes.OK:
            return None
        runs = resp.json().get("check_runs", [])
        if isinstance(runs, list) and runs:
            run_id = runs[0].get("id")
            return int(run_id) if isinstance(run_id, int) else None
        return None

    async def upsert_comment(
        self, *, token: str, full_name: str, pr_number: int, body: str
    ) -> None:
        validate_full_name(full_name)  # defensa en profundidad (se interpola en la URL de la API).
        marked_body = f"{COMMENT_MARKER}\n{body}"
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S) as client:
                existing_id = await self._find_comment_id(client, token, full_name, pr_number)
                if existing_id is None:
                    resp = await client.post(
                        f"{_GH_API_BASE}/repos/{full_name}/issues/{pr_number}/comments",
                        headers=_headers(token),
                        json={"body": marked_body},
                    )
                else:
                    resp = await client.patch(
                        f"{_GH_API_BASE}/repos/{full_name}/issues/comments/{existing_id}",
                        headers=_headers(token),
                        json={"body": marked_body},
                    )
                if resp.status_code >= httpx.codes.BAD_REQUEST:
                    raise PrApiError("No se pudo publicar el comentario del PR.")
        except httpx.HTTPError as exc:
            raise PrApiError("Error de red publicando el comentario del PR.") from exc

    async def _find_comment_id(
        self, client: httpx.AsyncClient, token: str, full_name: str, pr_number: int
    ) -> int | None:
        resp = await client.get(
            f"{_GH_API_BASE}/repos/{full_name}/issues/{pr_number}/comments",
            headers=_headers(token),
            params={"per_page": 100},
        )
        if resp.status_code != httpx.codes.OK:
            return None
        for comment in resp.json():
            if isinstance(comment, dict) and COMMENT_MARKER in str(comment.get("body", "")):
                comment_id = comment.get("id")
                return int(comment_id) if isinstance(comment_id, int) else None
        return None


class FakeGitHubPrClient:
    """Doble de test sin red: sirve un diff fijo y registra los upserts de check/comentario.

    `check_runs` y `comments` se indexan por (full_name, head_sha)/(full_name, pr_number) para
    modelar el UPSERT real: reprocesar el mismo head_sha SOBREESCRIBE en vez de duplicar (R6.6).
    """

    def __init__(self, files: list[str] | None = None) -> None:
        self._files = list(files or [])
        self.check_runs: dict[tuple[str, str], dict[str, str]] = {}
        self.comments: dict[tuple[str, int], str] = {}
        self.check_run_writes = 0
        self.comment_writes = 0

    async def list_pr_files(self, *, token: str, full_name: str, pr_number: int) -> list[str]:
        return list(self._files)

    async def upsert_check_run(
        self, *, token: str, full_name: str, head_sha: str, conclusion: str,
        title: str, summary: str,
    ) -> None:
        self.check_runs[(full_name, head_sha)] = {
            "conclusion": conclusion,
            "title": title,
            "summary": summary,
        }
        self.check_run_writes += 1

    async def upsert_comment(
        self, *, token: str, full_name: str, pr_number: int, body: str
    ) -> None:
        self.comments[(full_name, pr_number)] = body
        self.comment_writes += 1
