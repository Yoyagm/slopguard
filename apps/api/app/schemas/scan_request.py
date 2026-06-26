"""Schema de entrada `ScanRequest` (design §4.2, H5-T19).

Define el cuerpo del `POST /api/v1/scans`. Se modelan las dos fuentes:
- `source=inline`: el usuario pega/sube el contenido del manifiesto.
- `source=repo`: el usuario elige un repo conectado + ruta (camino preparado para T24;
  en T19 se devuelve un error saneado documentado, no se lee el repo todavía).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    """Cuerpo de `POST /api/v1/scans` (design §4.2)."""

    model_config = ConfigDict(frozen=True)

    # Fuente del manifiesto: "inline" (contenido pegado) | "repo" (repo conectado + ruta)
    source: str = Field(..., description="inline | repo")

    # Requerido si source=inline: texto del manifiesto (requirements.txt, package.json, etc.)
    content: str | None = Field(None, description="Texto del manifiesto (source=inline)")

    # Ayuda a autodetectar el ecosistema cuando source=inline (nombre del archivo original)
    filename: str | None = Field(None, description="Nombre de archivo para autodetección")

    # Requeridos si source=repo (T24)
    repo_id: str | None = Field(None, description="UUID del repo conectado (source=repo)")
    path: str | None = Field(None, description="Ruta del manifiesto en el repo (source=repo)")
    # Ref opcional (rama, tag o SHA). None = rama por defecto del repo.
    ref: str | None = Field(None, description="Rama, tag o SHA (source=repo). None = default.")

    # Override de ecosistema (opcional); None = autodetección; override gana (R3.2).
    # Allowlist: un valor fuera de dominio → 422 antes de tocar el motor.
    ecosystem: Literal["pypi", "npm"] | None = Field(
        None, description="pypi | npm | null (autodetección)"
    )
