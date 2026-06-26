"""El metadata ORM declara exactamente las 5 tablas del diseño (H5-T04, design §3.1)."""

from __future__ import annotations

from app.db import models  # noqa: F401  — registra las tablas
from app.db.base import Base


def test_metadata_declara_las_tablas_del_diseno() -> None:
    assert set(Base.metadata.tables) == {
        "users",
        "github_installations",
        "repos",
        "scans",
        "scan_results",
    }


def test_indice_de_idempotencia_de_pr_existe() -> None:
    # R6.6: índice único parcial para la idempotencia del escaneo de PR.
    scans = Base.metadata.tables["scans"]
    nombres = {ix.name for ix in scans.indexes}
    assert "uq_scans_pr_idempotency" in nombres
