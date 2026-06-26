"""La migración inicial (H5-T05) genera el DDL del modelo de datos sin necesitar DB viva.

Estos tests validan el ENTREGABLE de la migración como comportamiento observable: el SQL
que Alembic emite en modo offline (`upgrade head --sql`). Se evita una DB real, así el test no
es flaky por red/orden (env.py usa un placeholder cuando no hay `DATABASE_URL`).

Cubre los criterios de aceptación de H5-T10:
  - las 5 tablas del diseño (§3.1) se crean en upgrade,
  - existe el índice único PARCIAL de idempotencia de PR (R6.6 / ADR-2),
  - la migración es reversible (downgrade emite los DROP correspondientes).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# Raíz del paquete del API (apps/api), donde viven alembic.ini y el paquete `app`.
_API_DIR = Path(__file__).resolve().parent.parent

# Las 5 tablas del modelo de datos (design §3.1), en su orden de dependencias FK.
_EXPECTED_TABLES = (
    "users",
    "github_installations",
    "repos",
    "scans",
    "scan_results",
)


def _run_alembic_sql(*command: str) -> str:
    """Ejecuta `alembic <command...> --sql` por subprocess y devuelve el DDL (stdout).

    Modo offline: no abre conexión a Postgres. Se usa el intérprete del propio venv
    (`sys.executable`) para no depender del PATH del shell. Falla explícito si Alembic
    retorna != 0, incluyendo stderr para diagnóstico (nunca se silencia el error).
    """
    proc = subprocess.run(  # noqa: S603 (args fijos, sin shell ni entrada de usuario)
        [sys.executable, "-m", "alembic", *command, "--sql"],
        cwd=_API_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        joined = " ".join(command)
        pytest.fail(f"alembic {joined} --sql falló (rc={proc.returncode}):\n{proc.stderr}")
    return proc.stdout


@pytest.fixture(scope="module")
def upgrade_sql() -> str:
    """DDL de `alembic upgrade head --sql` (offline), compartido por el módulo."""
    return _run_alembic_sql("upgrade", "head")


@pytest.fixture(scope="module")
def downgrade_sql() -> str:
    """DDL de `alembic downgrade head:base --sql` (offline), para verificar reversibilidad."""
    return _run_alembic_sql("downgrade", "head:base")


@pytest.mark.parametrize("table", _EXPECTED_TABLES)
def test_upgrade_crea_cada_tabla_del_diseno(upgrade_sql: str, table: str) -> None:
    # Cada tabla del modelo de datos debe materializarse con su CREATE TABLE.
    assert f"CREATE TABLE {table} (" in upgrade_sql


def test_upgrade_no_crea_tablas_extra(upgrade_sql: str) -> None:
    # Solo las 5 del diseño + la tabla de control de Alembic; nada más se materializa.
    created = {
        line.split("CREATE TABLE ", 1)[1].split(" (", 1)[0].strip()
        for line in upgrade_sql.splitlines()
        if line.startswith("CREATE TABLE ")
    }
    assert created == {*_EXPECTED_TABLES, "alembic_version"}


def test_upgrade_declara_indice_de_idempotencia_de_pr(upgrade_sql: str) -> None:
    # R6.6 / ADR-2: índice ÚNICO PARCIAL que garantiza un solo escaneo por (repo, pr, head_sha)
    # de PRs. El filtro WHERE es lo que lo hace parcial; sin él no habría idempotencia correcta.
    assert "CREATE UNIQUE INDEX uq_scans_pr_idempotency ON scans" in upgrade_sql
    assert "(repo_id, pr_number, head_sha)" in upgrade_sql
    assert "WHERE origin = 'pull_request'" in upgrade_sql


def test_upgrade_habilita_pgcrypto_para_uuid_por_defecto(upgrade_sql: str) -> None:
    # Las PK usan gen_random_uuid(); requiere la extensión pgcrypto creada antes de las tablas.
    assert "CREATE EXTENSION IF NOT EXISTS pgcrypto" in upgrade_sql


def test_upgrade_registra_la_revision_inicial(upgrade_sql: str) -> None:
    # La migración sella su revisión: confirma que se aplicó la 0001 (estado reproducible).
    assert "INSERT INTO alembic_version (version_num) VALUES ('0001')" in upgrade_sql


def test_downgrade_es_reversible_y_elimina_cada_tabla(downgrade_sql: str) -> None:
    # Reversibilidad (criterio de aceptación H5-T10): el downgrade emite el DROP de cada tabla.
    for table in _EXPECTED_TABLES:
        assert f"DROP TABLE {table}" in downgrade_sql
