"""Migración inicial: crea las 5 tablas del modelo de datos (design §3.1/§3.2).

Revision ID: 0001
Revises:     —
Create Date: 2026-06-25

Tablas creadas (en orden de dependencias FK):
  users → github_installations → repos → scans → scan_results

Índices de negocio incluidos:
  - ix_repos_installation_id
  - ix_scans_user_created        (user_id, created_at DESC)
  - ix_scans_user_repo           (user_id, repo_id)
  - ix_scans_user_ecosystem      (user_id, ecosystem)
  - uq_scans_pr_idempotency      UNIQUE PARCIAL (repo_id, pr_number, head_sha)
                                   WHERE origin = 'pull_request'  (R6.6)
  - ix_scan_results_scan_id
  - ix_scan_results_scan_verdict (scan_id, verdict)
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Extensión necesaria para gen_random_uuid() en los DEFAULT de PKs.
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # ------------------------------------------------------------------ users
    op.create_table(
        "users",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("github_user_id", sa.BigInteger, unique=True, nullable=False),
        sa.Column("login", sa.Text, nullable=False),
        sa.Column("avatar_url", sa.Text, nullable=True),
        # Token OAuth cifrado AEAD en reposo (R8.2). Nunca al cliente ni a logs.
        sa.Column("access_token_enc", sa.LargeBinary, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # ------------------------------------------------- github_installations
    op.create_table(
        "github_installations",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("installation_id", sa.BigInteger, unique=True, nullable=False),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column("account_login", sa.Text, nullable=False),
        # Estado de la instalación: 'active' | 'revoked'. revoked NO borra histórico (R2.4).
        # server_default 1:1 con el modelo ORM (default Python-side): un INSERT crudo
        # (worker/SQL directo) obtiene 'active' a nivel de DB, no solo desde la app.
        sa.Column("status", sa.Text, nullable=False, server_default=sa.text("'active'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # --------------------------------------------------------------- repos
    op.create_table(
        "repos",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "installation_id",
            UUID(as_uuid=True),
            sa.ForeignKey("github_installations.id"),
            nullable=False,
        ),
        sa.Column("github_repo_id", sa.BigInteger, nullable=False),
        sa.Column("full_name", sa.Text, nullable=False),
        sa.Column("private", sa.Boolean, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("installation_id", "github_repo_id", name="uq_repos_installation_repo"),
    )
    op.create_index("ix_repos_installation_id", "repos", ["installation_id"])

    # -------------------------------------------------------------- scans
    op.create_table(
        "scans",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column(
            "repo_id",
            UUID(as_uuid=True),
            sa.ForeignKey("repos.id"),
            nullable=True,
        ),
        # Origen del escaneo: 'on_demand' | 'pull_request'
        sa.Column("origin", sa.Text, nullable=False),
        # Ecosistema detectado: 'pypi' | 'npm'
        sa.Column("ecosystem", sa.Text, nullable=False),
        sa.Column("schema_version", sa.Text, nullable=False),
        sa.Column("tool_version", sa.Text, nullable=False),
        sa.Column("exit_code", sa.SmallInteger, nullable=False),
        sa.Column("summary", JSONB, nullable=False),
        sa.Column("error_category", sa.Text, nullable=True),
        # ScanReport completo serializado (schema 1.2). Fuente del JSON crudo (R4.3).
        sa.Column("report_json", JSONB, nullable=False),
        # Campos de PR; NULL si origin=on_demand.
        sa.Column("pr_number", sa.Integer, nullable=True),
        sa.Column("head_sha", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    # Índice para listado del histórico, más reciente primero (R5.2).
    op.create_index(
        "ix_scans_user_created",
        "scans",
        ["user_id", sa.text("created_at DESC")],
    )
    # Índices de filtro básico (R5.2).
    op.create_index("ix_scans_user_repo", "scans", ["user_id", "repo_id"])
    op.create_index("ix_scans_user_ecosystem", "scans", ["user_id", "ecosystem"])
    # Índice único PARCIAL de idempotencia de PR (R6.6):
    # garantiza que el mismo PR+sha no genera dos escaneos distintos.
    op.create_index(
        "uq_scans_pr_idempotency",
        "scans",
        ["repo_id", "pr_number", "head_sha"],
        unique=True,
        postgresql_where=sa.text("origin = 'pull_request'"),
    )

    # --------------------------------------------------------- scan_results
    op.create_table(
        "scan_results",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.Text, nullable=False),
        # Estado: 'ok' | 'unverifiable'
        sa.Column("status", sa.Text, nullable=False),
        # Veredicto: 'allow' | 'warn' | 'block' | NULL (si unverifiable)
        sa.Column("verdict", sa.Text, nullable=True),
        # Score 0-100; NULL si unverifiable o block-override.
        sa.Column("score", sa.SmallInteger, nullable=True),
        sa.Column("suspected_target", sa.Text, nullable=True),
        # True si la dep tiene advisory MAL-* (R4.4 — destacar en UI).
        sa.Column("is_malicious", sa.Boolean, nullable=False, server_default=sa.text("false")),
    )
    op.create_index("ix_scan_results_scan_id", "scan_results", ["scan_id"])
    op.create_index("ix_scan_results_scan_verdict", "scan_results", ["scan_id", "verdict"])


def downgrade() -> None:
    # Eliminar en orden inverso de dependencias FK para evitar violaciones de constraint.
    op.drop_index("ix_scan_results_scan_verdict", table_name="scan_results")
    op.drop_index("ix_scan_results_scan_id", table_name="scan_results")
    op.drop_table("scan_results")

    op.drop_index("uq_scans_pr_idempotency", table_name="scans")
    op.drop_index("ix_scans_user_ecosystem", table_name="scans")
    op.drop_index("ix_scans_user_repo", table_name="scans")
    op.drop_index("ix_scans_user_created", table_name="scans")
    op.drop_table("scans")

    op.drop_index("ix_repos_installation_id", table_name="repos")
    op.drop_table("repos")

    op.drop_table("github_installations")
    op.drop_table("users")
