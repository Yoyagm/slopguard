"""Modelos ORM (Postgres) — design §3.1/§3.2.

Convenciones: PK `UUID` generada en servidor (`gen_random_uuid()`), timestamps `TIMESTAMPTZ`
en UTC, secretos como `BYTEA` cifrado AEAD (nunca texto plano, R8.2). Los índices del histórico
y la idempotencia del PR (R5.2/R6.6) se declaran en `__table_args__`.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class TimestampMixin:
    """`created_at`/`updated_at` en UTC, gestionados por el servidor."""

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )


class User(TimestampMixin, Base):
    """Identidad GitHub del dueño del demo (design §3.1)."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    github_user_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    login: Mapped[str] = mapped_column(Text, nullable=False)
    avatar_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Token OAuth de usuario, CIFRADO AEAD en reposo (R8.2). Nunca al cliente/logs.
    access_token_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    installations: Mapped[list[GithubInstallation]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    scans: Mapped[list[Scan]] = relationship(back_populates="user")


class GithubInstallation(TimestampMixin, Base):
    """Instalación de la GitHub App (R2). `revoked` NO borra histórico (R2.4)."""

    __tablename__ = "github_installations"

    id: Mapped[uuid.UUID] = _uuid_pk()
    installation_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    account_login: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")

    user: Mapped[User] = relationship(back_populates="installations")
    repos: Mapped[list[Repo]] = relationship(
        back_populates="installation", cascade="all, delete-orphan"
    )


class Repo(TimestampMixin, Base):
    """Repo accesible por una instalación (R2.3)."""

    __tablename__ = "repos"
    __table_args__ = (
        UniqueConstraint("installation_id", "github_repo_id", name="uq_repos_installation_repo"),
        Index("ix_repos_installation_id", "installation_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    installation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("github_installations.id"), nullable=False
    )
    github_repo_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    full_name: Mapped[str] = mapped_column(Text, nullable=False)
    private: Mapped[bool] = mapped_column(Boolean, nullable=False)

    installation: Mapped[GithubInstallation] = relationship(back_populates="repos")
    scans: Mapped[list[Scan]] = relationship(back_populates="repo")


class Scan(Base):
    """Un escaneo (on-demand o de PR), R5.1. `report_json` = `ScanReport` completo (schema 1.2)."""

    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_user_created", "user_id", text("created_at DESC")),
        Index("ix_scans_user_repo", "user_id", "repo_id"),
        Index("ix_scans_user_ecosystem", "user_id", "ecosystem"),
        # Idempotencia del escaneo de PR (R6.6): re-sync actualiza la misma fila.
        Index(
            "uq_scans_pr_idempotency",
            "repo_id",
            "pr_number",
            "head_sha",
            unique=True,
            postgresql_where=text("origin = 'pull_request'"),
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    repo_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("repos.id"), nullable=True)
    origin: Mapped[str] = mapped_column(Text, nullable=False)  # on_demand | pull_request
    ecosystem: Mapped[str] = mapped_column(Text, nullable=False)  # pypi | npm
    schema_version: Mapped[str] = mapped_column(Text, nullable=False)
    tool_version: Mapped[str] = mapped_column(Text, nullable=False)
    exit_code: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    summary: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    error_category: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_json: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    head_sha: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped[User] = relationship(back_populates="scans")
    repo: Mapped[Repo | None] = relationship(back_populates="scans")
    results: Mapped[list[ScanResult]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanResult(Base):
    """Fila por dependencia (desnormaliza `report_json` para listar/filtrar), R4.1/R5.2."""

    __tablename__ = "scan_results"
    __table_args__ = (
        Index("ix_scan_results_scan_id", "scan_id"),
        Index("ix_scan_results_scan_verdict", "scan_id", "verdict"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)  # ok | unverifiable
    verdict: Mapped[str | None] = mapped_column(Text, nullable=True)  # allow|warn|block|None
    score: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    suspected_target: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_malicious: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    scan: Mapped[Scan] = relationship(back_populates="results")
