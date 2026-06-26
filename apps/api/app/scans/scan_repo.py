"""Repositorio de scans: persiste + consulta `scans` + `scan_results` (design §3.1, H5-T19/T20).

Espejo del patrón de `user_repo.py`: Protocol inyectable + SqlScanRepository (SQLAlchemy
síncrono en threadpool) + FakeScanRepository (en memoria para tests).

El motor es síncrono; los métodos del repo también lo son por dentro, pero se exponen async
(vía threadpool) para no bloquear el event loop de FastAPI.

El manifiesto crudo del usuario NUNCA se persiste (NFR-Privacidad-1); solo el reporte derivado
(`report_json` = ScanReport serializado, design §3.3).
"""

from __future__ import annotations

import uuid
from typing import Any, Protocol

from anyio import to_thread
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from ..db.models import Scan, ScanResult
from ..schemas.scan import (
    AdvisoryDTO,
    DependencyResultDTO,
    LlmAssessmentDTO,
    ScanDTO,
    ScanListItemDTO,
    ScanPageDTO,
    ScanSummaryDTO,
    SignalDTO,
)


class ScanRepository(Protocol):
    """Contrato del repositorio de escaneos. Inyectable; se dobla en tests sin Postgres."""

    async def persist(
        self,
        dto: ScanDTO,
        *,
        user_id: uuid.UUID,
        repo_id: uuid.UUID | None = None,
        origin: str = "on_demand",
        pr_number: int | None = None,
        head_sha: str | None = None,
    ) -> uuid.UUID:
        """Persiste el escaneo + resultados por dependencia y devuelve el `scans.id`.

        Contrato (autoritativo en persistencia): la capa de persistencia GENERA el
        `scan_id` y lo DEVUELVE. El `dto.scan_id` de ENTRADA se IGNORA (es un
        placeholder del caller). El DTO almacenado se re-sella con el id autoritativo,
        de modo que el round-trip POST → GET /scans/{id} devuelve SIEMPRE el mismo
        `scan_id` en la URL y en el body.
        """
        ...

    async def list_by_user(
        self,
        user_id: uuid.UUID,
        *,
        repo_id: uuid.UUID | None = None,
        ecosystem: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> ScanPageDTO:
        """Lista paginada del histórico del usuario, orden created_at DESC (R5.2)."""
        ...

    async def get_by_id_for_user(
        self,
        scan_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> ScanDTO | None:
        """Devuelve el ScanDTO completo si pertenece al usuario; None si no existe O es de otro.

        El caller debe responder 404 en ambos casos (no 403): no filtramos existencia (R5.3).
        """
        ...


class SqlScanRepository:
    """Implementación SQLAlchemy. Cumple `ScanRepository`.

    Persiste en dos tablas en una sola transacción:
    - `scans`: resumen + report_json completo (schema 1.2).
    - `scan_results`: una fila por dependencia (desnormalización para filtrar).

    `report_json` proviene de `dto.report_dict` (JSON canónico del motor, schema 1.2).
    El manifiesto raw del usuario nunca se toca aquí; solo el reporte derivado del motor.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    async def persist(
        self,
        dto: ScanDTO,
        *,
        user_id: uuid.UUID,
        repo_id: uuid.UUID | None = None,
        origin: str = "on_demand",
        pr_number: int | None = None,
        head_sha: str | None = None,
    ) -> uuid.UUID:
        return await to_thread.run_sync(
            self._persist_sync, dto, user_id, repo_id, origin, pr_number, head_sha
        )

    async def list_by_user(
        self,
        user_id: uuid.UUID,
        *,
        repo_id: uuid.UUID | None = None,
        ecosystem: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> ScanPageDTO:
        return await to_thread.run_sync(
            self._list_by_user_sync, user_id, repo_id, ecosystem, page, page_size
        )

    async def get_by_id_for_user(
        self,
        scan_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> ScanDTO | None:
        return await to_thread.run_sync(self._get_by_id_for_user_sync, scan_id, user_id)

    def _persist_sync(
        self,
        dto: ScanDTO,
        user_id: uuid.UUID,
        repo_id: uuid.UUID | None,
        origin: str,
        pr_number: int | None,
        head_sha: str | None,
    ) -> uuid.UUID:
        scan_id = uuid.uuid4()
        # El reporte canónico ya viaja como dict en el DTO (sin re-parsear, R4.3).
        report_json: dict[str, object] = dict(dto.report_dict)
        summary_dict: dict[str, object] = {
            "total": dto.summary.total,
            "allow": dto.summary.allow,
            "warn": dto.summary.warn,
            "block": dto.summary.block,
            "unverifiable": dto.summary.unverifiable,
            "llm_unavailable": dto.summary.llm_unavailable,
            "exit_code": dto.summary.exit_code,
        }

        with self._session_factory() as session:
            # Idempotencia del escaneo de PR (R6.6, ADR-2): re-procesar el mismo (repo, pr,
            # head_sha) ACTUALIZA la misma fila en vez de insertar (el índice único parcial
            # `uq_scans_pr_idempotency` la haría fallar con IntegrityError). GitHub reentrega
            # webhooks y `synchronize` es frecuente, así que el re-sync debe ser no-duplicante.
            existing = self._find_existing_pr_scan(session, origin, repo_id, pr_number, head_sha)
            if existing is not None:
                return self._update_pr_scan(session, existing, dto, summary_dict, report_json)

            scan = Scan(
                id=scan_id,
                user_id=user_id,
                repo_id=repo_id,
                origin=origin,
                ecosystem=dto.ecosystem,
                schema_version=dto.schema_version,
                tool_version=dto.tool_version,
                exit_code=dto.summary.exit_code,
                summary=summary_dict,
                error_category=dto.error_category,
                report_json=report_json,
                pr_number=pr_number,
                head_sha=head_sha,
                created_at=dto.created_at,
            )
            session.add(scan)
            session.add_all([_build_scan_result(scan_id, dep) for dep in dto.results])
            session.commit()

        return scan_id

    def _find_existing_pr_scan(
        self,
        session: Session,
        origin: str,
        repo_id: uuid.UUID | None,
        pr_number: int | None,
        head_sha: str | None,
    ) -> Scan | None:
        """Busca la fila de un escaneo de PR ya persistido (clave de idempotencia, R6.6)."""
        if origin != "pull_request" or repo_id is None or pr_number is None or head_sha is None:
            return None
        return session.execute(
            select(Scan).where(
                Scan.origin == "pull_request",
                Scan.repo_id == repo_id,
                Scan.pr_number == pr_number,
                Scan.head_sha == head_sha,
            )
        ).scalar_one_or_none()

    def _update_pr_scan(
        self,
        session: Session,
        scan: Scan,
        dto: ScanDTO,
        summary_dict: dict[str, object],
        report_json: dict[str, object],
    ) -> uuid.UUID:
        """Re-sella un escaneo de PR existente con el nuevo reporte (reemplaza sus resultados)."""
        scan.ecosystem = dto.ecosystem
        scan.schema_version = dto.schema_version
        scan.tool_version = dto.tool_version
        scan.exit_code = dto.summary.exit_code
        scan.summary = summary_dict
        scan.error_category = dto.error_category
        scan.report_json = report_json
        session.execute(delete(ScanResult).where(ScanResult.scan_id == scan.id))
        session.add_all([_build_scan_result(scan.id, dep) for dep in dto.results])
        session.commit()
        return scan.id


    def _list_by_user_sync(
        self,
        user_id: uuid.UUID,
        repo_id: uuid.UUID | None,
        ecosystem: str | None,
        page: int,
        page_size: int,
    ) -> ScanPageDTO:
        """Consulta paginada con filtros opcionales, orden created_at DESC (R5.2)."""
        with self._session_factory() as session:
            base_filter = Scan.user_id == user_id
            if repo_id is not None:
                base_filter = base_filter & (Scan.repo_id == repo_id)
            if ecosystem is not None:
                base_filter = base_filter & (Scan.ecosystem == ecosystem)

            # Total sin paginar para que el cliente sepa cuántas páginas hay.
            total_result = session.execute(
                select(func.count()).select_from(Scan).where(base_filter)
            )
            total: int = total_result.scalar_one()

            offset = (page - 1) * page_size
            rows = session.execute(
                select(Scan)
                .where(base_filter)
                .order_by(Scan.created_at.desc())
                .offset(offset)
                .limit(page_size)
            ).scalars().all()

        items = [_scan_orm_to_list_item(row) for row in rows]
        return ScanPageDTO(items=items, total=total, page=page, page_size=page_size)

    def _get_by_id_for_user_sync(
        self,
        scan_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> ScanDTO | None:
        """Recupera el ScanDTO completo. Filtra por user_id: otro usuario → None (R5.3)."""
        with self._session_factory() as session:
            row = session.execute(
                select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
            ).scalar_one_or_none()

        if row is None:
            return None
        return _scan_orm_to_dto(row)


def _int_field(d: dict[str, Any], key: str, default: int = 0) -> int:
    """Extrae un entero de un dict JSONB con un default seguro."""
    val = d.get(key, default)
    return int(val) if val is not None else default


def _build_summary_dto(summary_raw: dict[str, Any]) -> ScanSummaryDTO:
    """Convierte el dict JSONB del campo `summary` al ScanSummaryDTO."""
    return ScanSummaryDTO(
        total=_int_field(summary_raw, "total"),
        allow=_int_field(summary_raw, "allow"),
        warn=_int_field(summary_raw, "warn"),
        block=_int_field(summary_raw, "block"),
        unverifiable=_int_field(summary_raw, "unverifiable"),
        llm_unavailable=_int_field(summary_raw, "llm_unavailable"),
        exit_code=_int_field(summary_raw, "exit_code"),
    )


def _scan_orm_to_list_item(scan: Scan) -> ScanListItemDTO:
    """Convierte una fila ORM al DTO liviano del listado (sin results ni report_raw)."""
    summary = _build_summary_dto(scan.summary)
    return ScanListItemDTO(
        scan_id=scan.id,
        origin=scan.origin,
        created_at=scan.created_at,
        ecosystem=scan.ecosystem,
        schema_version=scan.schema_version,
        tool_version=scan.tool_version,
        error_category=scan.error_category,
        summary=summary,
    )


def _scan_orm_to_dto(scan: Scan) -> ScanDTO:
    """Convierte una fila ORM al ScanDTO completo desde report_json (R4.3).

    Reconstruye el ScanDTO directamente desde el JSONB persistido, sin pasar por
    el motor de nuevo. `report_json` es la fuente canónica schema 1.2; los resultados
    se deserializan campo a campo para mantener tipos Pydantic correctos.
    """
    report_dict: dict[str, Any] = scan.report_json  # JSONB → dict en runtime

    summary = _build_summary_dto(scan.summary)

    results = [
        _dep_dict_to_dto(r) for r in (report_dict.get("results") or [])
        if isinstance(r, dict)
    ]

    return ScanDTO(
        scan_id=scan.id,
        origin=scan.origin,
        created_at=scan.created_at,
        schema_version=scan.schema_version,
        tool_version=scan.tool_version,
        ecosystem=scan.ecosystem,
        error_category=scan.error_category,
        summary=summary,
        results=results,
        report_dict=report_dict,
    )


def _dep_dict_to_dto(raw: dict[str, Any]) -> DependencyResultDTO:
    """Deserializa una dependencia desde el JSONB de report_json a DependencyResultDTO.

    No usa Pydantic model_validate directamente sobre el dict crudo para evitar acoplar
    el formato interno del motor a la validación de Pydantic: hacemos el mapeo explícito.
    """
    signals: list[SignalDTO] = [
        SignalDTO(
            layer=int(s["layer"]),
            code=str(s["code"]),
            weight=int(s["weight"]),
            is_soft=bool(s["is_soft"]),
            is_llm_channel=bool(s["is_llm_channel"]),
            detail=str(s["detail"]),
            suspected_target=str(s["suspected_target"]) if s.get("suspected_target") else None,
        )
        for s in (raw.get("signals") or [])
        if isinstance(s, dict)
    ]
    advisories: list[AdvisoryDTO] = [
        AdvisoryDTO(
            id=str(a["id"]),
            kind=str(a["kind"]),
            url=str(a["url"]),
            source=str(a["source"]),
        )
        for a in (raw.get("advisories") or [])
        if isinstance(a, dict)
    ]
    llm_raw = raw.get("llm_assessment")
    llm_assessment: LlmAssessmentDTO | None = None
    if isinstance(llm_raw, dict):
        llm_assessment = LlmAssessmentDTO(
            clasificacion=str(llm_raw["clasificacion"]),
            confianza=float(llm_raw["confianza"]),
            patron=str(llm_raw["patron"]),
            rationale=str(llm_raw["rationale"]),
            modelo=str(llm_raw["modelo"]),
            prompt_version=str(llm_raw["prompt_version"]),
        )

    score_raw = raw.get("score")
    score: int | None = int(score_raw) if score_raw is not None else None

    return DependencyResultDTO(
        name=str(raw["name"]),
        version_pin=str(raw["version_pin"]) if raw.get("version_pin") else None,
        status=str(raw["status"]),
        verdict=str(raw["verdict"]) if raw.get("verdict") else None,
        score=score,
        suspected_target=str(raw["suspected_target"]) if raw.get("suspected_target") else None,
        error_category=str(raw["error_category"]) if raw.get("error_category") else None,
        signals=signals,
        advisories=advisories,
        llm_assessment=llm_assessment,
    )


def _dep_is_malicious(dep: DependencyResultDTO) -> bool:
    """True si algún advisory tiene id con prefijo 'MAL-' (R4.4, design §3.1)."""
    return any(a.id.startswith("MAL-") for a in dep.advisories)


def _build_scan_result(scan_id: uuid.UUID, dep: DependencyResultDTO) -> ScanResult:
    """Construye un `ScanResult` ORM desde un `DependencyResultDTO`."""
    return ScanResult(
        id=uuid.uuid4(),
        scan_id=scan_id,
        name=dep.name,
        status=dep.status,
        verdict=dep.verdict,
        score=dep.score,
        suspected_target=dep.suspected_target,
        is_malicious=_dep_is_malicious(dep),
    )


class FakeScanRepository:
    """Repo en memoria para tests sin Postgres. Paridad de contrato con `SqlScanRepository`.

    Almacena los DTOs persistidos indexados por scan_id (con user_id y repo_id) para que
    los tests ejerciten list_by_user (incl. filtro repo_id) y get_by_id_for_user sin
    Postgres. Igual que el SQL, genera el scan_id autoritativo y re-sella el DTO con él.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        # Almacén interno: scan_id → (user_id, repo_id, ScanDTO re-sellado con scan_id)
        self._store: dict[uuid.UUID, tuple[uuid.UUID, uuid.UUID | None, ScanDTO]] = {}
        # Índice de idempotencia de PR: (repo_id, pr_number, head_sha) → scan_id (espejo del
        # índice único parcial `uq_scans_pr_idempotency` del SqlScanRepository, R6.6).
        self._pr_index: dict[tuple[uuid.UUID, int, str], uuid.UUID] = {}

    async def persist(
        self,
        dto: ScanDTO,
        *,
        user_id: uuid.UUID,
        repo_id: uuid.UUID | None = None,
        origin: str = "on_demand",
        pr_number: int | None = None,
        head_sha: str | None = None,
    ) -> uuid.UUID:
        # Contrato: la persistencia genera el id autoritativo e IGNORA dto.scan_id de
        # entrada; el DTO almacenado se re-sella con él para que el round-trip POST→GET
        # devuelva el mismo scan_id en URL y body (paridad con SqlScanRepository).
        pr_key = self._pr_key(origin, repo_id, pr_number, head_sha)
        # Idempotencia de PR: re-procesar el mismo head_sha re-usa el scan_id (UPDATE), no inserta.
        scan_id = self._pr_index.get(pr_key) if pr_key is not None else None
        scan_id = scan_id or uuid.uuid4()
        sealed_dto = dto.model_copy(update={"scan_id": scan_id})
        self.calls.append(
            {
                "scan_id": scan_id,
                "dto": sealed_dto,
                "user_id": user_id,
                "repo_id": repo_id,
                "origin": origin,
                "pr_number": pr_number,
                "head_sha": head_sha,
            }
        )
        self._store[scan_id] = (user_id, repo_id, sealed_dto)
        if pr_key is not None:
            self._pr_index[pr_key] = scan_id
        return scan_id

    @staticmethod
    def _pr_key(
        origin: str, repo_id: uuid.UUID | None, pr_number: int | None, head_sha: str | None
    ) -> tuple[uuid.UUID, int, str] | None:
        """Clave de idempotencia de un escaneo de PR, o None si no es un PR completo."""
        if origin != "pull_request" or repo_id is None or pr_number is None or head_sha is None:
            return None
        return (repo_id, pr_number, head_sha)

    async def list_by_user(
        self,
        user_id: uuid.UUID,
        *,
        repo_id: uuid.UUID | None = None,
        ecosystem: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> ScanPageDTO:
        """Lista ordenada por created_at DESC con filtros opcionales (repo_id + ecosystem)."""
        matching = [
            dto
            for (uid, rid, dto) in self._store.values()
            if uid == user_id
            and (repo_id is None or rid == repo_id)
            and (ecosystem is None or dto.ecosystem == ecosystem)
        ]
        # Ordenamos por created_at desc (los DTOs ya tienen el campo).
        matching.sort(key=lambda d: d.created_at, reverse=True)

        total = len(matching)
        offset = (page - 1) * page_size
        page_items = matching[offset : offset + page_size]

        items = [
            ScanListItemDTO(
                scan_id=dto.scan_id,
                origin=dto.origin,
                created_at=dto.created_at,
                ecosystem=dto.ecosystem,
                schema_version=dto.schema_version,
                tool_version=dto.tool_version,
                error_category=dto.error_category,
                summary=dto.summary,
            )
            for dto in page_items
        ]
        return ScanPageDTO(items=items, total=total, page=page, page_size=page_size)

    async def get_by_id_for_user(
        self,
        scan_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> ScanDTO | None:
        """Devuelve el DTO si existe Y es del usuario; None en cualquier otro caso (R5.3)."""
        entry = self._store.get(scan_id)
        if entry is None:
            return None
        owner_id, _repo_id, dto = entry
        if owner_id != user_id:
            # Aislamiento: otro usuario → tratamos como no encontrado (R5.3).
            return None
        return dto

    @property
    def persisted_count(self) -> int:
        """Filas únicas persistidas (un PR re-procesado con el mismo head_sha cuenta una vez)."""
        return len(self._store)

    def last_call(self) -> dict[str, object]:
        return self.calls[-1]
