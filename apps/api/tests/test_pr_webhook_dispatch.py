"""Aceptación del dispatch `pull_request` del webhook al worker async (Ola 5, R6.1/R9.3, ADR-2).

Verifica el COMPORTAMIENTO observable del receptor cuando llega un evento `pull_request`, con
dobles en memoria (sin Postgres, sin Redis, sin red). El webhook solo debe ENCOLAR el escaneo
(trabajo pesado en el worker) y hacer ack 202; el trabajo real se prueba en
`test_pr_scan_worker.py`. Mapea a los criterios EARS relevantes:

- R6.1 / NFR-Seg-2: HMAC sobre el raw body ANTES de parsear; firma inválida ⇒ 204 sin encolar.
- R9.3 / ADR-2: solo `opened`/`synchronize`/`reopened` encolan; otras `action` hacen ack sin job.
- El job encolado lleva EXACTAMENTE los ids del payload (installation/repo/pr/head_sha).

Reusa los helpers de firma (`_post_signed`) y el patrón `_build_client` de `test_webhook_github.py`;
la cola de jobs se dobla con `InMemoryJobQueue` vía `app.dependency_overrides`.
"""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.api import webhooks as webhooks_module
from app.github_app.deps import get_installation_repository
from app.github_app.installation_repo import FakeInstallationRepository
from app.main import create_app
from app.security.webhook_signature import expected_signature
from app.settings import get_settings
from app.worker.deps import get_job_queue
from app.worker.jobs import InMemoryJobQueue

_API = "/api/v1"
_WEBHOOK_SECRET = "test-webhook-secret-xyz"  # valor de prueba, no un secreto real

# Identificadores fijos del payload `pull_request` que esperamos ver reflejados en el job.
_INSTALLATION_ID = 4242
_GITHUB_REPO_ID = 9001
_REPO_FULL_NAME = "octo-owner/api"
_PR_NUMBER = 7
_HEAD_SHA = "deadbeefcafef00d1234567890abcdef12345678"


def _build_client(
    repo: FakeInstallationRepository, queue: InMemoryJobQueue
) -> TestClient:
    """TestClient con el repo de instalaciones y la cola de jobs doblados (sin Redis/Postgres)."""
    app: FastAPI = create_app()
    app.dependency_overrides[get_installation_repository] = lambda: repo
    app.dependency_overrides[get_job_queue] = lambda: queue

    patched = get_settings().model_copy(
        update={"github_webhook_secret": SecretStr(_WEBHOOK_SECRET)}
    )
    app.dependency_overrides[webhooks_module._settings_dep] = lambda: patched
    return TestClient(app)


def _post_signed(
    client: TestClient, *, event: str, payload: dict[str, object]
) -> httpx.Response:
    """POST firmado con HMAC sobre el cuerpo EXACTO que se envía (bytes canónicos)."""
    body = json.dumps(payload).encode("utf-8")
    signature = expected_signature(_WEBHOOK_SECRET, body)
    resp: httpx.Response = client.post(
        f"{_API}/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": event,
            "X-Hub-Signature-256": signature,
            "Content-Type": "application/json",
        },
    )
    return resp


def _pr_payload(
    *,
    action: str,
    installation_id: int = _INSTALLATION_ID,
    github_repo_id: int = _GITHUB_REPO_ID,
    repo_full_name: str = _REPO_FULL_NAME,
    pr_number: int = _PR_NUMBER,
    head_sha: str = _HEAD_SHA,
) -> dict[str, object]:
    """Payload `pull_request` con la forma exacta que GitHub envía y que el parser espera."""
    return {
        "action": action,
        "number": pr_number,
        "pull_request": {"number": pr_number, "head": {"sha": head_sha}},
        "repository": {"id": github_repo_id, "full_name": repo_full_name},
        "installation": {"id": installation_id},
        "sender": {"id": 1},
    }


@pytest.fixture
def repo() -> FakeInstallationRepository:
    return FakeInstallationRepository()


@pytest.fixture
def queue() -> InMemoryJobQueue:
    return InMemoryJobQueue()


# ---------------------------------------------------------------------------
# (a) R6.1 — HMAC inválido en `pull_request` ⇒ 204 y NINGÚN job encolado
# ---------------------------------------------------------------------------


def test_firma_invalida_no_encola_job(
    repo: FakeInstallationRepository, queue: InMemoryJobQueue
) -> None:
    """Firma HMAC incorrecta ⇒ 204 (descartado antes de parsear) y la cola queda vacía."""
    client = _build_client(repo, queue)
    body = json.dumps(_pr_payload(action="opened")).encode("utf-8")

    resp = client.post(
        f"{_API}/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": "sha256=" + "0" * 64,  # firma que no corresponde
        },
    )

    assert resp.status_code == 204
    assert queue.jobs == []  # nada se encoló: ni se parseó el evento


# ---------------------------------------------------------------------------
# (b) R9.3 — `opened` con firma válida ⇒ 202 y EXACTAMENTE 1 job con los ids correctos
# ---------------------------------------------------------------------------


def test_opened_encola_exactamente_un_job_con_ids_correctos(
    repo: FakeInstallationRepository, queue: InMemoryJobQueue
) -> None:
    """`pull_request/opened` firmado ⇒ ack 202 y un único job con todos los ids del payload."""
    client = _build_client(repo, queue)

    resp = _post_signed(client, event="pull_request", payload=_pr_payload(action="opened"))

    assert resp.status_code == 202
    assert len(queue.jobs) == 1
    job = queue.jobs[0]
    assert job.installation_id == _INSTALLATION_ID
    assert job.repo_full_name == _REPO_FULL_NAME
    assert job.github_repo_id == _GITHUB_REPO_ID
    assert job.pr_number == _PR_NUMBER
    assert job.head_sha == _HEAD_SHA


# ---------------------------------------------------------------------------
# (c) `closed` (fuera de opened/synchronize/reopened) ⇒ 202 y 0 jobs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["closed", "edited", "labeled", "assigned"])
def test_acciones_no_escaneables_no_encolan(
    repo: FakeInstallationRepository, queue: InMemoryJobQueue, action: str
) -> None:
    """Una `action` fuera del conjunto a escanear ⇒ ack 202 sin encolar (no genera ruido)."""
    client = _build_client(repo, queue)

    resp = _post_signed(client, event="pull_request", payload=_pr_payload(action=action))

    assert resp.status_code == 202
    assert queue.jobs == []


# ---------------------------------------------------------------------------
# (d) `synchronize` y `reopened` ⇒ 202 y SÍ encolan
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["synchronize", "reopened"])
def test_synchronize_y_reopened_encolan(
    repo: FakeInstallationRepository, queue: InMemoryJobQueue, action: str
) -> None:
    """`synchronize`/`reopened` también disparan un escaneo (nuevos commits / PR reabierto)."""
    client = _build_client(repo, queue)

    resp = _post_signed(client, event="pull_request", payload=_pr_payload(action=action))

    assert resp.status_code == 202
    assert len(queue.jobs) == 1
    assert queue.jobs[0].head_sha == _HEAD_SHA


# ---------------------------------------------------------------------------
# Robustez — payload `pull_request` malformado (firma válida) ⇒ 202 sin encolar (no 500)
# ---------------------------------------------------------------------------


def test_pull_request_malformado_hace_ack_sin_encolar(
    repo: FakeInstallationRepository, queue: InMemoryJobQueue
) -> None:
    """Payload sin `repository` (firma válida) ⇒ ack 202 sin job (el parser lanza y se ignora)."""
    client = _build_client(repo, queue)
    payload: dict[str, object] = {
        "action": "opened",
        "pull_request": {"number": 1, "head": {"sha": "abc"}},
        "installation": {"id": 1},
    }

    resp = _post_signed(client, event="pull_request", payload=payload)

    assert resp.status_code == 202
    assert queue.jobs == []


# ---------------------------------------------------------------------------
# Idempotencia del encolado — re-entrega del MISMO evento `opened`
# ---------------------------------------------------------------------------


def test_reentrega_del_mismo_evento_encola_otro_job_con_mismo_head_sha(
    repo: FakeInstallationRepository, queue: InMemoryJobQueue
) -> None:
    """GitHub puede reentregar el webhook: el dedup vive en el worker (por head_sha), no aquí.

    El webhook encola ambos; lo importante es que el head_sha se preserva idéntico para que el
    worker upsertee sin duplicar (idempotencia probada en test_pr_scan_worker.py).
    """
    client = _build_client(repo, queue)
    payload = _pr_payload(action="opened")

    first = _post_signed(client, event="pull_request", payload=payload)
    second = _post_signed(client, event="pull_request", payload=payload)

    assert first.status_code == 202
    assert second.status_code == 202
    assert [j.head_sha for j in queue.jobs] == [_HEAD_SHA, _HEAD_SHA]


# ---------------------------------------------------------------------------
# No regresión — un fallo de la cola NO rompe el ack (R9.3: GitHub no debe reintentar)
# ---------------------------------------------------------------------------


def test_fallo_de_la_cola_no_rompe_el_ack(
    repo: FakeInstallationRepository,
) -> None:
    """Si el encolado revienta (Redis caído), el webhook hace ack 202 igualmente (R9.3)."""

    class _ExplodingQueue:
        async def enqueue_pr_scan(self, job: object) -> None:
            raise RuntimeError("redis no disponible")

    app: FastAPI = create_app()
    app.dependency_overrides[get_installation_repository] = lambda: repo
    app.dependency_overrides[get_job_queue] = lambda: _ExplodingQueue()
    patched = get_settings().model_copy(
        update={"github_webhook_secret": SecretStr(_WEBHOOK_SECRET)}
    )
    app.dependency_overrides[webhooks_module._settings_dep] = lambda: patched
    client = TestClient(app)

    resp = _post_signed(client, event="pull_request", payload=_pr_payload(action="opened"))

    assert resp.status_code == 202


# ---------------------------------------------------------------------------
# No-fuga — el secreto del webhook nunca aparece en la respuesta del dispatch de PR
# ---------------------------------------------------------------------------


def test_secreto_no_aparece_en_respuesta_de_pr(
    repo: FakeInstallationRepository, queue: InMemoryJobQueue
) -> None:
    client = _build_client(repo, queue)
    resp = _post_signed(client, event="pull_request", payload=_pr_payload(action="opened"))
    haystack = resp.text + "".join(f"{k}:{v}" for k, v in resp.headers.items())
    assert _WEBHOOK_SECRET not in haystack
