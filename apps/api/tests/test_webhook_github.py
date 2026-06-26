"""Aceptación del Webhook Router de la GitHub App (H5-T22, R2.2/R2.4, R6.1, NFR-Seg-2/4).

Verifica el COMPORTAMIENTO observable del receptor con dobles en memoria (sin Postgres, sin red).
Mapea a los criterios EARS relevantes a esta tarea:

- R6.1 / NFR-Seg-2: HMAC sobre raw body ANTES de parsear; firma inválida/ausente ⇒ 204 sin efecto.
- R2.2: `installation` (created) persiste la instalación + repos accesibles.
- R2.4: `installation` (deleted/suspend) cambia `status` SIN borrar histórico.
- `installation_repositories`: sincroniza repos añadidos/quitados.
- `pull_request` queda PREPARADO (ack 202, sin encolar) para la Ola 5.
- Fail-closed: sin `github_webhook_secret` ⇒ 503, ningún evento procesado.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.api import webhooks as webhooks_module
from app.github_app.deps import get_installation_repository
from app.github_app.installation_repo import (
    STATUS_REVOKED,
    STATUS_SUSPENDED,
    FakeInstallationRepository,
)
from app.main import create_app
from app.security.webhook_signature import expected_signature
from app.settings import get_settings

_API = "/api/v1"
_WEBHOOK_SECRET = "test-webhook-secret-xyz"  # valor de prueba, no un secreto real
# `sender.github_user_id` del instalador conocido: el Fake lo resuelve a un users.id interno.
_INSTALLER_GH_ID = 7777


def _build_client(
    repo: FakeInstallationRepository,
    *,
    secret: str | None = _WEBHOOK_SECRET,
    max_body_bytes: int | None = None,
) -> TestClient:
    """TestClient con el repo de instalaciones doblado y un `github_webhook_secret` inyectado.

    `max_body_bytes` permite endurecer el tope del cuerpo del webhook para los tests de DoS.
    """
    app: FastAPI = create_app()
    app.dependency_overrides[get_installation_repository] = lambda: repo

    update: dict[str, object] = {
        "github_webhook_secret": SecretStr(secret) if secret is not None else None
    }
    if max_body_bytes is not None:
        update["webhook_max_body_bytes"] = max_body_bytes
    patched = get_settings().model_copy(update=update)
    # El router obtiene Settings vía `webhooks._settings_dep` → `get_settings()`. Lo parcheamos.
    app.dependency_overrides[webhooks_module._settings_dep] = lambda: patched
    return TestClient(app)


def _post_signed(
    client: TestClient, *, event: str, payload: dict[str, object], secret: str = _WEBHOOK_SECRET
) -> object:
    """POST firmado con HMAC sobre el cuerpo EXACTO que se envía (bytes canónicos)."""
    body = json.dumps(payload).encode("utf-8")
    signature = expected_signature(secret, body)
    return client.post(
        f"{_API}/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": event,
            "X-Hub-Signature-256": signature,
            "Content-Type": "application/json",
        },
    )


def _installation_payload(
    *, action: str, installation_id: int, repos: list[dict[str, object]] | None = None
) -> dict[str, object]:
    payload: dict[str, object] = {
        "action": action,
        "installation": {
            "id": installation_id,
            "account": {"login": "octo-owner", "id": 1},
        },
        "sender": {"id": _INSTALLER_GH_ID, "login": "octo-owner"},
    }
    if repos is not None:
        payload["repositories"] = repos
    return payload


@pytest.fixture
def repo() -> FakeInstallationRepository:
    r = FakeInstallationRepository()
    # El instalador es un usuario ya logueado: sembramos su mapping github_user_id → users.id.
    r.seed_owner(_INSTALLER_GH_ID, uuid.uuid4())
    return r


# ---------------------------------------------------------------------------
# R6.1 / NFR-Seg-2 — HMAC: firma inválida/ausente ⇒ 204 descartado sin efecto
# ---------------------------------------------------------------------------


def test_firma_invalida_descarta_sin_efecto(repo: FakeInstallationRepository) -> None:
    """Firma HMAC incorrecta ⇒ 204 y NADA persiste (no se parsea ni se toca el repo)."""
    client = _build_client(repo)
    payload = _installation_payload(action="created", installation_id=10, repos=[])
    body = json.dumps(payload).encode("utf-8")

    resp = client.post(
        f"{_API}/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": "installation",
            "X-Hub-Signature-256": "sha256=" + "0" * 64,  # firma que no corresponde
        },
    )

    assert resp.status_code == 204
    assert repo.get_state(10) is None  # no se persistió la instalación


def test_firma_ausente_descarta_sin_efecto(repo: FakeInstallationRepository) -> None:
    client = _build_client(repo)
    payload = _installation_payload(action="created", installation_id=11, repos=[])
    body = json.dumps(payload).encode("utf-8")

    resp = client.post(
        f"{_API}/webhooks/github",
        content=body,
        headers={"X-GitHub-Event": "installation"},  # sin X-Hub-Signature-256
    )

    assert resp.status_code == 204
    assert repo.get_state(11) is None


def test_cuerpo_alterado_tras_firmar_descarta(repo: FakeInstallationRepository) -> None:
    """Si el cuerpo cambia un byte respecto al firmado, el HMAC no valida ⇒ 204 (anti-tampering)."""
    client = _build_client(repo)
    payload = _installation_payload(action="created", installation_id=12, repos=[])
    body = json.dumps(payload).encode("utf-8")
    signature = expected_signature(_WEBHOOK_SECRET, body)

    resp = client.post(
        f"{_API}/webhooks/github",
        content=body + b" ",  # cuerpo enviado != cuerpo firmado
        headers={"X-GitHub-Event": "installation", "X-Hub-Signature-256": signature},
    )

    assert resp.status_code == 204
    assert repo.get_state(12) is None


# ---------------------------------------------------------------------------
# Fail-closed — sin secreto configurado ⇒ 503, ningún evento procesado
# ---------------------------------------------------------------------------


def test_sin_secreto_configurado_responde_503(repo: FakeInstallationRepository) -> None:
    client = _build_client(repo, secret=None)
    resp = _post_signed(
        client,
        event="installation",
        payload=_installation_payload(action="created", installation_id=13, repos=[]),
    )
    assert resp.status_code == 503
    assert repo.get_state(13) is None


# ---------------------------------------------------------------------------
# R2.2 — installation (created) persiste instalación + repos accesibles
# ---------------------------------------------------------------------------


def test_installation_created_persiste_instalacion_y_repos(
    repo: FakeInstallationRepository,
) -> None:
    client = _build_client(repo)
    payload = _installation_payload(
        action="created",
        installation_id=100,
        repos=[
            {"id": 501, "full_name": "octo-owner/repo-a", "private": False},
            {"id": 502, "full_name": "octo-owner/repo-b", "private": True},
        ],
    )

    resp = _post_signed(client, event="installation", payload=payload)

    assert resp.status_code == 202
    state = repo.get_state(100)
    assert state is not None
    assert state.status == "active"
    assert set(state.repos.keys()) == {501, 502}
    assert state.repos[502].private is True


def test_installation_reentregada_es_idempotente(repo: FakeInstallationRepository) -> None:
    """GitHub reentrega webhooks: un segundo `created` no duplica ni cambia el internal_id."""
    client = _build_client(repo)
    payload = _installation_payload(
        action="created",
        installation_id=101,
        repos=[{"id": 600, "full_name": "octo-owner/r", "private": False}],
    )

    first = _post_signed(client, event="installation", payload=payload)
    state_after_first = repo.get_state(101)
    second = _post_signed(client, event="installation", payload=payload)
    state_after_second = repo.get_state(101)

    assert first.status_code == 202
    assert second.status_code == 202
    assert state_after_first is not None
    assert state_after_second is not None
    assert state_after_first.internal_id == state_after_second.internal_id


def test_installation_de_usuario_desconocido_no_persiste(
    repo: FakeInstallationRepository,
) -> None:
    """Instalador sin login previo (sender desconocido) ⇒ ack 202 pero NO se asocia."""
    client = _build_client(repo)
    payload = _installation_payload(action="created", installation_id=102, repos=[])
    # `sender.id` desconocido: el Fake no tiene mapping para él.
    payload["sender"] = {"id": 99999, "login": "stranger"}

    resp = _post_signed(client, event="installation", payload=payload)

    assert resp.status_code == 202
    assert repo.get_state(102) is None


# ---------------------------------------------------------------------------
# R2.4 — deleted/suspend cambian status SIN borrar histórico
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "expected_status"),
    [("deleted", STATUS_REVOKED), ("suspend", STATUS_SUSPENDED)],
)
def test_desinstalacion_cambia_status_sin_borrar_repos(
    repo: FakeInstallationRepository, action: str, expected_status: str
) -> None:
    """`deleted`/`suspend` marca status y CONSERVA los repos (proxy de no borrar, R2.4)."""
    client = _build_client(repo)
    created = _installation_payload(
        action="created",
        installation_id=200,
        repos=[{"id": 700, "full_name": "octo-owner/keep", "private": False}],
    )
    _post_signed(client, event="installation", payload=created)

    deactivate = _installation_payload(action=action, installation_id=200)
    resp = _post_signed(client, event="installation", payload=deactivate)

    assert resp.status_code == 202
    state = repo.get_state(200)
    assert state is not None
    assert state.status == expected_status
    # R2.4: los repos (y por extensión el histórico de scans) NO se borran al desactivar.
    assert set(state.repos.keys()) == {700}
    assert (200, expected_status) in repo.status_changes


def test_desinstalacion_de_instalacion_desconocida_es_202(
    repo: FakeInstallationRepository,
) -> None:
    """`deleted` para una instalación que nunca persistimos ⇒ ack 202 sin error (idempotente)."""
    client = _build_client(repo)
    resp = _post_signed(
        client,
        event="installation",
        payload=_installation_payload(action="deleted", installation_id=999),
    )
    assert resp.status_code == 202


# ---------------------------------------------------------------------------
# installation_repositories — sincroniza repos added/removed
# ---------------------------------------------------------------------------


def test_installation_repositories_sincroniza_delta(
    repo: FakeInstallationRepository,
) -> None:
    client = _build_client(repo)
    _post_signed(
        client,
        event="installation",
        payload=_installation_payload(
            action="created",
            installation_id=300,
            repos=[{"id": 800, "full_name": "octo-owner/old", "private": False}],
        ),
    )

    delta = {
        "installation": {"id": 300, "account": {"login": "octo-owner", "id": 1}},
        "repositories_added": [
            {"id": 801, "full_name": "octo-owner/new", "private": True}
        ],
        "repositories_removed": [
            {"id": 800, "full_name": "octo-owner/old", "private": False}
        ],
    }
    resp = _post_signed(client, event="installation_repositories", payload=delta)

    assert resp.status_code == 202
    state = repo.get_state(300)
    assert state is not None
    assert set(state.repos.keys()) == {801}  # 800 quitado, 801 añadido


# ---------------------------------------------------------------------------
# pull_request — preparado (ack 202, sin encolar) para la Ola 5
# ---------------------------------------------------------------------------


def test_pull_request_hace_ack_sin_procesar(repo: FakeInstallationRepository) -> None:
    client = _build_client(repo)
    payload = {
        "action": "opened",
        "pull_request": {"number": 1, "head": {"sha": "abc"}},
        "installation": {"id": 1},
    }
    resp = _post_signed(client, event="pull_request", payload=payload)
    # Reconocido pero NO procesado en esta ola: solo ack 202 (el worker es de la Ola 5).
    assert resp.status_code == 202


# ---------------------------------------------------------------------------
# Robustez — ping y cuerpo malformado con firma válida
# ---------------------------------------------------------------------------


def test_ping_hace_ack(repo: FakeInstallationRepository) -> None:
    client = _build_client(repo)
    resp = _post_signed(client, event="ping", payload={"zen": "Keep it simple."})
    assert resp.status_code == 202


def test_cuerpo_no_json_con_firma_valida_se_ignora(
    repo: FakeInstallationRepository,
) -> None:
    """Cuerpo no-JSON pero correctamente firmado ⇒ ack 202 sin procesar (no reintento de GitHub)."""
    client = _build_client(repo)
    body = b"not-json-at-all"
    signature = expected_signature(_WEBHOOK_SECRET, body)
    resp = client.post(
        f"{_API}/webhooks/github",
        content=body,
        headers={"X-GitHub-Event": "installation", "X-Hub-Signature-256": signature},
    )
    assert resp.status_code == 202


def test_installation_payload_malformado_no_revienta(
    repo: FakeInstallationRepository,
) -> None:
    """Payload de installation con forma inesperada (firma válida) ⇒ 202 sin persistir (no 500)."""
    client = _build_client(repo)
    # Falta `installation`: el parser lanza MalformedEventError, el router hace ack sin persistir.
    resp = _post_signed(
        client, event="installation", payload={"action": "created", "sender": {"id": 1}}
    )
    assert resp.status_code == 202


# ---------------------------------------------------------------------------
# No-fuga — el secreto del webhook nunca aparece en una respuesta
# ---------------------------------------------------------------------------


def test_secreto_nunca_aparece_en_respuestas(repo: FakeInstallationRepository) -> None:
    client = _build_client(repo)
    responses = [
        _post_signed(
            client,
            event="installation",
            payload=_installation_payload(action="created", installation_id=400, repos=[]),
        ),
        client.post(
            f"{_API}/webhooks/github",
            content=b"{}",
            headers={"X-GitHub-Event": "installation", "X-Hub-Signature-256": "sha256=" + "0" * 64},
        ),
    ]
    for resp in responses:
        haystack = resp.text + "".join(f"{k}:{v}" for k, v in resp.headers.items())
        assert _WEBHOOK_SECRET not in haystack


# ---------------------------------------------------------------------------
# SEC MINOR 5 — DoS: cuerpo sobre el límite ⇒ 413 sin verificar HMAC ni parsear
# ---------------------------------------------------------------------------


def test_cuerpo_sobre_limite_responde_413_sin_procesar(
    repo: FakeInstallationRepository,
) -> None:
    """Un cuerpo que supera `webhook_max_body_bytes` ⇒ 413, ANTES de HMAC y parseo (anti-DoS).

    El cuerpo va correctamente FIRMADO: si el handler llegara a verificar el HMAC, devolvería 202
    (firma válida). Que devuelva 413 demuestra que el tope se aplica antes que la verificación.
    Y `get_state` None confirma que NADA se persistió (no se parseó el evento).
    """
    # Límite minúsculo (64 bytes) para forzar el rechazo con un payload normal.
    client = _build_client(repo, max_body_bytes=64)
    payload = _installation_payload(
        action="created",
        installation_id=900,
        repos=[{"id": 1, "full_name": "octo-owner/big", "private": False}],
    )
    body = json.dumps(payload).encode("utf-8")
    assert len(body) > 64  # garantizamos que excede el tope
    signature = expected_signature(_WEBHOOK_SECRET, body)  # firma VÁLIDA a propósito

    resp = client.post(
        f"{_API}/webhooks/github",
        content=body,
        headers={"X-GitHub-Event": "installation", "X-Hub-Signature-256": signature},
    )

    assert resp.status_code == 413
    assert repo.get_state(900) is None  # no se parseó ni persistió nada


def test_content_length_mentido_sobre_limite_responde_413(
    repo: FakeInstallationRepository,
) -> None:
    """Aunque el cuerpo real supere el tope, la lectura acotada lo corta ⇒ 413 (no se materializa).

    Verificamos que el tope no depende solo de `Content-Length`: el cuerpo real grande se rechaza
    al leer por chunks. (TestClient fija Content-Length correcto; el cuerpo grande basta para
    ejercitar la barrera de lectura acotada por chunks.)
    """
    client = _build_client(repo, max_body_bytes=128)
    big_body = b'{"action":"created","installation":{"id":901},"pad":"' + b"A" * 10_000 + b'"}'
    signature = expected_signature(_WEBHOOK_SECRET, big_body)

    resp = client.post(
        f"{_API}/webhooks/github",
        content=big_body,
        headers={"X-GitHub-Event": "installation", "X-Hub-Signature-256": signature},
    )

    assert resp.status_code == 413
    assert repo.get_state(901) is None


def test_cuerpo_bajo_limite_se_procesa_normal(repo: FakeInstallationRepository) -> None:
    """Un cuerpo dentro del límite (default 1 MiB) sigue procesándose con normalidad (202)."""
    client = _build_client(repo)  # default webhook_max_body_bytes = 1 MiB
    resp = _post_signed(
        client,
        event="installation",
        payload=_installation_payload(action="created", installation_id=902, repos=[]),
    )
    assert resp.status_code == 202
    assert repo.get_state(902) is not None
