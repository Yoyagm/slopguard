# GitHub App de SlopGuard — Permisos mínimos y configuración del webhook

Referencia operativa para registrar la GitHub App de SlopGuard SaaS con **mínimo privilegio**
(R2.1, NFR-Seg-4, ADR-4). Estos valores se configuran en GitHub al crear/editar la App; el código
(`apps/api/app/github_app/*`, `apps/api/app/api/webhooks.py`) asume exactamente este perfil.

> Principio rector: la App solo pide lo necesario para **leer** los manifiestos cambiados en un PR
> y **escribir** un check informativo + un comentario. Nada más. Cualquier permiso de escritura
> sobre código, settings o administración está **fuera de alcance** y NO debe concederse.

## Permisos de repositorio (Repository permissions)

| Permiso | Nivel | Por qué (mínimo privilegio) |
|---|---|---|
| **Contents** | `Read-only` | Bajar el contenido de los manifiestos cambiados (`package.json`, `requirements*.txt`, `pyproject.toml`) en el `head_sha` del PR. Solo lectura: SlopGuard nunca modifica el repo. |
| **Metadata** | `Read-only` | Obligatorio por GitHub para casi toda App; expone metadatos básicos del repo (id, full_name, visibilidad). Es el permiso que alimenta `repos.github_repo_id`/`full_name`/`private`. |
| **Pull requests** | `Read & write` | *Read*: listar los ficheros (diff) del PR y resolver `pr_number`/`head_sha`. *Write*: **solo** para publicar/actualizar el comentario informativo del PR. NO se usa para fusionar, cerrar ni editar el PR. |
| **Checks** | `Read & write` | Publicar/actualizar el **Check Run** informativo (`conclusion` = peor veredicto). NUNCA se marca como *required* (R6.3, solo informar). |

**Todo lo demás queda en `No access`.** En particular, NO se concede: Administration, Actions,
Secrets, Environments, Deployments, Webhooks (de repo), Workflows, Packages, ni ningún permiso de
organización o de cuenta más allá de los cuatro de arriba.

## Permisos de organización / cuenta

`No access` en todos. SlopGuard es single-tenant a nivel demo: no administra organizaciones,
equipos, miembros ni billing (fuera de alcance del Hito 5).

## Suscripción a eventos (Subscribe to events)

Solo los eventos que el backend procesa hoy o en la Ola 5. Suscribirse a más sería ruido y
superficie de ataque innecesaria:

| Evento | Quién lo maneja | Estado |
|---|---|---|
| **Installation** | `app/api/webhooks.py::_handle_installation` | Ola 4 (T22): upsert de instalación + repos; `deleted`/`suspend` cambian `status` sin borrar histórico (R2.4). |
| **Installation repositories** | `app/api/webhooks.py::_handle_installation_repositories` | Ola 4 (T22): sincroniza repos `added`/`removed`. |
| **Pull request** | `app/api/webhooks.py::_handle_pull_request` | Reconocido (ack 202); el dispatch al worker async es de la **Ola 5** (T26+). |

NO suscribir a: `push`, `release`, `issues`, `issue_comment`, `workflow_run`, etc.

## Webhook

- **Payload URL:** `https://<host>/api/v1/webhooks/github`
- **Content type:** `application/json`
- **Secret:** obligatorio. Se inyecta en el backend como `GITHUB_WEBHOOK_SECRET` (variable de
  entorno, `Settings.github_webhook_secret`, tipo `SecretStr`). Sin secreto configurado, el
  endpoint responde `503` y **descarta todos los webhooks** (fail-closed): preferimos no operar
  antes que aceptar eventos sin autenticar.
- **Verificación HMAC:** el receptor calcula `HMAC-SHA256` del **cuerpo crudo** y lo compara con la
  cabecera `X-Hub-Signature-256` en **tiempo constante** (`hmac.compare_digest`) **antes de
  parsear** el evento (ADR-4, R6.1). Firma inválida/ausente ⇒ `204` descartado sin efecto.
- **SSL verification:** habilitada (TLS obligatorio).

## Where the user installs

Recomendado **"Only on this account"** (instalación en la cuenta del dueño del demo) y selección de
repos explícita ("Only select repositories"), no "All repositories": refuerza el mínimo privilegio
y mantiene acotada la lista de `repos` accesibles (R2.3).

## Secretos de despliegue asociados (referencia)

Estos secretos viven SOLO como variables de entorno (nunca en DB ni en logs; `SecretStr`):

| Variable | Uso |
|---|---|
| `GITHUB_APP_ID` | Identificador (público) de la App; emisor del JWT de App. |
| `GITHUB_APP_PRIVATE_KEY` | Clave privada de la App para firmar el JWT y pedir installation tokens (Ola 5/T23). |
| `GITHUB_WEBHOOK_SECRET` | Secreto compartido para el HMAC del webhook (esta tarea). |

Los **installation tokens** son de vida corta (~1h) y se renuevan bajo demanda (R2.5); **no se
persisten** en DB (a lo sumo caché efímera cifrada en Redis con TTL < expiración). La clave privada
de la App nunca se persiste en DB.
