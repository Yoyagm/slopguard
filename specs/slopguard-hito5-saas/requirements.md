# Documento de Requisitos: SlopGuard SaaS (Hito 5)

## Introducción

SlopGuard SaaS es la cara web del motor de detección de slopsquatting/package-hallucination
de SlopGuard. **Reutiliza el motor existente** (`src/slopguard`, Python, cero dependencias de
runtime, fail-closed) **como librería in-process** y lo expone por dos vías: (a) un **dashboard
web** donde un desarrollador autenticado escanea manifiestos on-demand y consulta su histórico, y
(b) una **GitHub App** que, en cada Pull Request, escanea los manifiestos cambiados y publica un
**check informativo (NO bloqueante) + un comentario**. El objetivo de este hito es una **pieza de
portfolio** funcional y profesional: single-tenant, sin billing ni multi-tenant, un solo entorno.

El motor de detección permanece como **fuente de verdad y zero-deps**; el backend (que sí tiene
dependencias) lo envuelve sin reimplementar la lógica de capas/scoring.

## Usuarios objetivo

- **Desarrollador / dueño del demo (usuario primario).** Inicia sesión con GitHub, instala la
  GitHub App en sus repos, lanza escaneos on-demand y revisa veredictos e histórico. Necesita una
  UI limpia que **explique** cada veredicto (por qué *block*/*warn*/*allow*), no solo lo muestre.
- **Revisor de PR (consumidor pasivo).** Ve el check + comentario de SlopGuard dentro de un PR sin
  entrar al dashboard. Necesita un resumen accionable inline.
- **Evaluador del portfolio.** Recorre el demo end-to-end; valora claridad, pulcritud visual y que
  "funcione de verdad".

No hay roles de organización, admin multi-tenant ni billing en este hito.

## Requisitos funcionales

### Requisito 1: Autenticación con GitHub OAuth
**Historia:** Como desarrollador, quiero iniciar sesión con mi cuenta de GitHub, para acceder a mi
dashboard y a mis repos sin gestionar otra contraseña.
**Criterios de aceptación (EARS):**
1. WHEN un usuario no autenticado solicita una ruta protegida THE SYSTEM SHALL redirigirlo al flujo
   OAuth de GitHub con un `state` aleatorio de un solo uso.
2. WHEN GitHub redirige al callback con un `code` válido y un `state` que coincide con el emitido
   THE SYSTEM SHALL crear o recuperar la cuenta, abrir sesión y redirigir al dashboard.
3. IF el `state` del callback no coincide o expiró THEN THE SYSTEM SHALL rechazar el callback con un
   error y NO crear sesión (defensa CSRF).
4. WHEN el usuario cierra sesión THE SYSTEM SHALL invalidar la sesión del servidor y revocar/olvidar
   los tokens asociados.
5. WHILE exista una sesión THE SYSTEM SHALL guardar el token de acceso de GitHub **cifrado en reposo**
   y NUNCA exponerlo al cliente (ni en HTML, ni en JSON, ni en logs).

### Requisito 2: Instalación de la GitHub App y conexión de repos
**Historia:** Como desarrollador, quiero instalar la GitHub App en repos elegidos, para que SlopGuard
pueda leerlos y comentar en sus PRs.
**Criterios de aceptación (EARS):**
1. WHEN el usuario inicia la instalación THE SYSTEM SHALL dirigirlo al flujo de instalación de la
   GitHub App con permisos de **mínimo privilegio** (lectura de contenidos/metadatos y PRs; escritura
   de checks y comentarios de PR; nada más).
2. WHEN GitHub notifica una instalación nueva o actualizada THE SYSTEM SHALL persistir la instalación
   y la lista de repos accesibles, asociadas al usuario.
3. WHEN el usuario abre el dashboard THE SYSTEM SHALL listar solo los repos a los que la App tiene
   acceso para esa instalación.
4. WHEN la App se desinstala THE SYSTEM SHALL marcar la instalación como revocada y dejar de listar
   sus repos, sin borrar el histórico ya generado.
5. IF un token de instalación caduca THEN THE SYSTEM SHALL renovarlo bajo demanda; si falla, degradar
   a "repo no disponible" con mensaje accionable, nunca a un escaneo silenciosamente vacío.

### Requisito 3: Escaneo on-demand desde el dashboard
**Historia:** Como desarrollador, quiero escanear un manifiesto al instante, para ver el riesgo de
sus dependencias antes de instalarlas.
**Criterios de aceptación (EARS):**
1. WHEN el usuario pega o sube un manifiesto, o selecciona un repo conectado + ruta de manifiesto, y
   lanza el escaneo THE SYSTEM SHALL invocar el motor con el ecosistema correcto (autodetectado por
   nombre o forzado por el usuario) y devolver un reporte estructurado.
2. WHEN el ecosistema se autodetecta (package.json→npm; requirements*.txt/pyproject.toml→pypi)
   THE SYSTEM SHALL respetar la precedencia del motor (override explícito gana).
3. IF el manifiesto supera los límites del motor (tamaño o nº de dependencias) THEN THE SYSTEM SHALL
   rechazarlo con un error claro, sin parsearlo entero.
4. IF un nombre de paquete es inválido o no verificable THEN THE SYSTEM SHALL reportarlo como
   **UNVERIFIABLE**, nunca como *allow*/CLEAN (fail-closed, heredado del motor).
5. WHILE el escaneo consulta registros externos (PyPI/npm/OSV) THE SYSTEM SHALL aplicar el mismo
   trato de "entrada no confiable" del motor y degradar a UNVERIFIABLE ante fallo de red, sin
   inventar un veredicto limpio.

### Requisito 4: Visualización del reporte de escaneo
**Historia:** Como desarrollador, quiero un reporte claro y explicado, para entender por qué cada
dependencia es *allow*, *warn* o *block*.
**Criterios de aceptación (EARS):**
1. WHEN un escaneo termina THE SYSTEM SHALL mostrar, por dependencia: nombre normalizado, veredicto
   (allow/warn/block) o estado *unverifiable*, score, objetivo sospechado (si typosquat), y las
   señales por capa (code/peso/detalle).
2. WHEN se muestra el reporte THE SYSTEM SHALL incluir el **ecosistema** del escaneo y un resumen
   agregado (conteos + el exit code equivalente del CLI: 0/1/2/3).
3. WHEN el usuario lo solicite THE SYSTEM SHALL ofrecer la salida **JSON cruda** (`schema_version`
   actual del motor) además de la vista humana.
4. IF una dependencia es maliciosa confirmada (advisory `MAL-*`) THEN THE SYSTEM SHALL destacarla
   visualmente como bloqueo prioritario con enlace al advisory.

### Requisito 5: Histórico de escaneos
**Historia:** Como desarrollador, quiero conservar mis escaneos, para comparar en el tiempo y volver
a revisar resultados.
**Criterios de aceptación (EARS):**
1. WHEN un escaneo (on-demand o de PR) termina THE SYSTEM SHALL persistir su origen, autor, fecha
   (UTC), ecosistema, resumen y el reporte completo, asociado al usuario/repo.
2. WHEN el usuario abre el histórico THE SYSTEM SHALL listar sus escaneos (más reciente primero) con
   filtros básicos (por repo y por ecosistema) y permitir abrir cualquiera.
3. THE SYSTEM SHALL exponer cada escaneo solo a su propietario (aislamiento por usuario).
4. IF no hay escaneos THEN THE SYSTEM SHALL mostrar un estado vacío con una llamada a la acción para
   lanzar el primero.

### Requisito 6: GitHub App — check informativo en PRs (no bloqueante)
**Historia:** Como revisor de un PR, quiero ver el veredicto de SlopGuard sobre las dependencias
cambiadas, para detectar slopsquatting sin salir del PR.
**Criterios de aceptación (EARS):**
1. WHEN llega un webhook de PR (abierto/sincronizado) THE SYSTEM SHALL **verificar la firma HMAC**
   del webhook antes de procesarlo; si no valida, descartar sin efecto.
2. WHEN el PR modifica uno o más manifiestos soportados THE SYSTEM SHALL escanear cada uno y publicar
   un **Check Run** cuyo `conclusion` refleja el peor veredicto (allow→success, warn→neutral,
   block→failure) y un **comentario** que resume los hallazgos por manifiesto.
3. THE SYSTEM SHALL operar en modo **solo informar**: NUNCA configura su check como *required* ni usa
   mecanismo alguno que impida el merge.
4. IF el PR no cambia ningún manifiesto soportado THEN THE SYSTEM SHALL omitir el escaneo y publicar
   un check `neutral` "sin manifiestos que revisar" (o ninguno), sin ruido.
5. IF el escaneo de un manifiesto falla parcialmente (red/parsing) THEN THE SYSTEM SHALL reportar ese
   manifiesto como UNVERIFIABLE en el check/comentario, jamás como limpio.
6. WHEN se actualiza un PR ya comentado THE SYSTEM SHALL actualizar (no duplicar) su check y su
   comentario.

### Requisito 7: Integración del motor de detección
**Historia:** Como mantenedor, quiero que el SaaS use el motor existente tal cual, para no duplicar
ni divergir la lógica de detección.
**Criterios de aceptación (EARS):**
1. THE SYSTEM SHALL invocar el paquete `slopguard` **in-process** (import directo), soportando ambos
   ecosistemas (PyPI y npm) sin reimplementar capas ni scoring.
2. THE SYSTEM SHALL mantener la **Capa 4 (LLM) desactivada por defecto**; su activación es un
   conmutador server-side que requiere `ANTHROPIC_API_KEY` configurada, nunca expuesta al cliente.
3. THE SYSTEM SHALL preservar las invariantes del motor: fail-closed, anti-block de la Capa 4,
   y cero filtración de secretos.

### Requisito 8: Persistencia (Postgres)
**Historia:** Como sistema, necesito un almacén durable, para conservar usuarios, instalaciones y
escaneos.
**Criterios de aceptación (EARS):**
1. THE SYSTEM SHALL persistir en Postgres como mínimo: usuarios, instalaciones de la App, repos,
   escaneos y sus resultados, con migraciones versionadas.
2. THE SYSTEM SHALL cifrar en reposo los tokens/credenciales sensibles (no en texto plano).
3. WHEN arranca con un esquema desactualizado THE SYSTEM SHALL aplicar migraciones de forma
   determinista (idempotente), sin pérdida de datos.

### Requisito 9: Manejo de errores y degradación
**Historia:** Como usuario, quiero errores claros y nunca un falso "todo bien", para confiar en el
veredicto.
**Criterios de aceptación (EARS):**
1. IF una dependencia o lote no se puede verificar THEN THE SYSTEM SHALL mostrarlo como UNVERIFIABLE,
   nunca como allow/CLEAN.
2. WHEN una operación externa (GitHub/registro/OSV) falla THE SYSTEM SHALL devolver un error
   accionable y saneado, sin stacktrace crudo ni secretos.
3. WHILE procesa un webhook THE SYSTEM SHALL responder rápido (ack) y ejecutar el escaneo de forma
   **asíncrona** (trabajo en segundo plano), actualizando el check al terminar.

## Requisitos no-funcionales

### NFR-Seguridad
1. WHEN se inicia OAuth THE SYSTEM SHALL usar `state` anti-CSRF de un solo uso y validar el callback.
2. WHEN llega un webhook THE SYSTEM SHALL verificar su firma HMAC (secreto del webhook) antes de
   actuar.
3. THE SYSTEM SHALL almacenar tokens de GitHub y cualquier secreto **cifrados en reposo** y nunca
   emitirlos al cliente ni a logs (consistente con la no-fuga de `ANTHROPIC_API_KEY` del motor).
4. THE SYSTEM SHALL pedir **mínimo privilegio** en la GitHub App (solo lo necesario para leer PRs/
   contenido y escribir checks/comentarios).
5. THE SYSTEM SHALL tratar todo manifiesto/entrada como **no confiable** (validación, límites de
   tamaño, sin ejecución de código del paquete) y aplicar rate limiting básico a endpoints públicos.

### NFR-UX (directiva del usuario — prioritaria)
1. La UI SHALL ser **limpia, profesional y agradable a la vista**, coherente con la identidad de
   SlopGuard (estética de herramienta de seguridad / terminal moderna: tipografía nítida, jerarquía
   clara, color semántico para allow/warn/block).
2. La UI SHALL ser **responsive** y cumplir accesibilidad **WCAG AA básica** (contraste, foco,
   navegación por teclado, roles ARIA donde aplique).
3. La UI SHALL **explicar** los veredictos (no solo mostrarlos): cada señal debe ser legible para un
   humano. Estados de carga/empty/error cuidados.
4. *(Implementación)* La construcción del front en la Fase 4 SHALL realizarse con `developer-complex`
   inyectando **skills de UI/UX senior**, manteniendo un sistema de diseño consistente.

### NFR-Arquitectura
1. **Monorepo** en el repo `slopguard`: `apps/api` (FastAPI), `apps/web` (Next.js), y el motor
   `src/slopguard` reutilizado como librería.
2. El **core `slopguard` permanece zero-deps**; las dependencias viven en el backend/front. Frontera
   clara: web → api → motor; el motor no conoce al SaaS.
3. Código tipado estricto en ambos lados (mypy en Python; TypeScript estricto en el front).

### NFR-Rendimiento
1. El escaneo on-demand SHALL devolver dentro de un presupuesto razonable; al estar limitado por red
   (registros/OSV), SHALL reutilizar la caché del motor y paralelizar por dependencia.
2. Los escaneos de PR SHALL ejecutarse en segundo plano para no bloquear el ack del webhook.

### NFR-Privacidad
1. Heredado del motor: **solo nombres de paquete** salen a los registros, nunca versiones/rutas/
   manifiestos completos.
2. Los manifiestos del usuario SHALL tratarse como datos sensibles; el comentario de PR solo expone
   dependencias ya presentes en el diff del propio PR.

### NFR-Disponibilidad / Operación
1. Un solo entorno (demo-grade). Degradación elegante ante caída de dependencias externas.
2. Observabilidad mínima: logs estructurados sin secretos; healthcheck del API.

## Fuera de alcance (este hito)

- Multi-tenant, organizaciones, equipos, RBAC, panel de administración.
- Billing, planes, suscripciones, cuotas.
- **Bloqueo de merges** / checks *required* (explícitamente: solo informar).
- SSO no-GitHub, SAML, login por email/contraseña.
- Integraciones con Slack/Jira/otros.
- Distribución on-prem / self-managed empaquetada.
- Ecosistemas más allá de PyPI y npm.
- Aplicación móvil nativa.
