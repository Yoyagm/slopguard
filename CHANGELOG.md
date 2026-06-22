# Changelog

Todos los cambios notables de SlopGuard se documentan aquí.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el versionado [Semantic Versioning](https://semver.org/lang/es/).

## [Unreleased]

_Hito 2 (planeado): Capa 3 de threat-intel (OSV.dev + watchlist de alucinaciones)._

## [0.1.0] - 2026-06-22

Primer hito (**Hito 1**): núcleo determinista de detección de *slopsquatting*
para dependencias Python, sin LLMs y usando solo la PyPI JSON API.

### Added
- CLI `slopguard scan <ruta|->` y `slopguard version`; lectura desde `stdin` (`pip freeze`).
- **Capa 0** — existencia y edad del paquete vía PyPI JSON API (inexistencia → `block` por override).
- **Capa 1** — *typosquatting* por Damerau-Levenshtein + Jaro-Winkler contra el top-10k de PyPI embebido; sin red y determinista.
- **Capa 2** — señales de metadatos (releases, repo enlazado, completitud) con aporte acotado.
- Scoring determinista 0-100 → veredicto `allow`/`warn`/`block`, con invariante anti-falsos-positivos (señales blandas acotadas por debajo del umbral de `warn`).
- Parseo de `requirements.txt`, `pyproject.toml` y `pip freeze`; `-r`/`-c` resueltos confinados al árbol del proyecto (detección de ciclos y profundidad máxima).
- Salida humana explicable y JSON versionado (`schema_version` 1.0); exit codes estables (`0` allow / `1` warn / `2` block / `3` operacional·unverifiable) y `--strict`.
- Caché en disco atómica y segura (TTL, JSON-only, permisos `0700`/`0600`, clave por hash).
- Configuración vía `[tool.slopguard]` en `pyproject.toml` o `.slopguard.toml` y flags CLI (precedencia CLI > archivo > defaults) con validación de rangos.
- Dataset top-10k de PyPI con procedencia documentada, verificación de integridad SHA-256 y script de generación reproducible.

### Security
- HTTPS con verificación TLS **no desactivable** y *allowlist* de host (`pypi.org`); rechazo de redirecciones cross-host/cross-scheme.
- Defensas anti JSON-bomb, anti gzip-bomb y `Content-Length` excesivo (lectura *streaming* acotada con descompresión incremental).
- **No** se ejecuta ni importa el código de ningún paquete analizado; sin `eval`/`exec`/`pickle`/`marshal` (verificado por análisis estático AST con guardias anti-vacuos).
- **Cero dependencias de runtime** (solo stdlib): superficie de *supply-chain* mínima.
- Saneo anti-inyección de terminal (ANSI/C0-C1/CRLF) en toda salida; sin fuga de rutas absolutas ni del contenido del manifiesto en errores.
- Degradación segura: ante fallo de red persistente se reporta `unverifiable` (nunca un falso "todo bien").

### Notes
- **619 pruebas**; cobertura **95.3% global / 99% en paquetes críticos**.
- CI: mypy `--strict`, ruff (incl. reglas bandit), import-linter (frontera capas/scoring ↛ red) y compilación del documento técnico LaTeX a PDF.

[Unreleased]: https://github.com/Yoyagm/slopguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Yoyagm/slopguard/releases/tag/v0.1.0
