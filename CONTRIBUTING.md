# Contribuir a SlopGuard

Gracias por tu interés. SlopGuard es una herramienta de **seguridad de
supply-chain**; la barra de calidad es alta y los gates son bloqueantes.

## Entorno de desarrollo

```bash
make install          # crea .venv e instala el paquete editable + dev tools
```

## Gates de calidad (deben pasar todos)

Reproduce localmente exactamente lo que corre el CI:

```bash
make lint             # ruff (incl. reglas de seguridad bandit S)
make type             # mypy --strict
make imports          # import-linter (contratos de arquitectura)
make cov              # pytest + cobertura (≥90% global, ≥95% críticos)
make all              # todo lo anterior
```

Reglas no negociables:

- **Python 3.11+**, tipado estricto (`mypy --strict` limpio).
- Funciones **≤ 50 líneas**, responsabilidad única; *early returns*.
- **Cero dependencias de runtime** en las capas 0-2 (solo stdlib).
- Sin `eval`/`exec`/`pickle`/`marshal`; las capas/scoring **no** importan red ni el adapter concreto (lo verifica `import-linter`).
- Comentarios y docstrings en español; identificadores en inglés.

## Commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/) con scope:

```
feat(slopguard): <resumen en imperativo>
fix(slopguard): ...
test(slopguard): ...
docs(slopguard): ...
chore(slopguard): ...
```

Cambios que rompen compatibilidad: `tipo(scope)!:` o footer `BREAKING CHANGE:`.

## Pull requests

1. Asegúrate de que `make all` pasa en verde y la cobertura no baja del piso.
2. Añade pruebas para todo comportamiento nuevo (camino feliz, bordes y fallos).
3. Si tocas red, caché, dataset o saneo de salida, espera revisión de seguridad.
4. Mantén `CHANGELOG.md` actualizado en la sección `[Unreleased]`.

## Releases

Las versiones se etiquetan como `vX.Y.Z`; el workflow de release
construye los artefactos (sdist/wheel + PDF técnico) y publica un GitHub Release.
