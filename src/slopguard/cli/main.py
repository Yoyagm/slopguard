"""CLI de SlopGuard: subcomandos scan y version (§3.5, T34).

Punto de entrada del console_script: `slopguard = "slopguard.cli.main:main"`.
`main(argv)` retorna el exit code; `sys.exit(main())` lo convierte en exit del proceso.

Importa SOLO de `slopguard.core` (R10.3, verificado por import-linter).
Captura `SlopGuardError` y `ValueError` (de `get_adapter`); nunca propaga
stacktrace crudo. Todos los mensajes de error a stderr estan saneados (R6.5).

Garantias de ultimo nivel en `main()`:
- `KeyboardInterrupt` -> mensaje saneado + EXIT_OPERATIONAL (3).
- `BrokenPipeError`   -> suprimido silenciosamente + EXIT_OPERATIONAL (3).
- `UnicodeDecodeError`/`OSError` en stdin -> mensaje saneado + EXIT_OPERATIONAL (3).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

import slopguard
from slopguard.core import (
    Config,
    ManifestParseError,
    ScanReport,
    SlopGuardError,
    aggregate_exit_code,
    load_config,
    scan_manifest,
    scan_stdin,
)
from slopguard.core.normalize import sanitize_for_output

from .exit_codes import EXIT_OPERATIONAL
from .render_human import render_human
from .render_json import render_json_to

# Tipos de manifiesto validos (§3.5 / T11).
_MANIFEST_TYPES = ("requirements", "pyproject", "freeze")


def _build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argparse con subcomandos scan y version."""
    parser = argparse.ArgumentParser(
        prog="slopguard",
        description="Guardian pre-instalacion contra slopsquatting.",
    )
    sub = parser.add_subparsers(dest="command", metavar="comando")

    # Subcomando: version
    sub.add_parser("version", help="Muestra la version instalada.")

    # Subcomando: scan
    scan = sub.add_parser(
        "scan",
        help="Escanea un manifiesto (ruta o '-' para stdin).",
    )
    scan.add_argument("path", help="Ruta al manifiesto o '-' para stdin (pip freeze).")
    _add_scan_flags(scan)
    return parser


def _add_scan_flags(parser: argparse.ArgumentParser) -> None:
    """Agrega todos los flags del subcomando scan (§3.5)."""
    parser.add_argument(
        "--format",
        dest="fmt",
        choices=("human", "json"),
        default="human",
        help="Formato de salida (default: human).",
    )
    parser.add_argument("--no-cache", action="store_true", help="Deshabilita la cache en disco.")
    parser.add_argument("--strict", action="store_true", help="Warn cuenta como exit 2 (CI gate).")
    parser.add_argument("--config", metavar="PATH", help="Ruta explicita al archivo de config.")
    parser.add_argument(
        "--ecosystem",
        default="pypi",
        metavar="ID",
        help="Ecosistema a analizar (default: pypi).",
    )
    parser.add_argument(
        "--manifest-type",
        choices=_MANIFEST_TYPES,
        default=None,
        dest="manifest_type",
        help="Fuerza el tipo de parser del manifiesto.",
    )
    # Overrides de umbrales y red (van a cli_overrides de load_config).
    parser.add_argument("--umbral-block", type=int, default=None, dest="umbral_block")
    parser.add_argument("--umbral-warn", type=int, default=None, dest="umbral_warn")
    parser.add_argument("--edad-minima-dias", type=int, default=None, dest="edad_minima_dias")
    parser.add_argument("--concurrencia", type=int, default=None, dest="concurrencia_max")
    parser.add_argument("--connect-timeout", type=float, default=None, dest="connect_timeout_s")
    parser.add_argument("--read-timeout", type=float, default=None, dest="read_timeout_s")
    parser.add_argument("--reintentos", type=int, default=None, dest="reintentos_red")
    parser.add_argument("--timeout-total", type=float, default=None, dest="timeout_total_por_dep_s")
    parser.add_argument("--jw-min", type=float, default=None, dest="jw_min")
    parser.add_argument("--dl-max", type=int, default=None, dest="dl_max")


def _cli_overrides(args: argparse.Namespace) -> dict[str, object]:
    """Extrae los overrides de config desde los flags CLI (None = no pasado)."""
    keys = (
        "umbral_block", "umbral_warn", "edad_minima_dias", "concurrencia_max",
        "connect_timeout_s", "read_timeout_s", "reintentos_red",
        "timeout_total_por_dep_s", "jw_min", "dl_max",
    )
    return {k: getattr(args, k, None) for k in keys}


def _stderr(msg: str) -> None:
    """Escribe un mensaje saneado a stderr."""
    sys.stderr.write(sanitize_for_output(msg) + "\n")


def _run_scan(args: argparse.Namespace) -> int:
    """Orquesta el subcomando scan. Retorna el exit code entero."""
    # Validar ecosystem antes de construir la config (borde conocido: ValueError).
    ecosystem_id: str = args.ecosystem
    if not _validate_ecosystem(ecosystem_id):
        return EXIT_OPERATIONAL

    overrides = _cli_overrides(args)
    try:
        config = load_config(args.config, overrides)
    except SlopGuardError:
        # Mensaje fijo: no reenviar str(exc) porque puede contener rutas absolutas
        # del SO (OSError embebido en InvalidConfigError via config.py:109, R6.5).
        _stderr("Error de configuracion: verifique la ruta y el contenido del archivo.")
        return EXIT_OPERATIONAL

    use_cache = not args.no_cache
    path: str = args.path

    try:
        report = _fetch_report(path, config, use_cache, ecosystem_id, args.manifest_type)
    except SlopGuardError as exc:
        _stderr(f"Error: {exc}")
        return EXIT_OPERATIONAL
    except ValueError as exc:
        _stderr(f"Error de configuracion: {sanitize_for_output(str(exc))}")
        return EXIT_OPERATIONAL

    _render(report, fmt=args.fmt)

    if report.error_category is not None:
        return EXIT_OPERATIONAL
    return aggregate_exit_code(report, strict=args.strict)


def _validate_ecosystem(ecosystem_id: str) -> bool:
    """Valida que el ecosistema es soportado. Retorna True si es valido.

    Solo "pypi" esta soportado en Hito 1. Escribe a stderr y retorna False
    si el ecosistema no es reconocido. NUNCA llama sys.exit (el caller decide).
    """
    # Se valida aqui para capturar el ValueError de get_adapter antes de llamar al core.
    if ecosystem_id != "pypi":
        _stderr(
            f"Ecosistema '{sanitize_for_output(ecosystem_id)}' no soportado. "
            "Ecosistemas disponibles: ['pypi']."
        )
        return False
    return True


def _fetch_report(
    path: str,
    config: Config,
    use_cache: bool,
    ecosystem_id: str,
    manifest_type: str | None,
) -> ScanReport:
    """Llama a scan_manifest o scan_stdin segun si path es '-'.

    Captura UnicodeDecodeError y OSError de stdin para que no propaguen crudo
    a main() (stdin binario o fd cerrado -> EXIT_OPERATIONAL, R6.5).
    """
    if path == "-":
        try:
            text = sys.stdin.read()
        except (UnicodeDecodeError, OSError) as exc:
            raise ManifestParseError(
                f"No se pudo leer stdin: {type(exc).__name__}"
            ) from exc
        return scan_stdin(text, config, use_cache=use_cache, ecosystem_id=ecosystem_id)
    return scan_manifest(
        path,
        config,
        use_cache=use_cache,
        ecosystem_id=ecosystem_id,
        manifest_type=manifest_type,
    )


def _render(report: ScanReport, *, fmt: str) -> None:
    """Delega al renderer correcto segun el formato elegido."""
    if fmt == "json":
        render_json_to(report)
    else:
        render_human(report)


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del console_script. Retorna el exit code (R7).

    Guarda de ultimo nivel: captura KeyboardInterrupt y BrokenPipeError para
    nunca emitir stacktrace crudo (R6.5, NFR-Seguridad.5).
    """
    try:
        return _main_inner(argv)
    except KeyboardInterrupt:
        _stderr("Interrumpido por el usuario.")
        return EXIT_OPERATIONAL
    except BrokenPipeError:
        # El lector cerro el pipe (ej. `slopguard scan ... | head`).
        # Se suprime silenciosamente: no hay nada que imprimir a un pipe cerrado.
        return EXIT_OPERATIONAL


def _main_inner(argv: Sequence[str] | None) -> int:
    """Logica interna de main(), separada para que la guarda de excepcion sea clara."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"slopguard {slopguard.__version__}")
        return 0

    if args.command == "scan":
        return _run_scan(args)

    # Sin subcomando: mostrar ayuda.
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
