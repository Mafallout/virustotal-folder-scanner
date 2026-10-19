"""Línea de comandos de vtscan."""

from __future__ import annotations

import argparse
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path

from rich.markup import escape

from . import __version__
from .config import PROJECT_DIR, Config, ConfigError, load_config
from .db import Database
from .pipeline import ScanOptions, Scanner
from .ui import ConsoleUI
from .vtclient import AuthError
from .winutils import (
    AlreadyRunningError,
    SingleInstanceLock,
    configure_stdio,
    keep_awake,
    open_in_default_app,
    path_key,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_INCOMPLETE = 3

EPILOG = r"""
ejemplos:
  python vtscan.py "D:\Juegos\MiJuego"
  python vtscan.py "D:\Juegos\MiJuego" --defender --upload
  python vtscan.py "D:\Juegos" --dry-run
  python vtscan.py --resume --wait

códigos de salida: 0 sin hallazgos, 1 con hallazgos (Alto o Crítico),
2 error, 3 incompleto (pendiente de reanudar)
"""

KEY_HELP = """No encuentro la API key de VirusTotal (variable de entorno VT_API_KEY).

  1. Crea una cuenta gratuita en https://www.virustotal.com (solo pide un correo).
  2. En tu perfil, entra en "API key" y cópiala.
  3. Guárdala una sola vez y abre una terminal nueva:
       setx VT_API_KEY "tu_clave"
     O solo para la terminal actual de PowerShell:
       $env:VT_API_KEY = "tu_clave"
     También vale un archivo .env junto a vtscan.py con la línea: VT_API_KEY=tu_clave
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vtscan",
        description="Analiza una carpeta en busca de malware con VirusTotal (API v3, plan gratuito).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="help", help="muestra esta ayuda y sale")
    parser.add_argument("folder", nargs="?", help="carpeta (o archivo) que se quiere analizar")
    parser.add_argument(
        "--upload", action="store_true", help="sube los archivos que VirusTotal no conoce (pide confirmación)"
    )
    parser.add_argument(
        "--defender", action="store_true", help="antes de nada, analiza la carpeta con Microsoft Defender"
    )
    parser.add_argument(
        "--all-files", action="store_true", help="analiza todos los archivos, no solo ejecutables y scripts"
    )
    parser.add_argument("--resume", action="store_true", help="reanuda el último escaneo sin terminar")
    parser.add_argument(
        "--wait", action="store_true", help="si se agota la cuota diaria, espera al reinicio y sigue solo"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="no consulta VirusTotal: calcula hashes y estima el coste"
    )
    parser.add_argument(
        "--refresh", action="store_true", help="vuelve a consultar aunque ya haya resultado guardado"
    )
    parser.add_argument("--config", metavar="RUTA", help="usa otro archivo de configuración")
    parser.add_argument("--no-open", action="store_true", help="no abre el informe HTML al terminar")
    parser.add_argument("-v", "--verbose", action="store_true", help="log más detallado en data/logs")
    parser.add_argument(
        "--version", action="version", version=f"vtscan {__version__}", help="muestra la versión y sale"
    )
    return parser


def clean_path(raw: str) -> str:
    """Arregla rutas que llegan mal desde la terminal, como "D:\\Juegos\\" (que
    llega con una comilla al final) o "D:" sin barra."""
    path = raw.strip().strip('"').strip()
    if re.fullmatch(r"[A-Za-z]:", path):
        path += "\\"
    return path


def load_api_key() -> str | None:
    key = os.environ.get("VT_API_KEY", "").strip()
    if key:
        return key
    env_file = PROJECT_DIR / ".env"
    try:
        lines = env_file.read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if name.startswith("export "):
            name = name[len("export ") :].strip()
        if name == "VT_API_KEY":
            value = value.strip().strip('"').strip("'").strip()
            if value:
                return value
    return None


def setup_logging(cfg: Config, verbose: bool) -> Path | None:
    try:
        cfg.logs_path.mkdir(parents=True, exist_ok=True)
        old_logs = sorted(cfg.logs_path.glob("vtscan_*.log"))
        for old in old_logs[:-29]:
            try:
                old.unlink()
            except OSError:
                pass
        path = cfg.logs_path / f"vtscan_{time.strftime('%Y%m%d-%H%M%S')}.log"
        handler = logging.FileHandler(path, encoding="utf-8")
    except OSError:
        return None
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    # Solo el logger del programa: así no se cuela nada de urllib3 (que podría llevar la clave en la URL)
    logger = logging.getLogger("vtscanner")
    for old_handler in list(logger.handlers):
        logger.removeHandler(old_handler)
        old_handler.close()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(handler)
    return path


def resolve_options(
    args: argparse.Namespace, db: Database, ui: ConsoleUI
) -> tuple[ScanOptions | None, int | None]:
    target = clean_path(args.folder) if args.folder else None
    resume_id: int | None = None
    stored: dict[str, bool] = {}
    if args.resume:
        scan = db.find_resumable_scan(path_key(target) if target else None)
        if scan is None:
            where = " de esa carpeta" if target else ""
            ui.message(f"No hay ningún escaneo sin terminar{where}.", "error")
            return None, None
        target, resume_id, stored = scan.root, scan.id, scan.options
        started = datetime.fromtimestamp(scan.started_at).strftime("%d/%m/%Y %H:%M")
        ui.message(f"Reanudando el escaneo de {scan.root} (empezado el {started}).")
    if not target:
        ui.message("Indica la carpeta que quieres analizar (o usa --resume). Ayuda: python vtscan.py -h", "error")
        return None, None
    if not os.path.exists(target):
        ui.message(f"No existe la carpeta o archivo: {target}", "error")
        return None, None
    options = ScanOptions(
        target=os.path.abspath(target),
        upload=args.upload or bool(stored.get("upload")),
        defender=args.defender or bool(stored.get("defender")),
        all_files=args.all_files or bool(stored.get("all_files")),
        wait=args.wait,
        dry_run=args.dry_run,
        refresh=args.refresh,
    )
    return options, resume_id


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    args = build_parser().parse_args(argv)
    ui = ConsoleUI()
    try:
        cfg, warnings = load_config(Path(args.config) if args.config else None)
    except ConfigError as exc:
        ui.message(f"Error en la configuración: {exc}", "error")
        return EXIT_ERROR
    for warning in warnings:
        ui.message(warning, "warn")
    setup_logging(cfg, args.verbose)
    log = logging.getLogger("vtscanner")

    lock = SingleInstanceLock(cfg.lock_path)
    try:
        lock.acquire()
    except AlreadyRunningError:
        ui.message("Ya hay otro vtscan en marcha. Espera a que termine.", "error")
        return EXIT_ERROR

    try:
        db = Database(cfg.db_path)
        try:
            options, resume_id = resolve_options(args, db, ui)
            if options is None:
                return EXIT_ERROR
            api_key = None
            if not options.dry_run:
                api_key = load_api_key()
                if not api_key:
                    ui.message(KEY_HELP, "error")
                    return EXIT_ERROR
            ui.console.print(f"[bold]vtscan {__version__}[/]  {escape(options.target)}", highlight=False)
            log.info("Inicio: %s %s", options.target, options.labels())
            scanner = Scanner(cfg, ui, api_key, db=db)
            with keep_awake():
                outcome = scanner.run(options, resume_id)
            log.info("Fin: completo=%s hallazgos=%s", outcome.complete, outcome.findings)
        finally:
            db.close()
    except AuthError as exc:
        ui.message(f"VirusTotal rechaza la API key ({exc}). Revisa VT_API_KEY.", "error")
        return EXIT_ERROR
    except KeyboardInterrupt:
        ui.message("Cancelado.", "warn")
        return EXIT_INCOMPLETE
    finally:
        lock.release()

    if outcome.report_html and cfg.report.open_html and not args.no_open:
        open_in_default_app(outcome.report_html)
    if options.dry_run:
        return EXIT_OK
    if outcome.interrupted or not outcome.complete:
        return EXIT_INCOMPLETE
    return EXIT_FINDINGS if outcome.findings else EXIT_OK
