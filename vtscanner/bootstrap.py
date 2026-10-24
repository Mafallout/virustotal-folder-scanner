"""Arranque compartido por la terminal y la ventana: clave de la API, logs y rutas."""

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path

from .config import PROJECT_DIR, Config, is_writable, writable_base

_API_KEY_RE = re.compile(r"[0-9a-fA-F]{64}")


def clean_path(raw: str) -> str:
    """Arregla rutas que llegan mal desde la terminal, como "D:\\Juegos\\" (que
    llega con una comilla al final) o "D:" sin barra."""
    path = raw.strip().strip('"').strip()
    if re.fullmatch(r"[A-Za-z]:", path):
        path += "\\"
    return path


def looks_like_api_key(text: str) -> bool:
    """Las claves de VirusTotal son 64 caracteres hexadecimales."""
    return bool(_API_KEY_RE.fullmatch(text.strip()))


def env_files() -> list[Path]:
    """Dónde se busca el .env: junto al programa y, si es otra, en la carpeta de datos."""
    files = [PROJECT_DIR / ".env"]
    alternative = writable_base() / ".env"
    if alternative != files[0]:
        files.append(alternative)
    return files


def _read_env(path: Path) -> list[str]:
    """Líneas del .env. Con "VT_API_KEY=..." > .env, PowerShell 5.1 lo escribe en UTF-16,
    y el Bloc de notas antiguo lo guarda en ANSI."""
    data = path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16").splitlines()
    try:
        return data.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace").splitlines()


def _key_from_file(path: Path) -> str | None:
    try:
        lines = _read_env(path)
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
            value = value.split("#", 1)[0].strip().strip('"').strip("'").strip()
            if value:
                return value
    return None


def load_api_key(prefer_file: bool = False) -> str | None:
    """La clave sale de la variable de entorno VT_API_KEY o de un .env. La terminal
    da prioridad a la variable; la ventana, al .env (es donde ella la guarda)."""
    from_env = os.environ.get("VT_API_KEY", "").strip() or None
    from_file = next((key for key in map(_key_from_file, env_files()) if key), None)
    return (from_file or from_env) if prefer_file else (from_env or from_file)


def save_api_key(key: str) -> Path:
    """Guarda la clave en el .env junto al programa (o en la carpeta de datos si
    ahí no se puede escribir), respetando las demás líneas del archivo."""
    target = PROJECT_DIR / ".env" if is_writable(PROJECT_DIR) else writable_base() / ".env"
    lines: list[str] = []
    if target.exists():
        lines = _read_env(target)
    new_line = f"VT_API_KEY={key.strip()}"
    output: list[str] = []
    replaced = False
    for line in lines:
        name = line.split("=", 1)[0].strip()
        if name.startswith("export "):
            name = name[len("export ") :].strip()
        if "=" in line and name == "VT_API_KEY":
            if not replaced:
                output.append(new_line)
                replaced = True
            continue
        output.append(line)
    if not replaced:
        output.append(new_line)
    target.write_text("\n".join(output) + "\n", encoding="utf-8")
    return target


def setup_logging(cfg: Config, verbose: bool) -> Path | None:
    """Un log por ejecución en data\\logs (se conservan los 30 últimos)."""
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
