"""Análisis previo con Microsoft Defender (MpCmdRun.exe), en modo solo informe."""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

_FOUND_RE = re.compile(r"found\s+(\d+|no)\s+threats?", re.IGNORECASE)
_THREAT_RE = re.compile(r"^\s*Threat\s*:\s*(.+?)\s*$", re.IGNORECASE)
_RESOURCE_RE = re.compile(r"^\s*(file|containerfile)\s*:\s*(.+?)\s*$", re.IGNORECASE)


@dataclass
class DefenderThreat:
    name: str
    resources: list[str] = field(default_factory=list)


@dataclass
class DefenderResult:
    ok: bool
    exit_code: int | None = None
    found: int | None = None
    threats: list[DefenderThreat] = field(default_factory=list)
    error: str | None = None
    duration: float = 0.0
    raw_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["raw_output"] = self.raw_output[-4000:]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DefenderResult":
        threats = [DefenderThreat(t["name"], list(t.get("resources") or [])) for t in data.get("threats") or []]
        return cls(
            ok=bool(data.get("ok")),
            exit_code=data.get("exit_code"),
            found=data.get("found"),
            threats=threats,
            error=data.get("error"),
            duration=float(data.get("duration") or 0),
            raw_output=data.get("raw_output") or "",
        )

    def threat_by_path(self) -> dict[str, str]:
        """Ruta (normalizada) -> nombre de la amenaza. Para comprimidos, la ruta del comprimido."""
        mapping: dict[str, str] = {}
        for threat in self.threats:
            for resource in threat.resources:
                path = resource.split("->", 1)[0].strip()
                mapping.setdefault(os.path.normcase(os.path.abspath(path)), threat.name)
        return mapping


def find_mpcmdrun() -> str | None:
    """El MpCmdRun más reciente (carpeta Platform) o, si no, el de Program Files."""
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    platform = Path(program_data) / "Microsoft" / "Windows Defender" / "Platform"

    def version_key(p: Path) -> tuple[int, ...]:
        numbers = re.findall(r"\d+", p.name)
        return tuple(int(n) for n in numbers)

    try:
        candidates = sorted(
            (d for d in platform.iterdir() if d.is_dir() and (d / "MpCmdRun.exe").exists()),
            key=version_key,
            reverse=True,
        )
    except OSError:
        candidates = []
    if candidates:
        return str(candidates[0] / "MpCmdRun.exe")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    legacy = Path(program_files) / "Windows Defender" / "MpCmdRun.exe"
    return str(legacy) if legacy.exists() else None


def parse_output(text: str) -> tuple[int | None, list[DefenderThreat]]:
    found: int | None = None
    match = _FOUND_RE.search(text)
    if match:
        found = 0 if match.group(1).lower() == "no" else int(match.group(1))
    threats: list[DefenderThreat] = []
    current: DefenderThreat | None = None
    for line in text.splitlines():
        threat = _THREAT_RE.match(line)
        if threat:
            current = DefenderThreat(threat.group(1))
            threats.append(current)
            continue
        resource = _RESOURCE_RE.match(line)
        if resource and current is not None:
            current.resources.append(resource.group(2))
    return found, threats


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("oem", errors="replace")
        except LookupError:  # pragma: no cover - el códec "oem" solo existe en Windows
            return data.decode("latin-1", errors="replace")


def run_scan(
    folder: str,
    report_only: bool = True,
    on_tick: Callable[[float], None] | None = None,
    exe: str | None = None,
) -> DefenderResult:
    exe = exe or find_mpcmdrun()
    if exe is None:
        return DefenderResult(ok=False, error="No se encontró MpCmdRun.exe (¿Defender desinstalado?)")
    args = [exe, "-Scan", "-ScanType", "3", "-File", folder]
    if report_only:
        args.append("-DisableRemediation")
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as exc:
        return DefenderResult(ok=False, error=f"No se pudo ejecutar MpCmdRun: {exc}")
    chunks: list[bytes] = []
    try:
        # La salida es corta; se lee al final. Mientras, se informa del tiempo.
        while True:
            try:
                out, _ = proc.communicate(timeout=0.5)
                chunks.append(out or b"")
                break
            except subprocess.TimeoutExpired:
                if on_tick:
                    on_tick(time.monotonic() - start)
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    text = _decode(b"".join(chunks))
    duration = time.monotonic() - start
    found, threats = parse_output(text)
    code = proc.returncode
    if code not in (0, 2) or (code == 2 and found is None and not threats):
        last = text.strip().splitlines()[-1] if text.strip() else f"código {code}"
        hint = ""
        if "0x800106ba" in text.lower():
            hint = " Defender no está activo (¿hay otro antivirus instalado?)."
        return DefenderResult(
            ok=False, exit_code=code, error=f"{last}{hint}", duration=duration, raw_output=text
        )
    return DefenderResult(
        ok=True, exit_code=code, found=found, threats=threats, duration=duration, raw_output=text
    )
