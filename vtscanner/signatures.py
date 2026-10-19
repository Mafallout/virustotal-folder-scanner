"""Firmas digitales Authenticode con Get-AuthenticodeSignature (PowerShell), por lotes."""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable

from .winutils import IS_WINDOWS, fs_path

# Extensiones que pueden llevar firma además de los ejecutables PE
SIGNABLE_EXTENSIONS = {".msi", ".msp", ".ps1", ".psm1"}

BATCH_SIZE = 100
PARALLEL_BATCHES = 4
BATCH_TIMEOUT_SECONDS = 600

STATUS_VALID = "valid"
STATUS_UNSIGNED = "unsigned"
STATUS_TAMPERED = "tampered"  # firma rota: el archivo se modificó después de firmarlo
STATUS_UNTRUSTED = "untrusted"
STATUS_UNVERIFIABLE = "unverifiable"  # Windows no puede verificarla (formato raro, certificado caducado...)
STATUS_ERROR = "error"  # fallo al ejecutar la comprobación; se reintenta la próxima vez

_STATUS_MAP = {
    "Valid": STATUS_VALID,
    "NotSigned": STATUS_UNSIGNED,
    "NotSupportedFileFormat": STATUS_UNSIGNED,
    "HashMismatch": STATUS_TAMPERED,
    "NotTrusted": STATUS_UNTRUSTED,
    "Incompatible": STATUS_UNTRUSTED,
    "UnknownError": STATUS_UNVERIFIABLE,
}

STATUS_LABELS = {
    STATUS_VALID: "válida",
    STATUS_UNSIGNED: "sin firma",
    STATUS_TAMPERED: "rota (archivo modificado)",
    STATUS_UNTRUSTED: "no válida",
    STATUS_UNVERIFIABLE: "no verificable",
    STATUS_ERROR: "no se pudo comprobar",
}

# Script de PowerShell: lee las rutas de un archivo y escribe el resultado en JSON.
# Se pasa con -EncodedCommand, así no le afecta la directiva de ejecución.
_PS_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
$paths = @(Get-Content -LiteralPath $env:VTSCAN_SIG_IN -Encoding UTF8)
$out = New-Object System.Collections.Generic.List[object]
for ($i = 0; $i -lt $paths.Count; $i++) {
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $paths[$i] -ErrorAction Stop
    $subject = ''
    if ($s.SignerCertificate) { $subject = $s.SignerCertificate.Subject }
    $out.Add([pscustomobject]@{ i = $i; s = [string]$s.Status; c = $subject })
  } catch {
    $out.Add([pscustomobject]@{ i = $i; s = 'Error'; c = '' })
  }
}
ConvertTo-Json -InputObject $out.ToArray() -Compress | Out-File -LiteralPath $env:VTSCAN_SIG_OUT -Encoding UTF8
"""


@dataclass
class SignatureInfo:
    status: str
    signer: str  # organización (O=) o nombre común (CN=) del certificado


def _dn_field(subject: str, name: str) -> str:
    match = re.search(rf'(?:^|,\s*){name}=("(?:[^"]|"")*"|[^,]*)', subject)
    if not match:
        return ""
    value = match.group(1).strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1].replace('""', '"')
    return value


def signer_from_subject(subject: str) -> str:
    return _dn_field(subject, "O") or _dn_field(subject, "CN")


def needs_signature_check(ext: str, is_pe: bool) -> bool:
    return is_pe or ext in SIGNABLE_EXTENSIONS


def is_trusted(info_signer: str | None, status: str | None, trusted: Iterable[str]) -> bool:
    if status != STATUS_VALID or not info_signer:
        return False
    wanted = {t.casefold() for t in trusted}
    return info_signer.casefold() in wanted


def _run_batch(paths: list[str]) -> list[SignatureInfo]:
    results = [SignatureInfo(STATUS_ERROR, "") for _ in paths]
    with tempfile.TemporaryDirectory(prefix="vtscan_sig_") as tmp:
        in_file = os.path.join(tmp, "in.txt")
        out_file = os.path.join(tmp, "out.json")
        with open(in_file, "w", encoding="utf-8-sig") as f:
            f.write("\n".join(fs_path(p) for p in paths))
        env = dict(os.environ, VTSCAN_SIG_IN=in_file, VTSCAN_SIG_OUT=out_file)
        encoded = base64.b64encode(_PS_SCRIPT.encode("utf-16-le")).decode("ascii")
        try:
            subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                env=env,
                capture_output=True,
                timeout=BATCH_TIMEOUT_SECONDS,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            with open(out_file, encoding="utf-8-sig") as f:
                data = json.load(f)
        except (OSError, subprocess.SubprocessError, ValueError):
            return results
    if isinstance(data, dict):  # PowerShell devuelve un objeto suelto si solo hay uno
        data = [data]
    for item in data:
        index = item.get("i")
        if not isinstance(index, int) or not 0 <= index < len(paths):
            continue
        status = _STATUS_MAP.get(item.get("s", ""), STATUS_ERROR)
        results[index] = SignatureInfo(status, signer_from_subject(item.get("c") or ""))
    return results


def check_signatures(
    paths: list[str],
    on_progress: Callable[[int, int], None] | None = None,
) -> list[SignatureInfo]:
    """Comprueba la firma de cada ruta (mismo orden en la salida). Varios lotes a
    la vez, cada uno en su propio PowerShell."""
    if not IS_WINDOWS:
        return [SignatureInfo(STATUS_ERROR, "") for _ in paths]
    batches = [paths[i : i + BATCH_SIZE] for i in range(0, len(paths), BATCH_SIZE)]
    results: list[list[SignatureInfo]] = [[] for _ in batches]
    done = 0
    with ThreadPoolExecutor(max_workers=PARALLEL_BATCHES) as pool:
        futures = {pool.submit(_run_batch, batch): n for n, batch in enumerate(batches)}
        for future in as_completed(futures):
            n = futures[future]
            results[n] = future.result()
            done += len(batches[n])
            if on_progress:
                on_progress(done, len(paths))
    return [info for batch in results for info in batch]
