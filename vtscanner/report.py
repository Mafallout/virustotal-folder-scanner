"""Informes HTML (autocontenido, funciona sin internet) y CSV (listo para Excel en español)."""

from __future__ import annotations

import csv
import html
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .verdict import LEVEL_ORDER, Level

SIGNAL_LABELS = {
    "hidden": "oculto",
    "disguised": "ejecutable camuflado",
    "double_ext": "doble extensión",
    "rtlo": "nombre con carácter invertido",
    "sig_tampered": "firma rota",
    "sig_untrusted": "firma no válida",
    "trusted": "firmado por fabricante conocido",
}


@dataclass
class ReportRow:
    level: Level
    reason: str
    label: str
    path: str
    rel_path: str
    state: str
    sha256: str | None = None
    size: int | None = None
    malicious: int | None = None
    suspicious: int | None = None
    total: int | None = None
    main_detections: list[tuple[str, str]] = field(default_factory=list)
    detections_count: int = 0
    detected_by: list[tuple[str, str]] = field(default_factory=list)
    signature: str = ""
    signals: list[str] = field(default_factory=list)
    first_seen: int | None = None
    last_analysis: int | None = None
    vt_link: str | None = None

    @property
    def top_folder(self) -> str:
        parts = self.rel_path.split(os.sep)
        return parts[0] if len(parts) > 1 else "(raíz)"


@dataclass
class ReportSummary:
    root: str
    started_at: float
    finished_at: float
    options: list[str]
    complete: bool
    files_seen: int
    bytes_seen: int
    candidates: int
    unique_hashes: int
    requests_this_run: int
    used_today: int | None = None
    daily_limit: int | None = None
    reset_local: str | None = None
    pending: int = 0
    defender: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)
    dry_run: bool = False


def sort_key(row: ReportRow) -> tuple[int, int, int, str]:
    return (
        LEVEL_ORDER.index(row.level),
        -(row.malicious or 0),
        -(row.suspicious or 0),
        row.rel_path.lower(),
    )


def plural(n: int, singular: str, plural_form: str | None = None) -> str:
    """'1 archivo', '3 archivos'."""
    return f"{n} {singular if n == 1 else (plural_form or singular + 's')}"


def engines_text(names: list[str], shown: int = 3) -> str:
    """'Cynet', 'Kaspersky y Cynet' o 'Kaspersky, ESET-NOD32, Cynet y 4 más'."""
    if len(names) > shown:
        return ", ".join(names[:shown]) + f" y {len(names) - shown} más"
    if len(names) > 1:
        return ", ".join(names[:-1]) + " y " + names[-1]
    return "".join(names)


def human_size(size: int | None) -> str:
    if size is None:
        return ""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            text = f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            return text.replace(".", ",")
        value /= 1024
    return str(size)


def format_ts(ts: float | int | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M")


def detections_text(row: ReportRow) -> str:
    if row.total is None:
        return ""
    return f"{row.malicious or 0}/{row.suspicious or 0}/{row.total}"


def report_basename(root: str, when: float) -> str:
    name = os.path.basename(os.path.normpath(root)) or root.rstrip(":\\/") or "carpeta"
    name = re.sub(r"[^\w.-]+", "_", name, flags=re.UNICODE).strip("._")[:60] or "carpeta"
    return f"vtscan_{name}_{datetime.fromtimestamp(when).strftime('%Y%m%d-%H%M%S')}"


# ---- CSV ---------------------------------------------------------------------

CSV_COLUMNS = [
    "nivel", "motivo", "ruta", "ruta_relativa", "sha256", "tamano_bytes", "maliciosos",
    "sospechosos", "total_motores", "etiqueta", "detecciones_principales", "firma",
    "senales", "primer_envio", "ultimo_analisis", "estado", "enlace_vt",
]


def _csv_safe(value: Any) -> Any:
    """Evita que Excel interprete un texto como fórmula (=, +, -, @)."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def write_csv(rows: list[ReportRow], path: Path, delimiter: str = ";") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f, delimiter=delimiter)
        writer.writerow(CSV_COLUMNS)
        for row in sorted(rows, key=sort_key):
            writer.writerow(
                [
                    _csv_safe(v)
                    for v in (
                        row.level.label,
                        row.reason,
                        row.path,
                        row.rel_path,
                        row.sha256 or "",
                        "" if row.size is None else row.size,
                        "" if row.malicious is None else row.malicious,
                        "" if row.suspicious is None else row.suspicious,
                        "" if row.total is None else row.total,
                        row.label,
                        " | ".join(f"{e}: {r}" for e, r in row.main_detections),
                        row.signature,
                        ", ".join(SIGNAL_LABELS.get(s, s) for s in row.signals),
                        format_ts(row.first_seen),
                        format_ts(row.last_analysis),
                        row.state,
                        row.vt_link or "",
                    )
                ]
            )


# ---- HTML --------------------------------------------------------------------

_CSS = """
:root {
  --bg: #f5f6f8; --fg: #1c222b; --muted: #5d6877; --card: #ffffff; --border: #dce1e7;
  --accent: #2f6fdf;
  --critical: #c0161f; --critical-bg: #fde7e7;
  --high: #d9531e; --high-bg: #ffeee4;
  --medium: #a87900; --medium-bg: #fff5d4;
  --low: #77723a; --low-bg: #f5f3e6;
  --unknown: #3f6a92; --unknown-bg: #e7eff7;
  --pending: #687180; --pending-bg: #eef0f3;
  --clean: #1d7f47; --clean-bg: #e3f5ea;
  --skipped: #8a909a; --skipped-bg: #f1f2f4;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14171c; --fg: #e4e8ee; --muted: #9aa5b3; --card: #1c2027; --border: #2d333d;
    --accent: #6ea0ff;
    --critical: #ff6b6f; --critical-bg: #3b1518;
    --high: #ff9a5c; --high-bg: #3a2216;
    --medium: #f1c84b; --medium-bg: #352c12;
    --low: #c9c27a; --low-bg: #2c2a1b;
    --unknown: #8fb6e0; --unknown-bg: #1a2734;
    --pending: #a3abb7; --pending-bg: #23272e;
    --clean: #5fd18f; --clean-bg: #15291e;
    --skipped: #8a909a; --skipped-bg: #1f2227;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 14px/1.45 "Segoe UI", system-ui, -apple-system, sans-serif; }
main { max-width: 1500px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 28px 0 10px; }
.muted { color: var(--muted); }
.mono { font-family: Consolas, "Cascadia Mono", monospace; font-size: 12.5px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
.meta { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin-top: 12px; }
.meta dt { color: var(--muted); }
.meta dd { margin: 0; word-break: break-all; }
.status { margin-top: 14px; padding: 10px 14px; border-radius: 8px; font-weight: 600; }
.status.ok { background: var(--clean-bg); color: var(--clean); }
.status.partial { background: var(--medium-bg); color: var(--medium); }
.tiles { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 16px; }
.tile { flex: 1 1 110px; border-radius: 10px; padding: 10px 12px; background: var(--card);
  border: 1px solid var(--border); border-top: 4px solid var(--c); }
.tile b { display: block; font-size: 24px; color: var(--c); }
.tile span { color: var(--muted); font-size: 12.5px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px 14px; align-items: center; margin: 14px 0 10px; }
.toolbar label { display: inline-flex; gap: 5px; align-items: center; cursor: pointer; user-select: none; }
.toolbar input[type=search] { flex: 1 1 240px; min-width: 0; padding: 7px 10px; border-radius: 8px;
  border: 1px solid var(--border); background: var(--card); color: var(--fg); font: inherit; }
.table-wrap { overflow-x: auto; background: var(--card); border: 1px solid var(--border); border-radius: 10px; }
table { border-collapse: collapse; width: 100%; }
th, td { padding: 8px 10px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--border); }
th { position: sticky; top: 0; background: var(--card); font-size: 12.5px; color: var(--muted);
  cursor: pointer; white-space: nowrap; }
th.nosort { cursor: default; }
tbody tr { border-left: 4px solid var(--c); }
tbody tr:hover { background: color-mix(in srgb, var(--c) 6%, transparent); }
td.num { text-align: right; white-space: nowrap; }
td.filecell { min-width: 260px; }
td.det { min-width: 230px; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-weight: 600; font-size: 12px;
  color: var(--c); background: var(--cb); white-space: nowrap; }
.file { font-weight: 600; word-break: break-all; }
.dir { color: var(--muted); font-size: 12.5px; word-break: break-all; }
.reason { font-size: 12.5px; margin-top: 3px; }
.chip { display: inline-block; margin: 3px 4px 0 0; padding: 0 7px; border-radius: 6px; font-size: 11.5px;
  border: 1px solid var(--border); color: var(--muted); }
.chip.warn { border-color: var(--high); color: var(--high); }
.det { font-size: 12.5px; }
.det div { word-break: break-word; }
.det .eng { color: var(--muted); }
.counts b { color: var(--c); }
.hash { cursor: copy; }
a { color: var(--accent); }
.lv-critical { --c: var(--critical); --cb: var(--critical-bg); }
.lv-high { --c: var(--high); --cb: var(--high-bg); }
.lv-medium { --c: var(--medium); --cb: var(--medium-bg); }
.lv-low { --c: var(--low); --cb: var(--low-bg); }
.lv-unknown { --c: var(--unknown); --cb: var(--unknown-bg); }
.lv-pending { --c: var(--pending); --cb: var(--pending-bg); }
.lv-clean { --c: var(--clean); --cb: var(--clean-bg); }
.lv-skipped { --c: var(--skipped); --cb: var(--skipped-bg); }
.empty { padding: 24px; text-align: center; color: var(--muted); }
footer { margin-top: 28px; color: var(--muted); font-size: 12.5px; }
@media (max-width: 700px) { .meta { grid-template-columns: 1fr; } .meta dt { margin-top: 6px; } }
"""

_JS = """
(function () {
  const rows = Array.from(document.querySelectorAll('#results tbody tr[data-level]'));
  const boxes = Array.from(document.querySelectorAll('.toolbar input[type=checkbox]'));
  const search = document.getElementById('q');
  const empty = document.getElementById('empty');
  function apply() {
    const on = new Set(boxes.filter(b => b.checked).map(b => b.value));
    const q = search.value.trim().toLowerCase();
    let shown = 0;
    rows.forEach(r => {
      const ok = on.has(r.dataset.level) && (!q || r.dataset.text.includes(q));
      r.hidden = !ok; if (ok) shown++;
    });
    empty.hidden = shown !== 0;
  }
  boxes.forEach(b => b.addEventListener('change', apply));
  search.addEventListener('input', apply);
  const tbody = document.querySelector('#results tbody');
  document.querySelectorAll('#results th[data-key]').forEach(th => {
    th.addEventListener('click', () => {
      const key = th.dataset.key, num = th.dataset.num === '1';
      const dir = th.dataset.dir === 'asc' ? 'desc' : 'asc';
      document.querySelectorAll('#results th').forEach(o => delete o.dataset.dir);
      th.dataset.dir = dir;
      const sorted = rows.slice().sort((a, b) => {
        let x = a.dataset[key], y = b.dataset[key];
        if (num) { x = parseFloat(x); y = parseFloat(y); }
        const c = x < y ? -1 : x > y ? 1 : 0;
        return dir === 'asc' ? c : -c;
      });
      sorted.forEach(r => tbody.insertBefore(r, empty));
    });
  });
  document.querySelectorAll('.hash').forEach(el => el.addEventListener('click', () => {
    if (navigator.clipboard) navigator.clipboard.writeText(el.dataset.hash);
    const old = el.textContent; el.textContent = 'copiado';
    setTimeout(() => { el.textContent = old; }, 900);
  }));
  apply();
})();
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _row_html(row: ReportRow) -> str:
    level = row.level
    directory, filename = os.path.split(row.rel_path)
    signal_chips = "".join(
        f'<span class="chip{" warn" if s != "trusted" else ""}">{_e(SIGNAL_LABELS.get(s, s))}</span>'
        for s in row.signals
    )
    if row.total is not None:
        counts = (
            f'<span class="counts"><b>{row.malicious or 0}</b> / {row.suspicious or 0}'
            f' <span class="muted">de {row.total}</span></span>'
        )
    else:
        counts = '<span class="muted">-</span>'
    detections = "".join(
        f'<div><span class="eng">{_e(engine)}:</span> {_e(result)}</div>'
        for engine, result in row.main_detections
    )
    extra = row.detections_count - len(row.main_detections)
    if extra > 0:
        detections += f'<div class="muted">y {extra} motor{"es" if extra != 1 else ""} más</div>'
    shown_results = {result for _, result in row.main_detections}
    label_html = f"<div><b>{_e(row.label)}</b></div>" if row.label and row.label not in shown_results else ""
    sha = row.sha256 or ""
    hash_html = (
        f'<span class="mono hash" title="{_e(sha)} (clic para copiar)" data-hash="{_e(sha)}">'
        f"{_e(sha[:12])}…</span>"
        if sha
        else ""
    )
    link = f'<a href="{_e(row.vt_link)}" target="_blank" rel="noopener">Abrir</a>' if row.vt_link else ""
    search_text = " ".join(
        [row.rel_path, row.label, row.reason, sha, row.signature]
        + [r for _, r in row.main_detections]
    ).lower()
    return (
        f'<tr class="lv-{level.key}" data-level="{level.key}" data-order="{LEVEL_ORDER.index(level)}"'
        f' data-path="{_e(row.rel_path.lower())}" data-mal="{row.malicious or 0}"'
        f' data-size="{row.size or 0}" data-text="{_e(search_text)}">'
        f'<td><span class="badge">{_e(level.label)}</span></td>'
        f'<td class="filecell"><div class="file" title="{_e(row.path)}">{_e(filename)}</div>'
        f'<div class="dir">{_e(directory)}</div>{signal_chips}'
        f'<div class="reason">{_e(row.reason)}</div></td>'
        f'<td class="num">{counts}</td>'
        f'<td class="det">{label_html}{detections}</td>'
        f"<td>{_e(row.signature)}</td>"
        f'<td class="num">{_e(human_size(row.size))}</td>'
        f"<td>{hash_html}</td>"
        f"<td>{link}</td>"
        "</tr>"
    )


def _folder_summary(rows: list[ReportRow]) -> str:
    folders: dict[str, dict[Level, int]] = {}
    for row in rows:
        counts = folders.setdefault(row.top_folder, {})
        counts[row.level] = counts.get(row.level, 0) + 1
    if len(folders) < 2:
        return ""
    shown = [Level.CRITICAL, Level.HIGH, Level.MEDIUM, Level.LOW, Level.UNKNOWN, Level.PENDING]

    def severity(item: tuple[str, dict[Level, int]]) -> tuple[int, ...]:
        return tuple(-item[1].get(level, 0) for level in shown) + (0,)

    header = "".join(f"<th class='nosort'>{_e(level.label)}</th>" for level in shown)
    body = []
    for name, counts in sorted(folders.items(), key=lambda it: (severity(it), it[0].lower())):
        cells = "".join(
            f'<td class="num lv-{level.key}">'
            + (f'<b style="color:var(--c)">{counts[level]}</b>' if counts.get(level) else "")
            + "</td>"
            for level in shown
        )
        body.append(
            f"<tr><td>{_e(name)}</td><td class='num'>{sum(counts.values())}</td>{cells}</tr>"
        )
    return (
        "<h2>Por subcarpeta</h2><div class='table-wrap'><table>"
        f"<thead><tr><th class='nosort'>Subcarpeta</th><th class='nosort'>Archivos</th>{header}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table></div>"
    )


def _defender_html(defender: dict[str, Any] | None) -> str:
    if not defender:
        return ""
    if not defender.get("ok"):
        return (
            "<h2>Microsoft Defender</h2>"
            f"<div class='card'>No se pudo ejecutar el análisis: {_e(defender.get('error'))}</div>"
        )
    threats = defender.get("threats") or []
    if not threats:
        return (
            "<h2>Microsoft Defender</h2>"
            "<div class='card'>Análisis completado: <b>sin amenazas</b>.</div>"
        )
    items = "".join(
        f"<li><b>{_e(t.get('name'))}</b>"
        + "".join(f"<div class='mono muted'>{_e(r)}</div>" for r in t.get("resources") or [])
        + "</li>"
        for t in threats
    )
    return (
        "<h2>Microsoft Defender</h2>"
        f"<div class='card'><p>Defender encontró <b>{len(threats)}</b> amenaza(s). "
        "Se analizó en modo solo informe: no se ha movido nada a cuarentena.</p>"
        f"<ul>{items}</ul></div>"
    )


def write_html(rows: list[ReportRow], summary: ReportSummary, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(rows, key=sort_key)
    counts = {level: 0 for level in LEVEL_ORDER}
    for row in rows:
        counts[row.level] += 1

    tiles = "".join(
        f'<div class="tile lv-{level.key}"><b>{counts[level]}</b><span>{_e(level.label)}</span></div>'
        for level in LEVEL_ORDER
    )
    default_on = {level for level in LEVEL_ORDER if level != Level.CLEAN} if len(rows) > 300 else set(LEVEL_ORDER)
    toggles = "".join(
        f'<label class="lv-{level.key}"><input type="checkbox" value="{level.key}"'
        f'{" checked" if level in default_on else ""}><span class="badge">{_e(level.label)} ({counts[level]})</span></label>'
        for level in LEVEL_ORDER
        if counts[level]
    )
    if summary.dry_run:
        status = (
            f'<div class="status partial">Simulación (--dry-run): {summary.pending} archivo(s) sin consultar. '
            "Ejecuta el mismo comando sin --dry-run para analizarlos.</div>"
        )
    elif summary.complete:
        status = '<div class="status ok">Escaneo completo.</div>'
    else:
        when = f" La cuota se reinicia a las {summary.reset_local} (hora local)." if summary.reset_local else ""
        status = (
            f'<div class="status partial">Escaneo incompleto: quedan {summary.pending} '
            f"archivo(s) pendientes. Continúa con <span class='mono'>python vtscan.py --resume</span>.{when}</div>"
        )
    quota = ""
    if summary.used_today is not None and summary.daily_limit:
        quota = f"{summary.used_today} de {summary.daily_limit} hoy"
    meta_items = [
        ("Carpeta", summary.root),
        ("Fecha", f"{format_ts(summary.started_at)} - {format_ts(summary.finished_at)}"),
        ("Opciones", ", ".join(summary.options) or "ninguna"),
        (
            "Archivos",
            f"{summary.files_seen} vistos ({human_size(summary.bytes_seen)}), {summary.candidates} analizados, "
            f"{summary.unique_hashes} distintos",
        ),
        ("Peticiones", f"{summary.requests_this_run} en esta ejecución" + (f" ({quota})" if quota else "")),
    ]
    meta = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in meta_items)
    notes = "".join(f"<li>{_e(n)}</li>" for n in summary.notes)
    notes_html = f"<h2>Avisos</h2><div class='card'><ul>{notes}</ul></div>" if notes else ""
    body_rows = "".join(_row_html(r) for r in rows)

    document = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe vtscan</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<h1>Informe vtscan</h1>
<div class="muted">Análisis con VirusTotal (API v3, plan gratuito)</div>
<div class="card" style="margin-top:14px"><dl class="meta">{meta}</dl>{status}</div>
<div class="tiles">{tiles}</div>
{_defender_html(summary.defender)}
{notes_html}
{_folder_summary(rows)}
<h2>Archivos</h2>
<div class="toolbar">{toggles}<input id="q" type="search" placeholder="Buscar por ruta, etiqueta, hash..."></div>
<div class="table-wrap">
<table id="results">
<thead><tr>
<th data-key="order" data-num="1">Nivel</th>
<th data-key="path">Archivo y motivo</th>
<th data-key="mal" data-num="1">Maliciosos / sospechosos</th>
<th class="nosort">Etiqueta y detecciones</th>
<th class="nosort">Firma</th>
<th data-key="size" data-num="1">Tamaño</th>
<th class="nosort">SHA-256</th>
<th class="nosort">VirusTotal</th>
</tr></thead>
<tbody>{body_rows}<tr id="empty" hidden><td colspan="8" class="empty">No hay archivos con estos filtros.</td></tr></tbody>
</table>
</div>
<footer>Generado por vtscan {_e(__version__)}. Una detección no es una prueba y "Desconocido" no significa
seguro: revisa el motivo de cada fila y, ante la duda, el informe completo en VirusTotal.</footer>
</main>
<script>{_JS}</script>
</body>
</html>
"""
    path.write_text(document, encoding="utf-8")
