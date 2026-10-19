"""Niveles de gravedad: distingue las detecciones genéricas y las de herramientas
o software no deseado (HackTool, PUA...), muy habituales y a menudo falsos
positivos, de las familias de malware graves (stealers, RAT, mineros, ransomware...)."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable

from .config import VerdictConfig
from .vtclient import FileReport


class Level(IntEnum):
    SKIPPED = 0
    CLEAN = 1
    PENDING = 2
    UNKNOWN = 3
    LOW = 4
    MEDIUM = 5
    HIGH = 6
    CRITICAL = 7

    @property
    def label(self) -> str:
        return LEVEL_LABELS[self]

    @property
    def key(self) -> str:
        return self.name.lower()


LEVEL_LABELS = {
    Level.CRITICAL: "Crítico",
    Level.HIGH: "Alto",
    Level.MEDIUM: "Medio",
    Level.LOW: "Bajo",
    Level.UNKNOWN: "Desconocido",
    Level.PENDING: "Pendiente",
    Level.CLEAN: "Limpio",
    Level.SKIPPED: "Omitido",
}

# Orden en el informe: de más a menos peligroso
LEVEL_ORDER = [
    Level.CRITICAL, Level.HIGH, Level.MEDIUM, Level.LOW,
    Level.UNKNOWN, Level.PENDING, Level.CLEAN, Level.SKIPPED,
]

# Motores cuyo nombre de detección se prefiere para la etiqueta si VT no da una
PREFERRED_LABEL_ENGINES = ["Microsoft", "Kaspersky", "ESET-NOD32", "BitDefender", "Avast", "DrWeb"]

# Tipos de detección de Defender (lo que va antes de los dos puntos)
DEFENDER_SOFT_TYPES = {
    "hacktool", "pua", "puadlmanager", "puaminer", "puabundler", "program", "app",
    "softwarebundler", "browsermodifier", "adware", "monitoringtool", "remoteaccess",
    "misleading", "tool", "joke", "settingsmodifier",
}
DEFENDER_DANGEROUS_TYPES = {
    "trojan", "trojandownloader", "trojandropper", "trojanspy", "trojanclicker",
    "trojanproxy", "backdoor", "ransom", "pws", "worm", "virus", "exploit",
    "rootkit", "spyware",
}

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


@dataclass
class Verdict:
    level: Level
    reason: str
    label: str = ""


def tokens(text: str) -> list[str]:
    """Trocea una etiqueta de antivirus en palabras ("not-a-virus" cuenta como una)."""
    text = text.lower().replace("not-a-virus", "notavirus")
    return [t for t in _TOKEN_SPLIT.split(text) if t]


class KeywordSet:
    """Palabras cortas (4 letras o menos) deben coincidir enteras; las largas
    pueden ir dentro de otra (stealer en infostealer)."""

    def __init__(self, words: Iterable[str]) -> None:
        words = [w.lower() for w in words if w]
        self.short = {w for w in words if len(w) <= 4}
        self.long = [w for w in words if len(w) > 4]

    def match(self, toks: Iterable[str]) -> str | None:
        for t in toks:
            if t in self.short:
                return t
            for w in self.long:
                if w in t:
                    return w
        return None


def clean_label(text: str) -> str:
    """VirusTotal a veces deja la etiqueta a medias ("downloader.")."""
    return text.strip().strip("./ ")


class Classifier:
    def __init__(self, cfg: VerdictConfig) -> None:
        self.cfg = cfg
        self.dangerous = KeywordSet(cfg.dangerous_keywords)
        self.crack = KeywordSet(cfg.crack_keywords)
        self.generic = KeywordSet(cfg.generic_keywords)
        self.reliable = {e.lower() for e in cfg.reliable_engines}

    def _label(self, report: FileReport, family: str | None) -> str:
        if clean_label(report.threat_label):
            return clean_label(report.threat_label)
        if family:
            return family
        for engine in PREFERRED_LABEL_ENGINES:
            for name, (_, result) in report.detections.items():
                if name.lower() == engine.lower() and result:
                    return result
        for _, result in report.detections.values():
            if result:
                return result
        return ""

    def classify_report(self, report: FileReport) -> Verdict:
        mal, sus, total = report.malicious, report.suspicious, report.total
        if mal == 0 and sus == 0:
            return Verdict(Level.CLEAN, f"VT: 0 de {total} motores lo detectan", clean_label(report.threat_label))

        families: Counter[str] = Counter()
        dangerous_engines = crack = generic = 0
        for _, result in report.detections.values():
            toks = tokens(result)
            family = self.dangerous.match(toks)
            if family:
                families[family] += 1
                dangerous_engines += 1
            elif self.crack.match(toks):
                crack += 1
            elif self.generic.match(toks):
                generic += 1
        # La clasificación propia de VirusTotal también cuenta
        for value, count in report.threat_names + report.threat_categories:
            family = self.dangerous.match(tokens(value))
            if family and count >= 2:
                families[family] = max(families[family], count)
                dangerous_engines = max(dangerous_engines, count)

        # El nombre más repetido; a igualdad, el más largo (más concreto: redline mejor que psw)
        family = max(families, key=lambda f: (families[f], len(f))) if families else None
        family_count = dangerous_engines
        labeled = len(report.detections)
        all_crack = labeled > 0 and crack == labeled
        all_soft = labeled > 0 and crack + generic == labeled
        # ¿Lo detecta alguno de los antivirus de referencia? Si no, con 1 o 2
        # detecciones casi siempre es un falso positivo de un motor menor
        reliable_hit = any(name.lower() in self.reliable for name in report.detections)
        label = self._label(report, family)
        detected = f"{mal} de {total} motores lo detectan"
        not_reliable = "ninguno de los antivirus de referencia (probable falso positivo)"
        tools = "etiquetas de herramientas o software no deseado (HackTool, PUA...)"
        if generic == labeled:
            soft = "etiquetas genéricas"
        elif crack == labeled:
            soft = tools
        else:
            soft = "etiquetas genéricas o de herramientas"

        if family_count >= 2:
            return Verdict(
                Level.CRITICAL, f"VT: {detected}; {family_count} apuntan a malware grave ({family})", label
            )
        if mal >= self.cfg.critical_threshold:
            if all_crack:
                return Verdict(Level.HIGH, f"VT: {detected}, pero todas son {tools}", label)
            return Verdict(Level.CRITICAL, f"VT: {detected}", label)
        if mal >= self.cfg.high_threshold:
            if all_crack:
                return Verdict(Level.MEDIUM, f"VT: {detected}, solo con {tools}", label)
            return Verdict(Level.HIGH, f"VT: {detected}", label)
        if mal >= 1:
            if family_count == 1:
                return Verdict(Level.MEDIUM, f"VT: {detected}; uno apunta a malware grave ({family})", label)
            if all_soft:
                return Verdict(Level.LOW, f"VT: {detected} con {soft} (probable falso positivo)", label)
            if not reliable_hit:
                return Verdict(Level.LOW, f"VT: {detected}, {not_reliable}", label)
            return Verdict(Level.MEDIUM, f"VT: {detected}", label)
        if sus >= 2 and reliable_hit:
            return Verdict(Level.MEDIUM, f"VT: {sus} motores lo marcan como sospechoso", label)
        return Verdict(Level.LOW, f"VT: {sus} motor(es) lo marcan como sospechoso", label)


def classify_defender(name: str) -> Verdict:
    lower = name.lower()
    kind = lower.split(":", 1)[0] if ":" in lower else ""
    if kind in DEFENDER_SOFT_TYPES:
        return Verdict(Level.MEDIUM, f"Defender: {name} (herramienta o software no deseado)", name)
    if "!ml" in lower:
        return Verdict(Level.MEDIUM, f"Defender: {name} (detección por aprendizaje automático)", name)
    if kind in DEFENDER_DANGEROUS_TYPES:
        return Verdict(Level.CRITICAL, f"Defender: {name}", name)
    return Verdict(Level.HIGH, f"Defender: {name}", name)


def defender_blocked_verdict() -> Verdict:
    return Verdict(
        Level.HIGH, "Defender bloqueó la lectura del archivo (lo considera una amenaza)", "Defender"
    )


def combine(verdicts: Iterable[Verdict | None]) -> Verdict:
    """El veredicto más grave manda; se juntan los motivos de todo lo que detectó algo."""
    items = [v for v in verdicts if v is not None]
    if not items:
        return Verdict(Level.PENDING, "Sin datos")
    items.sort(key=lambda v: v.level, reverse=True)
    best = items[0]
    findings = [v.reason for v in items if v.level >= Level.LOW and v.reason]
    reason = " · ".join(dict.fromkeys(findings)) if findings else best.reason
    label = next((v.label for v in items if v.label), "")
    return Verdict(best.level, reason, label)
