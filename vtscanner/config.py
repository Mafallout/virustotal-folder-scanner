"""Configuración: valores por defecto y lectura de config.toml."""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field, fields
from functools import lru_cache
from pathlib import Path


def _base_dir() -> Path:
    """Carpeta del programa: la del .exe si va empaquetado, la del proyecto si no."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


PROJECT_DIR = _base_dir()
DEFAULT_CONFIG_PATH = PROJECT_DIR / "config.toml"


def fallback_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(base) / "vtscan"


def is_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".vtscan_prueba_escritura"
        probe.write_text("ok", encoding="ascii")
        probe.unlink()
        return True
    except OSError:
        return False


@lru_cache(maxsize=1)
def writable_base() -> Path:
    """Dónde se guardan caché, logs e informes: junto al programa si se puede
    escribir ahí; si no (por ejemplo, dentro de Archivos de programa), en LOCALAPPDATA."""
    return PROJECT_DIR if is_writable(PROJECT_DIR) else fallback_dir()


class ConfigError(Exception):
    """Error en el archivo de configuración."""


# Extensiones que se analizan por defecto (sin --all-files).
DEFAULT_EXTENSIONS = [
    # Las del enunciado
    ".exe", ".dll", ".sys", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".scr", ".com", ".jar",
    # Añadidas: código ejecutable o scripts que también aparecen en juegos
    ".asi", ".cpl", ".ocx", ".pif", ".hta", ".wsf", ".vbe", ".jse", ".psm1",
    ".lnk", ".msp",
]

# Archivos de datos que nunca se abren para buscar la cabecera MZ.
# Así no se leen miles de texturas o audios en una carpeta de juego.
DEFAULT_NO_SNIFF_EXTENSIONS = [
    # Imagen
    ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tga", ".dds", ".ktx", ".ktx2",
    ".webp", ".psd", ".tif", ".tiff", ".hdr", ".exr", ".svg", ".ico", ".cur",
    # Audio
    ".ogg", ".wav", ".mp3", ".flac", ".wem", ".bnk", ".bank", ".fsb", ".xwm",
    ".opus", ".m4a", ".aac", ".wma", ".mid", ".midi", ".xm", ".it", ".s3m",
    # Vídeo
    ".mp4", ".webm", ".bik", ".bk2", ".usm", ".avi", ".mkv", ".wmv", ".mov",
    ".ogv", ".mpg", ".mpeg", ".m4v",
    # Fuentes (.fon lleva cabecera MZ, pero es una fuente)
    ".ttf", ".otf", ".ttc", ".woff", ".woff2", ".fnt", ".fon",
    # Paquetes y datos de motores de juego
    ".pak", ".ucas", ".utoc", ".uasset", ".uexp", ".ubulk", ".umap", ".vpk",
    ".assets", ".ress", ".resource", ".bundle", ".unity3d", ".forge", ".rpf",
    ".big", ".wad", ".pck", ".arc", ".xnb", ".toc", ".cas", ".bdt", ".bhd",
    ".dcx", ".xp3", ".npk", ".cpk", ".awb", ".acb", ".rgssad", ".rgss2a",
    ".rgss3a", ".rpa", ".rpyc", ".rpgmvp", ".rpgmvo", ".rpgmvm", ".png_",
    ".ogg_", ".m4a_", ".cache", ".shader", ".cso", ".fxo", ".spv", ".pdb",
    # Modelos 3D
    ".fbx", ".obj", ".gltf", ".glb", ".dae", ".3ds", ".blend", ".mesh",
    # Texto y documentos (.txt, .nfo, .pdf, .rtf, .html y los comprimidos sí se miran:
    # son los disfraces típicos de un ejecutable y suele haber pocos)
    ".md", ".json", ".xml", ".ini", ".cfg", ".conf", ".yml",
    ".yaml", ".csv", ".log", ".lua", ".css",
    ".po", ".mo", ".srt", ".ass", ".vtt", ".manifest", ".config", ".resx",
    ".vdf", ".acf", ".locres", ".uplugin", ".uproject",
    # Código fuente y bytecode (motores de juego, Ren'Py, Python incluido)
    ".py", ".pyc", ".pyo", ".pyi", ".rpy", ".h", ".hpp", ".c", ".cpp", ".cs",
    ".ush", ".usf", ".hlsl", ".glsl", ".fx", ".tcl",
    # Comprimidos e imágenes de disco
    ".gz", ".tar", ".xz", ".bz2", ".zst", ".lz4",
    ".cab", ".iso", ".img",
    # Recursos de Windows con cabecera MZ que no son código
    ".mui",
    # Partidas guardadas y bases de datos
    ".sav", ".save", ".sqlite", ".db",
]

# Palabras que indican una familia o tipo de malware grave.
DEFAULT_DANGEROUS_KEYWORDS = [
    # Robo de credenciales (stealers)
    "stealer", "pws", "psw", "spy", "trojanspy", "spyware", "keylogger",
    "redline", "redlinestealer", "lumma", "lummac", "lummastealer", "vidar",
    "raccoon", "stealc", "rhadamanthys", "risepro", "meduza", "azorult",
    "formbook", "agenttesla", "lokibot", "mystic",
    # Acceso remoto (RAT) y puertas traseras
    "rat", "backdoor", "remcos", "asyncrat", "njrat", "bladabindi", "dcrat",
    "darkcomet", "quasar", "quasarrat", "nanocore", "xworm", "warzone",
    "netwire", "cobaltstrike", "meterpreter",
    # Mineros de criptomonedas
    "miner", "coinminer", "xmrig", "cryptominer",
    # Ransomware
    "ransom", "ransomware", "djvu", "stop", "lockbit", "phobos",
    # Cargadores y droppers conocidos
    "smokeloader", "privateloader", "amadey", "glupteba", "socelars",
    "gcleaner", "nymaim", "emotet", "qakbot", "icedid", "bumblebee",
    # Virus que infectan otros ejecutables
    "sality", "virut", "neshta", "expiro", "ramnit",
    # Otros
    "clipper", "clipbanker", "banker", "rootkit", "bootkit",
]

# Etiquetas de herramientas, parches y software no deseado (HackTool, PUA, RiskWare...).
DEFAULT_CRACK_KEYWORDS = [
    "hacktool", "crack", "cracktool", "keygen", "patch", "patcher",
    "activator", "kms", "kmsauto", "autokms", "riskware", "risktool", "pua",
    "pup", "unwanted", "notavirus", "gamehack", "cheat", "trainer", "hack",
    "tool", "program", "grayware", "adware", "softwarebundler", "bundler",
    "presenoker", "hackkms", "potentially",
]

# Detecciones genéricas, heurísticas o de aprendizaje automático (más falsos positivos).
DEFAULT_GENERIC_KEYWORDS = [
    "generic", "gen", "heur", "heuristic", "ml", "ai", "malicious",
    "confidence", "highconfidence", "unsafe", "suspicious", "static",
    "attribute", "score", "variant", "zusy", "razy", "tedy", "kryptik",
    "wacatac", "sabsik", "artemis", "malware", "dynamer", "deepscan",
    "reputation", "agent", "cloud", "lazy", "packed", "obfuscated",
    "behaveslike",
]

# Antivirus de referencia: si 1 o 2 detecciones no vienen de ninguno de ellos,
# casi siempre es un falso positivo de un motor menor.
DEFAULT_RELIABLE_ENGINES = [
    "Microsoft", "Kaspersky", "ESET-NOD32", "BitDefender", "Avast", "AVG",
    "Sophos", "Malwarebytes", "DrWeb", "Fortinet", "TrendMicro", "Symantec",
    "Avira", "GData", "Emsisoft",
]

DEFAULT_MAIN_ENGINES = [
    "Microsoft", "Kaspersky", "ESET-NOD32", "BitDefender", "Avast", "Sophos",
    "Malwarebytes", "DrWeb", "Fortinet", "TrendMicro",
]

DEFAULT_TRUSTED_PUBLISHERS = [
    "Microsoft Corporation", "Microsoft Windows", "NVIDIA Corporation",
    "Advanced Micro Devices, Inc.", "Advanced Micro Devices Inc.",
    "Intel Corporation", "Valve", "Valve Corp.", "Valve Corporation",
    "Epic Games Inc.", "Epic Games, Inc.", "Unity Technologies ApS",
    "Unity Technologies SF", "Audiokinetic Inc.", "Google LLC", "Discord Inc.",
]


@dataclass
class GeneralConfig:
    data_dir: str = "data"


@dataclass
class ScanConfig:
    extensions: list[str] = field(default_factory=lambda: list(DEFAULT_EXTENSIONS))
    detect_executables_by_content: bool = True
    no_sniff_extensions: list[str] = field(
        default_factory=lambda: list(DEFAULT_NO_SNIFF_EXTENSIONS)
    )
    exclude_dirs: list[str] = field(default_factory=list)
    max_file_size_mb: int = 650
    hash_workers: int = 4


@dataclass
class VirusTotalConfig:
    requests_per_minute: int = 4
    daily_limit: int = 500
    direct_upload_max_mb: int = 32
    not_found_cache_days: int = 7
    analysis_first_check_seconds: int = 90
    analysis_max_checks_per_run: int = 6
    request_timeout_seconds: int = 30
    upload_timeout_seconds: int = 900


@dataclass
class SignaturesConfig:
    enabled: bool = True
    skip_trusted_signed: bool = False
    trusted_publishers: list[str] = field(
        default_factory=lambda: list(DEFAULT_TRUSTED_PUBLISHERS)
    )


@dataclass
class VerdictConfig:
    critical_threshold: int = 10
    high_threshold: int = 3
    dangerous_keywords: list[str] = field(
        default_factory=lambda: list(DEFAULT_DANGEROUS_KEYWORDS)
    )
    crack_keywords: list[str] = field(default_factory=lambda: list(DEFAULT_CRACK_KEYWORDS))
    generic_keywords: list[str] = field(
        default_factory=lambda: list(DEFAULT_GENERIC_KEYWORDS)
    )
    reliable_engines: list[str] = field(
        default_factory=lambda: list(DEFAULT_RELIABLE_ENGINES)
    )


@dataclass
class ReportConfig:
    output_dir: str = "reports"
    open_html: bool = True
    csv_delimiter: str = ";"
    main_engines: list[str] = field(default_factory=lambda: list(DEFAULT_MAIN_ENGINES))


@dataclass
class DefenderConfig:
    report_only: bool = True


SECTIONS = {
    "general": GeneralConfig,
    "scan": ScanConfig,
    "virustotal": VirusTotalConfig,
    "signatures": SignaturesConfig,
    "verdict": VerdictConfig,
    "report": ReportConfig,
    "defender": DefenderConfig,
}


@dataclass
class Config:
    general: GeneralConfig = field(default_factory=GeneralConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    virustotal: VirusTotalConfig = field(default_factory=VirusTotalConfig)
    signatures: SignaturesConfig = field(default_factory=SignaturesConfig)
    verdict: VerdictConfig = field(default_factory=VerdictConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    defender: DefenderConfig = field(default_factory=DefenderConfig)
    source_path: Path | None = None

    def _resolve(self, value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else writable_base() / path

    @property
    def data_path(self) -> Path:
        return self._resolve(self.general.data_dir)

    @property
    def db_path(self) -> Path:
        return self.data_path / "vtscan.sqlite3"

    @property
    def logs_path(self) -> Path:
        return self.data_path / "logs"

    @property
    def lock_path(self) -> Path:
        return self.data_path / "vtscan.lock"

    @property
    def reports_path(self) -> Path:
        return self._resolve(self.report.output_dir)


def _check_type(section: str, key: str, value: object, default: object) -> None:
    """Comprueba que el valor del TOML tiene el mismo tipo que el valor por defecto."""
    where = f"[{section}] {key}"
    if isinstance(default, bool):
        ok = isinstance(value, bool)
        expected = "true o false"
    elif isinstance(default, int):
        ok = isinstance(value, int) and not isinstance(value, bool)
        expected = "un número entero"
    elif isinstance(default, str):
        ok = isinstance(value, str)
        expected = "un texto entre comillas"
    elif isinstance(default, list):
        ok = isinstance(value, list) and all(isinstance(v, str) for v in value)
        expected = "una lista de textos"
    else:
        ok, expected = True, ""
    if not ok:
        raise ConfigError(f"{where} debe ser {expected}")


def _normalize_ext(ext: str) -> str:
    ext = ext.strip().lower()
    return ext if ext.startswith(".") else "." + ext


def _normalize(cfg: Config) -> None:
    cfg.scan.extensions = sorted({_normalize_ext(e) for e in cfg.scan.extensions if e.strip()})
    cfg.scan.no_sniff_extensions = sorted(
        {_normalize_ext(e) for e in cfg.scan.no_sniff_extensions if e.strip()}
    )
    cfg.scan.exclude_dirs = [d.strip().lower() for d in cfg.scan.exclude_dirs if d.strip()]
    for name in ("dangerous_keywords", "crack_keywords", "generic_keywords"):
        words = getattr(cfg.verdict, name)
        setattr(cfg.verdict, name, [w.strip().lower() for w in words if w.strip()])


def _validate(cfg: Config) -> None:
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ConfigError(message)

    vt = cfg.virustotal
    require(vt.requests_per_minute >= 1, "[virustotal] requests_per_minute debe ser 1 o más")
    require(vt.daily_limit >= 1, "[virustotal] daily_limit debe ser 1 o más")
    require(1 <= vt.direct_upload_max_mb <= 32, "[virustotal] direct_upload_max_mb debe estar entre 1 y 32")
    require(vt.not_found_cache_days >= 0, "[virustotal] not_found_cache_days no puede ser negativo")
    require(vt.analysis_first_check_seconds >= 10, "[virustotal] analysis_first_check_seconds debe ser 10 o más")
    require(vt.analysis_max_checks_per_run >= 1, "[virustotal] analysis_max_checks_per_run debe ser 1 o más")
    require(vt.request_timeout_seconds >= 5, "[virustotal] request_timeout_seconds debe ser 5 o más")
    require(vt.upload_timeout_seconds >= 30, "[virustotal] upload_timeout_seconds debe ser 30 o más")
    require(1 <= cfg.scan.max_file_size_mb <= 650, "[scan] max_file_size_mb debe estar entre 1 y 650")
    require(1 <= cfg.scan.hash_workers <= 32, "[scan] hash_workers debe estar entre 1 y 32")
    require(cfg.scan.extensions != [], "[scan] extensions no puede estar vacía")
    require(len(cfg.report.csv_delimiter) == 1, "[report] csv_delimiter debe ser un solo carácter")
    require(cfg.verdict.high_threshold >= 1, "[verdict] high_threshold debe ser 1 o más")
    require(
        cfg.verdict.critical_threshold > cfg.verdict.high_threshold,
        "[verdict] critical_threshold debe ser mayor que high_threshold",
    )


def load_config(path: Path | None = None) -> tuple[Config, list[str]]:
    """Carga la configuración. Devuelve (config, avisos sobre opciones desconocidas)."""
    cfg = Config()
    warnings: list[str] = []
    config_path = path or DEFAULT_CONFIG_PATH
    if path is not None and not config_path.exists():
        raise ConfigError(f"No existe el archivo de configuración: {config_path}")
    if config_path.exists():
        try:
            # utf-8-sig: el Bloc de notas puede guardarlo con BOM
            data = tomllib.loads(config_path.read_text(encoding="utf-8-sig"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"{config_path}: {exc}") from exc
        for section_name, values in data.items():
            if section_name not in SECTIONS:
                warnings.append(f"Sección desconocida en la configuración: [{section_name}]")
                continue
            if not isinstance(values, dict):
                raise ConfigError(f"[{section_name}] debe ser una sección")
            section = getattr(cfg, section_name)
            valid = {f.name for f in fields(section)}
            for key, value in values.items():
                if key not in valid:
                    warnings.append(f"Opción desconocida en la configuración: [{section_name}] {key}")
                    continue
                _check_type(section_name, key, value, getattr(section, key))
                setattr(section, key, value)
        cfg.source_path = config_path
    _normalize(cfg)
    _validate(cfg)
    return cfg, warnings
