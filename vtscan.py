"""vtscan: analiza una carpeta en busca de malware con la API v3 gratuita de VirusTotal.

Uso:  python vtscan.py "C:\\ruta\\carpeta" [--upload] [--defender] [--all-files]
Ayuda: python vtscan.py -h
"""

import sys

if sys.version_info < (3, 11):
    sys.exit("vtscan necesita Python 3.11 o superior.")

from vtscanner.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
