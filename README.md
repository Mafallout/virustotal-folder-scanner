# vtscan

Programa para Windows que revisa una carpeta en busca de malware con VirusTotal. Busca los ejecutables y scripts que hay dentro, pregunta a VirusTotal si algún antivirus los detecta y te da un informe con los archivos ordenados de más a menos peligroso.

Está pensado para carpetas grandes, como programas descargados de fuentes no oficiales, y funciona con la cuenta gratuita de VirusTotal.

## Instalación

Necesitas Windows 10 u 11 y Python 3.11 o superior. En la carpeta del proyecto:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

También necesitas una clave de VirusTotal, que es gratis. Crea una cuenta en [virustotal.com](https://www.virustotal.com), copia la API key de tu perfil y guárdala con este comando (después abre una terminal nueva):

```powershell
setx VT_API_KEY "tu_clave"
```

Si lo prefieres, crea un archivo `.env` junto a `vtscan.py` con la línea `VT_API_KEY=tu_clave`. Ese archivo no se sube al repositorio.

## Uso

```powershell
.\.venv\Scripts\python.exe vtscan.py "D:\Descargas\Programa"
```

Cuando termina, abre el informe en el navegador y lo guarda también en CSV para abrirlo con Excel.

Opciones que te pueden venir bien:

- `--dry-run`: calcula cuánto tardaría, sin hacer ninguna consulta.
- `--defender`: pasa antes Microsoft Defender por la carpeta. Solo avisa.
- `--upload`: sube a VirusTotal los archivos que no conoce. Antes te enseña la lista y te pregunta.
- `--all-files`: revisa todos los archivos, no solo los ejecutables.

Con `-h` ves todas.

## Por qué puede tardar

La versión gratuita de VirusTotal deja hacer 4 consultas por minuto y 500 al día. Una carpeta con 250 ejecutables tarda alrededor de una hora la primera vez. El programa espera solo y guarda cada respuesta para no repetir consultas.

Si se acaban las consultas del día, guarda lo que lleva. Al día siguiente sigues con `--resume`, o lanzas el análisis con `--wait` para que espere y continúe solo.

## Cómo leer el informe

Cada archivo sale con un nivel y el motivo:

- Crítico: muchos antivirus lo detectan o varios lo señalan como malware peligroso, por ejemplo un ladrón de contraseñas o un ransomware. No lo ejecutes.
- Alto: varios antivirus lo detectan. Míralo en VirusTotal antes de usarlo.
- Medio y Bajo: una o dos detecciones, o detecciones genéricas. Muchas veces son falsos positivos, sobre todo en herramientas, parches y mods.
- Desconocido: VirusTotal no lo tiene. No quiere decir que sea seguro.
- Limpio: ningún antivirus lo detecta.

También pueden salir archivos pendientes (aún sin consultar) u omitidos (no se pudieron revisar, por ejemplo por ser demasiado grandes). Desde el informe puedes abrir la página de cada archivo en VirusTotal.

Una advertencia sobre `--upload`: lo que subes a VirusTotal lo pueden descargar otros investigadores, así que no subas archivos personales.

## Configuración

En `config.toml` puedes cambiar qué extensiones se revisan, qué carpetas se saltan o cuántas detecciones hacen falta para cada nivel. Cada opción lleva un comentario.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
```

Funcionan sin conexión y sin clave.
