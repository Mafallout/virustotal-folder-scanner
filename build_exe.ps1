# Genera dist\vtscan-<versión>-windows.zip: una carpeta con vtscan.exe (la ventana).
# Uso, desde la carpeta del proyecto y con el entorno .venv creado:
#   .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
#   powershell -ExecutionPolicy Bypass -File .\build_exe.ps1

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$version = (& $python -c "from vtscanner import __version__; print(__version__)").Trim()

function Remove-Folder([string]$path) {
    # Defender puede tener los archivos recién creados abiertos un momento: se reintenta
    for ($i = 0; $i -lt 5 -and (Test-Path $path); $i++) {
        try { Remove-Item $path -Recurse -Force -ErrorAction Stop } catch { Start-Sleep -Seconds 2 }
    }
    if (Test-Path $path) { throw "No se pudo borrar $path (¿está abierto vtscan.exe?)" }
}

Write-Host "Empaquetando vtscan $version"
Remove-Folder "build"
Remove-Folder "dist"
New-Item -ItemType Directory "build" | Out-Null

# Icono dibujado con Qt (sin imágenes de terceros)
& $python -c "import sys; from pathlib import Path; from PySide6.QtGui import QGuiApplication; app = QGuiApplication(sys.argv); from vtscanner.gui.theme import save_ico; sys.exit(0 if save_ico(Path('build/vtscan.ico')) else 1)"
if ($LASTEXITCODE -ne 0) { throw "No se pudo crear el icono" }

# Nombre, versión y autor en las propiedades del .exe: sin ellos los antivirus lo ven más sospechoso
$numbers = (($version.Split(".") + @("0", "0", "0"))[0..3]) -join ", "
$versionInfo = @"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($numbers), prodvers=($numbers)),
  kids=[
    StringFileInfo([StringTable('0C0A04B0', [
      StringStruct('CompanyName', 'Mafallout'),
      StringStruct('FileDescription', 'vtscan, revisa carpetas con VirusTotal'),
      StringStruct('FileVersion', '$version'),
      StringStruct('InternalName', 'vtscan'),
      StringStruct('LegalCopyright', 'Mafallout'),
      StringStruct('OriginalFilename', 'vtscan.exe'),
      StringStruct('ProductName', 'vtscan'),
      StringStruct('ProductVersion', '$version')])]),
    VarFileInfo([VarStruct('Translation', [0x0C0A, 1200])])
  ]
)
"@
[IO.File]::WriteAllText((Join-Path $PSScriptRoot "build\version.txt"), $versionInfo)

# Carpeta con el .exe (onedir): arranca rápido y da menos falsos positivos en antivirus.
# Rutas absolutas: con --specpath, PyInstaller resuelve las relativas desde build\
& $python -m PyInstaller --noconfirm --clean --windowed --onedir `
    --name vtscan --icon (Join-Path $PSScriptRoot "build\vtscan.ico") `
    --version-file (Join-Path $PSScriptRoot "build\version.txt") `
    --distpath dist --workpath "build\pyinstaller" --specpath build `
    --exclude-module tkinter --exclude-module pytest --exclude-module pytestqt `
    (Join-Path $PSScriptRoot "vtscan_gui.pyw")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller ha fallado" }

# Sobran el renderizador OpenGL por software (la ventana no usa OpenGL, unos 20 MB)
# y las traducciones de Qt a otros idiomas
$qt = "dist\vtscan\_internal\PySide6"
if (Test-Path "$qt\opengl32sw.dll") { Remove-Item "$qt\opengl32sw.dll" }
Get-ChildItem "$qt\translations" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '_es\.qm$' } | Remove-Item

# Junto al .exe: la configuración (editable), el README y las licencias.
# Nunca se copian .env, data ni reports: son datos de quien lo usa.
Copy-Item config.toml, README.md, LICENCIAS-TERCEROS.txt "dist\vtscan\"

$zip = "dist\vtscan-$version-windows.zip"
Compress-Archive -Path "dist\vtscan" -DestinationPath $zip
$size = (Get-ChildItem "dist\vtscan" -Recurse | Measure-Object Length -Sum).Sum / 1MB
Write-Host ("Listo: {0} ({1:N0} MB descomprimido)" -f $zip, $size)
