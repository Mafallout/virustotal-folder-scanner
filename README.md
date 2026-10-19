# vtscan

Analiza una carpeta en busca de malware con la API v3 gratuita de VirusTotal. Está pensado para carpetas grandes, como software descargado de fuentes no oficiales: calcula el SHA-256 de cada ejecutable, pregunta a VirusTotal si lo conoce y genera un informe HTML y CSV ordenado de más a menos peligroso.

El plan gratuito solo permite **4 peticiones por minuto y 500 al día**, así que el programa está hecho para no desperdiciar ninguna: guarda todo en una caché local, consulta primero lo más arriesgado y, si se acaba la cuota, guarda el progreso para seguir al día siguiente.

## Qué hace

- Recorre la carpeta (y sus subcarpetas) y se queda con los ejecutables y scripts: `.exe .dll .sys .msi .bat .cmd .ps1 .vbs .js .scr .com .jar` y otros menos conocidos que también ejecutan código (`.asi .cpl .ocx .pif .hta .wsf .vbe .jse .psm1 .lnk .msp`). Con `--all-files` analiza todo.
- Detecta **ejecutables camuflados**: archivos con otra extensión (por ejemplo `.dat`) que en realidad son un `.exe` o una `.dll`.
- Calcula el SHA-256 y elimina duplicados. Recuerda el hash de cada archivo, así que al volver a escanear no relee los gigas que no han cambiado.
- Comprueba la **firma digital** de cada ejecutable (gratis, en tu PC): válida, sin firma o rota (el archivo se modificó después de firmarlo).
- Consulta cada hash en VirusTotal (`GET /files/{hash}`) una sola vez: el resultado queda guardado en una base de datos SQLite.
- Con `--upload`, sube los archivos que VirusTotal no conoce, pero antes te enseña la lista y te pregunta.
- Con `--defender`, antes de nada analiza la carpeta con Microsoft Defender, en modo solo informe.
- Clasifica cada archivo en niveles (Crítico, Alto, Medio, Bajo...) distinguiendo las detecciones genéricas o de herramientas (HackTool, PUA), que a menudo son falsos positivos, del malware grave (robo de contraseñas, troyanos de acceso remoto, mineros, ransomware).

## Requisitos

- Windows 10 u 11.
- Python 3.11 o superior (probado con 3.12).
- Una cuenta gratuita de VirusTotal para obtener la API key.

## Instalación

Desde la carpeta del proyecto, en PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

No hace falta activar el entorno virtual: basta con usar `.\.venv\Scripts\python.exe` en lugar de `python`. Si prefieres activarlo y PowerShell se queja de que la ejecución de scripts está deshabilitada, usa `cmd` y `.venv\Scripts\activate.bat`.

## La API key (gratis)

1. Crea una cuenta en [virustotal.com](https://www.virustotal.com). Solo pide un correo y no pide tarjeta.
2. En tu perfil, entra en **API key** y cópiala.
3. Guárdala en la variable de entorno `VT_API_KEY` (solo una vez) y abre una terminal nueva:

```powershell
setx VT_API_KEY "tu_clave"
```

Para probar solo en la terminal actual: `$env:VT_API_KEY = "tu_clave"`. También puedes crear un archivo `.env` junto a `vtscan.py` con la línea `VT_API_KEY=tu_clave`.

La clave nunca va en el código ni en el repositorio: `.gitignore` excluye `.env`, la caché y los informes. El programa no la muestra ni la escribe en los logs.

## Uso

```powershell
.\.venv\Scripts\python.exe vtscan.py "D:\Descargas\Programa"
```

Ejemplos:

```powershell
# Ver cuánto costaría sin gastar cuota (no consulta VirusTotal)
.\.venv\Scripts\python.exe vtscan.py "D:\Descargas" --dry-run

# Pasar antes Defender y ofrecer subir lo desconocido
.\.venv\Scripts\python.exe vtscan.py "D:\Descargas\Programa" --defender --upload

# Seguir con el último escaneo que se quedó a medias y, si se acaba la cuota, esperar y continuar solo
.\.venv\Scripts\python.exe vtscan.py --resume --wait
```

| Opción | Qué hace |
|---|---|
| `--upload` | Sube los archivos que VirusTotal no conoce. Antes muestra la lista y puedes elegir todos, ninguno o algunos (`1,3,5-8`). |
| `--defender` | Antes de nada, analiza la carpeta con Microsoft Defender (`MpCmdRun.exe`) y muestra el resultado. No necesita administrador. |
| `--all-files` | Analiza todos los archivos, no solo ejecutables y scripts. Ojo: en una carpeta grande pueden ser miles (ver más abajo). |
| `--resume` | Reanuda el último escaneo sin terminar, sin escribir la ruta. |
| `--wait` | Si se acaba la cuota diaria, espera al reinicio y sigue solo. |
| `--dry-run` | Recorre y calcula hashes, y dice cuántas consultas y días costaría. No gasta cuota. |
| `--refresh` | Vuelve a consultar aunque ya haya un resultado guardado. |
| `--config RUTA` | Usa otro archivo de configuración. |
| `--no-open` | No abre el informe al terminar. |
| `-v` | Log más detallado en `data\logs`. |

También acepta un archivo suelto en lugar de una carpeta.

Códigos de salida: `0` sin hallazgos de nivel Alto o superior, `1` con hallazgos, `2` error, `3` incompleto (queda algo pendiente).

## Cuota y reanudación

- **4 peticiones por minuto**: el programa espera solo (verás una cuenta atrás). Una carpeta con 250 ejecutables son unos 63 minutos la primera vez.
- **500 peticiones al día**, que se reinician a las 00:00 UTC (las 02:00 en horario de verano y la 01:00 en invierno).
- Antes de consultar te dice cuántas peticiones hacen falta, cuántas te quedan hoy y cuánto tardará.
- Se consulta primero lo más arriesgado: ejecutables camuflados, scripts, ejecutables sin firma o con la firma rota. Lo firmado por fabricantes conocidos (Microsoft, NVIDIA, Valve, Epic...) va al final.
- Si se acaba la cuota, se guarda todo y se genera un informe parcial. Para seguir, repite el mismo comando o usa `--resume`. No se vuelve a leer ningún archivo que no haya cambiado ni se repite ninguna consulta.
- La caché crece con el uso: muchas DLL se repiten entre programas (librerías de Microsoft, NVIDIA...), así que cada carpeta nueva cuesta menos.
- Preguntar por un archivo que VirusTotal no conoce también gasta una petición. Comprobar la cuota al arrancar no gasta ninguna.
- Un hash que VirusTotal no conocía se vuelve a consultar pasados 7 días, por si alguien lo ha subido mientras tanto.

Sobre `--all-files`: cada imagen, audio o archivo de datos cuesta una petición. Una carpeta con 5.000 archivos son 10 días de cuota. Si lo que pides no cabe en la cuota de hoy, el programa te lo dice y pregunta antes de empezar. Para buscar malware, el modo normal es suficiente: el malware tiene que ser ejecutable para hacer algo, y los ejecutables camuflados se detectan por su contenido.

## Subir archivos

- Hasta 32 MB se suben directamente; de 32 a 650 MB, con una URL de subida especial. Los de más de 650 MB no se pueden analizar y salen como omitidos.
- Tras subir, el análisis tarda unos minutos. El programa lo recoge sin malgastar peticiones y, si cierras antes, lo recoge en la siguiente ejecución.
- **Importante**: lo que subes queda disponible para la comunidad de VirusTotal (investigadores y empresas con cuenta de pago pueden descargarlo). No subas nunca documentos personales. Por eso siempre se pide confirmación con la lista delante.

## Defender

`--defender` lanza `MpCmdRun.exe -Scan -ScanType 3 -File <carpeta> -DisableRemediation`:

- Solo informa: no mueve nada a cuarentena. Además entra en los archivos comprimidos e ignora las exclusiones de Defender.
- Lo que encuentra aparece al principio y dentro del informe.
- Aunque Defender esté en modo solo informe, su protección en tiempo real puede bloquear un archivo detectado en cuanto el programa intenta leerlo para calcular el hash. Ese archivo sale en el informe como "Defender bloqueó la lectura" con nivel Alto.
- Si tienes otro antivirus, Defender puede estar desactivado; el programa avisa y continúa con VirusTotal.

## Cómo interpretar los resultados

Cada fila muestra cuántos motores lo marcan como **malicioso / sospechoso de un total** (por ejemplo `3 / 0 de 72`), la etiqueta, lo que dicen los antivirus principales y el **motivo** del nivel.

| Nivel | Qué significa | Qué hacer |
|---|---|---|
| **Crítico** | 10 o más motores, o al menos 2 apuntan a malware grave: robo de contraseñas (RedLine, Lumma, Vidar), acceso remoto (AsyncRAT, Remcos), mineros (XMRig), ransomware (STOP/Djvu, frecuente en software de fuentes no oficiales), puertas traseras o virus que infectan otros ejecutables (Sality, Virut). | No lo ejecutes. Borra la carpeta o déjala en cuarentena. Si ya lo ejecutaste, mira más abajo. |
| **Alto** | 3 a 9 motores, o 10 o más pero todos con etiquetas de herramientas o software no deseado (HackTool, PUA, RiskWare). | Revisa el informe de VirusTotal antes de ejecutarlo (pestañas *Detection*, *Behavior* y *Community*). |
| **Medio** | 1 o 2 motores con una etiqueta concreta, o 3 a 9 solo con etiquetas de herramientas o software no deseado. | Habitual en herramientas, parches y mods. Decide tú; mira qué motores lo detectan. |
| **Bajo** | 1 o 2 motores con detecciones genéricas o de aprendizaje automático. | Casi siempre falso positivo (`Wacatac.B!ml` es el clásico). |
| **Desconocido** | VirusTotal no tiene ese archivo. | **No significa que sea seguro.** Mira sus señales y, si te preocupa, súbelo con `--upload`. |
| **Pendiente** | Aún sin consultar (cuota) o análisis en curso. | Reanuda con `--resume`. |
| **Limpio** | Ningún motor lo detecta. | Buena señal, pero no una garantía: el malware muy nuevo puede no estar detectado todavía. |
| **Omitido** | Demasiado grande, sin permisos o en la nube sin descargar. | Revísalo por otros medios si te interesa. |

**Señales locales** (no gastan cuota):

- *firma rota*: el archivo se modificó después de firmarlo. Puede deberse a un parche o un mod, pero también es justo donde se inyecta malware.
- *ejecutable camuflado*: tiene contenido de `.exe`/`.dll` con otra extensión. Muy sospechoso fuera de casos conocidos.
- *doble extensión* (`factura.pdf.exe`), *nombre con carácter invertido* y *oculto*: trucos clásicos para engañar.
- *firmado por fabricante conocido*: firma válida de Microsoft, NVIDIA, Valve, etc.

**En software modificado es habitual** (parches, mods, herramientas de terceros) que algunas DLL o el ejecutable principal salgan con detecciones de tipo HackTool o PUA y que tengan la firma rota. **No es normal**: familias de malware grave, ejecutables camuflados, scripts que lanzan PowerShell, archivos ocultos o ejecutables en carpetas donde no pintan nada (por ejemplo, en la carpeta de vídeos).

**Si ya ejecutaste algo Crítico**: desconecta el PC de internet, pasa un análisis completo de Defender (o el análisis sin conexión de Microsoft Defender), y desde **otro dispositivo** cambia las contraseñas importantes (correo, bancos, Steam, Discord) y activa la verificación en dos pasos. Los ladrones de contraseñas se llevan también las sesiones abiertas del navegador.

## Informes

Se guardan en `reports\` con el nombre de la carpeta y la fecha:

- **HTML**: funciona sin internet. Tiene filtros por nivel, buscador, ordenación por columnas, modo oscuro, resumen por subcarpeta (útil si escaneas una carpeta con muchos programas) y enlace al informe de cada archivo en VirusTotal. Haz clic en un hash para copiarlo.
- **CSV**: separado por `;` y en UTF-8 con BOM, para que Excel en español lo abra bien a la primera.

## Configuración

Todo está en `config.toml`, comentado: extensiones, carpetas excluidas, hilos para calcular hashes (pon 1 o 2 si la carpeta está en un disco mecánico), fabricantes de confianza, umbrales de los niveles, palabras clave de las etiquetas y motores principales del informe. Si borras una opción, se usa el valor por defecto.

## Problemas comunes

- **"No encuentro la API key"**: después de `setx` hay que abrir una terminal nueva.
- **"VirusTotal rechaza la API key"**: revisa que la copiaste entera y que activaste la cuenta desde el correo.
- **La ruta da error**: escríbela entre comillas y sin barra final (`"D:\Descargas\X"`, no `"D:\Descargas\X\"`). El programa intenta corregirlo, pero mejor así.
- **"Ya hay otro vtscan en marcha"**: solo se permite una ejecución a la vez, para no pasarse de las 4 peticiones por minuto.
- **Va lento al calcular hashes**: en discos mecánicos, baja `hash_workers` a 1 o 2.
- **Los logs** están en `data\logs` (nunca incluyen la clave).

## Coste

0 €. La API pública de VirusTotal es gratuita y no cobra por pasarse de la cuota: simplemente rechaza las peticiones hasta el día siguiente. Python y las librerías son libres, y Defender viene con Windows. Todo se queda en tu PC. Lo único a tener en cuenta: con `--upload` en una conexión de datos limitada, subir archivos grandes gasta datos.

## Límites de uso

La API pública es solo para uso personal y no comercial (condiciones de VirusTotal). Una detección no es una prueba, y que ningún antivirus detecte algo tampoco garantiza que sea seguro.

## Estructura

```
vtscan.py              punto de entrada
vtscanner\
  cli.py               argumentos y códigos de salida
  pipeline.py          orquesta las fases del escaneo
  config.py            config.toml y valores por defecto
  walker.py            recorrido, filtros y señales locales
  hashing.py           SHA-256 en paralelo con caché
  signatures.py        firmas Authenticode (PowerShell por lotes)
  db.py                SQLite: caché, cuota, escaneos y subidas
  ratelimit.py         4 por minuto y cuota diaria
  vtclient.py          cliente de la API v3 (requests)
  defender.py          Microsoft Defender
  verdict.py           niveles de gravedad
  report.py            informes HTML y CSV
  ui.py                consola (rich); una futura interfaz gráfica heredaría de BaseUI
  winutils.py          utilidades de Windows
tests\                 pruebas sin red
```

Se usa `requests` y no la librería oficial `vt-py` porque `vt-py` gasta una petición extra en cada subida y, al esperar un análisis, consulta cada 20 segundos sin límite, lo que agota enseguida las 4 peticiones por minuto del plan gratuito.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
```

No necesitan la API key ni conexión: las respuestas de VirusTotal están simuladas.
