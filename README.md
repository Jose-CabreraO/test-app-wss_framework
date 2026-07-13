# WSS Framework — App de Escritorio

App de escritorio para Windows que combina:

- **Calculadora Demo**: la misma calculadora interactiva de la landing comercial, para explicar el modelo WSS con escenarios de ejemplo (E1–E5, E-AN).
- **Mis Redes**: escaneo real de las redes Wi-Fi visibles desde este equipo (`netsh wlan show networks`), con el modelo WSS aplicado a cada red detectada.

## Requisitos

- Windows 10/11 (el escaneo real solo funciona en Windows; en otros sistemas operativos la pestaña "Mis Redes" ofrece datos de ejemplo para poder probar la interfaz).
- Python 3.9 o superior.

## Instalación

```bash
pip install -r requirements.txt
```

## Ejecución

```bash
python app.py
```

Se abre una ventana nativa con la aplicación. La pestaña "Calculadora Demo" está disponible siempre; la pestaña "Mis Redes" detecta automáticamente si el escaneo real está disponible en este sistema.

## Estructura

```text
wss-desktop-app/
├── app.py              ← punto de entrada, crea la ventana y expone la API a JS
├── wss_engine.py        ← motor de escaneo (netsh) y cálculo del modelo WSS
├── index.html           ← interfaz completa (landing demo + vista "Mis Redes")
└── requirements.txt
```

## Cómo se conecta Python con la interfaz

`app.py` crea una ventana con `pywebview` y expone una clase `WssApi` al JavaScript de `index.html` a través de `window.pywebview.api`. El frontend llama:

- `scan_networks()` — ejecuta el escaneo real y devuelve los resultados con el WSS calculado.
- `scan_networks_demo()` — devuelve datos de ejemplo (útil en sistemas no-Windows o para una demo controlada).
- `get_platform_info()` — informa si el escaneo real está disponible en este sistema.
- `export_json(resultados)` — guarda los resultados actuales como un reporte `.json` en el disco.

Toda la lógica de parseo de `netsh` y el cálculo del modelo WSS vive en `wss_engine.py`, que es independiente de la interfaz y puede probarse por separado:

```bash
python wss_engine.py
```

## Empaquetado como ejecutable (.exe)

Para distribuir la app sin que el cliente necesite instalar Python, usar PyInstaller en una máquina Windows:

```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed ^
  --add-data "index.html;." ^
  --name "WSS-Framework" ^
  app.py
```

El ejecutable resultante queda en `dist/WSS-Framework.exe`.

## Alcance y limitaciones

- El escaneo es pasivo: solo lee parámetros que los puntos de acceso ya transmiten públicamente (SSID, BSSID, autenticación, cifrado, intensidad de señal). No ejecuta pruebas activas ni intercepta tráfico, en línea con el alcance definido en la tesis (secciones 2.8 y 3.4).
- La detección de "condición anómala" (mismo SSID con BSSID distinto) es heurística y preliminar; indica un patrón que requiere revisión técnica, no confirma un ataque.
- La intensidad de señal que reporta `netsh` viene como porcentaje, no en dBm. Se aplica una aproximación estándar (`rssi_dbm = (pct / 2) - 100`) para clasificar el factor de exposición; no es una medición de precisión de laboratorio.
