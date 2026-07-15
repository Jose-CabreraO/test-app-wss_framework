# SPRINT_01_RESULTADOS

## Identificacion

| Campo | Valor |
| --- | --- |
| Sprint | Sprint 1: Correccion del parser de netsh y creacion de pruebas automatizadas con evidencias reales anonimizadas |
| Repositorio | `https://github.com/atreus-oss/test-app-wss_framework` |
| Copia local utilizada | `C:\Users\Jose\AppData\Local\Temp\test-app-wss_framework-sprint-01` |
| Commit base | `489d909` |
| Rama utilizada | `sprint-01-parser-fixtures` |
| Fecha de ejecucion | 2026-07-15 |

## Archivos modificados

- `wss_engine.py`

## Archivos agregados

- `requirements-dev.txt`
- `tests/test_wss_engine.py`
- `tests/fixtures/netsh/es_wpa3_ccmp.txt`
- `tests/fixtures/netsh/es_wpa2_ccmp.txt`
- `tests/fixtures/netsh/es_wpa_tkip.txt`
- `tests/fixtures/netsh/es_open_none.txt`
- `tests/fixtures/netsh/es_unknown.txt`
- `tests/fixtures/netsh/en_wpa2_ccmp.txt`

## Fixtures agregados

| Fixture | Origen | Uso |
| --- | --- | --- |
| `es_wpa3_ccmp.txt` | Copia anonimizada de `escenario_wpa3.txt` | Prueba WPA3-Personal con CCMP |
| `es_wpa2_ccmp.txt` | Copia anonimizada de `escenario_wpa2_aes.txt` | Prueba WPA2-Personal con CCMP/AES |
| `es_wpa_tkip.txt` | Copia anonimizada de `escenario_wpa2_tkip.txt` | Prueba WPA-Personal/TKIP observado por Windows |
| `es_open_none.txt` | Copia anonimizada de `escenario_open.txt` | Prueba red abierta con cifrado ninguno |
| `es_unknown.txt` | Fixture sintetico controlado | Prueba de valores no reconocidos |
| `en_wpa2_ccmp.txt` | Fixture sintetico controlado | Prueba de etiquetas en ingles |

No se utilizaron como prueba experimental valida:

- `escenario_WEP.txt`: se mantiene como limitacion experimental si WEP no puede instanciarse fisicamente.
- `escenario_AN.txt`: no contiene mas de un BSSID, por lo que no valida una condicion anomala por multiples BSSID.

## Comportamiento anterior

- El parser reconocia un conjunto limitado de etiquetas de `netsh`.
- Las etiquetas en ingles `Authentication` y `Encryption` no se interpretaban correctamente.
- Las variantes sin tilde o con etiquetas abreviadas podian quedar sin reconocer.
- Los valores desconocidos de autenticacion se convertian automaticamente en `OPEN`.
- Los valores desconocidos de cifrado se convertian automaticamente en `NONE`.
- Un resultado con datos no interpretados podia recibir score y clasificacion definitiva.

## Comportamiento corregido

- El parser acepta etiquetas en espanol con y sin tilde.
- El parser acepta etiquetas en ingles para autenticacion, cifrado, senal, canal, banda y tipo de radio.
- Se normaliza Unicode mediante NFC y se tolera BOM al inicio del texto.
- Se conservan `auth_raw` y `cipher_raw`.
- Los valores no reconocidos se normalizan como `UNKNOWN`.
- Si autenticacion o cifrado son `UNKNOWN`, el resultado queda como:
  - `evaluation_status = "INCOMPLETE"`
  - `wss_score = None`
  - `classification = "NO_EVALUABLE"`
- Los resultados incompletos conservan los datos observados y no generan conclusion definitiva.
- Los campos `band`, `radio_type`, `mfp_required` y `details` se agregan como informativos.
- Los resultados incompletos no rompen el ordenamiento.

## Tabla de casos probados

| Caso | Fixture | Resultado esperado | Estado |
| --- | --- | --- | --- |
| WPA3-Personal con CCMP | `es_wpa3_ccmp.txt` | `SAE`, `CCMP`, senal 99 %, canal 6, banda 2,4 GHz, MFP requerido 1, evaluacion completa | Aprobado |
| WPA2-Personal con CCMP/AES | `es_wpa2_ccmp.txt` | `WPA2-PSK`, `CCMP`, evaluacion completa | Aprobado |
| WPA-Personal con TKIP | `es_wpa_tkip.txt` | `WPA-PSK`, `TKIP`, no clasificado como WPA2, evaluacion completa | Aprobado |
| Red abierta | `es_open_none.txt` | `OPEN`, `NONE`, reconocimiento de `Abierta` y `Ninguna`, evaluacion completa | Aprobado |
| Valores desconocidos | `es_unknown.txt` | `UNKNOWN`, evaluacion incompleta, sin score definitivo | Aprobado |
| Salida en ingles | `en_wpa2_ccmp.txt` | `Authentication`, `Encryption`, `Signal`, `Channel` interpretados | Aprobado |
| Regresion demo | Datos demo internos | `evaluate_networks_demo()` sigue ejecutandose | Aprobado |
| Ordenamiento | Fixture mixto completo/incompleto | Resultados incompletos no provocan errores | Aprobado |
| Importacion | Modulo `wss_engine` | Importacion correcta | Aprobado |

## Resultado de py_compile

Comando ejecutado:

```powershell
python -m py_compile app.py wss_engine.py
```

Resultado:

```text
Sin errores.
```

Tambien se ejecuto con el runtime Python empaquetado de Codex:

```powershell
C:\Users\Jose\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m py_compile app.py wss_engine.py
```

Resultado:

```text
Sin errores.
```

## Resultado de pytest

Comando ejecutado:

```powershell
C:\Users\Jose\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m pytest -q
```

Resultado:

```text
.........                                                                [100%]
9 passed in 0.06s
```

## Dependencias

Se agrego `requirements-dev.txt` con:

```text
pytest>=8.0
```

No se incorporaron dependencias adicionales al proyecto.

## Correcciones realizadas

- Parser basado en division de campos `etiqueta: valor` en lugar de expresiones regulares estrechas.
- Normalizacion de etiquetas con tolerancia a acentos, BOM y variantes en ingles/espanol.
- Normalizacion explicita de autenticacion y cifrado.
- Tratamiento de valores no reconocidos como `UNKNOWN`.
- Estado `INCOMPLETE` para evaluaciones no concluyentes.
- Ordenamiento tolerante a `wss_score = None`.
- Pruebas automatizadas con fixtures reales anonimizados y casos sinteticos controlados.

## Limitaciones pendientes

- No se ejecuto escaneo real de redes.
- No se modifico la interfaz `index.html`.
- No se implemento exportacion PDF.
- No se implemento comparacion antes/despues.
- No se modifico la deteccion de anomalias.
- No se modificaron pesos, formula WSS ni umbrales de clasificacion.
- WEP queda pendiente como escenario fisico o como escenario no instanciado.
- El archivo AN revisado no valida una condicion anomala porque no contiene mas de un BSSID.
- La validacion completa del sistema requiere pruebas controladas adicionales y revision academica.

## Confirmacion de alcance

- No se modifico formula WSS.
- No se modificaron pesos WSS.
- No se modificaron umbrales de clasificacion.
- No se modifico `index.html`.
- No se implemento PDF.
- No se ejecuto escaneo real.
- No se realizo commit.
- No se realizo push.
- No se modificaron LaTeX, BibTeX ni PDF de la tesis.

## Revision final del Sprint 1

Revision ejecutada sobre la rama local `sprint-01-parser-fixtures`.

### Comandos ejecutados

| Comando | Resultado |
| --- | --- |
| `git diff --check` | Sin errores de espacios ni formato. Solo se informo la advertencia de Git sobre posible conversion LF/CRLF en `wss_engine.py`. |
| `python -m py_compile app.py wss_engine.py` | Sin errores. |
| `python -m pytest -q` | `9 passed in 0.02s`. |
| `python -m pytest -q -vv` | `9 passed in 0.02s`. |

### Tabla resumida de fixtures

| Fixture | SSID | auth_raw | auth_key | cipher_raw | cipher_key | signal_pct | channel | band | radio_type | mfp_required | evaluation_status | wss_score | classification |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `es_wpa3_ccmp.txt` | LAB-WPA3 | WPA3-Personal | SAE | CCMP | CCMP | 99 | 6 | 2,4 GHz | 802.11g | 1 | COMPLETE | 1.75 | BAJO |
| `es_wpa2_ccmp.txt` | LAB-WPA2-AES | WPA2-Personal | WPA2-PSK | CCMP | CCMP | 99 | 6 | 2,4 GHz | 802.11g | None | COMPLETE | 2.35 | BAJO |
| `es_wpa_tkip.txt` | LAB-WPA2-TKIP | WPA-Personal | WPA-PSK | TKIP | TKIP | 99 | 6 | 2,4 GHz | 802.11g | None | COMPLETE | 6.3 | ALTO |
| `es_open_none.txt` | LAB-OPEN | Abierta | OPEN | Ninguna | NONE | 99 | 6 | 2,4 GHz | 802.11g | None | COMPLETE | 7.7 | CRITICO |
| `es_unknown.txt` | LAB-UNKNOWN | Metodo-No-Reconocido | UNKNOWN | Cifrado-No-Reconocido | UNKNOWN | 80 | 11 | 2,4 GHz | 802.11n | None | INCOMPLETE | None | NO_EVALUABLE |
| `en_wpa2_ccmp.txt` | LAB-EN-WPA2 | WPA2-Personal | WPA2-PSK | CCMP | CCMP | 88 | 36 | 5 GHz | 802.11ac | None | COMPLETE | 2.35 | BAJO |

### Verificaciones especificas

- Ningun fixture real valido fue clasificado accidentalmente como `UNKNOWN`.
- `es_unknown.txt` no recibio score y quedo como `NO_EVALUABLE`.
- `OPEN/NONE` fue reconocido explicitamente desde `Abierta` y `Ninguna`.
- `WPA-Personal/TKIP` no fue convertido en WPA2.
- Los resultados incompletos quedaron despues de los completos en el ordenamiento.
- No se observaron datos reales sensibles evidentes en los fixtures: los SSID usan prefijo `LAB-` y los BSSID aparecen como valores anonimizados o de laboratorio.
- `git diff --check` no reporto errores de espacios ni formato.

### Compatibilidad con index.html

Se reviso la interfaz sin modificarla. Existe un riesgo de integracion pendiente: `index.html` asume que `net.wss_score` siempre es numerico y utiliza `net.wss_score.toFixed(1)` en la renderizacion de tarjetas y detalle.

Si el backend entrega un resultado incompleto con `wss_score = None`, en JavaScript llegaria como `null` y podria producir un error al ejecutar `toFixed(1)`. Este riesgo no se corrigio en Sprint 1 porque la interfaz `index.html` estaba fuera del alcance indicado.

### Defectos encontrados

- No se encontraron defectos criticos en `wss_engine.py` ni en las pruebas automatizadas.
- Se encontro un riesgo de integracion en `index.html` para resultados incompletos con `wss_score = None`.

### Recomendacion final

Recomendacion: APROBAR el Sprint 1 para commit, con la condicion de registrar como tarea inmediata del siguiente sprint la adaptacion de `index.html` para manejar resultados `INCOMPLETE` sin llamar `toFixed` sobre valores `null`.
