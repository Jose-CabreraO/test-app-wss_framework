# SPRINT_02_RESULTADOS

## Identificacion

| Campo | Valor |
| --- | --- |
| Sprint | Sprint 2: Integracion de fuentes de entrada, manejo visual de evaluaciones incompletas y exportacion JSON trazable |
| Commit base | `239b0ace8188a10952951ff4309a9a49ba2fccc2` |
| Rama | `sprint-02-input-traceability` |
| Estado | Implementado para revision, sin commit y sin push |

## Archivos modificados

- `app.py`
- `index.html`
- `wss_engine.py`
- `tests/test_app_io.py`
- `SPRINT_02_RESULTADOS.md`

## Funciones implementadas

- Distincion explicita de fuentes: `LIVE_SCAN`, `FILE_IMPORT` y `DEMO`.
- Metadata por resultado: `source_type`, `source_label`, `source_filename`, `captured_at`, `processed_at`, `engine_version` y `synthetic_data`.
- Carga de archivos `.txt` mediante API Python con lectura segura y sin modificar el archivo original.
- Manejo de cancelacion de seleccion como estado no critico.
- Exportacion JSON 2.0 desde los ultimos resultados conservados en memoria por Python.
- Opcion de exportacion con anonimizacion consistente de SSID y BSSID.
- Resumen de reporte con totales, evaluaciones completas, incompletas, clasificaciones y fuente.
- Interfaz adaptada para resultados `INCOMPLETE` con `wss_score = null`.
- Selector visual de fuente: escaneo real, archivo TXT y demostracion.

## Flujo de fuentes

| Fuente | Funcion API | Metadata | Observacion |
| --- | --- | --- | --- |
| `LIVE_SCAN` | `scan_networks()` | Escaneo real del equipo evaluador | Usa `netsh`; no se ejecuto durante el desarrollo. |
| `FILE_IMPORT` | `import_txt_file()` | Archivo TXT cargado por el usuario | Procesa contenido con `wss_engine.evaluate_networks(raw_output=...)`. |
| `DEMO` | `scan_networks_demo()` | Datos sinteticos de demostracion | Marcado con `synthetic_data = true`. |

## Esquema JSON

La exportacion genera un reporte con estructura:

```json
{
  "report_metadata": {
    "report_version": "2.0",
    "generated_at": "...",
    "engine_version": "...",
    "source_type": "LIVE_SCAN | FILE_IMPORT | DEMO",
    "source_label": "...",
    "source_filename": "...",
    "synthetic_data": false,
    "model_status": "PROVISIONAL",
    "anonymized": false
  },
  "scope": {
    "description": "Evaluacion de parametros Wi-Fi observables",
    "not_an_integral_security_audit": true
  },
  "summary": {},
  "results": []
}
```

Cada resultado exportado conserva SSID, BSSID, autenticacion original y normalizada, cifrado original y normalizado, senal, canal, banda, tipo de radio, MFP, estado de evaluacion, campos desconocidos, regla de recomendacion pendiente, fuente, timestamps y version del motor.

Para resultados no evaluables, `wss_score` se exporta como `null` y `classification` como `NO_EVALUABLE`.

## Casos de error contemplados

- Archivo inexistente.
- Archivo vacio.
- Extension no permitida.
- Codificacion no reconocida.
- Contenido sin redes reconocibles.
- Cancelacion del selector de archivo.
- Resultado con score nulo.
- Exportacion sin evaluacion previa.
- Diferenciacion de datos demo frente a archivo cargado.

Los mensajes destinados al usuario no incluyen trazas internas completas.

## Pruebas ejecutadas

Comandos ejecutados:

```powershell
python -m py_compile app.py wss_engine.py
python -m pytest -q
```

Resultado:

```text
18 passed
```

Casos cubiertos:

- lectura de fixture desde archivo;
- metadata `FILE_IMPORT`;
- cancelacion simulada de seleccion;
- evaluacion incompleta;
- serializacion JSON con `null`;
- resumen de completos e incompletos;
- anonimizacion consistente;
- preservacion de valores tecnicos;
- diferenciacion entre demo y archivo;
- exportacion sin resultados;
- ordenamiento con scores nulos.

## Verificacion estatica de interfaz

Se reviso `index.html` para evitar llamadas inseguras del tipo:

```javascript
net.wss_score.toFixed(1)
```

La interfaz usa `isComplete(net)` y `formatScore(net, fallback)` antes de formatear puntajes, por lo que un resultado `INCOMPLETE` no ejecuta `toFixed()` sobre `null`.

## Limitaciones

- No se ejecuto escaneo real de redes durante el desarrollo.
- No se implemento PDF definitivo.
- No se implemento comparacion antes/despues.
- No se implemento historial persistente.
- No se incorporo Android.
- La seleccion nativa de archivos se probo mediante logica separable, no mediante una ventana grafica completa.
- La regla de recomendacion queda registrada como pendiente (`recommendation_rule = null`).

## Riesgos pendientes

- Validar manualmente el dialogo nativo de `pywebview` en Windows.
- Verificar visualmente la interfaz con resultados mixtos completos/incompletos.
- Definir el flujo final de exportacion dentro de la experiencia de usuario.
- Revisar si conviene agregar hashes o identificadores de evidencia para trazabilidad experimental posterior.

## Ajuste posterior a validacion manual

Durante la validacion manual del Sprint 2 se detecto que la aplicacion interpretaba cualquier SSID con varios BSSID como anomalia. Esto podia generar falsos positivos en routers dual-band, redes mesh, repetidores o redes con varios Access Points.

### Causa

La heuristica anterior agrupaba por nombre de SSID y activaba automaticamente la anomalia cuando encontraba mas de un BSSID. Ese estado afectaba:

- `anomaly = True`;
- `AN = 1.0`;
- `BM = DEVIANT`;
- score WSS;
- mensajes visuales de alerta.

### Correccion aplicada

Se separo la observacion de infraestructura de la anomalia metodologica. Se agregaron estados descriptivos:

- `SINGLE_BSSID`;
- `MULTI_RADIO_OBSERVED`;
- `MULTI_AP_OBSERVED`;
- `SECURITY_PROFILE_MISMATCH`;
- `HIDDEN_SSID`;
- `BASELINE_MISMATCH`, reservado para implementacion futura.

Para este sprint, varios BSSID ya no activan automaticamente `AN=1`. El valor `AN=1` queda reservado hasta contar con una regla metodologica o linea base autorizada.

### Efecto sobre el score

- `MULTI_RADIO_OBSERVED`: `AN=0`, no modifica WSS.
- `MULTI_AP_OBSERVED`: `AN=0`, no modifica WSS.
- `SECURITY_PROFILE_MISMATCH`: `AN=0`, requiere revision tecnica, no confirma ataque.
- SSID ocultos: no se agrupan entre si y no reciben alerta automatica.

Una red WPA2/CCMP dual-band conserva el score esperado sin incremento por `AN=1` ni degradacion por `BM=DEVIANT`.

### Interfaz

Se reemplazo el mensaje `SSID duplicado detectado (BSSID distinto)` por mensajes neutrales:

- `Varias radios observadas`;
- `Varios puntos de acceso observados`;
- `Configuraciones diferentes: requiere verificacion tecnica`;
- `SSID oculto observado individualmente`.

La tarjeta sencilla agrupa por SSID visible y muestra cantidad de BSSID/radios y bandas observadas. El detalle tecnico lista los BSSID individuales con banda, canal, senal, tipo de radio, autenticacion y cifrado.

### Pruebas agregadas

Se agregaron pruebas automatizadas para:

- SSID con BSSID en 2,4 GHz y 5 GHz como `MULTI_RADIO_OBSERVED`, con `AN=0`;
- SSID con varios BSSID y mismo perfil como `MULTI_AP_OBSERVED`, sin alerta de ataque;
- mismo SSID con WPA2/CCMP y OPEN/NONE como `SECURITY_PROFILE_MISMATCH`, con revision tecnica y sin confirmar ataque;
- tres SSID ocultos separados, sin agrupacion ni alerta automatica;
- verificacion de que WPA2/CCMP dual-band no recibe el incremento de score causado anteriormente por `AN=1` y `BM=DEVIANT`.

### Limitaciones pendientes del ajuste

- La clasificacion visual de grupos debe validarse manualmente en la ventana `pywebview`.
- `BASELINE_MISMATCH` queda reservado hasta definir una linea base autorizada.
- No se implemento confirmacion de Evil Twin ni ataque; queda fuera del alcance de este sprint.

## Correccion de codificacion de interfaz

Durante la validacion manual tambien se detecto corrupcion visual de caracteres en la interfaz. Para evitar conservar mojibake literal en este informe, los ejemplos se registran como secuencias Unicode sospechosas: `U+00C3`, `U+00C2`, `U+00E2 U+20AC`, `U+00E2 U+2020` y `U+FFFD`.

### Diagnostico

- `index.html` ya contenia `<meta charset="UTF-8">`.
- El problema no era solamente la ausencia de declaracion de charset.
- El contenido fuente de `index.html` ya estaba almacenado con mojibake por conversion UTF-8 / Windows-1252.
- Algunos textos generados desde JavaScript tambien habian quedado guardados con caracteres corruptos.
- En `wss_engine.py` existian marcadores literales de mojibake usados para reparacion de texto; se reemplazaron por `chr(...)` para evitar que el archivo fuente contenga esos caracteres sospechosos.

### Correccion

- `index.html` fue guardado en UTF-8.
- Se restauraron textos visibles con caracteres correctos, incluyendo:
  - `Cómo funciona`;
  - `Clasificación`;
  - `Evaluación pasiva · sin intrusión`;
  - `Sabé qué tan expuesta está tu red Wi-Fi`;
  - `configuración`;
  - `inalámbrica`;
  - `autenticación`;
  - `cifrado`;
  - `señal`;
  - `técnica`;
  - `severidad técnica`;
  - `Probar la calculadora →`.

### Prueba preventiva agregada

Se agrego `tests/test_encoding_guard.py`, que:

- lee `index.html`, `app.py` y `wss_engine.py` como UTF-8;
- falla si encuentra patrones comunes de mojibake representados por `U+00C3`, `U+00C2`, `U+00E2 U+20AC`, `U+00E2 U+2020` o `U+FFFD`;
- confirma que `index.html` contiene `<meta charset="UTF-8">`;
- confirma que textos espanoles esperados estan presentes con UTF-8 correcto.

### Resultado posterior

La verificacion preventiva no encontro residuos de mojibake en:

- `index.html`;
- `app.py`;
- `wss_engine.py`;
- `tests/test_encoding_guard.py`.

La suite completa quedo en `24 passed`.

## Ajustes menores posteriores a validacion visual

Tras la validacion visual satisfactoria se aplicaron ajustes menores de interfaz, sin modificar formula, pesos, valores ni score:

- Se reemplazo `1 BSSID/radios observadas` por formato singular/plural:
  - `1 radio observada`;
  - `2 radios observadas`, `3 radios observadas`, etc.
- En la vista sencilla se elimino la palabra `BSSID`; el BSSID queda reservado para el detalle tecnico.
- Se cambio el titulo `AN - Anomalia` por `AN - Indicador de condicion anomala`.
- Cuando `AN=0`, el detalle muestra `No se identifico una condicion anomala.`.
- Para multiples radios legitimas se muestra un mensaje neutral: `Se observaron varias radios compatibles con una red de doble banda o infraestructura con multiples puntos de acceso.`.

Se actualizo la prueba preventiva de interfaz para verificar singular/plural y mensajes de AN.

## Confirmacion de alcance

- No se modifico formula WSS.
- No se modificaron pesos WSS.
- No se modificaron umbrales de clasificacion.
- No se implemento PDF definitivo.
- No se implemento comparacion antes/despues.
- No se implemento historial persistente.
- No se modificaron archivos de tesis.
- No se ejecuto escaneo real.
- No se afirmo validacion experimental completa del sistema.
- No se incorporo Android.

## Recomendacion

Recomendacion preliminar: APROBAR el Sprint 2 para revision, sujeto a validacion manual de la interfaz con `pywebview` en Windows antes de commit.
