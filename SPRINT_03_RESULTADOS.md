# SPRINT_03_RESULTADOS

## Identificacion

| Campo | Valor |
| --- | --- |
| Sprint | Sprint 3: Implementacion de la vista sencilla y del motor trazable de recomendaciones |
| Commit base | `81aa04e625ade15a4fdaf3322c4f4c9db28f48a3` |
| Rama | `sprint-03-simple-view-recommendations` |
| Estado | Implementado para revision manual, sin commit y sin push |

## Archivos modificados o creados

- `.gitignore`
- `app.py`
- `index.html`
- `recommendation_engine.py`
- `SPRINT_03_RESULTADOS.md`
- `tests/test_encoding_guard.py`
- `tests/test_recommendation_engine.py`

## Arquitectura del motor

Se creo `recommendation_engine.py` como modulo independiente del calculo WSS.

El flujo queda separado:

1. `wss_engine.py` parsea, normaliza y calcula los valores tecnicos.
2. `recommendation_engine.py` recibe cada resultado normalizado y devuelve la recomendacion trazable.
3. `app.py` enriquece los resultados antes de exponerlos a la interfaz o exportarlos a JSON.
4. `index.html` renderiza campos ya calculados, sin duplicar la logica central de reglas.

El motor no modifica formula WSS, pesos, umbrales ni tablas AU, EN o EX.

## Reglas implementadas

| Regla | Condicion | Estado sencillo | Prioridad |
| --- | --- | --- | --- |
| `REC-01` | WPA3-Personal con CCMP | Configuracion adecuada | Baja |
| `REC-02` | WPA2-Personal con CCMP/AES | Configuracion adecuada | Baja |
| `REC-03` | WPA/WPA2 con TKIP | Requiere atencion | Alta |
| `REC-04` | WEP | Proteccion insuficiente | Inmediata |
| `REC-05` | OPEN/NONE | Proteccion insuficiente | Inmediata |
| `REC-06` | UNKNOWN o evaluacion incompleta | No se pudo completar la evaluacion | Media |
| `REC-07` | `SECURITY_PROFILE_MISMATCH` | Requiere verificacion tecnica | Media |

Los estados `MULTI_RADIO_OBSERVED` y `MULTI_AP_OBSERVED` se muestran como informacion de infraestructura y no activan recomendaciones de riesgo ni modifican el WSS.

## Campos trazables agregados

Cada resultado enriquecido y cada elemento exportado en JSON incluye:

- `recommendation_rule_id`
- `recommendation_rule_version`
- `simple_status`
- `finding_title`
- `recommended_action`
- `priority`
- `limitations`
- `technical_interpretation`
- `simple_explanation`
- `warning`
- `complementary_practices`
- `complementary_practices_heading`
- `infrastructure_note`

No se eliminan los campos tecnicos originales: score, clasificacion, vector, AU, EN, EX, AN, BM, autenticacion, cifrado, senal, canal, banda, radio, BSSID y estado de observacion.

## Vista sencilla

La tarjeta inicial muestra primero:

1. Nombre de la red.
2. Estado sencillo.
3. Titulo del hallazgo.
4. Explicacion comprensible.
5. Accion recomendada.
6. Prioridad.
7. Limitaciones.
8. Observacion de infraestructura cuando corresponde.

La vista sencilla no muestra inicialmente vector WSS, AU, EN, EX, AN, BM, BSSID ni formula. El acceso a esos datos queda bajo la accion `Ver detalles tecnicos`.

## Vista tecnica

La vista tecnica conserva:

- score;
- clasificacion;
- vector WSS;
- AU, EN, EX, AN y BM;
- autenticacion;
- cifrado;
- senal;
- canal;
- banda;
- radio;
- BSSID individuales;
- estado de observacion;
- regla aplicada;
- version de regla;
- interpretacion tecnica;
- buenas practicas complementarias.

## Ejemplos de resultados

| Escenario | Regla | Estado sencillo | Accion principal |
| --- | --- | --- | --- |
| WPA3/CCMP | `REC-01` | Configuracion adecuada | Mantener configuracion y revisar actualizaciones |
| WPA2/CCMP | `REC-02` | Configuracion adecuada | Mantener WPA2 con CCMP/AES o verificar WPA3 |
| WPA/TKIP | `REC-03` | Requiere atencion | Migrar a WPA2 con CCMP/AES o WPA3 |
| WEP | `REC-04` | Proteccion insuficiente | Migrar o reemplazar equipo si no admite opciones modernas |
| OPEN/NONE | `REC-05` | Proteccion insuficiente | Activar WPA2 con CCMP/AES o WPA3 |
| UNKNOWN | `REC-06` | No se pudo completar la evaluacion | Repetir evaluacion o solicitar revision tecnica |
| Perfiles distintos | `REC-07` | Requiere verificacion tecnica | Confirmar puntos de acceso autorizados |

## Pruebas ejecutadas

Comandos requeridos para cierre:

```powershell
git diff --check
python -m py_compile app.py wss_engine.py recommendation_engine.py
python -m pytest -q
```

Resultado esperado al momento de esta actualizacion:

```text
41 passed
```

## Cobertura agregada

- `REC-01` WPA3/CCMP.
- `REC-02` WPA2/CCMP.
- `REC-03` WPA/TKIP.
- `REC-04` WEP sintetico con advertencia metodologica.
- `REC-05` OPEN/NONE.
- `REC-06` UNKNOWN sin score ni conclusion definitiva.
- `REC-07` perfiles de seguridad distintos sin afirmar ataque.
- `MULTI_RADIO_OBSERVED` como nota informativa.
- `MULTI_AP_OBSERVED` sin afirmacion de ataque.
- Buenas practicas complementarias separadas.
- Campos de recomendacion presentes en JSON.
- Codificacion UTF-8 correcta.
- Vista sencilla sin BSSID ni vector WSS inicial.
- Vista tecnica con trazabilidad completa.
- Boton real para `Ver detalles tecnicos`.
- Atributos `aria-expanded` y `aria-controls`.
- Panel tecnico oculto inicialmente y expandible por tarjeta.
- Proteccion contra `toFixed()` inseguro sobre valores nulos.

## Correccion posterior a validacion manual

Durante la validacion manual del Sprint 3 se detecto que `Ver detalles tecnicos` se mostraba visualmente, pero no funcionaba como boton y no desplegaba el detalle tecnico.

### Causa

El control estaba implementado como un `span` con apariencia de etiqueta informativa. Ademas, la tarjeta completa dependia de un evento `click` que renderizaba un panel tecnico global, lo que no cumplia la expectativa de boton accesible ni de estado independiente por tarjeta.

### Correccion

- Se reemplazo el `span` por un `<button type="button">`.
- Se agregaron `aria-expanded` y `aria-controls`.
- Cada tarjeta genera su propio panel tecnico oculto inicialmente.
- El boton alterna entre `Ver detalles tecnicos` y `Ocultar detalles tecnicos`.
- El panel se abre y cierra sin depender de un indice global ni mostrar detalles de otra red.
- Se permite que varias tarjetas permanezcan abiertas simultaneamente para comparar informacion tecnica.
- El detalle tecnico conserva los BSSID individuales de cada agrupacion.
- Los resultados `INCOMPLETE` tambien pueden abrir detalle tecnico, muestran parametros originales y no ejecutan `toFixed()` sobre valores nulos.

### Pruebas agregadas

- Existencia de un elemento `<button>`.
- Texto cerrado `Ver detalles tecnicos`.
- Texto abierto `Ocultar detalles tecnicos`.
- Atributos `aria-expanded` y `aria-controls`.
- Panel tecnico oculto inicialmente.
- Cambio de estado del panel al activar el control.
- Panel tecnico por tarjeta.
- Contenido tecnico obligatorio y trazabilidad.
- Proteccion contra `toFixed()` inseguro sobre `null`.

### Validacion manual pendiente

Queda pendiente una nueva validacion manual en `pywebview` para confirmar interaccion visual, foco de teclado, apertura/cierre y legibilidad del panel expandido.

## Ajuste visual posterior a segunda validacion manual

Durante una nueva validacion manual se confirmo que el boton funcionaba, pero se detectaron problemas de usabilidad:

- texto pequeno en las tarjetas;
- contraste bajo;
- demasiada informacion por tarjeta;
- expansion excesiva al abrir detalles;
- cuadricula desordenada;
- vista tecnica con demasiado peso visual dentro de la vista sencilla.

### Solucion implementada

- Se elimino la expansion tecnica dentro de la tarjeta.
- La cuadricula mantiene tarjetas de altura estable.
- Se incorporo un panel lateral derecho reutilizando `#detail-panel`.
- El panel lateral permanece cerrado inicialmente.
- El boton `Ver detalles tecnicos` abre el panel lateral sin deformar la cuadricula.
- El panel puede actualizarse al seleccionar otra red sin perder resultados.
- El panel se cierra con boton visible o tecla `Escape`.
- En pantallas pequenas el panel pasa a ocupar pantalla completa para evitar comprimir excesivamente la cuadricula.

### Estructura del panel lateral

El panel tecnico se organiza en secciones:

- Resumen tecnico;
- Vector WSS;
- Parametros observados;
- Radios o puntos de acceso;
- Buenas practicas complementarias;
- Trazabilidad.

### Mejoras tipograficas

- Nombre de red aumentado a 18 px.
- Estado sencillo aumentado a 15.5 px.
- Texto de explicacion, accion, prioridad y limitaciones aumentado a 14-15 px.
- `line-height` aumentado para mejorar lectura.
- Contraste de texto secundario elevado de `text-faint` a `text-dim` en informacion esencial.
- Boton con texto normal, sin mayusculas completas.

### Pruebas agregadas

- Tarjetas sin panel tecnico embebido.
- Existencia del panel lateral.
- Panel oculto inicialmente.
- Boton real con `aria-expanded` y `aria-controls`.
- Cierre mediante boton.
- Cierre mediante `Escape`.
- Cambio entre redes seleccionadas.
- Contenido tecnico completo.
- Resultado `INCOMPLETE` sin `toFixed()` inseguro.
- Ausencia de mojibake.

### Validacion manual pendiente

Queda pendiente revisar nuevamente en `pywebview` la usabilidad del panel lateral, el cierre con teclado, el comportamiento responsive y la lectura en redes individuales, dual-band e incompletas.

## Rediseño posterior del drawer técnico

Durante la siguiente validacion manual se detectaron problemas persistentes:

- el panel conservaba la posicion de scroll al cambiar de red;
- el encabezado y nombre de red podian quedar ocultos;
- el contenido tecnico seguia siendo demasiado largo;
- recomendacion, prioridad y limitacion no quedaban suficientemente visibles;
- la navegacion entre redes era confusa.

### Causa

El panel lateral anterior seguia funcionando como un bloque tecnico largo. Aunque ya no expandia la tarjeta, no tenia encabezado fijo, cuerpo con scroll claramente separado ni organizacion por pestañas.

### Rediseño implementado

- El panel tecnico ahora es un drawer fijo con `position: fixed`.
- Queda anclado al lado derecho, debajo de la barra principal y hasta el borde inferior.
- Usa ancho aproximado de 580 px, borde lateral y sombra.
- El encabezado interno permanece visible con nombre de red, estado sencillo, score y boton `Cerrar`.
- El cuerpo interno usa scroll independiente.
- Al abrir o cambiar de red se ejecuta `panelBody.scrollTop = 0`.
- Al cambiar de red se conserva el mismo drawer y se reemplaza el contenido.
- La tecla `Escape` cierra el drawer y se restaura el foco al boton que lo abrio.

### Pestañas implementadas

Se agregaron cuatro pestañas con roles accesibles:

- `Resumen`: estado sencillo, titulo, explicacion, recomendacion, prioridad, limitacion, observacion y regla aplicada.
- `Parametros`: autenticacion, cifrado, señal, canal, banda, radio, MFP, score, clasificacion, vector y factores WSS.
- `Radios`: BSSID individuales con señal, banda, canal, radio, autenticacion y cifrado.
- `Trazabilidad`: regla, version, fuente, archivo, motor, estado de evaluacion, estado de observacion y fecha de procesamiento.

La pestaña `Resumen` se activa siempre por defecto al abrir o cambiar de red.

### Pruebas añadidas

- Drawer fijo independiente.
- Encabezado sticky.
- Cuerpo con scroll independiente.
- `scrollTop = 0` al abrir/cambiar de red.
- Pestaña `Resumen` activa por defecto.
- Recomendacion, prioridad y limitacion visibles.
- Cambio entre redes sin acumular paneles.
- Resultado `INCOMPLETE`.
- Dual-band mediante lista de radios/BSSID.
- Cierre y restauracion de foco.
- Roles de pestañas y navegacion por teclado.

## Ajuste posterior de comprension y navegacion

Durante la validacion manual posterior se detectaron nuevos problemas de comprension:

- el drawer mostraba codigos de regla sin nombre explicativo;
- la pestana de trazabilidad exponia nombres internos de campos;
- algunos valores internos no estaban traducidos;
- la fecha no quedaba presentada en formato local legible;
- `es_unknown.txt` podia parecer una red o escenario normal;
- los enlaces globales no funcionaban correctamente cuando estaba activa la vista `Mis Redes`;
- el score tecnico no destacaba lo suficiente en el encabezado del drawer.

### Correccion implementada

- Se agregaron nombres visibles para `REC-01` a `REC-07`.
- En `Resumen` ahora se muestra `Regla aplicada` con codigo y nombre visible.
- La pestana visible pasa a llamarse `Trazabilidad avanzada`.
- Las etiquetas internas de trazabilidad se muestran en lenguaje comprensible.
- Los valores `LIVE_SCAN`, `FILE_IMPORT`, `DEMO`, `COMPLETE`, `INCOMPLETE`, `SINGLE_BSSID`, `MULTI_RADIO_OBSERVED`, `MULTI_AP_OBSERVED` y `SECURITY_PROFILE_MISMATCH` se traducen para la interfaz.
- La fecha de procesamiento se formatea como `DD/MM/AAAA HH:MM`.
- La grilla de trazabilidad separa etiqueta y valor para evitar textos pegados.
- El archivo `es_unknown.txt` queda identificado como fixture sintetico de desarrollo: `Archivo de prueba con parametros desconocidos`.
- Los enlaces `Como funciona`, `Calculadora`, `Clasificacion` y `Beneficios` activan primero `Calculadora Demo` y luego desplazan a la seccion correspondiente.
- El boton `Probar ahora` activa `Mis Redes` desde cualquier vista.
- El encabezado del drawer muestra el score tecnico en formato destacado; los resultados no evaluables muestran `Sin puntaje` y `Evaluacion incompleta`.

### Pruebas agregadas

- Nombres visibles de reglas de recomendacion.
- Traduccion de etiquetas de trazabilidad.
- Traduccion de valores internos.
- Formato local de fecha.
- Separacion visual entre etiqueta y valor.
- Score destacado y caso `NO_EVALUABLE` sin puntaje inventado.
- Navegacion global desde `Mis Redes` hacia `Calculadora Demo`.
- Accion `Probar ahora` hacia `Mis Redes`.
- Etiquetado especial de `es_unknown.txt`.
- Ausencia de mojibake en fuentes visibles.

### Validacion manual pendiente

Queda pendiente una nueva validacion manual para confirmar que la navegacion global, la legibilidad del drawer, el score destacado y la trazabilidad avanzada son comprensibles en `pywebview`.

## Ajuste final de severidad, estado y color

Durante la validacion manual final del Sprint 3 se detecto una inconsistencia semantica: un resultado con score `7,0` y clasificacion `ALTO` podia mostrarse con color verde y estado sencillo `Proteccion insuficiente`.

### Causa

La interfaz coloreaba algunos elementos a partir del score o de campos de recomendacion, mientras que el motor de recomendaciones podia asignar `simple_status` por regla. Esto permitia contradicciones entre clasificacion tecnica, estado sencillo y color semantico.

### Mapeo central implementado

Se adopto un unico mapeo para la vista sencilla:

| Clasificacion tecnica | Estado sencillo | Color |
| --- | --- | --- |
| `BAJO` | Configuracion adecuada | Verde |
| `MEDIO` | Puede mejorar | Amarillo |
| `ALTO` | Requiere atencion | Naranja |
| `CRITICO` | Proteccion insuficiente | Rojo |
| `NO_EVALUABLE` | No se pudo completar la evaluacion | Gris |

`SECURITY_PROFILE_MISMATCH` conserva el estado especial `Requiere verificacion tecnica` y usa color de advertencia, sin afirmar ataque.

### Correccion aplicada

- `recommendation_engine.py` deriva el estado sencillo desde la clasificacion tecnica.
- Las reglas de recomendacion conservan hallazgo, explicacion, accion, prioridad y advertencias, pero no sobrescriben el estado de forma contradictoria.
- `REC-04` con clasificacion `ALTO` queda como `Requiere atencion`, no como `Proteccion insuficiente`.
- `index.html` usa `CLASSIFICATION_PRESENTATION` como unico mapeo visual para score, clasificacion, estado, badge y acento de tarjeta.
- `MULTI_RADIO_OBSERVED` y `MULTI_AP_OBSERVED` permanecen como observaciones informativas y no alteran el color de severidad.
- `NO_EVALUABLE` muestra `Sin puntaje`, `No se pudo completar la evaluacion` y gris neutro.

### Pruebas agregadas

- `BAJO` -> verde + Configuracion adecuada.
- `MEDIO` -> amarillo + Puede mejorar.
- `ALTO` -> naranja + Requiere atencion.
- `CRITICO` -> rojo + Proteccion insuficiente.
- `NO_EVALUABLE` -> gris + Sin puntaje.
- `REC-04` no sobrescribe `ALTO` como Proteccion insuficiente.
- Observaciones multi-radio no alteran el color.
- Score, estado y clasificacion usan el mismo mapeo de presentacion.

### Validacion manual pendiente

Queda pendiente confirmar visualmente que un resultado `ALTO` se muestre en naranja con estado `Requiere atencion`, y que `CRITICO` quede reservado para `Proteccion insuficiente`.

## Validacion manual final aprobada

La validacion manual final del Sprint 3 fue aprobada.

Se confirmo:

- la vista sencilla funciona correctamente;
- el drawer tecnico funciona correctamente;
- el cambio entre redes reinicia el scroll;
- las pestanas del drawer funcionan correctamente;
- la navegacion global funciona desde `Calculadora Demo` y `Mis Redes`;
- la trazabilidad avanzada es comprensible;
- el score tecnico es visible;
- los estados y colores son coherentes:
  - `BAJO`: Configuracion adecuada, verde;
  - `MEDIO`: Puede mejorar, amarillo;
  - `ALTO`: Requiere atencion, naranja;
  - `CRITICO`: Proteccion insuficiente, rojo;
  - `NO_EVALUABLE`: No se pudo completar la evaluacion, gris;
- no existen afirmaciones de ataque ni de Evil Twin confirmado.

### Resultado final de pruebas

La suite automatizada final quedo en:

```text
56 passed
```

### Cierre del sprint

El Sprint 3 queda cerrado funcionalmente para commit local en la rama `sprint-03-simple-view-recommendations`.

## Limitaciones

- No se implemento PDF.
- No se implemento historial persistente.
- No se implemento Android.
- No se ejecuto escaneo real durante el desarrollo automatizado.
- No se afirma validacion experimental completa.
- No se afirma deteccion de Evil Twin.
- Las buenas practicas complementarias no son hallazgos observados por el escaneo.

## Riesgos pendientes

- Mantener en el siguiente sprint la coherencia entre clasificacion tecnica, estado sencillo y color semantico.
- Definir si en un sprint posterior corresponde persistir reportes en una carpeta `exports/`.
- Revisar con el tutor la redaccion final de recomendaciones antes de incorporarlas al documento academico.

## Confirmacion de alcance

- No se modifico formula WSS.
- No se modificaron pesos.
- No se modificaron umbrales.
- No se modificaron tablas AU, EN o EX.
- No se implemento PDF.
- No se modificaron archivos de tesis.
- La validacion manual final fue aprobada.
- No se hizo push.
