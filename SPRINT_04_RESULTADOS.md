# SPRINT_04_RESULTADOS

## Identificacion

| Campo | Valor |
| --- | --- |
| Sprint | Sprint 4: Priorizacion cualitativa de acciones y generacion de reporte PDF profesional |
| Commit base | `5eefd9203bbf8864d6a6d71ffc52d03958d59d91` |
| Rama | `sprint-04-prioritized-recommendations-pdf` |
| Estado | Implementado para revision manual, sin commit y sin push |

## Archivos modificados o creados

- `app.py`
- `index.html`
- `recommendation_engine.py`
- `requirements.txt`
- `SPRINT_04_RESULTADOS.md`
- `tests/test_recommendation_engine.py`
- `tests/test_sprint_04_prioritization_pdf.py`

## Modelo cualitativo de priorizacion

Se amplio `recommendation_engine.py` para generar acciones priorizadas sin calcular puntajes matematicos de costo-beneficio.

Cada accion incluye:

- `action_id`
- `action_type`
- `target_user`
- `title`
- `description`
- `effort_level`
- `benefit_level`
- `cost_level`
- `time_horizon`
- `display_order`
- `is_temporary`
- `prerequisites`
- `limitations`

Las acciones se ordenan manualmente con `display_order`, considerando beneficio esperado, esfuerzo, costo, plazo y capacidad del destinatario para ejecutar la accion.

## Perfiles de usuario

Se agregaron perfiles:

- `NETWORK_OWNER`: propietario o responsable de la red.
- `NETWORK_USER`: usuario que desea conectarse.
- `GENERAL`: recomendaciones prudentes cuando no se conoce el rol.

La interfaz muestra el control:

`¿Cual es su relacion con esta red?`

Opciones:

- Pertenece a mi organizacion.
- Solo deseo conectarme.
- No estoy seguro.

Cambiar el perfil actualiza recomendaciones y acciones sin modificar score, clasificacion, parametros tecnicos ni evidencia original.

## Acciones implementadas

Se implementaron acciones para:

- WPA3/CCMP.
- WPA2/CCMP.
- WPA/TKIP.
- WEP.
- Red abierta o sin cifrado.
- Parametros no interpretados.
- Configuraciones diferentes bajo el mismo SSID.

Para propietario se incluyen, segun corresponda:

- accion principal;
- alternativa inmediata;
- solucion definitiva;
- practicas complementarias.

Para usuario que desea conectarse se incluyen recomendaciones prudentes como evitar operaciones sensibles, preferir otra red o usar una VPN confiable o aprobada por la organizacion solo cuando no exista otra alternativa.

No se utiliza la expresion `VPN gratuita`.
No se afirma que una VPN vuelva segura toda la red.
No se afirma seguridad garantizada.
No se afirma ataque ni Evil Twin confirmado.
No se afirma principio de Pareto ni relacion 80/20.

## Vista sencilla

La tarjeta muestra:

- estado sencillo;
- explicacion;
- accion principal recomendada;
- esfuerzo;
- beneficio esperado;
- costo estimado;
- plazo;
- destinatario;
- prioridad;
- limitacion;
- observacion de infraestructura cuando corresponde;
- boton `Ver otras alternativas`.

Las alternativas permanecen ocultas inicialmente para no sobrecargar la vista sencilla.

## Trazabilidad de recomendaciones

Cada accion exportada incluye:

- regla REC;
- version de regla;
- perfil de usuario seleccionado;
- accion;
- orden;
- esfuerzo;
- beneficio;
- costo;
- plazo;
- fecha de generacion.

## Exportacion PDF

Se implemento exportacion PDF desde Python mediante `fpdf`.

El PDF se genera desde los ultimos resultados conservados en `WssApi.last_results` y `WssApi.last_metadata`, no desde datos modificables enviados desde JavaScript.

Se agrego `fpdf2>=2.7` a `requirements.txt`. La implementacion mantiene compatibilidad con la API clasica de `fpdf` disponible localmente.

La interfaz incluye:

- `Exportar PDF`;
- opcion de anonimizacion compartida con JSON;
- mensaje de generacion;
- nombre del archivo generado;
- error controlado si no existe evaluacion previa.

## Estructura del PDF

El PDF contiene:

- encabezado con WSS Framework, fecha, origen, motor, estado provisional y anonimizacion;
- resumen ejecutivo;
- texto de alcance;
- resultado por red;
- accion principal y alternativas;
- limitaciones;
- detalles tecnicos;
- trazabilidad;
- buenas practicas complementarias separadas de hallazgos observados;
- numeracion de paginas.

Texto de alcance incluido:

`Este reporte corresponde a una evaluacion de parametros Wi-Fi observables y no constituye una auditoria integral de ciberseguridad.`

## Anonimizacion

La exportacion PDF permite usar identificadores originales o anonimizados.

La anonimizacion reutiliza la misma logica del JSON:

- `SSID-001`
- `BSSID-001`

La correspondencia es consistente dentro del mismo reporte y no modifica parametros tecnicos.

## Pruebas

Se agregaron pruebas para:

- priorizacion por propietario;
- priorizacion por usuario;
- red abierta;
- WPA/TKIP;
- WPA2/CCMP;
- WPA3;
- UNKNOWN;
- acciones ordenadas;
- esfuerzo, beneficio, costo y plazo;
- ausencia de Pareto y 80/20;
- ausencia de `VPN gratuita`;
- generacion de PDF;
- rechazo de PDF vacio;
- PDF con varias redes;
- PDF con UNKNOWN;
- PDF anonimizado;
- metadata;
- texto de alcance;
- caracteres espanoles;
- JSON con recomendaciones priorizadas.

Resultado automatizado actual:

```text
78 passed
```

## Ajuste posterior: guardado accesible

Durante la validacion manual del Sprint 4 se detecto que los reportes JSON y PDF se guardaban en la carpeta de ejecucion del proyecto o en ubicaciones poco claras para el usuario.

### Problema detectado

La exportacion escribia directamente archivos `wss_report_*` en el directorio actual. Esto no era suficientemente accesible para usuarios no tecnicos y dependia de la ubicacion desde la cual se ejecutara la aplicacion.

### Dialogo de guardado implementado

Se implemento el flujo nativo `Guardar como` de `pywebview` para:

- JSON;
- PDF.

La aplicacion ya no guarda primero en la carpeta del proyecto. El usuario debe elegir o confirmar la ubicacion antes de crear el archivo.

### Carpeta inicial

La carpeta inicial se resuelve con el siguiente orden:

1. `Downloads` o `Descargas`, si existe.
2. `Documents` o `Documentos`, si existe.
3. Carpeta personal del usuario.

### Nombres sugeridos

Se agregaron nombres sugeridos:

- `WSS_Reporte_<AAAA-MM-DD>_<HHMMSS>.json`
- `WSS_Reporte_<AAAA-MM-DD>_<HHMMSS>.pdf`
- `WSS_Reporte_<AAAA-MM-DD>_<HHMMSS>_anon.json`
- `WSS_Reporte_<AAAA-MM-DD>_<HHMMSS>_anon.pdf`

La extension se corrige automaticamente si el usuario no la escribe o si intenta usar una extension incorrecta para el tipo exportado.

### Cancelacion

Si el usuario cancela el dialogo:

- no se crea archivo;
- la API devuelve `cancelled: true`;
- la interfaz muestra `La exportacion fue cancelada.`;
- no se presenta error critico.

### Confirmacion posterior

Luego de guardar correctamente, la API devuelve:

- `ok`;
- `saved_path`;
- `filename`;
- `file_type`;
- `anonymized`;
- `generated_at`.

La interfaz muestra:

- `Reporte guardado correctamente.`;
- ubicacion completa del archivo;
- boton `Abrir archivo`;
- boton `Mostrar en carpeta`.

### Apertura del archivo

En Windows:

- `Abrir archivo` usa la aplicacion predeterminada del sistema.
- `Mostrar en carpeta` abre el Explorador y selecciona el archivo cuando es posible.

Las rutas se validan como archivos existentes y se pasan como argumentos separados, sin construir comandos de shell desde texto del usuario.

### Pruebas agregadas

Se agregaron pruebas para:

- exportacion JSON normal;
- exportacion JSON anonimizada;
- exportacion PDF normal;
- exportacion PDF anonimizada;
- cancelacion;
- nombre sin extension;
- correccion de extension para evitar PDF con extension JSON y viceversa;
- directorio inexistente o sin escritura;
- apertura de archivo;
- mostrar en carpeta;
- exportacion sin evaluacion previa;
- carpeta inicial preferente;
- mantenimiento de `.gitignore` para patrones de reportes.

## Ajuste posterior: agrupacion y legibilidad del PDF

Durante la revision manual del PDF `WSS_Reporte_2026-07-16_162716.pdf` se detecto que el reporte generaba una seccion por BSSID o radio. Esto duplicaba redes logicas como `ASOC CAPELLANIA` y `Flia. Esquivel`.

### Problema detectado

El PDF se construia desde la lista plana de resultados tecnicos. Esa lista conserva un elemento por BSSID, pero la vista sencilla ya agrupa visualmente por red logica.

### Correccion implementada

- Se agrego `group_logical_networks()` para construir el PDF desde redes logicas agrupadas.
- Los SSID visibles se agrupan por nombre de red.
- Los SSID ocultos se mantienen separados por BSSID.
- Cada ficha de red contiene una lista interna de radios o puntos de acceso.
- El resumen ejecutivo usa la cantidad de redes logicas, no la cantidad de BSSID.
- La anonimizacion preserva la agrupacion: un mismo SSID mantiene el mismo identificador y cada BSSID recibe un identificador consistente.

### Traducciones visibles

Se agregaron traducciones de presentacion para evitar valores internos en el PDF:

- niveles de esfuerzo, beneficio, costo y plazo;
- estados de evaluacion;
- estados de infraestructura observada;
- etiquetas de BM;
- perfiles de recomendacion.

Los valores internos permanecen disponibles en JSON tecnico.

### Fechas

Las fechas visibles del PDF se muestran como:

`DD/MM/AAAA HH:MM`

La fecha ISO puede permanecer en JSON tecnico.

### Reorganizacion del PDF

El PDF queda organizado como:

1. Pagina inicial con titulo, metadatos, resumen ejecutivo, distribucion y alcance.
2. Una ficha compacta por red logica.
3. Detalles tecnicos dentro de cada ficha.
4. Trazabilidad compacta por ficha.
5. Buenas practicas complementarias una sola vez al final del reporte.

### Vector WSS

La cadena `WSS:1.0/...` ya no se presenta como si fuera el score. En el PDF se muestra como:

- `Version del esquema WSS: 1.0`;
- componentes separados `AU / EN / EX / AN / BM`.

No se modificaron formula, pesos ni umbrales.

### PDFs sinteticos generados

Se generaron dos PDFs sinteticos ignorados por Git:

- `WSS_Reporte_2026-07-16_ajuste_pdf.pdf`
- `WSS_Reporte_2026-07-16_ajuste_pdf_anon.pdf`

Escenario incluido:

- red dual-band;
- red abierta;
- resultado UNKNOWN;
- mas de un BSSID.

Resultado del escenario:

- resultados planos: 4;
- redes logicas esperadas: 3;
- redes logicas mostradas en el PDF: 3;
- paginas antes: no disponible en esta copia local porque el PDF revisado no se encuentra en el repositorio;
- paginas despues: 3.

### Pruebas agregadas

Se agregaron pruebas para:

- red dual-band como una sola seccion;
- varios BSSID del mismo SSID sin incremento del contador de redes;
- escenario equivalente a `ASOC CAPELLANIA` sin duplicacion;
- valores internos no visibles en el PDF;
- fechas visibles en formato `DD/MM/AAAA HH:MM`;
- buenas practicas complementarias una sola vez;
- perfil seleccionado visible;
- score y version del esquema WSS separados;
- anonimizacion preservando agrupacion y BSSID;
- SSID ocultos separados.

### Validacion manual pendiente

Queda pendiente revisar manualmente los dos PDFs generados para confirmar jerarquia visual, saltos de pagina, traducciones y agrupacion en el visor final.

## PDFs de prueba

Se genero un PDF sintetico de prueba para revision manual:

- `wss_report_20260716-153353_anon.pdf`

El patron `wss_report_*.pdf` esta ignorado por Git.

## Limitaciones

- No se implemento Android.
- No se modifico el sistema WSS.
- No se ejecutaron escaneos reales durante las pruebas automatizadas.
- No se implemento seleccion de organizacion desde la interfaz; la API ya acepta el campo para el PDF.
- El diseno PDF es profesional y funcional, pero puede refinarse visualmente en un sprint posterior.
- La validacion manual del PDF queda pendiente.

## Confirmacion de alcance

- No se modifico formula WSS.
- No se modificaron pesos.
- No se modificaron umbrales.
- No se modificaron tablas AU, EN o EX.
- No se modificaron archivos de tesis.
- No se modifico PDF academico.
- No se implemento Android.
- No se hizo commit.
- No se hizo push.

## Validacion manual pendiente

Queda pendiente revisar manualmente:

- el selector de relacion con la red;
- el cambio de recomendaciones por perfil;
- el boton `Ver otras alternativas`;
- la exportacion PDF con y sin anonimizacion;
- legibilidad del PDF generado;
- que el PDF no afirme seguridad garantizada ni deteccion confirmada de ataques.

## Ajuste posterior al segundo PDF revisado

### Problema detectado

Durante la revision manual de `WSS_Reporte_2026-07-16_164629.pdf` se observo que las observaciones de SSID oculto aparecian repetidas como `SSID oculto 1`, aunque correspondian a BSSID diferentes.

Tambien se detecto que el resumen ejecutivo no separaba claramente registros evaluados, redes con SSID identificable y observaciones de SSID oculto.

### Causa identificada

- Los SSID ocultos podian llegar al reporte ya numerados localmente por bloque de evaluacion.
- La anonimización trataba todos los nombres SSID como equivalentes a SSID visibles, aunque `SSID oculto N` funciona como identificador tecnico visual de la observacion.
- El PDF calculaba el resumen desde redes logicas agrupadas, no desde la combinacion de registros originales y redes logicas.

### Correccion aplicada

- Se agrego una normalizacion por evaluacion para asignar identificadores consecutivos y estables a SSID ocultos:
  - `SSID oculto 1`;
  - `SSID oculto 2`;
  - `SSID oculto 3`;
  - etc.
- Los SSID ocultos se agrupan por BSSID y no por autenticacion, cifrado, canal o fabricante.
- El identificador visible del SSID oculto se conserva en:
  - interfaz;
  - JSON;
  - PDF normal;
  - PDF anonimizado;
  - trazabilidad.
- En reportes anonimizados se anonimizan los BSSID, pero se conserva el identificador `SSID oculto N`.

### Resumen ejecutivo

El PDF ahora separa dinamicamente:

- registros evaluados;
- redes con SSID identificable;
- observaciones de SSID oculto;
- evaluaciones completas;
- evaluaciones incompletas;
- redes o registros que requieren atencion;
- distribucion por clasificacion.

### Paginacion y presentacion

- Se aumento el espacio minimo antes de iniciar cada resultado para evitar que una red comience sin espacio suficiente para encabezado, score, clasificacion, estado sencillo, hallazgo y accion principal.
- Se mantiene junto el bloque de trazabilidad cuando hay espacio suficiente.
- `PROVISIONAL` se muestra como `Provisional` en la presentacion visible del PDF.
- El perfil de recomendacion permanece en los metadatos generales y en la seccion de recomendacion de cada red, pero ya no se repite al final de la trazabilidad de cada red.

### Pruebas agregadas o ajustadas

- Nueve SSID ocultos reciben nueve identificadores diferentes.
- Los identificadores de SSID ocultos son estables dentro de la evaluacion.
- Los SSID ocultos no se agrupan sin evidencia.
- El resumen diferencia redes identificables y observaciones ocultas.
- El total general se calcula desde los registros evaluados.
- El PDF no muestra todos los ocultos como `SSID oculto 1`.
- `PROVISIONAL` no aparece en la presentacion visible.
- El perfil no se repite innecesariamente en trazabilidad.
- La anonimizacion conserva los identificadores de SSID ocultos.

### Validacion pendiente

Queda pendiente una nueva revision manual de los PDFs normal y anonimizado generados despues de este ajuste para confirmar:

- numeracion visible de SSID ocultos;
- resumen ejecutivo;
- saltos de pagina;
- ausencia de lineas huerfanas;
- legibilidad general.

### PDFs sinteticos generados para nueva revision

Se generaron dos PDFs sinteticos ignorados por Git:

- `WSS_Reporte_2026-07-16_sprint4_hidden.pdf`
- `WSS_Reporte_2026-07-16_sprint4_hidden_anon.pdf`

El escenario incluye:

- red dual-band;
- nueve observaciones de SSID oculto;
- red WEP;
- red abierta;
- resultado no evaluable.

### Verificacion automatizada posterior al ajuste

- `git diff --check`: sin errores de formato; solo advertencias LF/CRLF de Git.
- `python -m py_compile app.py wss_engine.py recommendation_engine.py`: sin errores.
- `python -m pytest -q --basetemp=.pytest-tmp`: `89 passed`.

Advertencia observada:

- `pytest` informo que no pudo escribir cache en `.pytest_cache` por permisos de la copia temporal. No afecta el resultado de las pruebas.
