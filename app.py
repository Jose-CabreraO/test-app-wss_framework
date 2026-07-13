"""
app.py
Punto de entrada de la aplicacion de escritorio WSS Framework.

Crea una ventana nativa (pywebview) que carga index.html, y expone
funciones de wss_engine.py al JavaScript del frontend a traves de
window.pywebview.api.

Uso:
    pip install -r requirements.txt
    python app.py
"""

import json
import platform
import webview

import wss_engine


class WssApi:
    """
    Clase expuesta a JavaScript. Cada metodo publico aqui es invocable
    desde el frontend como: window.pywebview.api.<metodo>(...)
    Todas las funciones devuelven JSON serializable (dict/list/str).
    """

    def scan_networks(self):
        """
        Ejecuta el escaneo real con netsh (en Windows) y devuelve la lista
        de redes evaluadas con su WSS. Si no se puede escanear (por ejemplo,
        corriendo en un sistema no-Windows durante desarrollo), devuelve un
        error explicito en lugar de datos falsos, salvo que se solicite el
        modo demo explicitamente desde el frontend.
        """
        try:
            results = wss_engine.evaluate_networks()
            return {"ok": True, "demo": False, "results": results}
        except RuntimeError as e:
            return {"ok": False, "demo": False, "error": str(e)}
        except Exception as e:  # noqa: BLE001 - queremos capturar y mostrar cualquier fallo al usuario
            return {"ok": False, "demo": False, "error": f"Error inesperado: {e}"}

    def scan_networks_demo(self):
        """
        Devuelve datos de ejemplo (incluyendo una anomalia de SSID duplicado)
        para poder probar/demostrar la interfaz sin un adaptador Windows real.
        Util durante desarrollo en macOS/Linux, o para hacer una demostracion
        comercial sin depender de las redes circundantes reales.
        """
        results = wss_engine.evaluate_networks_demo()
        return {"ok": True, "demo": True, "results": results}

    def get_platform_info(self):
        """Informa al frontend si el escaneo real esta disponible en este sistema."""
        return {
            "system": platform.system(),
            "scan_available": platform.system() == "Windows",
        }

    def export_json(self, results_json):
        """
        Recibe los resultados (como JSON string desde JS) y los guarda en disco
        como reporte exportado, replicando el formato de export_json.py
        del framework de laboratorio (mismo esquema, distinto origen de datos).
        """
        try:
            results = json.loads(results_json)
        except (TypeError, ValueError):
            return {"ok": False, "error": "No se pudieron interpretar los resultados a exportar."}

        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"wss_report_{ts}.json"

        report = {
            "report_metadata": {
                "title": "WSS Framework — Reporte de redes detectadas",
                "version": "1.0",
                "generated": datetime.now().isoformat(),
                "model": "WSS extendido (modelo de la tesis, seccion 4.5.1)",
                "origen": "Escaneo real del dispositivo cliente (netsh wlan show networks)",
            },
            "results": results,
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        except OSError as e:
            return {"ok": False, "error": f"No se pudo guardar el archivo: {e}"}

        return {"ok": True, "filename": filename}


def main():
    api = WssApi()
    window = webview.create_window(
        "WSS Framework",
        "index.html",
        js_api=api,
        width=1280,
        height=860,
        min_size=(1024, 700),
        background_color="#0B0E11",
    )
    webview.start(debug=False)


if __name__ == "__main__":
    main()
