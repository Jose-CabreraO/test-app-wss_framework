"""
app.py
Punto de entrada de la aplicacion de escritorio WSS Framework.
"""

import json
import platform
from copy import deepcopy
from datetime import datetime
from pathlib import Path

try:
    import webview
except ImportError:  # Permite probar la logica sin abrir ni instalar la GUI.
    webview = None

import wss_engine
import recommendation_engine


SOURCE_LIVE_SCAN = "LIVE_SCAN"
SOURCE_FILE_IMPORT = "FILE_IMPORT"
SOURCE_DEMO = "DEMO"
MODEL_STATUS = "PROVISIONAL"
REPORT_VERSION = "2.0"

RECOMMENDATION_FIELDS = (
    "recommendation_rule_id",
    "recommendation_rule_version",
    "simple_status",
    "finding_title",
    "recommended_action",
    "priority",
    "limitations",
)


def read_netsh_text_file(path):
    """Lee un TXT de netsh sin modificar el original."""
    file_path = Path(path)
    if file_path.suffix.lower() != ".txt":
        return {"ok": False, "error": "Solo se permiten archivos .txt."}
    if not file_path.exists():
        return {"ok": False, "error": "El archivo seleccionado no existe."}
    if not file_path.is_file():
        return {"ok": False, "error": "La ruta seleccionada no corresponde a un archivo."}
    if file_path.stat().st_size == 0:
        return {"ok": False, "error": "El archivo seleccionado esta vacio."}

    encodings = ("utf-8-sig", "utf-8", "cp1252", "latin-1")
    last_error = None
    for encoding in encodings:
        try:
            return {
                "ok": True,
                "text": file_path.read_text(encoding=encoding),
                "encoding": encoding,
                "filename": file_path.name,
            }
        except UnicodeDecodeError as exc:
            last_error = exc
        except OSError as exc:
            return {"ok": False, "error": f"No se pudo leer el archivo: {exc}"}

    return {
        "ok": False,
        "error": "No se pudo reconocer la codificacion del archivo.",
        "detail": str(last_error) if last_error else None,
    }


def process_raw_output(raw_output, source_type, source_label, source_filename=None, synthetic_data=False):
    if source_filename == "es_unknown.txt":
        source_label = "Archivo de prueba con parámetros desconocidos"

    results = wss_engine.evaluate_networks(
        raw_output=raw_output,
        source_type=source_type,
        source_label=source_label,
        source_filename=source_filename,
        synthetic_data=synthetic_data,
    )
    results = apply_recommendations(results)
    if not results:
        return {
            "ok": False,
            "error": "El archivo no contiene redes reconocibles en formato netsh.",
            "results": [],
        }
    metadata = {
        "source_type": source_type,
        "source_label": source_label,
        "source_filename": source_filename,
        "synthetic_data": synthetic_data,
        "processed_at": results[0].get("processed_at"),
        "engine_version": wss_engine.ENGINE_VERSION,
    }
    return {"ok": True, "results": results, "metadata": metadata}


def apply_recommendations(results):
    enriched = []
    for item in results:
        copy = deepcopy(item)
        recommendation = recommendation_engine.recommend_for_result(copy)
        copy["recommendation"] = recommendation
        copy["recommendation_rule_id"] = recommendation["rule_id"]
        copy["recommendation_rule_version"] = recommendation["rule_version"]
        copy["simple_status"] = recommendation["simple_status"]
        copy["finding_title"] = recommendation["finding_title"]
        copy["recommended_action"] = recommendation["recommended_action"]
        copy["priority"] = recommendation["priority"]
        copy["limitations"] = recommendation["limitations"]
        copy["technical_interpretation"] = recommendation["technical_interpretation"]
        copy["simple_explanation"] = recommendation["simple_explanation"]
        copy["warning"] = recommendation["warning"]
        copy["complementary_practices"] = recommendation["complementary_practices"]
        copy["complementary_practices_heading"] = recommendation["complementary_practices_heading"]
        copy["infrastructure_note"] = recommendation.get("infrastructure_note")
        enriched.append(copy)
    return enriched


def summarize_results(results, source_type=None):
    summary = {
        "total_results": len(results),
        "complete_evaluations": 0,
        "incomplete_evaluations": 0,
        "by_classification": {},
        "no_evaluable": 0,
        "source_type": source_type,
    }
    for item in results:
        if item.get("evaluation_status") == "COMPLETE":
            summary["complete_evaluations"] += 1
            classification = item.get("classification") or "UNKNOWN"
            summary["by_classification"][classification] = (
                summary["by_classification"].get(classification, 0) + 1
            )
        else:
            summary["incomplete_evaluations"] += 1
            if item.get("classification") == "NO_EVALUABLE":
                summary["no_evaluable"] += 1
    return summary


def anonymize_results(results):
    ssid_map = {}
    bssid_map = {}
    anonymized = []

    for item in results:
        copy = deepcopy(item)
        ssid = copy.get("ssid")
        bssid = copy.get("bssid")
        if ssid not in ssid_map:
            ssid_map[ssid] = f"SSID-{len(ssid_map) + 1:03d}"
        if bssid not in bssid_map:
            bssid_map[bssid] = f"BSSID-{len(bssid_map) + 1:03d}"
        copy["ssid"] = ssid_map[ssid]
        copy["bssid"] = bssid_map[bssid]
        anonymized.append(copy)

    return anonymized


def normalize_result_for_report(result):
    output = {
        "ssid": result.get("ssid"),
        "bssid": result.get("bssid"),
        "auth_raw": result.get("auth_raw"),
        "auth_key": result.get("auth_key"),
        "cipher_raw": result.get("cipher_raw"),
        "cipher_key": result.get("cipher_key"),
        "signal_pct": result.get("signal_pct"),
        "channel": result.get("channel"),
        "band": result.get("band"),
        "radio_type": result.get("radio_type"),
        "mfp_required": result.get("mfp_required"),
        "evaluation_status": result.get("evaluation_status"),
        "unknown_fields": result.get("unknown_fields", []),
        "recommendation_rule": result.get("recommendation_rule"),
        "recommendation_rule_id": result.get("recommendation_rule_id"),
        "recommendation_rule_version": result.get("recommendation_rule_version"),
        "simple_status": result.get("simple_status"),
        "finding_title": result.get("finding_title"),
        "recommended_action": result.get("recommended_action"),
        "priority": result.get("priority"),
        "limitations": result.get("limitations"),
        "technical_interpretation": result.get("technical_interpretation"),
        "simple_explanation": result.get("simple_explanation"),
        "warning": result.get("warning"),
        "complementary_practices": result.get("complementary_practices", []),
        "complementary_practices_heading": result.get("complementary_practices_heading"),
        "infrastructure_note": result.get("infrastructure_note"),
        "observation_status": result.get("observation_status"),
        "observation_message": result.get("observation_message"),
        "requires_technical_review": result.get("requires_technical_review"),
        "observed_bssid_count": result.get("observed_bssid_count"),
        "observed_bands": result.get("observed_bands"),
        "hidden_ssid": result.get("hidden_ssid"),
        "source_type": result.get("source_type"),
        "source_label": result.get("source_label"),
        "source_filename": result.get("source_filename"),
        "captured_at": result.get("captured_at"),
        "processed_at": result.get("processed_at"),
        "engine_version": result.get("engine_version"),
        "synthetic_data": result.get("synthetic_data"),
    }
    if result.get("evaluation_status") == "COMPLETE":
        output["wss_score"] = result.get("wss_score")
        output["classification"] = result.get("classification")
        output["wss_vector"] = result.get("wss_vector")
    else:
        output["wss_score"] = None
        output["classification"] = "NO_EVALUABLE"
    return output


def build_report(results, metadata, anonymize=False):
    report_results = anonymize_results(results) if anonymize else deepcopy(results)
    generated_at = datetime.now().isoformat()
    source_type = metadata.get("source_type")

    return {
        "report_metadata": {
            "report_version": REPORT_VERSION,
            "generated_at": generated_at,
            "engine_version": metadata.get("engine_version", wss_engine.ENGINE_VERSION),
            "source_type": source_type,
            "source_label": metadata.get("source_label"),
            "source_filename": metadata.get("source_filename"),
            "synthetic_data": bool(metadata.get("synthetic_data")),
            "model_status": MODEL_STATUS,
            "anonymized": bool(anonymize),
        },
        "scope": {
            "description": "Evaluacion de parametros Wi-Fi observables",
            "not_an_integral_security_audit": True,
        },
        "summary": summarize_results(results, source_type=source_type),
        "results": [normalize_result_for_report(item) for item in report_results],
    }


class WssApi:
    """
    Clase expuesta a JavaScript. Cada metodo publico aqui es invocable
    desde el frontend como: window.pywebview.api.<metodo>(...).
    """

    def __init__(self):
        self.last_results = []
        self.last_metadata = None

    def _store(self, response):
        if response.get("ok"):
            self.last_results = response.get("results", [])
            self.last_metadata = response.get("metadata")
        return response

    def scan_networks(self):
        try:
            results = wss_engine.evaluate_networks(
                source_type=SOURCE_LIVE_SCAN,
                source_label="Escaneo real del equipo evaluador",
                synthetic_data=False,
            )
            results = apply_recommendations(results)
            metadata = {
                "source_type": SOURCE_LIVE_SCAN,
                "source_label": "Escaneo real del equipo evaluador",
                "source_filename": None,
                "synthetic_data": False,
                "processed_at": results[0].get("processed_at") if results else datetime.now().isoformat(),
                "engine_version": wss_engine.ENGINE_VERSION,
            }
            return self._store({"ok": True, "demo": False, "results": results, "metadata": metadata})
        except RuntimeError as e:
            return {"ok": False, "demo": False, "error": str(e)}
        except Exception:
            return {"ok": False, "demo": False, "error": "Error inesperado durante el escaneo."}

    def scan_networks_demo(self):
        results = apply_recommendations(wss_engine.evaluate_networks_demo())
        metadata = {
            "source_type": SOURCE_DEMO,
            "source_label": "Datos sinteticos de demostracion",
            "source_filename": None,
            "synthetic_data": True,
            "processed_at": results[0].get("processed_at") if results else datetime.now().isoformat(),
            "engine_version": wss_engine.ENGINE_VERSION,
        }
        return self._store({"ok": True, "demo": True, "results": results, "metadata": metadata})

    def import_txt_file(self, selected_path=None):
        if selected_path is None:
            if webview is None or not getattr(webview, "windows", None):
                return {"ok": False, "cancelled": True, "error": "Seleccion de archivo no disponible."}
            selected = webview.windows[0].create_file_dialog(
                webview.OPEN_DIALOG,
                allow_multiple=False,
                file_types=("Archivos TXT (*.txt)",),
            )
            if not selected:
                return {"ok": False, "cancelled": True, "error": "Seleccion cancelada por el usuario."}
            selected_path = selected[0] if isinstance(selected, (list, tuple)) else selected

        read_result = read_netsh_text_file(selected_path)
        if not read_result.get("ok"):
            return read_result

        response = process_raw_output(
            read_result["text"],
            source_type=SOURCE_FILE_IMPORT,
            source_label="Archivo TXT cargado por el usuario",
            source_filename=read_result["filename"],
            synthetic_data=False,
        )
        if response.get("ok"):
            response["source_filename"] = read_result["filename"]
            response["encoding"] = read_result["encoding"]
        return self._store(response)

    def get_platform_info(self):
        return {
            "system": platform.system(),
            "scan_available": platform.system() == "Windows",
        }

    def export_json(self, anonymize=False):
        if not self.last_results or not self.last_metadata:
            return {"ok": False, "error": "No hay resultados para exportar."}

        report = build_report(self.last_results, self.last_metadata, anonymize=bool(anonymize))
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        suffix = "_anon" if anonymize else ""
        filename = f"wss_report_{ts}{suffix}.json"

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        except OSError as e:
            return {"ok": False, "error": f"No se pudo guardar el archivo: {e}"}

        return {"ok": True, "filename": filename, "report": report}


def main():
    if webview is None:
        raise RuntimeError("pywebview no esta instalado. Ejecute pip install -r requirements.txt.")

    api = WssApi()
    webview.create_window(
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
