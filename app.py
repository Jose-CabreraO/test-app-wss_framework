"""
app.py
Punto de entrada de la aplicacion de escritorio WSS Framework.
"""

import json
import os
import platform
import subprocess
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from fpdf import FPDF

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
DEFAULT_USER_PROFILE = recommendation_engine.TARGET_GENERAL
EXPORT_BASENAME = "WSS_Reporte"
SCOPE_TEXT = (
    "Este reporte corresponde a una evaluación de parámetros Wi-Fi observables "
    "y no constituye una auditoría integral de ciberseguridad."
)


def default_export_directory():
    home = Path.home()
    for candidate in (home / "Downloads", home / "Descargas", home / "Documents", home / "Documentos", home):
        if candidate.exists() and candidate.is_dir():
            return candidate
    return home


def suggested_report_filename(file_type, anonymize=False, generated_at=None):
    generated_at = generated_at or datetime.now()
    suffix = "_anon" if anonymize else ""
    extension = ".pdf" if file_type == "PDF" else ".json"
    return f"{EXPORT_BASENAME}_{generated_at.strftime('%Y-%m-%d')}_{generated_at.strftime('%H%M%S')}{suffix}{extension}"


def ensure_extension(path, extension):
    file_path = Path(path)
    if file_path.suffix.lower() != extension.lower():
        file_path = file_path.with_suffix(extension)
    return file_path


def _dialog_result_to_path(selected):
    if not selected:
        return None
    if isinstance(selected, (list, tuple)):
        return selected[0] if selected else None
    return selected


def choose_save_path(file_type, anonymize=False):
    if webview is None or not getattr(webview, "windows", None):
        return {"ok": False, "error": "Dialogo de guardado no disponible."}
    extension = ".pdf" if file_type == "PDF" else ".json"
    filter_label = "PDF (*.pdf)" if file_type == "PDF" else "JSON (*.json)"
    selected = webview.windows[0].create_file_dialog(
        webview.SAVE_DIALOG,
        directory=str(default_export_directory()),
        save_filename=suggested_report_filename(file_type, anonymize=anonymize),
        file_types=(filter_label,),
    )
    selected_path = _dialog_result_to_path(selected)
    if not selected_path:
        return {"ok": False, "cancelled": True}
    return {"ok": True, "path": ensure_extension(selected_path, extension)}


def write_json_report(path, report):
    output_path = ensure_extension(path, ".json")
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    except OSError as e:
        return {"ok": False, "error": f"No se pudo guardar el archivo: {e}"}
    return {"ok": True, "path": output_path}


def write_pdf_report(path, pdf_bytes):
    output_path = ensure_extension(path, ".pdf")
    try:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)
    except OSError as e:
        return {"ok": False, "error": f"No se pudo guardar el archivo: {e}"}
    return {"ok": True, "path": output_path}


def export_success_response(path, file_type, anonymize=False, generated_at=None, report=None):
    generated_at = generated_at or datetime.now().isoformat()
    output_path = Path(path)
    response = {
        "ok": True,
        "saved_path": str(output_path),
        "filename": output_path.name,
        "file_type": file_type,
        "anonymized": bool(anonymize),
        "generated_at": generated_at,
    }
    if report is not None:
        response["report"] = report
    return response

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


def process_raw_output(raw_output, source_type, source_label, source_filename=None,
                       synthetic_data=False, target_user=DEFAULT_USER_PROFILE):
    if source_filename == "es_unknown.txt":
        source_label = "Archivo de prueba con parámetros desconocidos"

    results = wss_engine.evaluate_networks(
        raw_output=raw_output,
        source_type=source_type,
        source_label=source_label,
        source_filename=source_filename,
        synthetic_data=synthetic_data,
    )
    results = assign_hidden_ssid_identifiers(results)
    results = apply_recommendations(results, target_user=target_user)
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


def assign_hidden_ssid_identifiers(results):
    hidden_map = {}
    renamed = []
    for item in results:
        copy = deepcopy(item)
        if copy.get("hidden_ssid"):
            key = copy.get("bssid") or copy.get("ssid") or f"hidden-{len(hidden_map) + 1}"
            if key not in hidden_map:
                hidden_map[key] = f"SSID oculto {len(hidden_map) + 1}"
            copy["ssid"] = hidden_map[key]
        renamed.append(copy)
    return renamed


def apply_recommendations(results, target_user=DEFAULT_USER_PROFILE):
    enriched = []
    for item in results:
        copy = deepcopy(item)
        recommendation = recommendation_engine.recommend_for_result(copy, target_user=target_user)
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
        copy["prioritized_actions"] = recommendation.get("prioritized_actions", [])
        copy["selected_user_profile"] = recommendation_engine.normalize_target_user(target_user)
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


def summarize_pdf_results(raw_results, logical_results, source_type=None):
    summary = summarize_results(logical_results, source_type=source_type)
    visible_networks = {
        item.get("ssid")
        for item in logical_results
        if not item.get("hidden_ssid") and item.get("ssid")
    }
    hidden_observations = sum(1 for item in logical_results if item.get("hidden_ssid"))
    observed_radios = sum(item.get("logical_bssid_count") or 1 for item in logical_results)
    attention = sum(
        1 for item in logical_results
        if item.get("classification") in {"ALTO", "CRITICO", "CRÍTICO"}
        or item.get("evaluation_status") != "COMPLETE"
    )
    by_classification = {}
    for item in logical_results:
        classification = item.get("classification") or "NO_EVALUABLE"
        by_classification[classification] = by_classification.get(classification, 0) + 1
    summary.update({
        "identifiable_networks": len(visible_networks),
        "hidden_observations": hidden_observations,
        "observed_radios": observed_radios,
        "attention_required": attention,
        "by_classification": by_classification,
    })
    return summary


def anonymize_results(results):
    ssid_map = {}
    bssid_map = {}
    anonymized = []

    for item in results:
        copy = deepcopy(item)
        ssid = copy.get("ssid")
        bssid = copy.get("bssid")
        if copy.get("hidden_ssid"):
            copy["ssid"] = ssid
        else:
            if ssid not in ssid_map:
                ssid_map[ssid] = f"SSID-{len(ssid_map) + 1:03d}"
            copy["ssid"] = ssid_map[ssid]
        if bssid not in bssid_map:
            bssid_map[bssid] = f"BSSID-{len(bssid_map) + 1:03d}"
        copy["bssid"] = bssid_map[bssid]
        anonymized.append(copy)

    return anonymized


CLASSIFICATION_RANK = {
    "NO_EVALUABLE": 0,
    "BAJO": 1,
    "MEDIO": 2,
    "ALTO": 3,
    "CRITICO": 4,
    "CRÍTICO": 4,
}

DISPLAY_LABELS = {
    "LOW": "Bajo",
    "MEDIUM": "Medio",
    "HIGH": "Alto",
    "UNKNOWN": "No interpretada",
    "OPEN": "Abierta",
    "NONE": "Ninguna",
    "NO_COST": "Sin costo",
    "SHORT_TERM": "Corto plazo",
    "IMMEDIATE": "Inmediato",
    "PLANNED": "Planificado",
    "COMPLETE": "Evaluación completa",
    "INCOMPLETE": "Evaluación incompleta",
    "SINGLE_BSSID": "Un solo punto de acceso observado",
    "MULTI_RADIO_OBSERVED": "Varias radios observadas",
    "MULTI_AP_OBSERVED": "Varios puntos de acceso observados",
    "SECURITY_PROFILE_MISMATCH": "Configuraciones diferentes bajo el mismo SSID",
    "HIDDEN_SSID": "SSID oculto observado individualmente",
    "ALIGNED": "Alineado",
    "DEVIANT": "Desviado",
    "PARTIAL": "Parcial",
    "NETWORK_OWNER": "Propietario o administrador de la red.",
    "NETWORK_USER": "Persona que desea conectarse.",
    "GENERAL": "Perfil no especificado.",
    "PROVISIONAL": "Provisional",
    "PRIMARY": "Acción principal recomendada",
    "ALTERNATIVE": "Alternativa inmediata",
    "DEFINITIVE": "Solución definitiva",
    "COMPLEMENTARY": "Complementaria",
    "CRITICO": "Crítico",
    "CRÍTICO": "Crítico",
    "BAJO": "Bajo",
    "MEDIO": "Medio",
    "ALTO": "Alto",
    "NO_EVALUABLE": "No evaluable",
}


def display_label(value):
    return DISPLAY_LABELS.get(value, value if value is not None else "s/d")


def format_display_datetime(value):
    if not value:
        return "s/d"
    if isinstance(value, datetime):
        date = value
    else:
        try:
            date = datetime.fromisoformat(str(value))
        except ValueError:
            return str(value)
    return date.strftime("%d/%m/%Y %H:%M")


def split_wss_vector(vector):
    components = {"schema_version": None}
    if not vector:
        return components
    for part in str(vector).split("/"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        key = key.strip().upper()
        value = value.strip()
        if key == "WSS":
            components["schema_version"] = value
        else:
            components[key] = value
    return components


def _logical_group_key(item):
    if item.get("hidden_ssid"):
        return f"HIDDEN::{item.get('bssid') or item.get('ssid')}"
    return item.get("ssid") or item.get("bssid")


def _best_representative(items):
    def sort_key(item):
        classification = item.get("classification") or "NO_EVALUABLE"
        score = item.get("wss_score")
        return (
            CLASSIFICATION_RANK.get(classification, 0),
            -1 if score is None else float(score),
        )

    return sorted(items, key=sort_key, reverse=True)[0]


def group_logical_networks(results):
    grouped = {}
    for item in results:
        grouped.setdefault(_logical_group_key(item), []).append(item)

    logical = []
    for items in grouped.values():
        representative = deepcopy(_best_representative(items))
        radios = []
        bands = set()
        security_profiles = set()
        for item in items:
            radios.append({
                "bssid": item.get("bssid"),
                "band": item.get("band"),
                "channel": item.get("channel"),
                "signal_pct": item.get("signal_pct"),
                "radio_type": item.get("radio_type"),
                "auth_raw": item.get("auth_raw"),
                "auth_key": item.get("auth_key"),
                "cipher_raw": item.get("cipher_raw"),
                "cipher_key": item.get("cipher_key"),
                "mfp_required": item.get("mfp_required"),
            })
            if item.get("band"):
                bands.add(item.get("band"))
            security_profiles.add((item.get("auth_key"), item.get("cipher_key")))

        if representative.get("hidden_ssid"):
            observation_status = "HIDDEN_SSID"
        elif len(security_profiles) > 1:
            observation_status = "SECURITY_PROFILE_MISMATCH"
        elif len(items) > 1 and len(bands) > 1:
            observation_status = "MULTI_RADIO_OBSERVED"
        elif len(items) > 1:
            observation_status = "MULTI_AP_OBSERVED"
        else:
            observation_status = representative.get("observation_status") or "SINGLE_BSSID"

        representative["logical_radios"] = radios
        representative["logical_bssid_count"] = len(radios)
        representative["observed_bands"] = sorted(bands)
        representative["observation_status"] = observation_status
        representative["infrastructure_note"] = (
            representative.get("infrastructure_note")
            or display_label(observation_status)
        )
        logical.append(representative)

    return logical


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
        "prioritized_actions": result.get("prioritized_actions", []),
        "selected_user_profile": result.get("selected_user_profile"),
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
        output["au"] = result.get("au")
        output["en"] = result.get("en")
        output["ex"] = result.get("ex")
        output["an"] = result.get("an")
        output["bm"] = result.get("bm")
        output["bm_label"] = result.get("bm_label")
    else:
        output["wss_score"] = None
        output["classification"] = "NO_EVALUABLE"
        output["au"] = result.get("au")
        output["en"] = result.get("en")
        output["ex"] = result.get("ex")
        output["an"] = result.get("an")
        output["bm"] = result.get("bm")
        output["bm_label"] = result.get("bm_label")
    return output


def build_report(results, metadata, anonymize=False, user_profile=DEFAULT_USER_PROFILE, organization=None):
    report_results = anonymize_results(results) if anonymize else deepcopy(results)
    generated_at = datetime.now().isoformat()
    source_type = metadata.get("source_type")
    user_profile = recommendation_engine.normalize_target_user(user_profile)

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
            "organization": organization or None,
            "selected_user_profile": user_profile,
        },
        "scope": {
            "description": "Evaluacion de parametros Wi-Fi observables",
            "not_an_integral_security_audit": True,
            "text": SCOPE_TEXT,
        },
        "summary": summarize_results(results, source_type=source_type),
        "results": [normalize_result_for_report(item) for item in report_results],
    }


def visible_actions(actions):
    allowed = {"PRIMARY", "ALTERNATIVE", "DEFINITIVE"}
    return [item for item in sorted(actions or [], key=lambda action: action["display_order"])
            if item["action_type"] in allowed][:3]


def _pdf_text(value):
    if value is None:
        return "s/d"
    text = str(value)
    return (
        text.replace("→", "->")
        .replace("—", "-")
        .replace("–", "-")
        .replace("“", '"')
        .replace("”", '"')
        .replace("’", "'")
    )


def _display_value(value):
    if value is None:
        return "s/d"
    return str(value)


class WssPdf(FPDF):
    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(90, 98, 110)
        self.cell(0, 8, f"Página {self.page_no()}", align="C")


def _add_pdf_line(pdf, label, value, width=0):
    _ensure_pdf_space(pdf, 10)
    line = f"{_pdf_text(label)}: {_pdf_text(value)}"
    if hasattr(pdf, "visible_text"):
        pdf.visible_text.append(line)
    pdf.set_font("Helvetica", "B", 9)
    text = f"{_pdf_text(label)}: "
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(width or 0, 5, text + _pdf_text(value))


def _ensure_pdf_space(pdf, height):
    if pdf.get_y() + height > pdf.page_break_trigger:
        pdf.add_page()


def _pdf_section(pdf, title, visible_text):
    _ensure_pdf_space(pdf, 14)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_fill_color(238, 242, 246)
    pdf.cell(0, 7, _pdf_text(title), ln=1, fill=True)
    visible_text.append(title)


def _pdf_badge(pdf, label, color):
    pdf.set_fill_color(*color)
    pdf.set_text_color(20, 24, 30)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(35, 7, _pdf_text(label), ln=0, align="C", fill=True)
    pdf.set_text_color(20, 24, 30)


def _pdf_score_classification_row(pdf, score_text, classification):
    _ensure_pdf_space(pdf, 14)
    score_width = 58
    badge_width = 44
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(score_width, 10, _pdf_text(score_text), ln=0)
    pdf.set_fill_color(*_classification_color(classification))
    pdf.set_text_color(20, 24, 30)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(badge_width, 7, _pdf_text(display_label(classification)), ln=1, align="C", fill=True)
    pdf.set_text_color(20, 24, 30)
    pdf.ln(2)


def _classification_color(classification):
    colors = {
        "BAJO": (111, 227, 166),
        "MEDIO": (242, 196, 92),
        "ALTO": (255, 145, 86),
        "CRITICO": (255, 86, 64),
        "CRÍTICO": (255, 86, 64),
        "NO_EVALUABLE": (155, 167, 180),
    }
    return colors.get(classification, colors["NO_EVALUABLE"])


def _visible_action_meta(action):
    return (
        f"Esfuerzo: {display_label(action.get('effort_level'))}; "
        f"Beneficio: {display_label(action.get('benefit_level'))}; "
        f"Costo: {display_label(action.get('cost_level'))}; "
        f"Plazo: {display_label(action.get('time_horizon'))}"
    )


def _technical_value(raw_value, key_value):
    if key_value == "UNKNOWN":
        return "No interpretada (UNKNOWN)"
    raw_label = display_label(raw_value)
    key_label = display_label(key_value)
    if key_value and raw_value != key_value:
        return f"{raw_label} ({key_value})"
    if key_value and key_label != key_value:
        return f"{key_label} ({key_value})"
    return raw_label


def _wss_component_value(value):
    if value is None:
        return "s/d"
    return value


def build_pdf_report(results, metadata, anonymize=False, user_profile=DEFAULT_USER_PROFILE,
                     organization=None):
    if not results or not metadata:
        return {"ok": False, "error": "No hay resultados para exportar."}

    report = build_report(
        results,
        metadata,
        anonymize=bool(anonymize),
        user_profile=user_profile,
        organization=organization,
    )
    pdf = WssPdf(format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_margins(16, 16, 16)
    pdf.add_page()

    meta = report["report_metadata"]
    logical_results = group_logical_networks(report["results"])
    pdf_summary = summarize_pdf_results(report["results"], logical_results, source_type=meta["source_type"])
    source_labels = {
        SOURCE_LIVE_SCAN: "escaneo real",
        SOURCE_FILE_IMPORT: "archivo TXT",
        SOURCE_DEMO: "demostración",
    }
    visible_text = []
    pdf.visible_text = visible_text

    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(20, 24, 30)
    pdf.multi_cell(0, 8, "WSS Framework")
    pdf.set_font("Helvetica", "", 12)
    pdf.multi_cell(
        0,
        6,
        "Sistema automatizado de evaluación de seguridad Wi-Fi",
    )
    pdf.ln(4)
    _add_pdf_line(pdf, "Organización evaluada", organization or "No informada")
    _add_pdf_line(pdf, "Fecha y hora", format_display_datetime(datetime.now()))
    _add_pdf_line(pdf, "Tipo de origen", source_labels.get(meta["source_type"], meta["source_type"]))
    _add_pdf_line(pdf, "Datos sintéticos", "Sí" if meta["synthetic_data"] else "No")
    _add_pdf_line(pdf, "Versión del motor", meta["engine_version"])
    _add_pdf_line(pdf, "Estado del modelo", display_label(MODEL_STATUS))
    _add_pdf_line(pdf, "Anonimización aplicada", "Sí" if meta["anonymized"] else "No")
    _add_pdf_line(pdf, "Perfil de recomendación", display_label(meta["selected_user_profile"]))
    visible_text.extend([
        "WSS Framework",
        organization or "No informada",
        display_label(meta["selected_user_profile"]),
    ])

    pdf.ln(4)
    _pdf_section(pdf, "Resumen ejecutivo", visible_text)
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 5, _pdf_text(SCOPE_TEXT))
    summary_lines = [
        f"Resultados de red generados: {pdf_summary['total_results']}",
        f"Redes con SSID identificable: {pdf_summary['identifiable_networks']}",
        f"Observaciones de SSID oculto: {pdf_summary['hidden_observations']}",
        f"Evaluaciones completas: {pdf_summary['complete_evaluations']}",
        f"Evaluaciones incompletas: {pdf_summary['incomplete_evaluations']}",
        f"BSSID o radios observados: {pdf_summary['observed_radios']}",
        f"Resultados que requieren atención: {pdf_summary['attention_required']}",
        "Distribución: " + ", ".join(
            f"{display_label(key)}: {value}" for key, value in sorted(pdf_summary["by_classification"].items())
        ),
    ]
    for line in summary_lines:
        pdf.multi_cell(0, 5, _pdf_text(line))
        visible_text.append(line)

    practices = []
    for index, item in enumerate(logical_results, start=1):
        _ensure_pdf_space(pdf, 106)
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_fill_color(248, 250, 252)
        pdf.cell(0, 8, _pdf_text(f"Resultado por red {index}: {item.get('ssid')}"), ln=1, fill=True)
        visible_text.append(f"Resultado por red {index}: {item.get('ssid')}")
        classification = item.get("classification") or "NO_EVALUABLE"
        score_text = "Sin puntaje" if item.get("wss_score") is None else str(item.get("wss_score")).replace(".", ",")
        _pdf_score_classification_row(pdf, score_text, classification)
        _add_pdf_line(pdf, "Estado sencillo", item.get("simple_status"))
        _add_pdf_line(pdf, "Clasificación", display_label(classification))
        _add_pdf_line(pdf, "Hallazgo", item.get("finding_title"))
        _add_pdf_line(pdf, "Acción principal", item.get("recommended_action"))
        _add_pdf_line(pdf, "Perfil de recomendación", display_label(item.get("selected_user_profile")))
        visible_text.extend([score_text, display_label(classification), item.get("simple_status") or ""])

        actions = visible_actions(item.get("prioritized_actions", []))
        if actions:
            primary = actions[0]
            _add_pdf_line(pdf, "Esfuerzo / beneficio / costo / plazo", _visible_action_meta(primary))
            visible_text.append(_visible_action_meta(primary))
            if len(actions) > 1:
                _add_pdf_line(
                    pdf,
                    "Alternativas",
                    "; ".join(action["title"] for action in actions[1:]),
                )

        _add_pdf_line(pdf, "Limitaciones", item.get("limitations"))
        _add_pdf_line(pdf, "Observación sobre radios o AP", display_label(item.get("observation_status")))
        _add_pdf_line(pdf, "Regla aplicada", item.get("recommendation_rule_id"))

        _pdf_section(pdf, "Detalles técnicos", visible_text)
        vector = split_wss_vector(item.get("wss_vector"))
        technical_rows = [
            ("Autenticación", _technical_value(item.get("auth_raw"), item.get("auth_key"))),
            ("Cifrado", _technical_value(item.get("cipher_raw"), item.get("cipher_key"))),
            ("Versión del esquema WSS", vector.get("schema_version")),
            ("AU / EN / EX / AN / BM", (
                f"{_display_value(item.get('au'))} / {_display_value(item.get('en'))} / "
                f"{_display_value(item.get('ex'))} / {_display_value(item.get('an'))} / "
                f"{display_label(_wss_component_value(item.get('bm_label') or item.get('bm')))}"
            )),
        ]
        for label, value in technical_rows:
            _add_pdf_line(pdf, label, value)

        _ensure_pdf_space(pdf, 10 + (len(item.get("logical_radios", [])) * 6))
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 6, "Radios o puntos de acceso", ln=1)
        pdf.set_font("Helvetica", "", 8)
        for radio in item.get("logical_radios", []):
            row = (
                f"BSSID: {_display_value(radio.get('bssid'))} | "
                f"Señal: {_display_value(radio.get('signal_pct'))} | "
                f"Banda: {_display_value(radio.get('band'))} | "
                f"Canal: {_display_value(radio.get('channel'))} | "
                f"Radio: {_display_value(radio.get('radio_type'))} | "
                f"Autenticación: {_technical_value(radio.get('auth_raw'), radio.get('auth_key'))} | "
                f"Cifrado: {_technical_value(radio.get('cipher_raw'), radio.get('cipher_key'))} | "
                f"MFP: {_display_value(radio.get('mfp_required'))}"
            )
            pdf.multi_cell(0, 5, _pdf_text(row))
            visible_text.append(row)

        _ensure_pdf_space(pdf, 62)
        _pdf_section(pdf, "Trazabilidad", visible_text)
        trace_rows = [
            ("Origen", meta.get("source_label")),
            ("Archivo", meta.get("source_filename")),
            ("Versión del motor", meta.get("engine_version")),
            ("Regla y versión", f"{item.get('recommendation_rule_id')} / {item.get('recommendation_rule_version')}"),
            ("Estado de evaluación", display_label(item.get("evaluation_status"))),
            ("Estado de infraestructura", display_label(item.get("observation_status"))),
            ("Fecha de procesamiento", format_display_datetime(item.get("processed_at"))),
            ("Anonimización aplicada", "Sí" if meta["anonymized"] else "No"),
        ]
        for label, value in trace_rows:
            _add_pdf_line(pdf, label, value)
            visible_text.append(f"{label}: {_display_value(value)}")
        practices.extend(item.get("complementary_practices", []))

    if practices:
        _pdf_section(pdf, "Buenas prácticas complementarias", visible_text)
        pdf.set_font("Helvetica", "", 9)
        for practice in sorted(set(practices)):
            pdf.multi_cell(0, 5, _pdf_text(f"- {practice}"))
            visible_text.append(practice)

    page_count = pdf.page_no()
    raw_output = pdf.output(dest="S")
    pdf_bytes = raw_output.encode("latin-1") if isinstance(raw_output, str) else bytes(raw_output)
    return {
        "ok": True,
        "pdf_bytes": pdf_bytes,
        "report": report,
        "logical_network_count": len(logical_results),
        "page_count": page_count,
        "visible_text": "\n".join(_pdf_text(text) for text in visible_text if text),
    }


class WssApi:
    """
    Clase expuesta a JavaScript. Cada metodo publico aqui es invocable
    desde el frontend como: window.pywebview.api.<metodo>(...).
    """

    def __init__(self):
        self.last_results = []
        self.last_metadata = None
        self.selected_user_profile = DEFAULT_USER_PROFILE

    def _store(self, response):
        if response.get("ok"):
            self.last_results = response.get("results", [])
            self.last_metadata = response.get("metadata")
        return response

    def update_recommendation_profile(self, target_user=DEFAULT_USER_PROFILE):
        if not self.last_results or not self.last_metadata:
            return {"ok": False, "error": "No hay resultados para actualizar."}
        self.selected_user_profile = recommendation_engine.normalize_target_user(target_user)
        self.last_results = apply_recommendations(
            self.last_results,
            target_user=self.selected_user_profile,
        )
        return {
            "ok": True,
            "results": self.last_results,
            "metadata": self.last_metadata,
            "selected_user_profile": self.selected_user_profile,
        }

    def scan_networks(self):
        try:
            results = wss_engine.evaluate_networks(
                source_type=SOURCE_LIVE_SCAN,
                source_label="Escaneo real del equipo evaluador",
                synthetic_data=False,
            )
            results = assign_hidden_ssid_identifiers(results)
            results = apply_recommendations(results, target_user=self.selected_user_profile)
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
        results = assign_hidden_ssid_identifiers(wss_engine.evaluate_networks_demo())
        results = apply_recommendations(
            results,
            target_user=self.selected_user_profile,
        )
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
            target_user=self.selected_user_profile,
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

    def _resolve_export_path(self, file_type, anonymize=False, selected_path=None):
        extension = ".pdf" if file_type == "PDF" else ".json"
        if selected_path is not None:
            if not selected_path:
                return {"ok": False, "cancelled": True}
            return {"ok": True, "path": ensure_extension(selected_path, extension)}
        return choose_save_path(file_type, anonymize=bool(anonymize))

    def export_json(self, anonymize=False, selected_path=None):
        if not self.last_results or not self.last_metadata:
            return {"ok": False, "error": "No hay resultados para exportar."}

        path_result = self._resolve_export_path("JSON", anonymize=anonymize, selected_path=selected_path)
        if not path_result.get("ok"):
            if path_result.get("cancelled"):
                return {"ok": False, "cancelled": True, "message": "La exportación fue cancelada."}
            return path_result

        report = build_report(
            self.last_results,
            self.last_metadata,
            anonymize=bool(anonymize),
            user_profile=self.selected_user_profile,
        )
        generated_at = datetime.now().isoformat()
        write_result = write_json_report(path_result["path"], report)
        if not write_result.get("ok"):
            return write_result

        return export_success_response(
            write_result["path"],
            "JSON",
            anonymize=anonymize,
            generated_at=generated_at,
            report=report,
        )

    def export_pdf(self, anonymize=False, organization=None, selected_path=None):
        if not self.last_results or not self.last_metadata:
            return {"ok": False, "error": "No hay resultados para exportar."}

        path_result = self._resolve_export_path("PDF", anonymize=anonymize, selected_path=selected_path)
        if not path_result.get("ok"):
            if path_result.get("cancelled"):
                return {"ok": False, "cancelled": True, "message": "La exportación fue cancelada."}
            return path_result

        built = build_pdf_report(
            self.last_results,
            self.last_metadata,
            anonymize=bool(anonymize),
            user_profile=self.selected_user_profile,
            organization=organization,
        )
        if not built.get("ok"):
            return built

        generated_at = datetime.now().isoformat()
        write_result = write_pdf_report(path_result["path"], built["pdf_bytes"])
        if not write_result.get("ok"):
            return write_result

        return export_success_response(
            write_result["path"],
            "PDF",
            anonymize=anonymize,
            generated_at=generated_at,
            report=built["report"],
        ) | {
            "logical_network_count": built.get("logical_network_count"),
            "page_count": built.get("page_count"),
        }

    def open_exported_file(self, saved_path):
        file_path = Path(saved_path)
        if not file_path.exists() or not file_path.is_file():
            return {"ok": False, "error": "El archivo indicado no existe."}
        try:
            if platform.system() == "Windows":
                os.startfile(str(file_path.resolve()))  # noqa: S606 - ruta validada como archivo existente.
            else:
                return {"ok": False, "error": "Apertura automatica no disponible en este sistema."}
        except OSError as e:
            return {"ok": False, "error": f"No se pudo abrir el archivo: {e}"}
        return {"ok": True}

    def show_exported_file_in_folder(self, saved_path):
        file_path = Path(saved_path)
        if not file_path.exists() or not file_path.is_file():
            return {"ok": False, "error": "El archivo indicado no existe."}
        try:
            if platform.system() == "Windows":
                subprocess.Popen(["explorer", "/select,", str(file_path.resolve())])
            else:
                return {"ok": False, "error": "Mostrar en carpeta no esta disponible en este sistema."}
        except OSError as e:
            return {"ok": False, "error": f"No se pudo abrir la carpeta: {e}"}
        return {"ok": True}


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
