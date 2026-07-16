"""
recommendation_engine.py
Motor trazable de recomendaciones para resultados normalizados del WSS.

Este modulo no calcula WSS ni altera pesos, umbrales o tablas tecnicas.
Solo interpreta el resultado ya normalizado para producir mensajes de vista
sencilla y campos de trazabilidad.
"""

RULE_VERSION = "REC-2026-07-15"

CLASSIFICATION_PRESENTATION = {
    "BAJO": "Configuración adecuada",
    "MEDIO": "Puede mejorar",
    "ALTO": "Requiere atención",
    "CRITICO": "Protección insuficiente",
    "CRÍTICO": "Protección insuficiente",
    "NO_EVALUABLE": "No se pudo completar la evaluación",
}

COMPLEMENTARY_PRACTICES = [
    "Utilizar una contraseña segura.",
    "Mantener el firmware del router actualizado.",
    "Cambiar credenciales predeterminadas del equipo.",
    "Utilizar una red separada para invitados.",
    "Revisar periódicamente los dispositivos conectados.",
]

COMPLEMENTARY_PRACTICES_HEADING = (
    "Buenas prácticas complementarias no verificadas por esta evaluación"
)

INFRASTRUCTURE_NOTES = {
    "MULTI_RADIO_OBSERVED": (
        "Se observaron varias radios compatibles con una red de doble banda."
    ),
    "MULTI_AP_OBSERVED": (
        "Se observaron varios puntos de acceso con el mismo nombre. Esto puede "
        "ser normal en redes mesh, repetidores o instalaciones con varios equipos."
    ),
}

DEFAULT_LIMITATION = (
    "Esta evaluación no comprobó contraseña, firmware, dispositivos conectados "
    "ni tráfico privado."
)

NO_ATTACK_WARNING = (
    "Esta evaluación no confirma ataque, intrusión ni Evil Twin."
)


def _base_response(rule_id, simple_status, finding_title, simple_explanation,
                   recommended_action, priority, technical_interpretation,
                   warning=None, limitations=None):
    return {
        "rule_id": rule_id,
        "simple_status": simple_status,
        "finding_title": finding_title,
        "technical_interpretation": technical_interpretation,
        "simple_explanation": simple_explanation,
        "recommended_action": recommended_action,
        "priority": priority,
        "warning": warning,
        "limitations": limitations or DEFAULT_LIMITATION,
        "complementary_practices": COMPLEMENTARY_PRACTICES,
        "complementary_practices_heading": COMPLEMENTARY_PRACTICES_HEADING,
        "rule_version": RULE_VERSION,
    }


def _with_infrastructure_note(response, result):
    note = INFRASTRUCTURE_NOTES.get(result.get("observation_status"))
    response["infrastructure_note"] = note
    response["simple_status"] = simple_status_for_result(result)
    return response


def simple_status_for_result(result):
    if result.get("observation_status") == "SECURITY_PROFILE_MISMATCH":
        return "Requiere verificación técnica"
    if result.get("evaluation_status") != "COMPLETE":
        return CLASSIFICATION_PRESENTATION["NO_EVALUABLE"]
    classification = result.get("classification") or "NO_EVALUABLE"
    return CLASSIFICATION_PRESENTATION.get(classification, CLASSIFICATION_PRESENTATION["NO_EVALUABLE"])


def recommend_for_result(result):
    """Devuelve la recomendacion trazable para un resultado de wss_engine."""
    observation_status = result.get("observation_status")
    auth_key = result.get("auth_key")
    cipher_key = result.get("cipher_key")
    classification = result.get("classification")

    if observation_status == "SECURITY_PROFILE_MISMATCH":
        return _with_infrastructure_note(_base_response(
            "REC-07",
            "Requiere verificación técnica",
            "Configuraciones diferentes bajo el mismo nombre de red",
            "Se observaron configuraciones de seguridad diferentes asociadas al mismo nombre de red.",
            "Confirmar con el responsable técnico cuáles son los puntos de acceso autorizados.",
            "Media",
            "El mismo SSID aparece con autenticación o cifrado diferente; requiere verificación técnica.",
            warning=NO_ATTACK_WARNING,
            limitations="No confirma ataque, Evil Twin ni intrusión.",
        ), result)

    if result.get("evaluation_status") != "COMPLETE" or classification == "NO_EVALUABLE":
        return _with_infrastructure_note(_base_response(
            "REC-06",
            "No se pudo completar la evaluación",
            "Parámetro no interpretado",
            "El sistema detectó la red, pero no pudo interpretar uno o más parámetros.",
            "Repetir la evaluación o solicitar una revisión técnica.",
            "Media",
            "Existen campos no interpretados; no se asigna score ni conclusión definitiva.",
            warning="No se asignó score ni conclusión definitiva.",
            limitations="La evaluación queda incompleta hasta interpretar los parámetros faltantes.",
        ), result)

    if auth_key == "SAE" and cipher_key == "CCMP":
        return _with_infrastructure_note(_base_response(
            "REC-01",
            "Configuración adecuada",
            "Protección inalámbrica moderna",
            "La red utiliza una tecnología moderna de protección inalámbrica dentro de los parámetros observados.",
            "Mantener la configuración y verificar periódicamente las actualizaciones del router.",
            "Baja",
            "WPA3-Personal con CCMP dentro de los parámetros observados.",
            limitations="No se evaluaron contraseña, firmware ni dispositivos conectados.",
        ), result)

    if auth_key == "WPA2-PSK" and cipher_key == "CCMP":
        return _with_infrastructure_note(_base_response(
            "REC-02",
            "Configuración adecuada",
            "Configuración de protección adecuada",
            "La red utiliza una configuración adecuada dentro de los parámetros observados.",
            "Mantener WPA2 con CCMP/AES o verificar si el equipo admite WPA3.",
            "Baja",
            "WPA2-Personal con CCMP/AES dentro de los parámetros observados.",
            warning="No recomendar TKIP.",
        ), result)

    if auth_key in {"WPA-PSK", "WPA2-PSK"} and cipher_key == "TKIP":
        return _with_infrastructure_note(_base_response(
            "REC-03",
            "Requiere atención",
            "Método de protección antiguo",
            "La red utiliza un método de protección antiguo que ofrece menor seguridad que las alternativas actuales.",
            "Migrar a WPA2 con CCMP/AES o a WPA3.",
            "Alta",
            "Uso de WPA/WPA2 con TKIP dentro de los parametros observados.",
            warning="Cambiar solamente la contraseña no reemplaza el cifrado antiguo.",
        ), result)

    if cipher_key == "WEP":
        return _with_infrastructure_note(_base_response(
            "REC-04",
            "Protección insuficiente",
            "Tecnología de seguridad obsoleta",
            "La red utiliza una tecnología de seguridad obsoleta dentro de los parámetros observados.",
            "Migrar a WPA2 con CCMP/AES o WPA3. Considerar reemplazar el equipo si no admite opciones modernas.",
            "Inmediata",
            "WEP observado como mecanismo de cifrado.",
            warning="No afirmar validacion experimental si WEP no fue instanciado fisicamente.",
        ), result)

    if auth_key == "OPEN" or cipher_key == "NONE":
        return _with_infrastructure_note(_base_response(
            "REC-05",
            "Protección insuficiente",
            "Red sin cifrado inalámbrico",
            "La red no utiliza cifrado para proteger la comunicación inalámbrica.",
            "Activar WPA2 con CCMP/AES o WPA3 y establecer una contraseña segura.",
            "Inmediata",
            "Red abierta o sin cifrado dentro de los parametros observados.",
        ), result)

    return _with_infrastructure_note(_base_response(
        "REC-06",
            "No se pudo completar la evaluación",
            "Parámetro no interpretado",
            "El sistema detectó la red, pero no pudo interpretar uno o más parámetros.",
            "Repetir la evaluación o solicitar una revisión técnica.",
        "Media",
            "Combinación no contemplada por las reglas actuales.",
        warning="No se asigna conclusión definitiva.",
    ), result)
