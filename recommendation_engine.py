"""
recommendation_engine.py
Motor trazable de recomendaciones para resultados normalizados del WSS.

Este modulo no calcula WSS ni altera pesos, umbrales o tablas tecnicas.
Solo interpreta el resultado ya normalizado para producir mensajes de vista
sencilla, acciones priorizadas y campos de trazabilidad.
"""

from copy import deepcopy
from datetime import datetime


RULE_VERSION = "REC-2026-07-15"

TARGET_NETWORK_OWNER = "NETWORK_OWNER"
TARGET_NETWORK_USER = "NETWORK_USER"
TARGET_TECHNICAL_RESPONSIBLE = "TECHNICAL_RESPONSIBLE"
TARGET_GENERAL = "GENERAL"

ALLOWED_TARGET_USERS = {
    TARGET_NETWORK_OWNER,
    TARGET_NETWORK_USER,
    TARGET_TECHNICAL_RESPONSIBLE,
    TARGET_GENERAL,
}
ALLOWED_EFFORT_LEVELS = {"LOW", "MEDIUM", "HIGH"}
ALLOWED_BENEFIT_LEVELS = {"LOW", "MEDIUM", "HIGH"}
ALLOWED_COST_LEVELS = {"NO_COST", "LOW", "MEDIUM", "HIGH", "UNKNOWN"}
ALLOWED_TIME_HORIZONS = {"IMMEDIATE", "SHORT_TERM", "PLANNED"}
ALLOWED_ACTION_TYPES = {"PRIMARY", "ALTERNATIVE", "DEFINITIVE", "COMPLEMENTARY"}

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


def _action(action_id, action_type, target_user, title, description,
            effort_level, benefit_level, cost_level, time_horizon,
            display_order, is_temporary=False, prerequisites=None,
            limitations=None):
    action = {
        "action_id": action_id,
        "action_type": action_type,
        "target_user": target_user,
        "title": title,
        "description": description,
        "effort_level": effort_level,
        "benefit_level": benefit_level,
        "cost_level": cost_level,
        "time_horizon": time_horizon,
        "display_order": display_order,
        "is_temporary": bool(is_temporary),
        "prerequisites": prerequisites or [],
        "limitations": limitations or [],
    }
    _validate_action(action)
    return action


def _validate_action(action):
    if action["target_user"] not in ALLOWED_TARGET_USERS:
        raise ValueError(f"target_user no permitido: {action['target_user']}")
    if action["effort_level"] not in ALLOWED_EFFORT_LEVELS:
        raise ValueError(f"effort_level no permitido: {action['effort_level']}")
    if action["benefit_level"] not in ALLOWED_BENEFIT_LEVELS:
        raise ValueError(f"benefit_level no permitido: {action['benefit_level']}")
    if action["cost_level"] not in ALLOWED_COST_LEVELS:
        raise ValueError(f"cost_level no permitido: {action['cost_level']}")
    if action["time_horizon"] not in ALLOWED_TIME_HORIZONS:
        raise ValueError(f"time_horizon no permitido: {action['time_horizon']}")
    if action["action_type"] not in ALLOWED_ACTION_TYPES:
        raise ValueError(f"action_type no permitido: {action['action_type']}")


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


def _with_infrastructure_note(response, result, target_user=TARGET_GENERAL):
    note = INFRASTRUCTURE_NOTES.get(result.get("observation_status"))
    response["infrastructure_note"] = note
    response["simple_status"] = simple_status_for_result(result)
    response["prioritized_actions"] = prioritized_actions_for_result(
        result,
        response["rule_id"],
        response["rule_version"],
        target_user=target_user,
    )
    primary = first_display_action(response["prioritized_actions"])
    if primary:
        response["recommended_action"] = primary["title"]
    return response


def simple_status_for_result(result):
    if result.get("observation_status") == "SECURITY_PROFILE_MISMATCH":
        return "Requiere verificación técnica"
    if result.get("evaluation_status") != "COMPLETE":
        return CLASSIFICATION_PRESENTATION["NO_EVALUABLE"]
    classification = result.get("classification") or "NO_EVALUABLE"
    return CLASSIFICATION_PRESENTATION.get(classification, CLASSIFICATION_PRESENTATION["NO_EVALUABLE"])


def normalize_target_user(target_user):
    if target_user in {TARGET_NETWORK_OWNER, TARGET_NETWORK_USER}:
        return target_user
    return TARGET_GENERAL


def first_display_action(actions):
    visible = [item for item in actions if item["action_type"] in {"PRIMARY", "ALTERNATIVE", "DEFINITIVE"}]
    return sorted(visible, key=lambda item: item["display_order"])[0] if visible else None


def prioritized_actions_for_result(result, rule_id, rule_version=RULE_VERSION,
                                   target_user=TARGET_GENERAL, generated_at=None):
    generated_at = generated_at or datetime.now().isoformat()
    target_user = normalize_target_user(target_user)
    base_actions = _actions_for_rule(rule_id, result, target_user)
    ordered = sorted(base_actions, key=lambda item: item["display_order"])
    traced = []
    for item in ordered:
        copy = deepcopy(item)
        copy["recommendation_rule_id"] = rule_id
        copy["recommendation_rule_version"] = rule_version
        copy["selected_user_profile"] = target_user
        copy["generated_at"] = generated_at
        traced.append(copy)
    return traced


def _actions_for_rule(rule_id, result, target_user):
    if target_user == TARGET_NETWORK_USER:
        return _user_actions(rule_id)
    if target_user == TARGET_NETWORK_OWNER:
        return _owner_actions(rule_id)
    return _general_actions(rule_id, result)


def _owner_actions(rule_id):
    if rule_id == "REC-01":
        return [
            _action("ACT-REC01-OWN-01", "PRIMARY", TARGET_NETWORK_OWNER,
                    "Mantener la configuración actual",
                    "Conservar WPA3 con CCMP dentro de los parámetros observados.",
                    "LOW", "MEDIUM", "NO_COST", "IMMEDIATE", 1),
            _action("ACT-REC01-OWN-02", "COMPLEMENTARY", TARGET_NETWORK_OWNER,
                    "Revisar actualizaciones del router",
                    "Verificar periódicamente firmware y configuración del equipo.",
                    "LOW", "MEDIUM", "NO_COST", "SHORT_TERM", 2),
            _action("ACT-REC01-OWN-03", "COMPLEMENTARY", TARGET_NETWORK_OWNER,
                    "Conservar buenas prácticas complementarias",
                    "Mantener contraseña robusta y revisar dispositivos conectados.",
                    "LOW", "MEDIUM", "NO_COST", "PLANNED", 3),
        ]
    if rule_id == "REC-02":
        return [
            _action("ACT-REC02-OWN-01", "PRIMARY", TARGET_NETWORK_OWNER,
                    "Mantener WPA2 con CCMP/AES",
                    "La configuración observada es adecuada dentro del alcance del sistema.",
                    "LOW", "MEDIUM", "NO_COST", "IMMEDIATE", 1),
            _action("ACT-REC02-OWN-02", "ALTERNATIVE", TARGET_NETWORK_OWNER,
                    "Verificar compatibilidad con WPA3",
                    "Revisar si el equipo permite migrar a WPA3 sin afectar dispositivos autorizados.",
                    "MEDIUM", "MEDIUM", "UNKNOWN", "PLANNED", 2),
            _action("ACT-REC02-OWN-03", "COMPLEMENTARY", TARGET_NETWORK_OWNER,
                    "Mantener firmware actualizado",
                    "Aplicar actualizaciones del fabricante como práctica complementaria no verificada.",
                    "LOW", "MEDIUM", "NO_COST", "SHORT_TERM", 3),
        ]
    if rule_id == "REC-03":
        return [
            _action("ACT-REC03-OWN-01", "PRIMARY", TARGET_NETWORK_OWNER,
                    "Migrar a WPA2 con CCMP/AES o WPA3",
                    "Cambiar la configuración para dejar de usar TKIP.",
                    "MEDIUM", "HIGH", "LOW", "SHORT_TERM", 1),
            _action("ACT-REC03-OWN-02", "ALTERNATIVE", TARGET_NETWORK_OWNER,
                    "Solicitar asistencia técnica",
                    "Pedir apoyo al responsable técnico o proveedor para aplicar la configuración.",
                    "LOW", "HIGH", "UNKNOWN", "SHORT_TERM", 2),
            _action("ACT-REC03-OWN-03", "DEFINITIVE", TARGET_NETWORK_OWNER,
                    "Reemplazar el equipo si no admite configuraciones modernas",
                    "Planificar el reemplazo del router si no permite WPA2/CCMP o WPA3.",
                    "HIGH", "HIGH", "HIGH", "PLANNED", 3),
        ]
    if rule_id == "REC-04":
        return [
            _action("ACT-REC04-OWN-01", "PRIMARY", TARGET_NETWORK_OWNER,
                    "Migrar a WPA2 con CCMP/AES o WPA3",
                    "Reemplazar WEP por una configuración moderna de autenticación y cifrado.",
                    "MEDIUM", "HIGH", "LOW", "SHORT_TERM", 1),
            _action("ACT-REC04-OWN-02", "ALTERNATIVE", TARGET_NETWORK_OWNER,
                    "Solicitar configuración técnica",
                    "Pedir al responsable técnico o proveedor que retire WEP.",
                    "LOW", "HIGH", "UNKNOWN", "SHORT_TERM", 2),
            _action("ACT-REC04-OWN-03", "DEFINITIVE", TARGET_NETWORK_OWNER,
                    "Reemplazar el equipo si es necesario",
                    "Sustituir el router si no admite WPA2 con CCMP/AES o WPA3.",
                    "HIGH", "HIGH", "HIGH", "PLANNED", 3),
        ]
    if rule_id == "REC-05":
        return [
            _action("ACT-REC05-OWN-01", "PRIMARY", TARGET_NETWORK_OWNER,
                    "Activar WPA2 con CCMP/AES o WPA3 y establecer una contraseña",
                    "Configurar protección inalámbrica moderna para la red.",
                    "MEDIUM", "HIGH", "LOW", "SHORT_TERM", 1),
            _action("ACT-REC05-OWN-02", "ALTERNATIVE", TARGET_NETWORK_OWNER,
                    "Solicitar al responsable técnico o proveedor que realice la configuración",
                    "Delegar la configuración cuando no se tenga acceso o conocimiento técnico suficiente.",
                    "LOW", "HIGH", "UNKNOWN", "SHORT_TERM", 2),
            _action("ACT-REC05-OWN-03", "DEFINITIVE", TARGET_NETWORK_OWNER,
                    "Reemplazar el router si no admite WPA2 o WPA3",
                    "Planificar el cambio del equipo si no permite una configuración protegida.",
                    "HIGH", "HIGH", "HIGH", "PLANNED", 3),
        ]
    return _general_actions(rule_id, {})


def _user_actions(rule_id):
    if rule_id in {"REC-04", "REC-05"}:
        return [
            _action("ACT-USER-UNSAFE-01", "PRIMARY", TARGET_NETWORK_USER,
                    "Evitar operaciones sensibles, financieras o institucionales",
                    "No enviar información sensible cuando la red observada sea abierta o use WEP.",
                    "LOW", "HIGH", "NO_COST", "IMMEDIATE", 1, is_temporary=True),
            _action("ACT-USER-UNSAFE-02", "ALTERNATIVE", TARGET_NETWORK_USER,
                    "Utilizar datos móviles o un punto de acceso personal",
                    "Preferir una conexión alternativa cuando sea posible.",
                    "MEDIUM", "HIGH", "UNKNOWN", "IMMEDIATE", 2, is_temporary=True),
            _action("ACT-USER-UNSAFE-03", "COMPLEMENTARY", TARGET_NETWORK_USER,
                    "Utilizar una VPN confiable o aprobada por la organización",
                    "Aplicarla solo cuando no exista otra alternativa y sin asumir seguridad absoluta.",
                    "MEDIUM", "MEDIUM", "UNKNOWN", "IMMEDIATE", 3, is_temporary=True,
                    limitations=["Una VPN no vuelve segura toda la red."]),
        ]
    if rule_id == "REC-03":
        return [
            _action("ACT-USER-TKIP-01", "PRIMARY", TARGET_NETWORK_USER,
                    "Evitar enviar información sensible si existe otra alternativa",
                    "Reducir el uso de la red para operaciones sensibles.",
                    "LOW", "MEDIUM", "NO_COST", "IMMEDIATE", 1, is_temporary=True),
            _action("ACT-USER-TKIP-02", "ALTERNATIVE", TARGET_NETWORK_USER,
                    "Preferir otra red con WPA2/CCMP o WPA3",
                    "Usar una red con configuración más adecuada si está disponible.",
                    "MEDIUM", "HIGH", "UNKNOWN", "IMMEDIATE", 2, is_temporary=True),
            _action("ACT-USER-TKIP-03", "COMPLEMENTARY", TARGET_NETWORK_USER,
                    "Consultar al responsable de la red",
                    "Informar la observación para que pueda revisarse la configuración.",
                    "LOW", "MEDIUM", "NO_COST", "SHORT_TERM", 3),
        ]
    if rule_id in {"REC-01", "REC-02"}:
        return [
            _action("ACT-USER-OK-01", "PRIMARY", TARGET_NETWORK_USER,
                    "Puede utilizarse dentro de los parámetros observados",
                    "La configuración visible es adecuada, sin representar seguridad absoluta.",
                    "LOW", "MEDIUM", "NO_COST", "IMMEDIATE", 1),
            _action("ACT-USER-OK-02", "COMPLEMENTARY", TARGET_NETWORK_USER,
                    "Mantener precauciones normales",
                    "Evitar compartir credenciales y verificar que se trata de la red esperada.",
                    "LOW", "MEDIUM", "NO_COST", "IMMEDIATE", 2),
        ]
    return _general_actions(rule_id, {})


def _general_actions(rule_id, result):
    if rule_id in {"REC-01", "REC-02"}:
        return [
            _action("ACT-GEN-OK-01", "PRIMARY", TARGET_GENERAL,
                    "Puede utilizarse dentro de los parámetros observados",
                    "La configuración visible es adecuada, sin representar seguridad absoluta.",
                    "LOW", "MEDIUM", "NO_COST", "IMMEDIATE", 1),
            _action("ACT-GEN-OK-02", "COMPLEMENTARY", TARGET_GENERAL,
                    "Mantener precauciones normales",
                    "Verificar que se trata de la red esperada y evitar compartir credenciales.",
                    "LOW", "MEDIUM", "NO_COST", "IMMEDIATE", 2),
        ]
    if rule_id in {"REC-03", "REC-04", "REC-05"}:
        return [
            _action("ACT-GEN-ATT-01", "PRIMARY", TARGET_GENERAL,
                    "Solicitar revisión al responsable de la red",
                    "Usar el resultado como alerta técnica inicial y pedir verificación autorizada.",
                    "LOW", "HIGH", "UNKNOWN", "SHORT_TERM", 1),
            _action("ACT-GEN-ATT-02", "ALTERNATIVE", TARGET_GENERAL,
                    "Evitar operaciones sensibles si solo desea conectarse",
                    "Cuando no se conoce la responsabilidad sobre la red, actuar con prudencia.",
                    "LOW", "MEDIUM", "NO_COST", "IMMEDIATE", 2, is_temporary=True),
        ]
    if rule_id == "REC-07":
        return [
            _action("ACT-REC07-GEN-01", "PRIMARY", TARGET_GENERAL,
                    "Solicitar verificación técnica de la infraestructura",
                    "Confirmar cuáles puntos de acceso están autorizados antes de concluir.",
                    "MEDIUM", "HIGH", "UNKNOWN", "SHORT_TERM", 1,
                    limitations=["No confirma ataque ni Evil Twin."]),
            _action("ACT-REC07-GEN-02", "ALTERNATIVE", TARGET_GENERAL,
                    "Comparar con una línea base autorizada",
                    "Revisar inventario o configuración esperada de la organización.",
                    "MEDIUM", "HIGH", "UNKNOWN", "PLANNED", 2),
        ]
    if rule_id == "REC-06":
        return [
            _action("ACT-REC06-GEN-01", "PRIMARY", TARGET_GENERAL,
                    "Repetir la evaluación o cargar una captura legible",
                    "Obtener datos interpretables antes de emitir una conclusión.",
                    "LOW", "MEDIUM", "NO_COST", "IMMEDIATE", 1),
            _action("ACT-REC06-GEN-02", "ALTERNATIVE", TARGET_GENERAL,
                    "Solicitar revisión técnica",
                    "Pedir apoyo para interpretar los campos no reconocidos.",
                    "MEDIUM", "MEDIUM", "UNKNOWN", "SHORT_TERM", 2),
        ]
    return [
        _action("ACT-GEN-01", "PRIMARY", TARGET_GENERAL,
                "Revisar la configuración con el responsable de la red",
                "Usar el resultado como orientación técnica inicial.",
                "MEDIUM", "MEDIUM", "UNKNOWN", "SHORT_TERM", 1),
    ]


def recommend_for_result(result, target_user=TARGET_GENERAL):
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
        ), result, target_user)

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
        ), result, target_user)

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
        ), result, target_user)

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
        ), result, target_user)

    if auth_key in {"WPA-PSK", "WPA2-PSK"} and cipher_key == "TKIP":
        return _with_infrastructure_note(_base_response(
            "REC-03",
            "Requiere atención",
            "Método de protección antiguo",
            "La red utiliza un método de protección antiguo que ofrece menor seguridad que las alternativas actuales.",
            "Migrar a WPA2 con CCMP/AES o a WPA3.",
            "Alta",
            "Uso de WPA/WPA2 con TKIP dentro de los parámetros observados.",
            warning="Cambiar solamente la contraseña no reemplaza el cifrado antiguo.",
        ), result, target_user)

    if cipher_key == "WEP":
        return _with_infrastructure_note(_base_response(
            "REC-04",
            "Protección insuficiente",
            "Tecnología de seguridad obsoleta",
            "La red utiliza una tecnología de seguridad obsoleta dentro de los parámetros observados.",
            "Migrar a WPA2 con CCMP/AES o WPA3. Considerar reemplazar el equipo si no admite opciones modernas.",
            "Inmediata",
            "WEP observado como mecanismo de cifrado.",
            warning="No afirmar validación experimental si WEP no fue instanciado físicamente.",
        ), result, target_user)

    if auth_key == "OPEN" or cipher_key == "NONE":
        return _with_infrastructure_note(_base_response(
            "REC-05",
            "Protección insuficiente",
            "Red sin cifrado inalámbrico",
            "La red no utiliza cifrado para proteger la comunicación inalámbrica.",
            "Activar WPA2 con CCMP/AES o WPA3 y establecer una contraseña segura.",
            "Inmediata",
            "Red abierta o sin cifrado dentro de los parámetros observados.",
        ), result, target_user)

    return _with_infrastructure_note(_base_response(
        "REC-06",
        "No se pudo completar la evaluación",
        "Parámetro no interpretado",
        "El sistema detectó la red, pero no pudo interpretar uno o más parámetros.",
        "Repetir la evaluación o solicitar una revisión técnica.",
        "Media",
        "Combinación no contemplada por las reglas actuales.",
        warning="No se asigna conclusión definitiva.",
    ), result, target_user)
