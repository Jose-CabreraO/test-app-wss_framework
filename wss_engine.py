"""
wss_engine.py
Motor de escaneo y calculo WSS para la app de escritorio.

Ejecuta `netsh wlan show networks mode=bssid` en Windows, parsea la salida,
normaliza los parametros segun el modelo de la tesis y calcula el Wireless
Severity Score (WSS) para cada red detectada.
"""

import platform
import re
import subprocess
import unicodedata
from datetime import datetime


ENGINE_VERSION = "2.0"

OBS_SINGLE_BSSID = "SINGLE_BSSID"
OBS_MULTI_RADIO = "MULTI_RADIO_OBSERVED"
OBS_MULTI_AP = "MULTI_AP_OBSERVED"
OBS_SECURITY_PROFILE_MISMATCH = "SECURITY_PROFILE_MISMATCH"
OBS_HIDDEN_SSID = "HIDDEN_SSID"
OBS_BASELINE_MISMATCH = "BASELINE_MISMATCH"

OBSERVATION_MESSAGES = {
    OBS_SINGLE_BSSID: "Se observo un unico BSSID para este nombre de red.",
    OBS_MULTI_RADIO: "Se observaron varias radios asociadas al mismo nombre de red. Esto es habitual en routers de doble banda.",
    OBS_MULTI_AP: "Se observaron varios puntos de acceso con el mismo nombre de red. Esto puede ser normal en redes mesh, repetidores o instalaciones con varios equipos.",
    OBS_SECURITY_PROFILE_MISMATCH: "Se observaron configuraciones de seguridad diferentes bajo el mismo nombre de red. Requiere verificacion tecnica.",
    OBS_HIDDEN_SSID: "Red con SSID oculto observada individualmente por BSSID.",
    OBS_BASELINE_MISMATCH: "Estado reservado para una linea base autorizada futura.",
}


# ---------------------------------------------------------------------------
# Modelo WSS - pesos y tablas de normalizacion
# ---------------------------------------------------------------------------

WEIGHTS = {
    "au": 0.30,
    "en": 0.25,
    "ex": 0.15,
    "an": 0.20,
    "bm": 0.10,
}

AUTH_VALUES = {
    "SAE": 0.1,        # WPA3-Personal
    "WPA2-PSK": 0.3,
    "WPA-PSK": 0.7,
    "OPEN": 1.0,
}

CIPHER_VALUES = {
    "CCMP": 0.1,
    "TKIP": 0.8,
    "WEP": 0.9,
    "NONE": 1.0,
}

EXPOSURE_VALUES = {
    "HIGH": 1.0,
    "MEDIUM": 0.8,
    "LOW": 0.5,
}

ANOMALY_VALUES = {
    "YES": 1.0,
    "NO": 0.0,
}

BM_VALUES = {
    "ALIGNED": 0.0,
    "PARTIAL": 0.5,
    "DEVIANT": 1.0,
}


def classify_exposure(rssi_dbm):
    """Clasifica el factor de exposicion EX a partir del RSSI medido."""
    if rssi_dbm is None:
        return "LOW"
    if rssi_dbm >= -50:
        return "HIGH"
    elif rssi_dbm >= -70:
        return "MEDIUM"
    return "LOW"


def determine_bm(auth_key, cipher_key, anomaly):
    """
    Determina el valor de benchmark (BM) comparando contra la linea base segura.
    Linea base: WPA3-SAE o WPA2-PSK con cifrado CCMP, sin anomalia.
    """
    secure_auth = auth_key in ("SAE", "WPA2-PSK")
    secure_cipher = cipher_key == "CCMP"
    no_anomaly = not anomaly

    if secure_auth and secure_cipher and no_anomaly:
        return "ALIGNED"
    elif secure_cipher and no_anomaly:
        return "PARTIAL"
    return "DEVIANT"


def calculate_wss(au, en, ex, an, bm):
    """Modelo extendido: R = (w1*AU + w2*EN + w3*EX + w4*AN + w5*BM) x 10"""
    r = (
        WEIGHTS["au"] * au +
        WEIGHTS["en"] * en +
        WEIGHTS["ex"] * ex +
        WEIGHTS["an"] * an +
        WEIGHTS["bm"] * bm
    ) * 10
    return round(r, 2)


def classify_score(score):
    if score <= 2.5:
        return "BAJO"
    elif score <= 5.0:
        return "MEDIO"
    elif score <= 7.5:
        return "ALTO"
    return "CRITICO"


# ---------------------------------------------------------------------------
# Parser de netsh (Windows)
# ---------------------------------------------------------------------------

def _repair_mojibake(text):
    """Repara texto UTF-8 leido accidentalmente como latin-1, si aplica."""
    if not isinstance(text, str) or not any(marker in text for marker in (chr(0x00C3), chr(0x00C2))):
        return text
    try:
        return text.encode("latin-1").decode("utf-8")
    except UnicodeError:
        return text


def _normalize_text(text):
    """Normaliza texto para parseo sin destruir el texto original almacenado."""
    if text is None:
        return ""
    text = str(text).lstrip("\ufeff")
    text = _repair_mojibake(text)
    return unicodedata.normalize("NFC", text)


def _strip_accents(text):
    return "".join(
        char for char in unicodedata.normalize("NFD", text)
        if unicodedata.category(char) != "Mn"
    )


def _normalize_label(label):
    label = _strip_accents(_normalize_text(label).casefold().strip())
    return re.sub(r"\s+", " ", label)


def _normalize_key(value):
    return _strip_accents(_normalize_text(value).upper())


def _split_netsh_field(line):
    if ":" not in line:
        return None, None
    label, value = line.split(":", 1)
    return _normalize_label(label), _normalize_text(value).strip()


def _map_auth(raw_auth):
    """Traduce el texto crudo de netsh a una clave normalizada de AUTH_VALUES."""
    raw = _normalize_key(raw_auth)
    if "WPA3" in raw or "SAE" in raw:
        return "SAE"
    if "WPA2" in raw:
        return "WPA2-PSK"
    if "WPA" in raw:
        return "WPA-PSK"
    if "OPEN" in raw or "ABIERTA" in raw or "ABIERTO" in raw:
        return "OPEN"
    return "UNKNOWN"


def _map_cipher(raw_cipher):
    """Traduce el texto crudo de netsh a una clave normalizada de CIPHER_VALUES."""
    raw = _normalize_key(raw_cipher)
    if "CCMP" in raw or "AES" in raw:
        return "CCMP"
    if "TKIP" in raw:
        return "TKIP"
    if "WEP" in raw:
        return "WEP"
    if "NONE" in raw or "NINGUNA" in raw or "NINGUNO" in raw:
        return "NONE"
    return "UNKNOWN"


def _signal_pct_to_rssi(pct):
    """
    netsh reporta intensidad de senal como porcentaje (0-100), no en dBm.
    Aproximacion estandar: rssi_dbm = (pct / 2) - 100
    (0% -> -100 dBm, 100% -> -50 dBm).
    """
    try:
        pct = float(pct)
    except (TypeError, ValueError):
        return None
    return round((pct / 2.0) - 100.0, 1)


def run_netsh_scan():
    """
    Ejecuta `netsh wlan show networks mode=bssid` y devuelve la salida cruda.
    Lanza RuntimeError con un mensaje claro si no se puede ejecutar.
    """
    if platform.system() != "Windows":
        raise RuntimeError(
            "El escaneo de redes solo esta disponible en Windows. "
            "Esta funcion utiliza 'netsh wlan show networks', que es "
            "especifico de ese sistema operativo."
        )

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8-sig",
            errors="replace",
        )
    except FileNotFoundError:
        raise RuntimeError(
            "No se encontro 'netsh'. Verifique que esta ejecutando la "
            "aplicacion en Windows con el servicio de WLAN habilitado."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("El escaneo de redes tardo demasiado y fue cancelado.")

    if result.returncode != 0:
        raise RuntimeError(
            "netsh no pudo completar el escaneo. Verifique que el "
            "adaptador Wi-Fi este habilitado.\n" + (result.stderr or "")
        )

    return result.stdout


def parse_netsh_output(raw_output):
    """
    Parsea la salida de `netsh wlan show networks mode=bssid` en una lista
    de redes con sus BSSIDs y parametros tecnicos.
    """
    networks = []
    current = None
    current_bssid = None

    lines = _normalize_text(raw_output).splitlines()

    for line in lines:
        line = _normalize_text(line).rstrip()
        stripped = line.strip()

        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", stripped)
        if ssid_match:
            if current and current.get("bssids"):
                networks.append(current)
            ssid_name = ssid_match.group(1).strip()
            current = {
                "ssid": ssid_name if ssid_name else "(SSID oculto)",
                "auth_raw": None,
                "cipher_raw": None,
                "bssids": [],
            }
            current_bssid = None
            continue

        if current is None:
            continue

        bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*(.*)$", stripped)
        if bssid_match:
            current_bssid = {
                "bssid": bssid_match.group(1).strip(),
                "signal_pct": None,
                "channel": None,
                "band": None,
                "radio_type": None,
                "mfp_required": None,
                "details": None,
            }
            current["bssids"].append(current_bssid)
            continue

        label, value = _split_netsh_field(stripped)
        if label is None:
            continue

        if label in {"autenticacion", "autenticacion de red", "authentication", "network authentication"}:
            current["auth_raw"] = value
            continue

        if label in {"cifrado", "cifrado de red", "encryption", "cipher", "network cipher"}:
            current["cipher_raw"] = value
            continue

        if current_bssid is None:
            continue

        if label in {"senal", "signal"}:
            signal_match = re.search(r"(\d+)", value)
            if signal_match:
                current_bssid["signal_pct"] = signal_match.group(1)
            continue

        if label in {"canal", "channel"}:
            channel_match = re.search(r"(\d+)", value)
            if channel_match:
                current_bssid["channel"] = channel_match.group(1)
            continue

        if label in {"banda", "band"}:
            current_bssid["band"] = value
            continue

        if label in {"tipo de radio", "radio type"}:
            current_bssid["radio_type"] = value
            continue

        if label == "mfp requerido":
            current_bssid["mfp_required"] = value
            continue

        if label == "detalles":
            current_bssid["details"] = value
            continue

    if current and current.get("bssids"):
        networks.append(current)

    hidden_count = 0
    for net in networks:
        net["hidden_ssid"] = net["ssid"] == "(SSID oculto)"
        if net["hidden_ssid"]:
            hidden_count += 1
            net["ssid"] = f"SSID oculto {hidden_count}"

    return networks


def analyze_observations(networks):
    """Clasifica observaciones de infraestructura sin convertirlas en anomalia WSS."""
    grouped = {}
    for net in networks:
        if net.get("hidden_ssid"):
            grouped[net["ssid"]] = {
                "status": OBS_HIDDEN_SSID,
                "message": OBSERVATION_MESSAGES[OBS_HIDDEN_SSID],
                "bssid_count": len(net.get("bssids", [])),
                "bands": sorted({b.get("band") for b in net.get("bssids", []) if b.get("band")}),
                "requires_review": False,
            }
            continue
        grouped.setdefault(net["ssid"], []).append(net)

    observations = {}
    for ssid, nets in grouped.items():
        if isinstance(nets, dict):
            observations[ssid] = nets
            continue

        bssids = []
        bands = set()
        profiles = set()
        for net in nets:
            auth_key = _map_auth(net.get("auth_raw"))
            cipher_key = _map_cipher(net.get("cipher_raw"))
            profiles.add((auth_key, cipher_key))
            for bssid in net.get("bssids", []):
                bssids.append(bssid)
                if bssid.get("band"):
                    bands.add(bssid["band"])

        if len(profiles) > 1:
            status = OBS_SECURITY_PROFILE_MISMATCH
            requires_review = True
        elif len(bssids) <= 1:
            status = OBS_SINGLE_BSSID
            requires_review = False
        elif len(bands) > 1:
            status = OBS_MULTI_RADIO
            requires_review = False
        else:
            status = OBS_MULTI_AP
            requires_review = False

        observations[ssid] = {
            "status": status,
            "message": OBSERVATION_MESSAGES[status],
            "bssid_count": len(bssids),
            "bands": sorted(bands),
            "requires_review": requires_review,
        }

    return observations


def detect_anomalies(networks):
    """Compatibilidad: AN=1 queda reservado y no se asigna automaticamente."""
    return set()


def evaluate_networks(
    raw_output=None,
    source_type="LIVE_SCAN",
    source_label=None,
    source_filename=None,
    captured_at=None,
    synthetic_data=False,
):
    """
    Punto de entrada principal: escanea si no se provee raw_output, parsea,
    detecta anomalias y calcula el WSS para cada BSSID evaluable.
    """
    if raw_output is None:
        raw_output = run_netsh_scan()

    processed_at = datetime.now().isoformat()
    networks = parse_netsh_output(raw_output)
    observations = analyze_observations(networks)

    results = []
    for net in networks:
        ssid = net["ssid"]
        auth_key = _map_auth(net.get("auth_raw"))
        cipher_key = _map_cipher(net.get("cipher_raw"))
        observation = observations.get(ssid, {
            "status": OBS_SINGLE_BSSID,
            "message": OBSERVATION_MESSAGES[OBS_SINGLE_BSSID],
            "bssid_count": len(net.get("bssids", [])),
            "bands": [],
            "requires_review": False,
        })
        is_anomalous_ssid = False

        for bssid_info in net["bssids"]:
            rssi = _signal_pct_to_rssi(bssid_info.get("signal_pct"))
            ex_label = classify_exposure(rssi)
            ex_val = EXPOSURE_VALUES[ex_label]
            an_val = ANOMALY_VALUES["YES"] if is_anomalous_ssid else ANOMALY_VALUES["NO"]

            unknown_fields = []
            if auth_key == "UNKNOWN":
                unknown_fields.append("auth")
            if cipher_key == "UNKNOWN":
                unknown_fields.append("cipher")

            if unknown_fields:
                au_val = None
                en_val = None
                bm_label = None
                bm_val = None
                score = None
                classification = "NO_EVALUABLE"
                vector = "INCOMPLETE"
                evaluation_status = "INCOMPLETE"
            else:
                au_val = AUTH_VALUES[auth_key]
                en_val = CIPHER_VALUES[cipher_key]
                bm_label = determine_bm(auth_key, cipher_key, is_anomalous_ssid)
                bm_val = BM_VALUES[bm_label]
                score = calculate_wss(au_val, en_val, ex_val, an_val, bm_val)
                classification = classify_score(score)
                vector = (
                    f"WSS:1.0/AU:{au_val}/EN:{en_val}/"
                    f"EX:{ex_val}/AN:{an_val}/BM:{bm_label}"
                )
                evaluation_status = "COMPLETE"

            results.append({
                "ssid": ssid,
                "bssid": bssid_info.get("bssid", "-"),
                "auth_raw": net.get("auth_raw") or "Desconocida",
                "cipher_raw": net.get("cipher_raw") or "Desconocido",
                "auth_key": auth_key,
                "cipher_key": cipher_key,
                "channel": bssid_info.get("channel"),
                "signal_pct": bssid_info.get("signal_pct"),
                "band": bssid_info.get("band"),
                "radio_type": bssid_info.get("radio_type"),
                "mfp_required": bssid_info.get("mfp_required"),
                "details": bssid_info.get("details"),
                "rssi_dbm": rssi,
                "exposure_label": ex_label,
                "anomaly": is_anomalous_ssid,
                "observation_status": observation["status"],
                "observation_message": observation["message"],
                "requires_technical_review": observation["requires_review"],
                "observed_bssid_count": observation["bssid_count"],
                "observed_bands": observation["bands"],
                "hidden_ssid": net.get("hidden_ssid", False),
                "evaluation_status": evaluation_status,
                "unknown_fields": unknown_fields,
                "au": au_val,
                "en": en_val,
                "ex": ex_val,
                "an": an_val,
                "bm_label": bm_label,
                "bm": bm_val,
                "wss_score": score,
                "classification": classification,
                "wss_vector": vector,
                "timestamp": processed_at,
                "source_type": source_type,
                "source_label": source_label or source_type,
                "source_filename": source_filename,
                "captured_at": captured_at,
                "processed_at": processed_at,
                "engine_version": ENGINE_VERSION,
                "synthetic_data": synthetic_data,
                "recommendation_rule": None,
            })

    # Orden por severidad descendente: resultados incompletos quedan al final.
    results.sort(key=lambda r: (r["wss_score"] is not None, r["wss_score"] or -1), reverse=True)
    return results


# ---------------------------------------------------------------------------
# Modo de prueba en sistemas no-Windows (desarrollo / demo sin hardware)
# ---------------------------------------------------------------------------

_SAMPLE_NETSH_OUTPUT = """
Interfaz en el equipo: Wi-Fi
Hay 3 redes disponibles actualmente.

SSID 1 : OFICINA-WIFI
    Tipo de red             : Infraestructura
    Autenticacion de red    : WPA2-Personal
    Cifrado de red          : CCMP
    BSSID 1                 : aa:bb:cc:11:22:33
         Senal              : 78%
         Tipo de radio      : 802.11ac
         Canal              : 6

SSID 2 : OFICINA-WIFI
    Tipo de red             : Infraestructura
    Autenticacion de red    : WPA2-Personal
    Cifrado de red          : CCMP
    BSSID 1                 : aa:bb:cc:99:88:77
         Senal              : 65%
         Tipo de radio      : 802.11n
         Canal              : 6

SSID 3 : CAFE_INVITADOS
    Tipo de red             : Infraestructura
    Autenticacion de red    : Abierta
    Cifrado de red          : Ninguno
    BSSID 1                 : dd:ee:ff:44:55:66
         Senal              : 90%
         Tipo de radio      : 802.11n
         Canal              : 11
"""


def evaluate_networks_demo():
    """Usa una salida de ejemplo para probar la interfaz sin Windows."""
    return evaluate_networks(
        raw_output=_SAMPLE_NETSH_OUTPUT,
        source_type="DEMO",
        source_label="Datos sinteticos de demostracion",
        synthetic_data=True,
    )


if __name__ == "__main__":
    try:
        data = evaluate_networks()
    except RuntimeError as e:
        print(f"[AVISO] {e}")
        print("Usando datos de ejemplo para demostracion...\n")
        data = evaluate_networks_demo()

    for r in data:
        print(f"{r['ssid']:<20} {r['bssid']:<20} score={r['wss_score']} "
              f"{r['classification']:<12} {r['wss_vector']}")
