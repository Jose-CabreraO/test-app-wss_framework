"""
wss_engine.py
Motor de escaneo y calculo WSS para la app de escritorio.

Ejecuta `netsh wlan show networks mode=bssid` en Windows, parsea la salida,
normaliza los parametros segun el modelo de la tesis (seccion 4.5.2) y calcula
el Wireless Severity Score (WSS) para cada red detectada.

Referencia: Tesis "Sistema automatizado de evaluacion de seguridad Wi-Fi
con validacion experimental controlada" — secciones 4.4.1, 4.5, 4.5.1, 4.5.2.
"""

import subprocess
import re
import platform
from datetime import datetime


# ---------------------------------------------------------------------------
# Modelo WSS — pesos y tablas de normalizacion (seccion 4.5.1 / 4.5.2)
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
    Linea base: WPA3-SAE o WPA2-PSK con cifrado CCMP, sin anomalia (seccion 4.5.2).
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
# Parser de netsh (Windows) — seccion 4.4.1 de la tesis
# ---------------------------------------------------------------------------

def _map_auth(raw_auth):
    """Traduce el texto crudo de netsh a una clave normalizada de AUTH_VALUES."""
    raw = (raw_auth or "").upper()
    if "WPA3" in raw or "SAE" in raw:
        return "SAE"
    if "WPA2" in raw:
        return "WPA2-PSK"
    if "WPA" in raw:
        return "WPA-PSK"
    if "OPEN" in raw:
        return "OPEN"
    return "OPEN"


def _map_cipher(raw_cipher):
    """Traduce el texto crudo de netsh a una clave normalizada de CIPHER_VALUES."""
    raw = (raw_cipher or "").upper()
    if "CCMP" in raw or "AES" in raw:
        return "CCMP"
    if "TKIP" in raw:
        return "TKIP"
    if "WEP" in raw:
        return "WEP"
    if "NONE" in raw:
        return "NONE"
    return "NONE"


def _signal_pct_to_rssi(pct):
    """
    netsh reporta intensidad de señal como porcentaje (0-100), no en dBm.
    Aproximacion estandar: rssi_dbm = (pct / 2) - 100
    (0% -> -100 dBm, 100% -> -50 dBm). Es una aproximacion razonable
    para clasificar el factor de exposicion EX, no una medicion de
    precisión de laboratorio.
    """
    try:
        pct = float(pct)
    except (TypeError, ValueError):
        return None
    return round((pct / 2.0) - 100.0, 1)


def run_netsh_scan():
    """
    Ejecuta `netsh wlan show networks mode=bssid` y devuelve la salida cruda.
    Lanza RuntimeError con un mensaje claro si no se puede ejecutar
    (por ejemplo, en un sistema no-Windows, o sin adaptador Wi-Fi).
    """
    if platform.system() != "Windows":
        raise RuntimeError(
            "El escaneo de redes solo esta disponible en Windows. "
            "Esta funcion utiliza 'netsh wlan show networks', que es "
            "especifico de ese sistema operativo (seccion 4.4.1 de la tesis)."
        )

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="ignore",
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

    Estructura tipica de la salida (en español, Windows en español):

    SSID 1 : MiRed
        Tipo de red             : Infraestructura
        Autenticación de red    : WPA2-Personal
        Cifrado de red          : CCMP
        BSSID 1                 : aa:bb:cc:dd:ee:ff
             Señal              : 80%
             Tipo de radio      : 802.11ac
             Canal              : 6
    """
    networks = []
    current = None
    current_bssid = None

    lines = raw_output.splitlines()

    for line in lines:
        line = line.rstrip()

        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line.strip())
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

        # Autenticacion (varía: "Autenticación de red" / "Network authentication" / "Authentication")
        auth_match = re.match(
            r"^(Autenticaci[oó]n de red|Network [Aa]uthentication|Autenticaci[oó]n)\s*:\s*(.*)$",
            line.strip(),
        )
        if auth_match:
            current["auth_raw"] = auth_match.group(2).strip()
            continue

        # Cifrado
        cipher_match = re.match(
            r"^(Cifrado de red|Network [Cc]ipher|Cifrado)\s*:\s*(.*)$",
            line.strip(),
        )
        if cipher_match:
            current["cipher_raw"] = cipher_match.group(2).strip()
            continue

        # BSSID
        bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*(.*)$", line.strip())
        if bssid_match:
            current_bssid = {
                "bssid": bssid_match.group(1).strip(),
                "signal_pct": None,
                "channel": None,
            }
            current["bssids"].append(current_bssid)
            continue

        # Señal (porcentaje)
        signal_match = re.match(r"^(Señal|Signal)\s*:\s*(\d+)\s*%?", line.strip())
        if signal_match and current_bssid is not None:
            current_bssid["signal_pct"] = signal_match.group(2)
            continue

        # Canal
        channel_match = re.match(r"^(Canal|Channel)\s*:\s*(\d+)", line.strip())
        if channel_match and current_bssid is not None:
            current_bssid["channel"] = channel_match.group(2)
            continue

    if current and current.get("bssids"):
        networks.append(current)

    return networks


def detect_anomalies(networks):
    """
    Heuristica de deteccion de condicion anomala de infraestructura
    (seccion 4.4.2 de la tesis): mismo SSID anunciado por mas de un BSSID.
    No confirma un ataque; marca el patron para revision tecnica.

    netsh puede reportar el mismo SSID en bloques separados (una entrada
    "SSID N :" por cada agrupacion que detecta), o agrupar varios BSSIDs
    bajo un mismo bloque. Por eso la deteccion agrupa por nombre de SSID
    a traves de TODOS los bloques antes de contar BSSIDs distintos.

    Devuelve un set de SSIDs que presentan mas de un BSSID distinto.
    """
    bssids_by_ssid = {}
    for net in networks:
        ssid = net["ssid"]
        bssids_by_ssid.setdefault(ssid, set())
        for b in net.get("bssids", []):
            if b.get("bssid"):
                bssids_by_ssid[ssid].add(b["bssid"].lower())

    flagged = {ssid for ssid, bssid_set in bssids_by_ssid.items() if len(bssid_set) > 1}
    return flagged


def evaluate_networks(raw_output=None):
    """
    Punto de entrada principal: escanea (si no se provee raw_output),
    parsea, detecta anomalias y calcula el WSS para cada BSSID detectado.

    Devuelve una lista de diccionarios, uno por cada punto de acceso
    (SSID + BSSID), listos para mostrar en la interfaz.
    """
    if raw_output is None:
        raw_output = run_netsh_scan()

    networks = parse_netsh_output(raw_output)
    anomalous_ssids = detect_anomalies(networks)

    results = []
    for net in networks:
        ssid = net["ssid"]
        auth_key = _map_auth(net.get("auth_raw"))
        cipher_key = _map_cipher(net.get("cipher_raw"))
        is_anomalous_ssid = ssid in anomalous_ssids

        for bssid_info in net["bssids"]:
            rssi = _signal_pct_to_rssi(bssid_info.get("signal_pct"))
            ex_label = classify_exposure(rssi)

            au_val = AUTH_VALUES.get(auth_key, 1.0)
            en_val = CIPHER_VALUES.get(cipher_key, 1.0)
            ex_val = EXPOSURE_VALUES[ex_label]
            an_val = ANOMALY_VALUES["YES"] if is_anomalous_ssid else ANOMALY_VALUES["NO"]

            bm_label = determine_bm(auth_key, cipher_key, is_anomalous_ssid)
            bm_val = BM_VALUES[bm_label]

            score = calculate_wss(au_val, en_val, ex_val, an_val, bm_val)
            classification = classify_score(score)

            vector = (
                f"WSS:1.0/AU:{au_val}/EN:{en_val}/"
                f"EX:{ex_val}/AN:{an_val}/BM:{bm_label}"
            )

            results.append({
                "ssid": ssid,
                "bssid": bssid_info.get("bssid", "—"),
                "auth_raw": net.get("auth_raw") or "Desconocida",
                "cipher_raw": net.get("cipher_raw") or "Desconocido",
                "auth_key": auth_key,
                "cipher_key": cipher_key,
                "channel": bssid_info.get("channel"),
                "signal_pct": bssid_info.get("signal_pct"),
                "rssi_dbm": rssi,
                "exposure_label": ex_label,
                "anomaly": is_anomalous_ssid,
                "au": au_val,
                "en": en_val,
                "ex": ex_val,
                "an": an_val,
                "bm_label": bm_label,
                "bm": bm_val,
                "wss_score": score,
                "classification": classification,
                "wss_vector": vector,
                "timestamp": datetime.now().isoformat(),
            })

    # Orden por severidad descendente: lo mas critico primero
    results.sort(key=lambda r: r["wss_score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Modo de prueba en sistemas no-Windows (desarrollo / demo sin hardware)
# ---------------------------------------------------------------------------

_SAMPLE_NETSH_OUTPUT = """
Interfaz en el equipo: Wi-Fi
Hay 3 redes disponibles actualmente.

SSID 1 : OFICINA-WIFI
    Tipo de red             : Infraestructura
    Autenticación de red    : WPA2-Personal
    Cifrado de red          : CCMP
    BSSID 1                 : aa:bb:cc:11:22:33
         Señal              : 78%
         Tipo de radio      : 802.11ac
         Canal              : 6

SSID 2 : OFICINA-WIFI
    Tipo de red             : Infraestructura
    Autenticación de red    : WPA2-Personal
    Cifrado de red          : CCMP
    BSSID 1                 : aa:bb:cc:99:88:77
         Señal              : 65%
         Tipo de radio      : 802.11n
         Canal              : 6

SSID 3 : CAFE_INVITADOS
    Tipo de red             : Infraestructura
    Autenticación de red    : Abierta
    Cifrado de red          : Ninguno
    BSSID 1                 : dd:ee:ff:44:55:66
         Señal              : 90%
         Tipo de radio      : 802.11n
         Canal              : 11
"""


def evaluate_networks_demo():
    """Usa una salida de ejemplo (incluye una anomalia de SSID duplicado)
    para poder probar la interfaz en macOS/Linux sin un adaptador Windows real."""
    return evaluate_networks(raw_output=_SAMPLE_NETSH_OUTPUT)


if __name__ == "__main__":
    # Prueba rapida desde linea de comandos
    try:
        data = evaluate_networks()
    except RuntimeError as e:
        print(f"[AVISO] {e}")
        print("Usando datos de ejemplo para demostracion...\n")
        data = evaluate_networks_demo()

    for r in data:
        print(f"{r['ssid']:<20} {r['bssid']:<20} score={r['wss_score']:<5} "
              f"{r['classification']:<8} {r['wss_vector']}")
