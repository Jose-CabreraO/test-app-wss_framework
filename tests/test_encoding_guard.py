from pathlib import Path


FILES_TO_SCAN = [
    Path("index.html"),
    Path("app.py"),
    Path("wss_engine.py"),
]

MOJIBAKE_PATTERNS = [
    chr(0x00C3),              # ?
    chr(0x00C2),              # ?
    chr(0x00E2) + chr(0x20AC),  # ??
    chr(0x00E2) + chr(0x2020),  # ??
    chr(0xFFFD),              # replacement character
]

EXPECTED_UTF8_TEXT = [
    "Cómo funciona",
    "Clasificación",
    "Evaluación pasiva · sin intrusión",
    "Sabé qué tan expuesta está tu red Wi-Fi",
    "Probar la calculadora →",
    "configuración",
    "inalámbrica",
    "señal",
    "técnica",
    "severidad técnica",
    "CRÍTICO",
    "AN · Indicador de condición anómala",
    "No se identificó una condición anómala.",
    "1 radio observada",
    "radios observadas",
    "Se observaron varias radios compatibles con una red de doble banda o infraestructura con múltiples puntos de acceso.",
]


def test_visible_sources_do_not_contain_common_mojibake():
    offenders = []
    for path in FILES_TO_SCAN:
        text = path.read_text(encoding="utf-8")
        for pattern in MOJIBAKE_PATTERNS:
            if pattern in text:
                offenders.append((str(path), pattern))

    assert offenders == []


def test_index_html_contains_expected_utf8_text_and_charset():
    text = Path("index.html").read_text(encoding="utf-8")

    assert '<meta charset="UTF-8">' in text
    for expected in EXPECTED_UTF8_TEXT:
        assert expected in text


def test_index_html_uses_neutral_radio_and_an_labels():
    text = Path("index.html").read_text(encoding="utf-8")

    assert "BSSID/radios observadas" not in text
    assert "AN · Anomalía" not in text
    assert "radioCountLabel(net)" in text
    assert "anDetailMessage(net)" in text
