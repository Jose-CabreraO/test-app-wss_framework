from pathlib import Path


FILES_TO_SCAN = [
    Path("index.html"),
    Path("app.py"),
    Path("wss_engine.py"),
    Path("recommendation_engine.py"),
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
    "CRITICO",
    "No se identificó una condición anómala.",
    "1 radio observada",
    "radios observadas",
    "Se observaron varias radios compatibles con una red de doble banda.",
    "Ver detalles técnicos",
        "Detalles técnicos abiertos",
    "Resumen",
    "Vector WSS",
    "Trazabilidad avanzada",
    "Autenticación normalizada",
    "Cifrado normalizado",
    "Resumen",
    "Parámetros",
    "Radios",
    "Limitaciones de la evaluación",
    "REC-01 — WPA3 con CCMP",
    "REC-02 — WPA2 con CCMP/AES",
    "REC-03 — WPA/TKIP",
    "REC-04 — WEP",
    "REC-05 — Red abierta o sin cifrado",
    "REC-06 — Parámetro no interpretado",
    "REC-07 — Configuraciones diferentes bajo el mismo SSID",
    "Archivo de prueba con parámetros desconocidos",
    "Sin puntaje",
    "Clasificación técnica:",
    "Puede mejorar",
    "Requiere atención",
    "Protección insuficiente",
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


def test_simple_card_omits_technical_wss_and_bssid_details():
    text = Path("index.html").read_text(encoding="utf-8")
    start = text.index("function renderCard")
    end = text.index("function resetDetailButtons")
    render_card = text[start:end]

    assert "Vector WSS" not in render_card
    assert "wss_vector" not in render_card
    assert "BSSID" not in render_card
    assert "AU ·" not in render_card
    assert "EN ·" not in render_card
    assert "EX ·" not in render_card
    assert "AN ·" not in render_card
    assert "BM ·" not in render_card
    assert "${renderDetail(net)}" not in render_card
    assert "card-technical-panel" not in render_card


def test_technical_view_keeps_traceability_fields():
    text = Path("index.html").read_text(encoding="utf-8")

    for expected in [
        "Vector WSS",
        "Resumen",
        "Parámetros",
        "Radios",
        "Trazabilidad avanzada",
        "Regla aplicada",
        "recommendation_rule_id",
        "recommendation_rule_version",
        "Autenticación normalizada",
        "Cifrado normalizado",
        "source_type",
        "engine_version",
        "evaluation_status",
        "observation_status",
    ]:
        assert expected in text


def test_technical_details_control_is_real_button_with_aria_state_and_sidebar():
    text = Path("index.html").read_text(encoding="utf-8")

    assert '<button type="button" class="net-card-badge technical-toggle"' in text
    assert 'aria-expanded="false"' in text
    assert 'aria-controls="detail-panel"' in text
    assert '<aside id="detail-panel" class="detail-panel" style="display:none;" aria-live="polite"></aside>' in text
    assert "Ver detalles técnicos" in text
    assert "Detalles técnicos abiertos" in text
    assert "toggle.addEventListener('click'" in text
    assert "openDetailPanel(net, toggle)" in text
    assert "detailPanel.style.display = 'block'" in text
    assert "position: fixed" in text
    assert "right: 0" in text
    assert "bottom: 0" in text
    assert "width: min(580px, 94vw)" in text
    assert "box-shadow: -24px 0 60px" in text
    assert "detail-drawer-header" in text
    assert "position: sticky" in text
    assert "detail-drawer-body" in text
    assert "overflow-y: auto" in text
    assert "detail-score-main" in text
    assert "formatScoreLocal(net, 'Sin puntaje')" in text
    assert "presentationForNetwork(net)" in text


def test_technical_panel_is_sidebar_not_embedded_in_cards():
    text = Path("index.html").read_text(encoding="utf-8")
    start = text.index("function renderCard")
    end = text.index("function resetDetailButtons")
    render_card = text[start:end]

    assert "detailPanel.innerHTML" not in render_card
    assert "renderDetail(net);" not in render_card
    assert "card-technical-panel" not in text
    assert "real-results-layout" in text
    assert "grid-template-columns: minmax(0, 1fr) minmax(480px, 520px)" in text


def test_sidebar_can_close_and_switch_between_networks():
    text = Path("index.html").read_text(encoding="utf-8")

    assert "function closeDetailPanel()" in text
    assert "detailPanel.innerHTML = ''" in text
    assert "id=\"detail-close-btn\"" in text
    assert "addEventListener('click', closeDetailPanel)" in text
    assert "event.key === 'Escape'" in text
    assert "resetDetailButtons()" in text
    assert "activeDetailButton = button" in text
    assert "selectedIndex = index" in text
    assert "if (buttonToFocus) buttonToFocus.focus()" in text
    assert "panelBody.scrollTop = 0" in text
    assert "activateDetailTab('summary')" in text


def test_detail_tabs_have_accessible_roles_and_keyboard_navigation():
    text = Path("index.html").read_text(encoding="utf-8")

    assert 'role="tablist"' in text
    assert 'role="tab"' in text
    assert 'role="tabpanel"' in text
    assert 'aria-selected="true">Resumen' in text
    assert 'aria-selected="false" tabindex="-1">Parámetros' in text
    assert "function setupDetailTabs()" in text
    assert "function activateDetailTab(tabName)" in text
    assert "ArrowRight" in text
    assert "ArrowLeft" in text
    assert "Home" in text
    assert "End" in text
    assert "panel.hidden = panel.dataset.panel !== tabName" in text


def test_summary_tab_exposes_recommendation_priority_and_limitations():
    text = Path("index.html").read_text(encoding="utf-8")

    for expected in [
        "Estado sencillo",
        "Score técnico",
        "Clasificación técnica",
        "Hallazgo",
        "Explicación",
        "Recomendación",
        "Prioridad",
        "Limitaciones de la evaluación",
        "Observación de infraestructura",
        "Regla aplicada",
        "ruleDisplayName(net.recommendation_rule_id)",
    ]:
        assert expected in text


def test_parameters_radios_and_traceability_tabs_are_translated_and_compact():
    text = Path("index.html").read_text(encoding="utf-8")

    assert "detailKeyValues" in text
    assert "detail-kv" in text
    assert "radio-card" in text
    for expected in [
        "Regla aplicada",
        "Versión de la regla",
        "Tipo de origen",
        "Descripción del origen",
        "Archivo procesado",
        "Versión del motor",
        "Estado de la evaluación",
        "Estado de la infraestructura observada",
        "Fecha de procesamiento",
        "translateValue(net.source_type, SOURCE_TYPE_LABELS)",
        "translateValue(net.evaluation_status, EVALUATION_STATUS_LABELS)",
        "translateValue(net.observation_status, OBSERVATION_STATUS_LABELS)",
        "formatLocalDateTime(net.processed_at)",
        "MFP",
        "Score WSS",
    ]:
        assert expected in text


def test_rule_names_and_internal_value_translations_are_visible():
    text = Path("index.html").read_text(encoding="utf-8")

    for expected in [
        "'REC-01': 'REC-01 — WPA3 con CCMP'",
        "'REC-02': 'REC-02 — WPA2 con CCMP/AES'",
        "'REC-03': 'REC-03 — WPA/TKIP'",
        "'REC-04': 'REC-04 — WEP'",
        "'REC-05': 'REC-05 — Red abierta o sin cifrado'",
        "'REC-06': 'REC-06 — Parámetro no interpretado'",
        "'REC-07': 'REC-07 — Configuraciones diferentes bajo el mismo SSID'",
        "LIVE_SCAN: 'Escaneo real'",
        "FILE_IMPORT: 'Archivo TXT cargado'",
        "DEMO: 'Datos de demostración'",
        "COMPLETE: 'Evaluación completa'",
        "INCOMPLETE: 'Evaluación incompleta'",
        "SINGLE_BSSID: 'Una radio observada'",
        "MULTI_RADIO_OBSERVED: 'Varias radios observadas'",
        "MULTI_AP_OBSERVED: 'Varios puntos de acceso observados'",
        "SECURITY_PROFILE_MISMATCH: 'Configuraciones diferentes'",
    ]:
        assert expected in text


def test_traceability_grid_keeps_labels_and_values_separated():
    text = Path("index.html").read_text(encoding="utf-8")

    assert "grid-template-columns: minmax(130px, 0.42fr) minmax(0, 1fr)" in text
    assert "<dt>${escapeHtml(row[0])}</dt><dd>${escapeHtml" in text
    assert "recommendation_rule_versionREC" not in text


def test_cards_use_legible_normal_case_button_text():
    text = Path("index.html").read_text(encoding="utf-8")

    assert "VER DETALLES TÉCNICOS" not in text
    assert "text-transform: none" in text
    assert "font-size: 18px" in text
    assert "font-size: 15px" in text
    assert "line-height: 1.55" in text


def test_incomplete_details_keep_safe_score_formatting():
    text = Path("index.html").read_text(encoding="utf-8")

    assert "formatScore(net, 'Sin score')" in text
    assert "formatScoreLocal(net, 'Sin puntaje')" in text
    assert "net.wss_score.toFixed" not in text
    assert "isComplete(net) ? Number(net.wss_score).toFixed(1)" in text
    assert "Parámetros no interpretados" in text
    assert "Evaluación incompleta" in text


def test_classification_presentation_is_the_single_real_scan_color_mapping():
    text = Path("index.html").read_text(encoding="utf-8")

    assert "const CLASSIFICATION_PRESENTATION = {" in text
    assert "BAJO: { label: 'BAJO', simpleStatus: 'Configuración adecuada', color: '#6FE3A6' }" in text
    assert "MEDIO: { label: 'MEDIO', simpleStatus: 'Puede mejorar', color: '#F2C45C' }" in text
    assert "ALTO: { label: 'ALTO', simpleStatus: 'Requiere atención', color: '#FF9156' }" in text
    assert "CRITICO: { label: 'CRITICO', simpleStatus: 'Protección insuficiente', color: '#FF5640' }" in text
    assert "NO_EVALUABLE: { label: 'NO_EVALUABLE', simpleStatus: 'No se pudo completar la evaluación', color: '#9BA7B4' }" in text
    assert "SECURITY_PROFILE_MISMATCH: { label: 'Revisión técnica', simpleStatus: 'Requiere verificación técnica', color: '#F2C45C' }" in text


def test_score_status_and_classification_use_same_presentation_mapping():
    text = Path("index.html").read_text(encoding="utf-8")

    for expected in [
        "const presentation = presentationForNetwork(net);",
        "style=\"color:${presentation.color};\"",
        "style=\"color:${presentation.color}; font-size:13px;\"",
        "presentation.simpleStatus",
        "presentation.label",
        "card.style.borderLeft = `4px solid ${presentation.color}`",
    ]:
        assert expected in text


def test_multi_radio_observations_do_not_override_severity_color():
    text = Path("index.html").read_text(encoding="utf-8")

    assert "MULTI_RADIO_OBSERVED" in text
    assert "MULTI_AP_OBSERVED" in text
    assert "if (net.observation_status === 'SECURITY_PROFILE_MISMATCH')" in text
    assert "CLASSIFICATION_PRESENTATION.MULTI_RADIO_OBSERVED" not in text
    assert "CLASSIFICATION_PRESENTATION.MULTI_AP_OBSERVED" not in text


def test_global_navigation_switches_to_demo_view_before_scrolling():
    text = Path("index.html").read_text(encoding="utf-8")

    for expected in [
        "function activateAppView(viewId)",
        "function scrollToDemoSection(sectionId)",
        "activateAppView('view-demo')",
        "target.scrollIntoView({ behavior: 'smooth', block: 'start' })",
        "['como-funciona', 'calculadora', 'clasificacion', 'beneficios'].includes(sectionId)",
        "document.querySelectorAll('a[href^=\"#\"]')",
    ]:
        assert expected in text


def test_try_now_navigation_switches_to_real_view():
    text = Path("index.html").read_text(encoding="utf-8")

    assert "function scrollToRealView()" in text
    assert "activateAppView('view-real')" in text
    assert "document.querySelectorAll('.nav-cta')" in text
    assert "scrollToRealView()" in text
