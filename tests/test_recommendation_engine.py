import app
import recommendation_engine
import wss_engine


def _single(auth, cipher, observation_status="SINGLE_BSSID", evaluation_status="COMPLETE", classification="BAJO"):
    return {
        "auth_key": auth,
        "cipher_key": cipher,
        "classification": classification,
        "evaluation_status": evaluation_status,
        "observation_status": observation_status,
        "unknown_fields": [],
    }


def test_rec_01_wpa3_ccmp():
    rec = recommendation_engine.recommend_for_result(_single("SAE", "CCMP"))

    assert rec["rule_id"] == "REC-01"
    assert rec["simple_status"] == "Configuración adecuada"
    assert rec["finding_title"] == "Protección inalámbrica moderna"
    assert rec["priority"] == "Baja"


def test_rec_02_wpa2_ccmp_does_not_recommend_tkip():
    rec = recommendation_engine.recommend_for_result(_single("WPA2-PSK", "CCMP"))

    assert rec["rule_id"] == "REC-02"
    assert rec["simple_status"] == "Configuración adecuada"
    assert rec["warning"] == "No recomendar TKIP."
    assert "TKIP" not in rec["recommended_action"]


def test_rec_03_wpa_tkip():
    rec = recommendation_engine.recommend_for_result(_single("WPA-PSK", "TKIP", classification="ALTO"))

    assert rec["rule_id"] == "REC-03"
    assert rec["simple_status"] == "Requiere atención"
    assert rec["priority"] == "Alta"
    assert "contraseña" in rec["warning"]


def test_rec_04_wep_synthetic_not_physical_validation():
    rec = recommendation_engine.recommend_for_result(_single("WPA-PSK", "WEP", classification="ALTO"))

    assert rec["rule_id"] == "REC-04"
    assert rec["simple_status"] == "Requiere atención"
    assert "No afirmar validación experimental" in rec["warning"]


def test_rec_05_open_none():
    rec = recommendation_engine.recommend_for_result(_single("OPEN", "NONE", classification="CRITICO"))

    assert rec["rule_id"] == "REC-05"
    assert rec["simple_status"] == "Protección insuficiente"
    assert "sin cifrado" in rec["finding_title"].lower()


def test_rec_06_unknown_no_score_or_definitive_conclusion():
    rec = recommendation_engine.recommend_for_result(_single(
        "UNKNOWN",
        "UNKNOWN",
        evaluation_status="INCOMPLETE",
    ))

    assert rec["rule_id"] == "REC-06"
    assert rec["simple_status"] == "No se pudo completar la evaluación"
    assert "no se asigna score" in rec["technical_interpretation"]
    assert "definitiva" in rec["warning"]


def test_rec_07_security_profile_mismatch_does_not_confirm_attack():
    rec = recommendation_engine.recommend_for_result(_single(
        "WPA2-PSK",
        "CCMP",
        observation_status="SECURITY_PROFILE_MISMATCH",
    ))

    assert rec["rule_id"] == "REC-07"
    assert rec["simple_status"] == "Requiere verificación técnica"
    forbidden = [
        "ataque " + "detectado",
        "Evil Twin " + "confirmado",
        "punto de acceso " + "malicioso",
    ]
    combined = " ".join(str(value) for value in rec.values())
    assert all(term not in combined for term in forbidden)


def test_multi_radio_and_multi_ap_are_informational_notes():
    radio = recommendation_engine.recommend_for_result(_single(
        "WPA2-PSK",
        "CCMP",
        observation_status="MULTI_RADIO_OBSERVED",
    ))
    multi_ap = recommendation_engine.recommend_for_result(_single(
        "WPA2-PSK",
        "CCMP",
        observation_status="MULTI_AP_OBSERVED",
    ))

    assert radio["rule_id"] == "REC-02"
    assert "doble banda" in radio["infrastructure_note"]
    assert multi_ap["rule_id"] == "REC-02"
    assert "ataque" not in multi_ap["infrastructure_note"].lower()


def test_simple_status_is_derived_from_classification():
    cases = [
        ("BAJO", "Configuración adecuada"),
        ("MEDIO", "Puede mejorar"),
        ("ALTO", "Requiere atención"),
        ("CRITICO", "Protección insuficiente"),
    ]

    for classification, expected_status in cases:
        result = _single("WPA2-PSK", "CCMP", classification=classification)
        assert recommendation_engine.simple_status_for_result(result) == expected_status


def test_no_evaluable_uses_neutral_incomplete_status():
    result = _single(
        "UNKNOWN",
        "UNKNOWN",
        evaluation_status="INCOMPLETE",
        classification="NO_EVALUABLE",
    )

    assert recommendation_engine.simple_status_for_result(result) == "No se pudo completar la evaluación"


def test_security_profile_mismatch_keeps_review_status():
    result = _single(
        "WPA2-PSK",
        "CCMP",
        observation_status="SECURITY_PROFILE_MISMATCH",
        classification="BAJO",
    )

    assert recommendation_engine.simple_status_for_result(result) == "Requiere verificación técnica"


def test_complementary_practices_are_separate_from_findings():
    rec = recommendation_engine.recommend_for_result(_single("WPA2-PSK", "CCMP"))

    assert rec["complementary_practices_heading"] == (
        "Buenas prácticas complementarias no verificadas por esta evaluación"
    )
    assert "contraseña" in " ".join(rec["complementary_practices"])
    assert rec["finding_title"] not in rec["complementary_practices"]


def test_recommendation_fields_are_present_in_export_json():
    raw = """
SSID 1 : LAB-WPA2
    Autenticacion           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 00:11:22:33:44:20
         Senal              : 80%
         Canal              : 6
"""
    response = app.process_raw_output(raw, app.SOURCE_FILE_IMPORT, "Fixture", "fixture.txt")
    report = app.build_report(response["results"], response["metadata"])
    item = report["results"][0]

    for field in (
        "recommendation_rule_id",
        "recommendation_rule_version",
        "simple_status",
        "finding_title",
        "recommended_action",
        "priority",
        "limitations",
    ):
        assert item[field]


def test_wss_values_are_not_changed_by_recommendations():
    raw = """
SSID 1 : LAB-WPA2
    Autenticacion           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 00:11:22:33:44:21
         Senal              : 80%
         Canal              : 6
"""
    plain = wss_engine.evaluate_networks(raw)[0]
    enriched = app.process_raw_output(raw, app.SOURCE_FILE_IMPORT, "Fixture", "fixture.txt")["results"][0]

    assert enriched["wss_score"] == plain["wss_score"]
    assert enriched["wss_vector"] == plain["wss_vector"]
    assert enriched["classification"] == plain["classification"]
