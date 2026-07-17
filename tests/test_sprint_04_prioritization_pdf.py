import json
import inspect
from pathlib import Path

import app
import recommendation_engine


def _result(auth, cipher, classification="BAJO", evaluation_status="COMPLETE"):
    return {
        "ssid": "LAB",
        "bssid": "00:11:22:33:44:55",
        "auth_raw": auth,
        "auth_key": auth,
        "cipher_raw": cipher,
        "cipher_key": cipher,
        "signal_pct": 80,
        "channel": 6,
        "band": "2,4 GHz",
        "radio_type": "802.11n",
        "mfp_required": None,
        "classification": classification,
        "evaluation_status": evaluation_status,
        "observation_status": "SINGLE_BSSID",
        "unknown_fields": [] if evaluation_status == "COMPLETE" else ["auth"],
        "wss_score": 2.35 if evaluation_status == "COMPLETE" else None,
        "wss_vector": "AU=0.3;EN=0.1;EX=1.0;AN=0;BM=0",
        "au": 0.3,
        "en": 0.1,
        "ex": 1.0,
        "an": 0,
        "bm": 0,
        "bm_label": "ALIGNED",
        "source_type": app.SOURCE_FILE_IMPORT,
        "source_label": "Fixture",
        "source_filename": "fixture.txt",
        "processed_at": "2026-07-16T12:00:00",
        "engine_version": "test",
    }


def _network(ssid, bssid, auth="WPA2-PSK", cipher="CCMP", band="2,4 GHz", channel=6):
    item = _result(auth, cipher, "BAJO")
    item.update({
        "ssid": ssid,
        "bssid": bssid,
        "auth_raw": "WPA2-Personal" if auth == "WPA2-PSK" else auth,
        "cipher_raw": "CCMP" if cipher == "CCMP" else cipher,
        "band": band,
        "channel": channel,
        "wss_vector": "WSS:1.0/AU:0.3/EN:0.1/EX:0.8/AN:0.0/BM:ALIGNED",
    })
    return item


def _actions_for(auth, cipher, target_user, classification="BAJO", evaluation_status="COMPLETE"):
    rec = recommendation_engine.recommend_for_result(
        _result(auth, cipher, classification=classification, evaluation_status=evaluation_status),
        target_user=target_user,
    )
    return rec["rule_id"], rec["prioritized_actions"]


def _sprint4_pdf_scenario():
    hidden_blocks = []
    for index in range(1, 10):
        hidden_blocks.append(f"""
SSID {index + 5} :
    Tipo de red             : Infraestructura
    Autenticación           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 00:11:22:33:55:{index:02d}
         Señal              : 80%
         Tipo de radio      : 802.11n
         Banda              : 2,4 GHz
         Canal              : {index}
""")
    raw = """
Nombre de interfaz : Wi-Fi
Actualmente hay 14 redes visibles.

SSID 1 : ASOC CAPELLANIA
    Tipo de red             : Infraestructura
    Autenticación           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 00:11:22:33:44:01
         Señal              : 80%
         Tipo de radio      : 802.11n
         Banda              : 2,4 GHz
         Canal              : 6
    BSSID 2                 : 00:11:22:33:44:02
         Señal              : 82%
         Tipo de radio      : 802.11ac
         Banda              : 5 GHz
         Canal              : 36

SSID 2 : LAB-WEP
    Tipo de red             : Infraestructura
    Autenticación           : WPA-Personal
    Cifrado                 : WEP
    BSSID 1                 : 00:11:22:33:44:03
         Señal              : 80%
         Tipo de radio      : 802.11n
         Banda              : 2,4 GHz
         Canal              : 7

SSID 3 : LAB-OPEN
    Tipo de red             : Infraestructura
    Autenticación           : Abierta
    Cifrado                 : Ninguna
    BSSID 1                 : 00:11:22:33:44:04
         Señal              : 80%
         Tipo de radio      : 802.11n
         Banda              : 2,4 GHz
         Canal              : 8

SSID 4 : LAB-UNKNOWN
    Tipo de red             : Infraestructura
    Autenticacion           : Metodo-No-Reconocido
    Cifrado                 : Cifrado-No-Reconocido
    BSSID 1                 : 00:11:22:33:44:05
         Senal              : 80%
         Tipo de radio      : 802.11n
         Banda              : 2,4 GHz
         Canal              : 9
""" + "\n".join(hidden_blocks)
    return app.process_raw_output(
        raw,
        app.SOURCE_DEMO,
        "Escenario sintético Sprint 4",
        synthetic_data=True,
        target_user="NETWORK_OWNER",
    )


def test_owner_prioritization_for_open_network():
    rule_id, actions = _actions_for("OPEN", "NONE", "NETWORK_OWNER", classification="CRITICO")

    assert rule_id == "REC-05"
    assert [item["action_type"] for item in actions[:3]] == ["PRIMARY", "ALTERNATIVE", "DEFINITIVE"]
    assert actions[0]["title"] == "Activar WPA2 con CCMP/AES o WPA3 y establecer una contraseña"
    assert actions[0]["effort_level"] == "MEDIUM"
    assert actions[0]["benefit_level"] == "HIGH"
    assert actions[0]["cost_level"] == "LOW"
    assert actions[0]["time_horizon"] == "SHORT_TERM"
    assert actions[0]["selected_user_profile"] == "NETWORK_OWNER"


def test_user_prioritization_for_open_and_wep_avoids_free_vpn_claims():
    for auth, cipher in [("OPEN", "NONE"), ("WPA-PSK", "WEP")]:
        _, actions = _actions_for(auth, cipher, "NETWORK_USER", classification="CRITICO")
        combined = " ".join(action["title"] + " " + action["description"] for action in actions)

        assert actions[0]["title"] == "Evitar operaciones sensibles, financieras o institucionales"
        assert "VPN gratuita" not in combined
        assert "vuelve segura toda la red" not in combined


def test_wpa_tkip_owner_actions_are_ordered():
    rule_id, actions = _actions_for("WPA-PSK", "TKIP", "NETWORK_OWNER", classification="ALTO")

    assert rule_id == "REC-03"
    assert [action["display_order"] for action in actions[:3]] == [1, 2, 3]
    assert actions[0]["title"] == "Migrar a WPA2 con CCMP/AES o WPA3"
    assert actions[2]["action_type"] == "DEFINITIVE"


def test_wpa2_and_wpa3_have_maintenance_actions():
    _, wpa2_actions = _actions_for("WPA2-PSK", "CCMP", "NETWORK_OWNER")
    _, wpa3_actions = _actions_for("SAE", "CCMP", "NETWORK_OWNER")

    assert wpa2_actions[0]["title"] == "Mantener WPA2 con CCMP/AES"
    assert any("WPA3" in action["title"] for action in wpa2_actions)
    assert wpa3_actions[0]["title"] == "Mantener la configuración actual"


def test_unknown_keeps_incomplete_cautious_action():
    rule_id, actions = _actions_for(
        "UNKNOWN",
        "UNKNOWN",
        "GENERAL",
        classification="NO_EVALUABLE",
        evaluation_status="INCOMPLETE",
    )

    assert rule_id == "REC-06"
    assert actions[0]["title"] == "Repetir la evaluación o cargar una captura legible"
    assert actions[0]["benefit_level"] == "MEDIUM"


def test_general_profile_uses_prudent_general_actions():
    _, actions = _actions_for("OPEN", "NONE", "GENERAL", classification="CRITICO")

    assert actions[0]["target_user"] == "GENERAL"
    assert actions[0]["title"] == "Solicitar revisión al responsable de la red"
    assert actions[1]["is_temporary"] is True


def test_recommendation_text_does_not_claim_pareto_or_absolute_security():
    text = json.dumps(recommendation_engine._owner_actions("REC-05"), ensure_ascii=False)
    text += json.dumps(recommendation_engine._user_actions("REC-05"), ensure_ascii=False)

    forbidden = ["Pareto", "80/20", "seguridad garantizada", "ataque confirmado", "Evil Twin confirmado"]
    assert all(term not in text for term in forbidden)


def test_json_report_contains_prioritized_action_traceability():
    response = app.process_raw_output(
        """
SSID 1 : LAB-OPEN
    Autenticacion           : Abierta
    Cifrado                 : Ninguna
    BSSID 1                 : 00:11:22:33:44:10
         Senal              : 80%
         Canal              : 6
""",
        app.SOURCE_FILE_IMPORT,
        "Fixture",
        "open.txt",
        target_user="NETWORK_OWNER",
    )
    report = app.build_report(response["results"], response["metadata"], user_profile="NETWORK_OWNER")
    action = report["results"][0]["prioritized_actions"][0]

    assert action["recommendation_rule_id"] == "REC-05"
    assert action["recommendation_rule_version"] == recommendation_engine.RULE_VERSION
    assert action["selected_user_profile"] == "NETWORK_OWNER"
    assert action["display_order"] == 1
    assert action["generated_at"]


def test_pdf_generation_rejects_empty_results():
    built = app.build_pdf_report([], {"source_type": app.SOURCE_DEMO})

    assert built["ok"] is False
    assert "No hay resultados" in built["error"]


def test_pdf_generation_with_multiple_networks_unknown_and_metadata():
    results = app.apply_recommendations([
        _result("SAE", "CCMP", "BAJO"),
        _result("OPEN", "NONE", "CRITICO"),
        _result("UNKNOWN", "UNKNOWN", "NO_EVALUABLE", evaluation_status="INCOMPLETE"),
    ], target_user="NETWORK_OWNER")
    metadata = {
        "source_type": app.SOURCE_DEMO,
        "source_label": "Datos de demostración",
        "source_filename": None,
        "synthetic_data": True,
        "processed_at": "2026-07-16T12:00:00",
        "engine_version": "test",
    }
    built = app.build_pdf_report(results, metadata, anonymize=True, user_profile="NETWORK_OWNER")

    assert built["ok"] is True
    assert built["pdf_bytes"].startswith(b"%PDF")
    assert len(built["pdf_bytes"]) > 1000
    assert built["report"]["report_metadata"]["anonymized"] is True
    assert built["report"]["report_metadata"]["synthetic_data"] is True
    assert built["report"]["results"][0]["ssid"] == "SSID-001"
    assert app.SCOPE_TEXT in built["report"]["scope"]["text"]


def test_pdf_groups_dual_band_as_one_logical_network():
    results = app.apply_recommendations([
        _network("ASOC CAPELLANIA", "00:11:22:33:44:01", band="2,4 GHz", channel=6),
        _network("ASOC CAPELLANIA", "00:11:22:33:44:02", band="5 GHz", channel=36),
        _network("LAB-OPEN", "00:11:22:33:44:03", auth="OPEN", cipher="NONE"),
    ], target_user="NETWORK_OWNER")
    metadata = {
        "source_type": app.SOURCE_DEMO,
        "source_label": "Datos de demostración",
        "source_filename": None,
        "synthetic_data": True,
        "processed_at": "2026-07-16T16:27:14.772068",
        "engine_version": "test",
    }

    built = app.build_pdf_report(results, metadata, user_profile="NETWORK_OWNER")

    assert built["logical_network_count"] == 2
    assert built["visible_text"].count("Resultado por red") == 2
    assert built["visible_text"].count("ASOC CAPELLANIA") == 1
    assert "Varias radios observadas" in built["visible_text"]


def test_pdf_keeps_hidden_ssids_separate_when_grouping():
    hidden_1 = _network("SSID oculto 1", "00:11:22:33:44:11")
    hidden_2 = _network("SSID oculto 2", "00:11:22:33:44:12")
    hidden_1["hidden_ssid"] = True
    hidden_2["hidden_ssid"] = True
    results = app.apply_recommendations([hidden_1, hidden_2], target_user="GENERAL")
    metadata = {
        "source_type": app.SOURCE_DEMO,
        "source_label": "Datos de demostración",
        "synthetic_data": True,
        "engine_version": "test",
    }

    built = app.build_pdf_report(results, metadata)

    assert built["logical_network_count"] == 2


def test_hidden_ssids_receive_distinct_stable_identifiers():
    hidden_results = []
    for index in range(1, 10):
        item = _network("(SSID oculto)", f"00:11:22:33:55:{index:02d}")
        item["hidden_ssid"] = True
        hidden_results.append(item)

    first = app.assign_hidden_ssid_identifiers(hidden_results)
    second = app.assign_hidden_ssid_identifiers(hidden_results)

    assert [item["ssid"] for item in first] == [f"SSID oculto {index}" for index in range(1, 10)]
    assert [item["ssid"] for item in first] == [item["ssid"] for item in second]
    assert len(app.group_logical_networks(app.apply_recommendations(first))) == 9


def test_pdf_summary_separates_records_visible_networks_and_hidden_observations():
    results = app.apply_recommendations([
        _network("ASOC CAPELLANIA", "00:11:22:33:44:01", band="2,4 GHz"),
        _network("ASOC CAPELLANIA", "00:11:22:33:44:02", band="5 GHz"),
        {
            **_network("LAB-OPEN", "00:11:22:33:44:03", auth="OPEN", cipher="NONE"),
            "classification": "CRITICO",
            "wss_score": 7.7,
        },
        *[
            {
                **_network(f"SSID oculto {index}", f"00:11:22:33:55:{index:02d}"),
                "hidden_ssid": True,
            }
            for index in range(1, 10)
        ],
    ], target_user="NETWORK_OWNER")
    metadata = {
        "source_type": app.SOURCE_DEMO,
        "source_label": "Datos de demostración",
        "synthetic_data": True,
        "engine_version": "test",
    }

    built = app.build_pdf_report(results, metadata, user_profile="NETWORK_OWNER")
    visible = built["visible_text"]

    assert "Resultados de red generados: 11" in visible
    assert "Redes con SSID identificable: 2" in visible
    assert "Observaciones de SSID oculto: 9" in visible
    assert "BSSID o radios observados: 12" in visible
    assert "Redes lógicas evaluadas" not in visible
    assert built["logical_network_count"] == 11


def test_pdf_summary_matches_grouped_sprint4_synthetic_scenario():
    response = _sprint4_pdf_scenario()
    assert response["ok"] is True
    built = app.build_pdf_report(
        response["results"],
        response["metadata"],
        user_profile="NETWORK_OWNER",
        organization="Validación sintética Sprint 4",
    )
    visible = built["visible_text"]

    assert built["logical_network_count"] == 13
    assert "Resultados de red generados: 13" in visible
    assert "Redes con SSID identificable: 4" in visible
    assert "Observaciones de SSID oculto: 9" in visible
    assert "Evaluaciones completas: 12" in visible
    assert "Evaluaciones incompletas: 1" in visible
    assert "BSSID o radios observados: 14" in visible
    assert "Bajo: 10" in visible
    assert "Alto: 1" in visible
    assert "Crítico: 1" in visible
    assert "No evaluable: 1" in visible
    distribution = next(line for line in visible.splitlines() if line.startswith("Distribución: "))
    total = sum(int(part.rsplit(": ", 1)[1]) for part in distribution.replace("Distribución: ", "").split(", "))
    assert total == built["logical_network_count"]


def test_dual_band_counts_as_one_logical_result_and_two_radios():
    response = _sprint4_pdf_scenario()
    logical = app.group_logical_networks(response["results"])
    dual = next(item for item in logical if item["ssid"] == "ASOC CAPELLANIA")

    assert dual["logical_bssid_count"] == 2
    assert len([item for item in logical if item["ssid"] == "ASOC CAPELLANIA"]) == 1


def test_pdf_summary_counts_are_preserved_when_anonymized():
    response = _sprint4_pdf_scenario()
    normal = app.build_pdf_report(response["results"], response["metadata"], user_profile="NETWORK_OWNER")
    anonymized = app.build_pdf_report(
        response["results"],
        response["metadata"],
        anonymize=True,
        user_profile="NETWORK_OWNER",
    )

    for expected in [
        "Resultados de red generados: 13",
        "Redes con SSID identificable: 4",
        "Observaciones de SSID oculto: 9",
        "BSSID o radios observados: 14",
    ]:
        assert expected in normal["visible_text"]
        assert expected in anonymized["visible_text"]


def test_pdf_score_and_classification_use_independent_columns():
    build_source = inspect.getsource(app.build_pdf_report)
    row_source = inspect.getsource(app._pdf_score_classification_row)

    assert "_pdf_score_classification_row(pdf, score_text, classification)" in build_source
    assert "score_width" in row_source
    assert "badge_width" in row_source
    assert "set_x" not in row_source


def test_synthetic_scenarios_have_coherent_engine_components_and_translations():
    response = _sprint4_pdf_scenario()
    by_ssid = {item["ssid"]: item for item in response["results"]}

    assert by_ssid["LAB-WEP"]["classification"] == "ALTO"
    assert by_ssid["LAB-WEP"]["au"] > by_ssid["ASOC CAPELLANIA"]["au"]
    assert by_ssid["LAB-OPEN"]["classification"] == "CRITICO"
    assert by_ssid["LAB-OPEN"]["auth_key"] == "OPEN"
    assert by_ssid["LAB-OPEN"]["cipher_key"] == "NONE"
    assert by_ssid["LAB-UNKNOWN"]["classification"] == "NO_EVALUABLE"
    assert by_ssid["LAB-UNKNOWN"]["wss_score"] is None

    built = app.build_pdf_report(response["results"], response["metadata"])
    visible = built["visible_text"]

    assert "Abierta (OPEN)" in visible
    assert "Ninguna (NONE)" in visible
    assert "No interpretada (UNKNOWN)" in visible


def test_no_evaluable_missing_components_are_presented_as_sd():
    response = _sprint4_pdf_scenario()
    unknown = next(item for item in response["results"] if item["ssid"] == "LAB-UNKNOWN")

    assert unknown["classification"] == "NO_EVALUABLE"
    assert unknown["au"] is None
    assert unknown["en"] is None

    built = app.build_pdf_report(response["results"], response["metadata"])
    visible = built["visible_text"]

    assert "AU / EN / EX / AN / BM: s/d / s/d / 0.8 / 0.0 / s/d" in visible
    assert "None" not in visible
    assert "null" not in visible
    assert "undefined" not in visible


def test_pdf_does_not_collapse_hidden_ssids_or_reveal_provisional_internal_value():
    results = app.apply_recommendations([
        {
            **_network(f"SSID oculto {index}", f"00:11:22:33:66:{index:02d}"),
            "hidden_ssid": True,
        }
        for index in range(1, 10)
    ], target_user="NETWORK_OWNER")
    metadata = {
        "source_type": app.SOURCE_DEMO,
        "source_label": "Datos de demostración",
        "synthetic_data": True,
        "engine_version": "test",
    }

    built = app.build_pdf_report(results, metadata)
    visible = built["visible_text"]

    for index in range(1, 10):
        assert f"SSID oculto {index}" in visible
    assert visible.count("Resultado por red") == 9
    assert visible.count("Resultado por red 1: SSID oculto 1") == 1
    assert "PROVISIONAL" not in visible
    assert "Provisional" in visible


def test_anonymized_pdf_preserves_hidden_ssid_identifiers():
    results = app.apply_recommendations([
        {
            **_network(f"SSID oculto {index}", f"00:11:22:33:77:{index:02d}"),
            "hidden_ssid": True,
        }
        for index in range(1, 4)
    ])
    metadata = {
        "source_type": app.SOURCE_DEMO,
        "source_label": "Datos de demostración",
        "synthetic_data": True,
        "engine_version": "test",
    }

    built = app.build_pdf_report(results, metadata, anonymize=True)
    visible = built["visible_text"]

    assert "SSID oculto 1" in visible
    assert "SSID oculto 2" in visible
    assert "SSID oculto 3" in visible
    assert "Resultado por red 1: SSID-001" not in visible
    assert built["visible_text"].count("BSSID-") == 3


def test_profile_is_not_repeated_in_each_traceability_block():
    results = app.apply_recommendations([
        _network("LAB-1", "00:11:22:33:44:01"),
        _network("LAB-2", "00:11:22:33:44:02"),
    ], target_user="NETWORK_OWNER")
    metadata = {
        "source_type": app.SOURCE_DEMO,
        "source_label": "Datos de demostración",
        "synthetic_data": True,
        "engine_version": "test",
    }

    built = app.build_pdf_report(results, metadata, user_profile="NETWORK_OWNER")

    assert built["visible_text"].count("Perfil de recomendación") == 3
    assert "Fecha de procesamiento" in built["visible_text"]


def test_pdf_visible_values_are_translated_and_dates_are_readable():
    item = _network("LAB", "00:11:22:33:44:55")
    item["processed_at"] = "2026-07-16T16:27:14.772068"
    results = app.apply_recommendations([item], target_user="NETWORK_OWNER")
    metadata = {
        "source_type": app.SOURCE_DEMO,
        "source_label": "Datos de demostración",
        "synthetic_data": True,
        "engine_version": "test",
    }

    built = app.build_pdf_report(results, metadata, user_profile="NETWORK_OWNER")
    visible = built["visible_text"]

    for internal in [
        "LOW", "MEDIUM", "HIGH", "UNKNOWN", "NO_COST", "SHORT_TERM",
        "IMMEDIATE", "PLANNED", "COMPLETE", "SINGLE_BSSID", "ALIGNED", "DEVIANT",
        "2026-07-16T16:27:14.772068",
    ]:
        assert internal not in visible
    assert "Bajo" in visible
    assert "Sin costo" in visible
    assert "Evaluación completa" in visible
    assert "16/07/2026 16:27" in visible


def test_pdf_wss_schema_version_is_not_confused_with_score():
    item = _network("LAB", "00:11:22:33:44:55")
    item["wss_score"] = 7.0
    item["classification"] = "ALTO"
    results = app.apply_recommendations([item], target_user="NETWORK_OWNER")
    metadata = {
        "source_type": app.SOURCE_DEMO,
        "source_label": "Datos de demostración",
        "synthetic_data": True,
        "engine_version": "test",
    }

    built = app.build_pdf_report(results, metadata)
    visible = built["visible_text"]

    assert "7,0" in visible
    assert "Versión del esquema WSS: 1.0" in visible
    assert "WSS:1.0/AU" not in visible


def test_pdf_complementary_practices_appear_once():
    results = app.apply_recommendations([
        _network("LAB-1", "00:11:22:33:44:01"),
        _network("LAB-2", "00:11:22:33:44:02"),
    ])
    metadata = {
        "source_type": app.SOURCE_DEMO,
        "source_label": "Datos de demostración",
        "synthetic_data": True,
        "engine_version": "test",
    }

    built = app.build_pdf_report(results, metadata)

    assert built["visible_text"].count("Buenas prácticas complementarias") == 1


def test_pdf_anonymization_preserves_grouping_and_bssids():
    results = app.apply_recommendations([
        _network("Flia. Esquivel", "00:11:22:33:44:01", band="2,4 GHz"),
        _network("Flia. Esquivel", "00:11:22:33:44:02", band="5 GHz"),
        _network("Flia. Esquivel", "00:11:22:33:44:03", band="6 GHz"),
    ])
    metadata = {
        "source_type": app.SOURCE_DEMO,
        "source_label": "Datos de demostración",
        "synthetic_data": True,
        "engine_version": "test",
    }

    built = app.build_pdf_report(results, metadata, anonymize=True)

    assert built["logical_network_count"] == 1
    assert "SSID-001" in built["visible_text"]
    assert built["visible_text"].count("BSSID-") == 3


def test_api_export_pdf_requires_previous_results(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    api = app.WssApi()

    assert api.export_pdf()["ok"] is False


def test_api_export_pdf_writes_anonymized_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    api = app.WssApi()
    api.scan_networks_demo()

    response = api.export_pdf(
        anonymize=True,
        organization="Organización de prueba",
        selected_path=tmp_path / "reporte_pdf",
    )

    assert response["ok"] is True
    assert response["filename"] == "reporte_pdf.pdf"
    assert Path(response["saved_path"]).exists()
    assert response["report"]["report_metadata"]["organization"] == "Organización de prueba"
