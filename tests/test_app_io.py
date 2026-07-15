import json
from pathlib import Path

import app


FIXTURES = Path(__file__).parent / "fixtures" / "netsh"


def test_read_fixture_from_file_and_file_import_metadata():
    api = app.WssApi()
    response = api.import_txt_file(str(FIXTURES / "es_wpa3_ccmp.txt"))

    assert response["ok"] is True
    assert response["metadata"]["source_type"] == app.SOURCE_FILE_IMPORT
    assert response["metadata"]["source_filename"] == "es_wpa3_ccmp.txt"
    assert response["metadata"]["synthetic_data"] is False
    assert response["results"][0]["source_type"] == app.SOURCE_FILE_IMPORT


def test_cancelled_selection_is_explicit():
    api = app.WssApi()
    response = api.import_txt_file()

    assert response["ok"] is False
    assert response["cancelled"] is True


def test_incomplete_result_serializes_json_null():
    api = app.WssApi()
    response = api.import_txt_file(str(FIXTURES / "es_unknown.txt"))
    report = app.build_report(response["results"], response["metadata"])

    encoded = json.dumps(report)
    assert '"wss_score": null' in encoded
    assert report["results"][0]["classification"] == "NO_EVALUABLE"


def test_summary_counts_complete_and_incomplete():
    raw = (FIXTURES / "es_open_none.txt").read_text(encoding="utf-8-sig")
    raw += "\n"
    raw += (FIXTURES / "es_unknown.txt").read_text(encoding="utf-8-sig")
    response = app.process_raw_output(raw, app.SOURCE_FILE_IMPORT, "Fixture mixto", "mixed.txt")
    summary = app.summarize_results(response["results"], source_type=app.SOURCE_FILE_IMPORT)

    assert summary["total_results"] == 2
    assert summary["complete_evaluations"] == 1
    assert summary["incomplete_evaluations"] == 1
    assert summary["no_evaluable"] == 1
    assert summary["by_classification"]["CRITICO"] == 1


def test_anonymization_is_consistent_and_preserves_technical_values():
    api = app.WssApi()
    response = api.import_txt_file(str(FIXTURES / "es_wpa2_ccmp.txt"))
    original = response["results"][0]
    report = app.build_report(response["results"], response["metadata"], anonymize=True)
    anon = report["results"][0]

    assert report["report_metadata"]["anonymized"] is True
    assert anon["ssid"] == "SSID-001"
    assert anon["bssid"] == "BSSID-001"
    assert anon["auth_key"] == original["auth_key"]
    assert anon["cipher_key"] == original["cipher_key"]
    assert anon["signal_pct"] == original["signal_pct"]
    assert anon["channel"] == original["channel"]
    assert response["results"][0]["ssid"] == original["ssid"]


def test_demo_is_distinct_from_file_import():
    api = app.WssApi()
    demo = api.scan_networks_demo()
    file_response = api.import_txt_file(str(FIXTURES / "es_wpa2_ccmp.txt"))

    assert demo["metadata"]["source_type"] == app.SOURCE_DEMO
    assert demo["metadata"]["synthetic_data"] is True
    assert file_response["metadata"]["source_type"] == app.SOURCE_FILE_IMPORT
    assert file_response["metadata"]["synthetic_data"] is False


def test_export_without_results_returns_error():
    api = app.WssApi()
    response = api.export_json()

    assert response["ok"] is False
    assert "No hay resultados" in response["error"]


def test_export_json_from_memory_with_anonymization(tmp_path, monkeypatch):
    api = app.WssApi()
    api.import_txt_file(str(FIXTURES / "es_wpa3_ccmp.txt"))
    monkeypatch.chdir(tmp_path)

    response = api.export_json(anonymize=True)

    assert response["ok"] is True
    assert (tmp_path / response["filename"]).exists()
    assert response["report"]["report_metadata"]["report_version"] == "2.0"
    assert response["report"]["report_metadata"]["anonymized"] is True
    assert response["report"]["results"][0]["ssid"] == "SSID-001"
    assert response["report"]["results"][0]["source_type"] == app.SOURCE_FILE_IMPORT
    assert response["report"]["results"][0]["engine_version"]


def test_invalid_file_cases(tmp_path):
    missing = app.read_netsh_text_file(tmp_path / "missing.txt")
    wrong_ext = tmp_path / "fixture.csv"
    empty = tmp_path / "empty.txt"
    no_networks = tmp_path / "no_networks.txt"
    wrong_ext.write_text("data", encoding="utf-8")
    empty.write_text("", encoding="utf-8")
    no_networks.write_text("sin redes reconocibles", encoding="utf-8")

    assert missing["ok"] is False
    assert app.read_netsh_text_file(wrong_ext)["ok"] is False
    assert app.read_netsh_text_file(empty)["ok"] is False

    read = app.read_netsh_text_file(no_networks)
    response = app.process_raw_output(read["text"], app.SOURCE_FILE_IMPORT, "Sin redes", "no_networks.txt")
    assert response["ok"] is False
    assert "no contiene redes" in response["error"]
