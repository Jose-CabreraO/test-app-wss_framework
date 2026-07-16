from pathlib import Path

import app


FIXTURES = Path(__file__).parent / "fixtures" / "netsh"


def _api_with_results():
    api = app.WssApi()
    api.import_txt_file(str(FIXTURES / "es_wpa2_ccmp.txt"))
    return api


def test_suggested_report_names_are_windows_safe_and_anonymized():
    generated_at = __import__("datetime").datetime(2026, 7, 16, 15, 45, 3)

    assert app.suggested_report_filename("PDF", generated_at=generated_at) == "WSS_Reporte_2026-07-16_154503.pdf"
    assert app.suggested_report_filename("JSON", anonymize=True, generated_at=generated_at) == (
        "WSS_Reporte_2026-07-16_154503_anon.json"
    )


def test_ensure_extension_prevents_cross_type_exports(tmp_path):
    assert app.ensure_extension(tmp_path / "reporte", ".pdf").name == "reporte.pdf"
    assert app.ensure_extension(tmp_path / "reporte.json", ".pdf").name == "reporte.pdf"
    assert app.ensure_extension(tmp_path / "reporte.pdf", ".json").name == "reporte.json"


def test_export_json_normal_and_anonymized_to_selected_path(tmp_path):
    api = _api_with_results()

    normal = api.export_json(selected_path=tmp_path / "normal")
    anon = api.export_json(anonymize=True, selected_path=tmp_path / "anon.json")

    assert normal["ok"] is True
    assert normal["file_type"] == "JSON"
    assert normal["filename"] == "normal.json"
    assert Path(normal["saved_path"]).exists()
    assert anon["anonymized"] is True
    assert anon["report"]["results"][0]["ssid"] == "SSID-001"


def test_export_pdf_normal_and_anonymized_to_selected_path(tmp_path):
    api = _api_with_results()

    normal = api.export_pdf(selected_path=tmp_path / "normal_pdf")
    anon = api.export_pdf(anonymize=True, selected_path=tmp_path / "anon_pdf")

    assert normal["ok"] is True
    assert normal["file_type"] == "PDF"
    assert normal["filename"] == "normal_pdf.pdf"
    assert Path(normal["saved_path"]).read_bytes().startswith(b"%PDF")
    assert anon["filename"] == "anon_pdf.pdf"
    assert anon["anonymized"] is True


def test_export_cancellation_does_not_create_file(tmp_path):
    api = _api_with_results()

    response = api.export_json(selected_path="")

    assert response["ok"] is False
    assert response["cancelled"] is True
    assert response["message"] == "La exportación fue cancelada."
    assert list(tmp_path.iterdir()) == []


def test_export_without_previous_evaluation_is_error(tmp_path):
    api = app.WssApi()

    assert api.export_json(selected_path=tmp_path / "x.json")["ok"] is False
    assert api.export_pdf(selected_path=tmp_path / "x.pdf")["ok"] is False


def test_export_to_unwritable_or_missing_directory_returns_error(tmp_path):
    api = _api_with_results()
    missing = tmp_path / "missing" / "report.json"

    response = api.export_json(selected_path=missing)

    assert response["ok"] is False
    assert "No se pudo guardar" in response["error"]


def test_default_export_directory_prefers_existing_user_folder(monkeypatch, tmp_path):
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    assert app.default_export_directory() == downloads


def test_open_file_and_show_in_folder_validate_missing_file(tmp_path):
    api = app.WssApi()
    missing = tmp_path / "missing.pdf"

    assert api.open_exported_file(missing)["ok"] is False
    assert api.show_exported_file_in_folder(missing)["ok"] is False


def test_open_file_and_show_in_folder_use_safe_system_calls(monkeypatch, tmp_path):
    api = app.WssApi()
    target = tmp_path / "report.pdf"
    target.write_bytes(b"%PDF-test")
    calls = {}

    monkeypatch.setattr(app.platform, "system", lambda: "Windows")
    monkeypatch.setattr(app.os, "startfile", lambda path: calls.setdefault("startfile", path), raising=False)
    monkeypatch.setattr(app.subprocess, "Popen", lambda args: calls.setdefault("popen", args))

    assert api.open_exported_file(target)["ok"] is True
    assert api.show_exported_file_in_folder(target)["ok"] is True
    assert calls["startfile"] == str(target.resolve())
    assert calls["popen"] == ["explorer", "/select,", str(target.resolve())]
