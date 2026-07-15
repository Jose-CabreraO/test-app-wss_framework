from pathlib import Path

import wss_engine


FIXTURES = Path(__file__).parent / "fixtures" / "netsh"


def read_fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8-sig")


def single_result(name):
    results = wss_engine.evaluate_networks(read_fixture(name))
    assert len(results) == 1
    return results[0]


def test_parse_wpa3_ccmp_fixture():
    result = single_result("es_wpa3_ccmp.txt")

    assert result["auth_key"] == "SAE"
    assert result["cipher_key"] == "CCMP"
    assert result["signal_pct"] == "99"
    assert result["channel"] == "6"
    assert "2,4" in result["band"]
    assert result["mfp_required"] == "1"
    assert result["evaluation_status"] == "COMPLETE"


def test_parse_wpa2_ccmp_fixture():
    result = single_result("es_wpa2_ccmp.txt")

    assert result["auth_key"] == "WPA2-PSK"
    assert result["cipher_key"] == "CCMP"
    assert result["evaluation_status"] == "COMPLETE"


def test_parse_wpa_tkip_fixture_does_not_become_wpa2():
    result = single_result("es_wpa_tkip.txt")

    assert result["auth_key"] == "WPA-PSK"
    assert result["cipher_key"] == "TKIP"
    assert result["auth_key"] != "WPA2-PSK"
    assert result["evaluation_status"] == "COMPLETE"


def test_parse_open_none_fixture():
    result = single_result("es_open_none.txt")

    assert result["auth_raw"] == "Abierta"
    assert result["cipher_raw"] == "Ninguna"
    assert result["auth_key"] == "OPEN"
    assert result["cipher_key"] == "NONE"
    assert result["evaluation_status"] == "COMPLETE"


def test_unknown_values_are_not_converted_to_open_or_none():
    result = single_result("es_unknown.txt")

    assert result["auth_key"] == "UNKNOWN"
    assert result["cipher_key"] == "UNKNOWN"
    assert result["evaluation_status"] == "INCOMPLETE"
    assert result["wss_score"] is None
    assert result["classification"] == "NO_EVALUABLE"
    assert result["unknown_fields"] == ["auth", "cipher"]


def test_parse_english_authentication_encryption_signal_channel():
    result = single_result("en_wpa2_ccmp.txt")

    assert result["auth_key"] == "WPA2-PSK"
    assert result["cipher_key"] == "CCMP"
    assert result["signal_pct"] == "88"
    assert result["channel"] == "36"
    assert result["band"] == "5 GHz"
    assert result["radio_type"] == "802.11ac"
    assert result["evaluation_status"] == "COMPLETE"


def test_evaluate_networks_demo_still_runs_and_is_sorted():
    results = wss_engine.evaluate_networks_demo()

    assert results
    assert all("wss_score" in item for item in results)
    complete_scores = [
        item["wss_score"] for item in results
        if item["evaluation_status"] == "COMPLETE"
    ]
    assert complete_scores == sorted(complete_scores, reverse=True)


def test_incomplete_results_do_not_break_sorting():
    raw = read_fixture("es_unknown.txt") + "\n" + read_fixture("es_open_none.txt")
    results = wss_engine.evaluate_networks(raw)

    assert len(results) == 2
    assert results[0]["evaluation_status"] == "COMPLETE"
    assert results[1]["evaluation_status"] == "INCOMPLETE"


def test_wss_engine_importable():
    assert hasattr(wss_engine, "evaluate_networks")
