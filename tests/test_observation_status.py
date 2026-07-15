import wss_engine


def test_dual_band_same_profile_is_multi_radio_without_anomaly_increment():
    raw = """
SSID 1 : LAB-DUAL
    Autenticacion           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 00:11:22:33:44:01
         Senal              : 80%
         Banda              : 2,4 GHz
         Canal              : 6
    BSSID 2                 : 00:11:22:33:44:02
         Senal              : 78%
         Banda              : 5 GHz
         Canal              : 36
"""
    results = wss_engine.evaluate_networks(raw)

    assert len(results) == 2
    assert {item["observation_status"] for item in results} == {"MULTI_RADIO_OBSERVED"}
    assert all(item["anomaly"] is False for item in results)
    assert all(item["an"] == 0.0 for item in results)
    assert all(item["bm_label"] == "ALIGNED" for item in results)
    assert all(item["wss_score"] == 2.35 for item in results)


def test_multi_ap_same_profile_is_not_attack_alert():
    raw = """
SSID 1 : LAB-MESH
    Autenticacion           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 00:11:22:33:44:03
         Senal              : 80%
         Banda              : 2,4 GHz
         Canal              : 1
    BSSID 2                 : 00:11:22:33:44:04
         Senal              : 75%
         Banda              : 2,4 GHz
         Canal              : 6
"""
    results = wss_engine.evaluate_networks(raw)

    assert {item["observation_status"] for item in results} == {"MULTI_AP_OBSERVED"}
    assert all(item["anomaly"] is False for item in results)
    assert all(item["an"] == 0.0 for item in results)
    assert all("normal" in item["observation_message"] for item in results)


def test_security_profile_mismatch_requires_review_without_confirming_attack():
    raw = """
SSID 1 : LAB-MISMATCH
    Autenticacion           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 00:11:22:33:44:05
         Senal              : 70%
         Banda              : 2,4 GHz
         Canal              : 1

SSID 2 : LAB-MISMATCH
    Autenticacion           : Abierta
    Cifrado                 : Ninguna
    BSSID 1                 : 00:11:22:33:44:06
         Senal              : 70%
         Banda              : 2,4 GHz
         Canal              : 11
"""
    results = wss_engine.evaluate_networks(raw)

    assert {item["observation_status"] for item in results} == {"SECURITY_PROFILE_MISMATCH"}
    assert all(item["requires_technical_review"] is True for item in results)
    assert all(item["anomaly"] is False for item in results)
    assert all(item["an"] == 0.0 for item in results)
    assert all("ataque" not in item["observation_message"].lower() for item in results)


def test_hidden_ssids_remain_separate_and_are_not_grouped():
    raw = """
SSID 1 :
    Autenticacion           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 00:11:22:33:44:07
         Senal              : 70%
         Canal              : 1

SSID 2 :
    Autenticacion           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 00:11:22:33:44:08
         Senal              : 70%
         Canal              : 6

SSID 3 :
    Autenticacion           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 00:11:22:33:44:09
         Senal              : 70%
         Canal              : 11
"""
    results = wss_engine.evaluate_networks(raw)

    assert [item["ssid"] for item in results] == ["SSID oculto 1", "SSID oculto 2", "SSID oculto 3"]
    assert all(item["hidden_ssid"] is True for item in results)
    assert all(item["observation_status"] == "HIDDEN_SSID" for item in results)
    assert all(item["anomaly"] is False for item in results)
    assert all(item["an"] == 0.0 for item in results)
