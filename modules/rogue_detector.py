import pandas as pd
import re

def get_authorized_baseline():
    """Returns a baseline of expected/authorized access points."""
    return pd.DataFrame([
        {"Expected_SSID": "CorpWiFi", "Expected_OUI": "Cisco Systems", "Expected_Security": "WPA2", "Expected_Channel": 1},
        {"Expected_SSID": "CorpGuest", "Expected_OUI": "Cisco Systems", "Expected_Security": "WPA2", "Expected_Channel": 6},
        {"Expected_SSID": "CorpNet", "Expected_OUI": "Cisco Systems", "Expected_Security": "WPA2", "Expected_Channel": 6},
        {"Expected_SSID": "Guest", "Expected_OUI": "Aruba Networks", "Expected_Security": "WPA3", "Expected_Channel": 36}
    ])

def normalize_homoglyphs(text):
    """Normalizes lookalike characters used in SSID spoofing."""
    t = str(text).strip()
    t = re.sub(r'\s+', '', t)
    t = t.replace('0', 'o').replace('O', 'o')
    t = t.replace('1', 'i').replace('l', 'i').replace('I', 'i')
    return t.lower()

def detect_rogues(inventory_df, baseline_df):
    """
    Compares observed wireless inventory against the authorized baseline to detect:
    1. Exact Evil Twins (SSID match with encryption downgrade or OUI mismatch)
    2. Homoglyph / Typo-Squatting Clones (e.g. C0rpWiFi, CorpWiFl, CorpWiFi )
    3. Multi-SSID Karma / Beacon Flood Attacks (same BSSID broadcasting multiple networks)
    4. Known Rogue Hardware (Hak5 WiFi Pineapple, Pwnagotchi)
    5. Insecure Legacy Networks (WEP encryption)
    """
    if inventory_df is None or inventory_df.empty:
        return pd.DataFrame()

    alerts = []
    
    # 1. Multi-SSID Karma / Beacon Flooding detection
    bssid_ssids = {}
    for _, row in inventory_df.iterrows():
        bssid = str(row.get("BSSID", "")).strip().upper()
        ssid = str(row.get("SSID", "")).strip()
        if bssid and bssid != "UNKNOWN" and ssid:
            bssid_ssids.setdefault(bssid, set()).add(ssid)
            
    karma_bssids = {bssid: ssids for bssid, ssids in bssid_ssids.items() if len(ssids) > 1}

    # Expected SSIDs from baseline
    expected_ssids = set(baseline_df["Expected_SSID"].dropna().astype(str).str.strip().unique()) if baseline_df is not None and not baseline_df.empty else set()
    norm_baseline = {normalize_homoglyphs(s): s for s in expected_ssids}

    # Track already flagged BSSIDs
    flagged_bssids = set()

    for _, observed in inventory_df.iterrows():
        bssid = str(observed.get("BSSID", "")).strip().upper()
        ssid = str(observed.get("SSID", "")).strip()
        sec = str(observed.get("Security", "Open")).strip()
        oui = str(observed.get("OUI", "Unknown")).strip()
        sig = str(observed.get("Signal", "N/A"))
        raw_enc = str(observed.get("Encryption", "")).upper()
        
        # Check Karma Flood
        if bssid in karma_bssids and bssid not in flagged_bssids:
            all_spoofed = ", ".join(list(karma_bssids[bssid])[:4])
            alerts.append({
                "Threat Type": "Multi-SSID Karma / Beacon Flood",
                "Target SSID": f"{ssid} (+{len(karma_bssids[bssid])-1} more)",
                "Suspicious BSSID": bssid,
                "Signal": sig,
                "Alert Details": f"BSSID is broadcasting {len(karma_bssids[bssid])} distinct SSIDs ({all_spoofed}). Characteristic of WiFi Pineapple Karma attack.",
                "Wireshark Filter": f"wlan.bssid == {bssid}"
            })
            flagged_bssids.add(bssid)
            continue

        # Check Known Attack Hardware (e.g. Pineapple5_A1B2)
        if any(tool in ssid.lower() for tool in ["pineapple", "pwnagotchi", "flipper", "wifiphisher"]) and bssid not in flagged_bssids:
            alerts.append({
                "Threat Type": "Rogue Pentest Tool / Pineapple",
                "Target SSID": ssid,
                "Suspicious BSSID": bssid,
                "Signal": sig,
                "Alert Details": f"Transmitter broadcasts known attack tool signature ('{ssid}'). Rogue auditing hardware active in area.",
                "Wireshark Filter": f"wlan.bssid == {bssid}"
            })
            flagged_bssids.add(bssid)
            continue

        # Check WEP Vulnerability
        if "WEP" in sec.upper() and bssid not in flagged_bssids:
            alerts.append({
                "Threat Type": "Vulnerable Protocol (WEP)",
                "Target SSID": ssid,
                "Suspicious BSSID": bssid,
                "Signal": sig,
                "Alert Details": "Deprecated 802.11 WEP encryption in use. Vulnerable to instantaneous statistical key recovery via IV replay.",
                "Wireshark Filter": f"wlan.bssid == {bssid} && wlan.wep.iv"
            })
            flagged_bssids.add(bssid)
            continue

        # Check Exact Evil Twin against Baseline
        match = baseline_df[baseline_df["Expected_SSID"] == ssid] if baseline_df is not None and not baseline_df.empty else pd.DataFrame()
        
        if not match.empty and bssid not in flagged_bssids:
            expected = match.iloc[0]
            reasons = []
            exp_sec = str(expected.get("Expected_Security", "WPA2")).strip()
            exp_oui = str(expected.get("Expected_OUI", "Cisco Systems")).strip()

            # OUI check (if OUI is spoofed or unknown or doesn't match expected vendor)
            if oui != exp_oui and oui != "Cisco Systems":
                reasons.append(f"OUI Mismatch (Expected: {exp_oui}, Observed: {oui})")

            # Encryption downgrade check
            if "OPEN" in sec.upper() or "NONE" in sec.upper():
                reasons.append(f"Security Downgrade (Expected: {exp_sec}, Observed: Unencrypted Open)")
            elif "PSK" in raw_enc and "EAP" in exp_sec.upper():
                reasons.append(f"Enterprise Downgrade (Expected 802.1X/EAP, Observed Pre-Shared Key PSK)")

            # Spoofed MAC check
            if bssid.startswith("02:") or "Locally Administered" in oui:
                reasons.append("Spoofed Locally Administered MAC address (02:xx:xx...)")

            if reasons:
                alerts.append({
                    "Threat Type": "Evil Twin / Rogue AP",
                    "Target SSID": ssid,
                    "Suspicious BSSID": bssid,
                    "Signal": sig,
                    "Alert Details": " | ".join(reasons),
                    "Wireshark Filter": f"wlan.bssid == {bssid}"
                })
                flagged_bssids.add(bssid)
                continue

        # Check Homoglyph / Typo-Squatting Clones
        norm_ssid = normalize_homoglyphs(ssid)
        if norm_ssid in norm_baseline and ssid != norm_baseline[norm_ssid] and bssid not in flagged_bssids:
            alerts.append({
                "Threat Type": "Homoglyph / Typo-Squatting Clone",
                "Target SSID": f"{ssid} (Mimicking {norm_baseline[norm_ssid]})",
                "Suspicious BSSID": bssid,
                "Signal": sig,
                "Alert Details": f"Lookalike SSID detected mimicking authorized '{norm_baseline[norm_ssid]}' using homoglyphs, typos, or hidden whitespace.",
                "Wireshark Filter": f"wlan.bssid == {bssid}"
            })
            flagged_bssids.add(bssid)

    return pd.DataFrame(alerts)
