import pandas as pd

def get_authorized_baseline():
    """Returns a baseline of expected/authorized access points."""
    return pd.DataFrame([
        {"Expected_SSID": "CorpNet", "Expected_OUI": "Cisco Systems", "Expected_Security": "WPA2", "Expected_Channel": 6},
        {"Expected_SSID": "Guest", "Expected_OUI": "Aruba Networks", "Expected_Security": "WPA3", "Expected_Channel": 36}
    ])

def detect_rogues(inventory_df, baseline_df):
    """Compares observed wireless inventory against the authorized baseline to detect anomalies."""
    if inventory_df is None or inventory_df.empty:
        return pd.DataFrame()

    alerts = []

    for _, observed in inventory_df.iterrows():
        ssid = str(observed.get("SSID", "")).strip()
        
        # Check if the observed SSID matches any in our authorized baseline
        match = baseline_df[baseline_df["Expected_SSID"] == ssid]
        
        if not match.empty:
            expected = match.iloc[0]
            reasons = []
            
            # Check for OUI/Vendor mismatch (Classic Evil Twin indicator)
            if str(observed.get("OUI", "")) != expected["Expected_OUI"]:
                reasons.append(f"OUI Mismatch (Expected: {expected['Expected_OUI']}, Observed: {observed.get('OUI', 'Unknown')})")
                
            # Check for encryption downgrade (e.g., WPA2 downgraded to Open)
            if str(observed.get("Security", "")) != expected["Expected_Security"]:
                reasons.append(f"Security Downgrade (Expected: {expected['Expected_Security']}, Observed: {observed.get('Security', 'Unknown')})")
                
            # Flag if there are any anomalies for an expected SSID
            if reasons:
                alerts.append({
                    "Threat Type": "Evil Twin / Rogue AP",
                    "Target SSID": ssid,
                    "Suspicious BSSID": observed.get("BSSID", "Unknown"),
                    "Signal": observed.get("Signal", "N/A"),
                    "Alert Details": " | ".join(reasons)
                })

    return pd.DataFrame(alerts)