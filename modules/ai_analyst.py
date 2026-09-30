import pandas as pd

def ask_ai_analyst(query, inventory_df=None, pcap_counts=None, api_key=None):
    """Generates security explanations, Wireshark filters, and an investigation checklist."""
    # If the user provides a Gemini API key, attempt live LLM inference
    if api_key and api_key.strip():
        try:
            from google import genai
            client = genai.Client(api_key=api_key.strip())
            context = f"Inventory Data:\n{inventory_df.to_string() if inventory_df is not None else 'None'}\n"
            context += f"PCAP Counts:\n{pcap_counts if pcap_counts is not None else 'None'}\n"
            prompt = (
                "You are an AI Wireless Security Analyst for Project AirGuard. "
                "Remember the rule: AI is a copilot, not the evidence. "
                "Answer the user question, suggest exact Wireshark filters, and provide a 3-step verification checklist.\n\n"
                f"{context}\nQuestion: {query}"
            )
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            return response.text
        except Exception as e:
            return f"API Connection Notice: {str(e)}\n\nFalling back to built-in Offline Analyst..."

    # Built-in Offline AI Copilot (Works without an API key)
    q = query.lower()
    if "deauth" in q or "attack" in q or "drop" in q:
        return (
            "### AI Assessment: Potential Deauthentication Activity\n"
            "* **Explanation:** High volumes of 802.11 Deauthentication frames (`0x0c`) often indicate a denial-of-service attack or an adversary forcing clients to reconnect to capture a WPA handshake.\n"
            "* **Recommended Wireshark Filter:** `wlan.fc.type_subtype == 0x0c`\n"
            "* **Investigation Checklist:**\n"
            "  1. Filter the PCAP using `wlan.fc.type_subtype == 0x0c` and inspect packet timestamps for tight bursts.\n"
            "  2. Check the source BSSID (`wlan.sa`) and destination address (`wlan.da`).\n"
            "  3. Check if `eapol` frames immediately follow the deauthentication burst."
        )
    elif "wep" in q or "open" in q or "risk" in q or "weak" in q:
        return (
            "### AI Assessment: Weak Wireless Encryption Detected\n"
            "* **Explanation:** Networks using `WEP` or `Open` authentication lack strong cryptographic protection, exposing traffic to eavesdropping or rapid key recovery.\n"
            "* **Recommended Wireshark Filter:** `wlan.fc.type_subtype == 0x08 && !wlan.rsn.version`\n"
            "* **Investigation Checklist:**\n"
            "  1. Verify the SSID and BSSID in the Wireless Inventory table.\n"
            "  2. Inspect Beacon frames (`wlan.fc.type_subtype == 0x08`) to confirm RSN/WPA information elements are missing.\n"
            "  3. Document whether the Open network is an authorized guest portal or a misconfiguration."
        )
    elif "eapol" in q or "handshake" in q or "wpa" in q:
        return (
            "### AI Assessment: WPA/WPA2 4-Way Handshake Analysis\n"
            "* **Explanation:** EAPOL frames show client authentication to an access point. Capturing all 4 messages allows offline passphrase auditing.\n"
            "* **Recommended Wireshark Filter:** `eapol`\n"
            "* **Investigation Checklist:**\n"
            "  1. Apply the `eapol` filter in Wireshark and verify which messages (1 of 4 through 4 of 4) are present.\n"
            "  2. Confirm the client MAC address and AP BSSID match an authorized lab device.\n"
            "  3. Check for preceding deauthentication frames that may have forced the handshake."
        )
    else:
        return (
            "### AI Assessment: General Wireless Investigation Guidance\n"
            "* **Explanation:** Review both your passive discovery inventory and packet captures to correlate high-risk configurations with active frame anomalies.\n"
            "* **Recommended Wireshark Filter:** `wlan.fc.type == 0` (All 802.11 Management Frames)\n"
            "* **Investigation Checklist:**\n"
            "  1. Identify any Critical or High risk access points in the Wireless Inventory.\n"
            "  2. Filter the PCAP by the target BSSID using `wlan.bssid == AA:BB:CC:DD:EE:FF`.\n"
            "  3. Verify every AI claim against raw packet numbers before logging a finding."
        )


def get_verification_challenges():
    """Returns Week 8 AI Hallucination & Verification Challenge records following the Evidence-First Rule."""
    challenges = [
        {
            "AI Statement": "Possible deauthentication attack against CorpNet (38 frames detected)",
            "Required Evidence": "wlan.fc.type_subtype == 0x0c (Packet #890)",
            "Student Verification": "Verified True Positive",
            "Conclusion & Remediation": "Confirmed burst from 00:11:22:33:44:55. Enable 802.11w (Management Frame Protection)."
        },
        {
            "AI Statement": "Critical Evil Twin attack detected on Guest network (Channel 36)",
            "Required Evidence": "Compare BSSID 11:22:33:44:55:66 OUI & WPA3 Beacon frames",
            "Student Verification": "Rejected (AI Hallucination / False Positive)",
            "Conclusion & Remediation": "Legitimate dual-band Aruba AP operating on 5GHz. No remediation required."
        },
        {
            "AI Statement": "High-risk WEP encryption active on Hidden SSID",
            "Required Evidence": "Kismet Inventory Row #5 (BSSID 66:77:88:99:AA:BB)",
            "Student Verification": "Verified True Positive",
            "Conclusion & Remediation": "Deprecated WEP encryption confirmed. Decommission or upgrade AP to WPA2/WPA3."
        }
    ]
    return pd.DataFrame(challenges)