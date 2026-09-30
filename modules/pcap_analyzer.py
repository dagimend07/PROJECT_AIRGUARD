import tempfile
import os
import pandas as pd

try:
    from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Auth, Dot11Deauth, EAPOL
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def get_wireshark_filters():
    """Returns verified Wireshark filters for the Week 5 Evidence Worksheet."""
    filters = [
        {"Frame Category": "Beacon Frames", "Wireshark Filter": "wlan.fc.type_subtype == 0x08", "Purpose": "Identify access points broadcasting their SSID"},
        {"Frame Category": "Probe Requests", "Wireshark Filter": "wlan.fc.type_subtype == 0x04", "Purpose": "See client devices actively searching for networks"},
        {"Frame Category": "Probe Responses", "Wireshark Filter": "wlan.fc.type_subtype == 0x05", "Purpose": "See AP replies to client probe requests"},
        {"Frame Category": "Authentication", "Wireshark Filter": "wlan.fc.type_subtype == 0x0b", "Purpose": "Track 802.11 authentication attempts"},
        {"Frame Category": "Deauthentication", "Wireshark Filter": "wlan.fc.type_subtype == 0x0c", "Purpose": "Investigate potential deauth attacks or drops"},
        {"Frame Category": "EAPOL (WPA Handshake)", "Wireshark Filter": "eapol", "Purpose": "Verify WPA/WPA2 4-way handshake messages"}
    ]
    return pd.DataFrame(filters)


def get_sample_pcap_summary():
    """Returns simulated lab capture counts for testing when no PCAP is uploaded."""
    counts = {
        "Total Packets": 1420,
        "Beacon": 850,
        "Probe Request": 210,
        "Probe Response": 145,
        "Authentication": 24,
        "Deauthentication": 38,
        "EAPOL": 12
    }
    events = pd.DataFrame([
        {"Packet #": 104, "Type": "Probe Request", "Source": "AA:BB:CC:11:22:33", "Destination": "ff:ff:ff:ff:ff:ff", "Details": "Client probing for CorpNet"},
        {"Packet #": 312, "Type": "Authentication", "Source": "AA:BB:CC:11:22:33", "Destination": "00:11:22:33:44:55", "Details": "Open System Auth"},
        {"Packet #": 315, "Type": "EAPOL", "Source": "00:11:22:33:44:55", "Destination": "AA:BB:CC:11:22:33", "Details": "WPA2 4-Way Handshake (Message 1 of 4)"},
        {"Packet #": 890, "Type": "Deauthentication", "Source": "00:11:22:33:44:55", "Destination": "AA:BB:CC:11:22:33", "Details": "Unusual burst of deauth frames detected"}
    ])
    return counts, events


def analyze_pcap(uploaded_file):
    """Safely parses an uploaded PCAP file and extracts 802.11 frame counts."""
    if not SCAPY_AVAILABLE:
        return None, None, "Scapy is not installed. Run: python -m pip install scapy"

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name

    counts = {
        "Total Packets": 0,
        "Beacon": 0,
        "Probe Request": 0,
        "Probe Response": 0,
        "Authentication": 0,
        "Deauthentication": 0,
        "EAPOL": 0
    }
    notable_events = []

    try:
        packets = rdpcap(tmp_path)
        counts["Total Packets"] = len(packets)

        for idx, pkt in enumerate(packets, start=1):
            src = pkt[Dot11].addr2 if pkt.haslayer(Dot11) and pkt[Dot11].addr2 else "Unknown"
            dst = pkt[Dot11].addr1 if pkt.haslayer(Dot11) and pkt[Dot11].addr1 else "Unknown"

            if pkt.haslayer(Dot11Beacon):
                counts["Beacon"] += 1
            elif pkt.haslayer(Dot11ProbeReq):
                counts["Probe Request"] += 1
            elif pkt.haslayer(Dot11ProbeResp):
                counts["Probe Response"] += 1
            elif pkt.haslayer(Dot11Auth):
                counts["Authentication"] += 1
                if len(notable_events) <= 50:
                    notable_events.append({"Packet #": idx, "Type": "Authentication", "Source": src, "Destination": dst, "Details": "802.11 Auth Frame"})
            elif pkt.haslayer(Dot11Deauth):
                counts["Deauthentication"] += 1
                if len(notable_events) <= 50:
                    notable_events.append({"Packet #": idx, "Type": "Deauthentication", "Source": src, "Destination": dst, "Details": "802.11 Deauth Frame"})

            if pkt.haslayer(EAPOL):
                counts["EAPOL"] += 1
                if len(notable_events) <= 50:
                    notable_events.append({"Packet #": idx, "Type": "EAPOL", "Source": src, "Destination": dst, "Details": "WPA/WPA2 Handshake Frame"})

        events_df = pd.DataFrame(notable_events)
        return counts, events_df, None

    except Exception as e:
        return None, None, f"Error parsing PCAP: {str(e)}"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)