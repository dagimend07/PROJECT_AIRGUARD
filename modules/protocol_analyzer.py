import tempfile
import os
from datetime import datetime
import pandas as pd

try:
    from scapy.all import rdpcap, Dot11, Dot11Deauth, Dot11Disas, EAPOL
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def get_sample_protocol_data():
    """Returns controlled lab evidence for Week 10 (EAPOL) and Week 11 (Deauth/Disas)."""
    eapol_df = pd.DataFrame([
        {"Packet #": 315, "Timestamp": "10:14:22.104", "Source (AP/Client)": "00:11:22:33:44:55 (AP)", "Destination": "AA:BB:CC:11:22:33 (Client)", "Handshake Step": "Message 1 of 4 (ANonce sent by AP)"},
        {"Packet #": 316, "Timestamp": "10:14:22.112", "Source (AP/Client)": "AA:BB:CC:11:22:33 (Client)", "Destination": "00:11:22:33:44:55 (AP)", "Handshake Step": "Message 2 of 4 (SNonce + MIC sent by Client)"},
        {"Packet #": 317, "Timestamp": "10:14:22.118", "Source (AP/Client)": "00:11:22:33:44:55 (AP)", "Destination": "AA:BB:CC:11:22:33 (Client)", "Handshake Step": "Message 3 of 4 (GTK + MIC sent by AP)"},
        {"Packet #": 318, "Timestamp": "10:14:22.125", "Source (AP/Client)": "AA:BB:CC:11:22:33 (Client)", "Destination": "00:11:22:33:44:55 (AP)", "Handshake Step": "Message 4 of 4 (Confirmation ACK from Client)"}
    ])

    deauth_df = pd.DataFrame([
        {"Packet #": 890, "Timestamp": "10:14:19.401", "Frame Type": "Deauthentication (0x0c)", "Source Address": "00:11:22:33:44:55", "Destination Address": "AA:BB:CC:11:22:33", "Reason Code": "7 (Class 3 frame received from nonassociated STA)"},
        {"Packet #": 891, "Timestamp": "10:14:19.405", "Frame Type": "Deauthentication (0x0c)", "Source Address": "00:11:22:33:44:55", "Destination Address": "AA:BB:CC:11:22:33", "Reason Code": "7 (Class 3 frame received from nonassociated STA)"},
        {"Packet #": 892, "Timestamp": "10:14:19.409", "Frame Type": "Deauthentication (0x0c)", "Source Address": "00:11:22:33:44:55", "Destination Address": "FF:FF:FF:FF:FF:FF", "Reason Code": "2 (Previous authentication no longer valid)"},
        {"Packet #": 910, "Timestamp": "10:14:20.002", "Frame Type": "Disassociation (0x0a)", "Source Address": "AA:BB:CC:11:22:33", "Destination Address": "00:11:22:33:44:55", "Reason Code": "8 (Disassociated because sending STA is leaving)"}
    ])

    summary = {
        "eapol_count": 4,
        "handshake_complete": True,
        "deauth_count": 3,
        "disas_count": 1,
        "burst_detected": True
    }
    return eapol_df, deauth_df, summary, None


def analyze_protocols(uploaded_file=None):
    """Extracts WPA/EAPOL handshakes and Deauth/Disassociation patterns from a PCAP."""
    if uploaded_file is None:
        return get_sample_protocol_data()

    if not SCAPY_AVAILABLE:
        return None, None, None, "Scapy is not installed. Run: python -m pip install scapy"

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name

    eapol_records = []
    deauth_records = []
    deauth_count = 0
    disas_count = 0

    try:
        packets = rdpcap(tmp_path)
        for idx, pkt in enumerate(packets, start=1):
            ts = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]
            src = pkt[Dot11].addr2 if pkt.haslayer(Dot11) and pkt[Dot11].addr2 else "Unknown"
            dst = pkt[Dot11].addr1 if pkt.haslayer(Dot11) and pkt[Dot11].addr1 else "Unknown"

            if pkt.haslayer(EAPOL):
                step_num = (len(eapol_records) % 4) + 1
                eapol_records.append({
                    "Packet #": idx,
                    "Timestamp": ts,
                    "Source (AP/Client)": src,
                    "Destination": dst,
                    "Handshake Step": f"EAPOL Key Frame (Observed Message {step_num})"
                })

            if pkt.haslayer(Dot11Deauth):
                deauth_count += 1
                reason = getattr(pkt[Dot11Deauth], "reason", "Unknown")
                deauth_records.append({
                    "Packet #": idx,
                    "Timestamp": ts,
                    "Frame Type": "Deauthentication (0x0c)",
                    "Source Address": src,
                    "Destination Address": dst,
                    "Reason Code": str(reason)
                })
            elif pkt.haslayer(Dot11Disas):
                disas_count += 1
                reason = getattr(pkt[Dot11Disas], "reason", "Unknown")
                deauth_records.append({
                    "Packet #": idx,
                    "Timestamp": ts,
                    "Frame Type": "Disassociation (0x0a)",
                    "Source Address": src,
                    "Destination Address": dst,
                    "Reason Code": str(reason)
                })

        summary = {
            "eapol_count": len(eapol_records),
            "handshake_complete": len(eapol_records) >= 4,
            "deauth_count": deauth_count,
            "disas_count": disas_count,
            "burst_detected": (deauth_count + disas_count) >= 3
        }
        return pd.DataFrame(eapol_records), pd.DataFrame(deauth_records), summary, None

    except Exception as e:
        return None, None, None, f"Error analyzing protocol frames: {str(e)}"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)