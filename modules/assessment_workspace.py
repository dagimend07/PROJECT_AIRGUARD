import pandas as pd
from datetime import datetime, timedelta

def get_assessment_scope():
    """Returns the authorized rules of engagement and scope for the project."""
    # Calculates a default authorized window (e.g., today through the end of the semester)
    start_date = datetime.now()
    end_date = start_date + timedelta(days=60)
    
    return {
        "Project Name": "NWIT 275 Capstone Assessment",
        "Client / Instructor": "NWIT Security Department",
        "Authorized Start": start_date.strftime("%Y-%m-%d"),
        "Authorized End": end_date.strftime("%Y-%m-%d"),
        "In-Scope Targets": "CorpNet (00:11:22:33:44:55), Guest (11:22:33:44:55:66)",
        "Out-of-Scope": "Any physical infrastructure, personal student devices, real-world campus networks",
        "Approved Tools": "Wireshark, Kismet, Scapy, Streamlit, Gemini API (Lab data only)"
    }

def get_findings_log():
    """Returns an interactive dataframe for tracking vulnerabilities and remediation."""
    findings = [
        {
            "ID": "VULN-01",
            "Severity": "Critical",
            "Title": "Deprecated WEP Encryption in Use",
            "Target": "Hidden (66:77:88:99:AA:BB)",
            "Evidence (Packet/Log)": "Kismet row #5",
            "Status": "Open",
            "Remediation": "Decommission access point or upgrade to WPA3."
        },
        {
            "ID": "VULN-02",
            "Severity": "High",
            "Title": "Management Frame Burst / Possible Deauth Attack",
            "Target": "CorpNet (00:11:22:33:44:55)",
            "Evidence (Packet/Log)": "PCAP Packets #890-892 (wlan.fc.type_subtype == 0x0c)",
            "Status": "Verified",
            "Remediation": "Enable 802.11w Management Frame Protection (MFP)."
        }
    ]
    return pd.DataFrame(findings)