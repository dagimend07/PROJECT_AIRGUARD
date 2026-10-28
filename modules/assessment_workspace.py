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
    cols = ["ID", "Severity", "Title", "Target", "Evidence (Packet/Log)", "Status", "Remediation"]
    return pd.DataFrame(columns=cols)