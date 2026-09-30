import pandas as pd
from datetime import datetime

def generate_markdown_report(scope, findings_df):
    """Generates a professional Markdown report combining scope and verified findings."""
    date_str = datetime.now().strftime("%B %d, %Y")
    
    # Report Header & Executive Summary
    report = f"# Wireless Security Assessment Report\n"
    report += f"**Project:** {scope.get('Project Name', 'NWIT 275 Capstone')}\n"
    report += f"**Date Generated:** {date_str}\n"
    report += f"**Prepared For:** {scope.get('Client / Instructor', 'NWIT Security Dept')}\n\n"
    
    report += "## 1. Executive Summary\n"
    report += "This report details the findings of an authorized wireless security assessment. "
    report += f"Testing was strictly limited to approved targets: `{scope.get('In-Scope Targets', 'Lab Environment')}`. "
    
    if findings_df.empty:
        report += "No vulnerabilities were identified during this assessment window.\n\n"
        return report

    # Calculate metrics for the summary
    critical_count = len(findings_df[findings_df["Severity"] == "Critical"])
    high_count = len(findings_df[findings_df["Severity"] == "High"])
    report += f"During the assessment, **{len(findings_df)}** verified security finding(s) were identified, "
    report += f"including **{critical_count} Critical** and **{high_count} High** severity issues.\n\n"

    # Technical Findings Section
    report += "## 2. Technical Findings & Remediation\n"
    
    for index, row in findings_df.iterrows():
        # Only include verified/open findings in the final report, exclude False Positives
        if str(row.get("Status", "")) == "False Positive":
            continue
            
        report += f"### {row.get('ID', 'VULN')}: {row.get('Title', 'Unknown Issue')}\n"
        report += f"* **Severity:** {row.get('Severity', 'Unknown')}\n"
        report += f"* **Target / BSSID:** {row.get('Target', 'Unknown')}\n"
        report += f"* **Status:** {row.get('Status', 'Open')}\n"
        report += f"* **Evidence (Packet/Log):** {row.get('Evidence (Packet/Log)', 'None Provided')}\n"
        report += f"* **Recommended Remediation:** {row.get('Remediation', 'Requires investigation.')}\n\n"
        
    report += "## 3. Methodology & Authorization\n"
    report += "All activities were conducted using passive and authorized analytical methods. "
    report += f"Tools utilized: {scope.get('Approved Tools', 'Wireshark, Python, Streamlit')}.\n"
    
    return report

def get_security_checklist():
    """Returns the Week 14 Platform Security Checklist."""
    return pd.DataFrame([
        {"Control": "API Key Protection", "Status": "Pass", "Details": "Keys are entered via UI password fields, not hardcoded in Git."},
        {"Control": "Input Validation", "Status": "Pass", "Details": "File uploaders restrict types to .csv and .pcap/.pcapng only."},
        {"Control": "Dependency Hygiene", "Status": "Pending", "Details": "Review requirements.txt for outdated packages before final demo."},
        {"Control": "Safe Logging", "Status": "Pass", "Details": "No private credential data or PII is written to console logs."}
    ])