import pandas as pd
from datetime import datetime

def generate_markdown_report(scope, findings_df, inv_df=None, pcap_counts=None, proto_summary=None):
    """
    Generates a professional Markdown technical report combining:
    - Scope and Rules of Engagement
    - Wireless Environment Telemetry (Inventory)
    - Frame Traffic & Handshake Analysis (PCAP / Protocol Audit)
    - Technical Vulnerability Findings with verified Wireshark filters & remediations
    - Ethical Methodology & Authorization
    """
    date_str = datetime.now().strftime("%B %d, %Y")
    
    # Report Header & Executive Summary
    report = f"# Wireless Security Assessment & Penetration Testing Report\n\n"
    report += f"**Engagement / Project:** {scope.get('Project Name', 'NWIT 275 Capstone Assessment')}\n\n"
    report += f"**Assessment Date:** {date_str}\n\n"
    report += f"**Prepared For:** {scope.get('Client / Instructor', 'NWIT Security Dept')}\n\n"
    report += f"**Authorized Assessment Window:** {scope.get('Authorized Start', 'N/A')} to {scope.get('Authorized End', 'N/A')}\n\n"
    report += f"**In-Scope Targets:** `{scope.get('In-Scope Targets', 'Authorized Lab Environment')}`\n\n"
    report += f"**Out-of-Scope Restrictions:** `{scope.get('Out-of-Scope', 'Production networks, physical hardware, student devices')}`\n\n"
    report += "---\n\n"
    
    report += "## 1. Executive Summary\n\n"
    report += (
        "This technical deliverable documents the results of an authorized wireless security evaluation conducted under the "
        "rules of engagement specified above. Testing combined passive 802.11 spectrum discovery, packet frame analysis, "
        "cryptographic key exchange verification, and rogue access point correlation.\n\n"
    )
    
    # High-level metrics
    valid_findings = findings_df[findings_df["Status"] != "False Positive"] if not findings_df.empty else pd.DataFrame()
    crit_cnt = len(valid_findings[valid_findings["Severity"] == "Critical"]) if not valid_findings.empty else 0
    high_cnt = len(valid_findings[valid_findings["Severity"] == "High"]) if not valid_findings.empty else 0
    med_cnt = len(valid_findings[valid_findings["Severity"] == "Medium"]) if not valid_findings.empty else 0
    low_cnt = len(valid_findings[valid_findings["Severity"].isin(["Low", "Informational"])]) if not valid_findings.empty else 0

    report += (
        f"A total of **{len(valid_findings)} verified security findings** were documented across all assessment modules, comprising "
        f"**{crit_cnt} Critical**, **{high_cnt} High**, **{med_cnt} Medium**, and **{low_cnt} Low/Informational** severity issues.\n\n"
    )

    # Telemetry summaries if available
    has_telemetry = (inv_df is not None and not inv_df.empty) or (pcap_counts is not None) or (proto_summary is not None)
    if has_telemetry:
        report += "### 1.1 Wireless Environment Telemetry Overview\n\n"
        
        if inv_df is not None and not inv_df.empty:
            total_aps = len(inv_df)
            wpa_sec = len(inv_df[inv_df["Security"].isin(["WPA2", "WPA3"])]) if "Security" in inv_df.columns else 0
            open_sec = len(inv_df[inv_df["Security"] == "Open"]) if "Security" in inv_df.columns else 0
            wep_sec = len(inv_df[inv_df["Security"] == "WEP"]) if "Security" in inv_df.columns else 0
            report += f"* **Passive Discovery (Kismet):** **{total_aps}** total access points recorded. Encryption distribution: **{wpa_sec}** WPA2/WPA3, **{open_sec}** Unencrypted (Open), **{wep_sec}** Deprecated WEP.\n"

        if pcap_counts is not None:
            report += (
                f"* **Packet Capture Telemetry:** **{pcap_counts.get('Total Packets', 0):,}** frames inspected. "
                f"Management breakdown: **{pcap_counts.get('Beacon', 0)}** Beacons, "
                f"**{pcap_counts.get('Probe Request', 0)}** Probes, "
                f"**{pcap_counts.get('Deauthentication', 0)}** Deauths, "
                f"**{pcap_counts.get('EAPOL', 0)}** EAPOL Handshakes.\n"
            )

        if proto_summary is not None:
            hs_status = "Complete (4/4 messages captured)" if proto_summary.get("handshake_complete") else "Partial / Incomplete"
            burst_status = "MALICIOUS BURST DETECTED" if proto_summary.get("burst_detected") else "Normal traffic baseline"
            report += f"* **Protocol Cryptanalysis:** WPA 4-way key exchange: `{hs_status}`. Deauthentication pattern: `{burst_status}` ({proto_summary.get('deauth_count', 0)} frames observed).\n"

        report += "\n---\n\n"

    # Technical Findings Section
    report += "## 2. Verified Technical Findings & Remediation\n\n"
    
    if valid_findings.empty:
        report += "*(No verified vulnerabilities or rogue threats are currently logged in the Assessment Workspace findings log.)*\n\n"
    else:
        for _, row in valid_findings.iterrows():
            f_id = row.get("ID", "FIND-xx")
            f_title = row.get("Title", "Untitled Finding")
            f_sev = row.get("Severity", "Informational")
            f_tgt = row.get("Target", "Unknown Target")
            f_stat = row.get("Status", "Open")
            f_evid = row.get("Evidence (Packet/Log)", "No technical evidence attached.")
            f_rem = row.get("Remediation", "Investigate and apply wireless hardening controls.")
            
            report += f"### [{f_id}] {f_title}\n\n"
            report += f"* **Severity:** `{f_sev}`\n"
            report += f"* **Target / Affected Emitter:** `{f_tgt}`\n"
            report += f"* **Remediation Status:** **{f_stat}**\n"
            report += f"* **Technical Evidence (Filters & Logs):**\n  > `{f_evid}`\n"
            report += f"* **Actionable Remediation Guidance:**\n  {f_rem}\n\n"

    report += "---\n\n"
    report += "## 3. Methodology & Authorization Compliance\n\n"
    report += (
        f"All assessment procedures strictly adhered to authorized methodology. "
        f"Approved analytical tools utilized: `{scope.get('Approved Tools', 'Wireshark, Kismet, Scapy, Streamlit, Gemini API')}`. "
        "In accordance with the Evidence-First Rule, all automated detections were validated against raw packet captures and BSSID telemetry.\n"
    )
    
    return report


def get_security_checklist():
    """Returns the Week 14 Platform Security Checklist."""
    return pd.DataFrame([
        {"Control": "API Key Protection", "Status": "Pass", "Details": "Keys are entered via UI password fields, not hardcoded in Git."},
        {"Control": "Input Validation", "Status": "Pass", "Details": "File uploaders restrict types to .csv and .pcap/.pcapng only."},
        {"Control": "Dependency Hygiene", "Status": "Pass", "Details": "Clean requirements.txt maintained with locked versions."},
        {"Control": "Safe Logging", "Status": "Pass", "Details": "No private credential data or PII is written to console logs."}
    ])
