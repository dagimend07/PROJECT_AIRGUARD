import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import os 
import importlib

import modules.inventory
import modules.pcap_analyzer
import modules.ai_analyst
import modules.rogue_detector
import modules.protocol_analyzer
import modules.assessment_workspace
import modules.reporter
import modules.ui_theme

importlib.reload(modules.inventory)
importlib.reload(modules.pcap_analyzer)
importlib.reload(modules.ai_analyst)
importlib.reload(modules.rogue_detector)
importlib.reload(modules.protocol_analyzer)
importlib.reload(modules.assessment_workspace)
importlib.reload(modules.reporter)
importlib.reload(modules.ui_theme)

from modules.inventory import load_inventory_data
from modules.pcap_analyzer import analyze_pcap, get_wireshark_filters
from modules.ai_analyst import ask_ai_analyst, get_verification_challenges
from modules.rogue_detector import get_authorized_baseline, detect_rogues
from modules.protocol_analyzer import analyze_protocols
from modules.assessment_workspace import get_assessment_scope, get_findings_log
from modules.reporter import generate_markdown_report, get_security_checklist
from modules.ui_theme import get_custom_css, get_stitch_radar_scanner_component, render_page_header

# Configure page
st.set_page_config(page_title="Project AirGuard | Wireless Security Platform", layout="wide", initial_sidebar_state="expanded")

# Inject Design System CSS
st.markdown(get_custom_css(), unsafe_allow_html=True)

# -------------------------------------------------------------
# Central Shared Session State (Starts Purely Empty - No Fake Samples)
# -------------------------------------------------------------
if "inventory_df" not in st.session_state:
    st.session_state["inventory_df"] = pd.DataFrame()

if "baseline_df" not in st.session_state:
    st.session_state["baseline_df"] = get_authorized_baseline()

if "findings_df" not in st.session_state:
    st.session_state["findings_df"] = get_findings_log()

if "pcap_counts" not in st.session_state:
    st.session_state["pcap_counts"] = None

if "pcap_events" not in st.session_state:
    st.session_state["pcap_events"] = pd.DataFrame()

if "protocol_summary" not in st.session_state:
    st.session_state["protocol_summary"] = None

if "scope" not in st.session_state:
    st.session_state["scope"] = get_assessment_scope()

# Active correlated threats
active_inv = st.session_state["inventory_df"]
active_baseline = st.session_state["baseline_df"]
live_alerts_df = detect_rogues(active_inv, active_baseline) if not active_inv.empty else pd.DataFrame()

# -------------------------------------------------------------
# Sidebar Navigation & Telemetry
# -------------------------------------------------------------
st.sidebar.markdown("""
<div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px; padding: 4px 0;">
    <div style="width: 34px; height: 34px; border-radius: 8px; background: rgba(0, 240, 255, 0.12); border: 1px solid rgba(0, 219, 233, 0.35); display: flex; align-items: center; justify-content: center; font-size: 16px;">
        🛡️
    </div>
    <div>
        <div style="font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 16px; color: #dbfcff; letter-spacing: -0.01em; line-height: 1.1;">AirGuard</div>
        <div style="font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #849495; letter-spacing: 0.08em; text-transform: uppercase;">SpectralSec v4.2</div>
    </div>
</div>
""", unsafe_allow_html=True)

ap_cnt = len(active_inv)
th_cnt = len(live_alerts_df) if not live_alerts_df.empty else 0
has_data = ap_cnt > 0 or (st.session_state["pcap_counts"] is not None)

interface_badge_html = f"""
<div style="background: #191b23; border: 1px solid rgba(59, 73, 75, 0.35); border-radius: 10px; padding: 10px 12px; margin-bottom: 14px;">
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px;">
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #849495; text-transform: uppercase;">Active Interface</span>
        <span style="display: inline-flex; align-items: center; gap: 4px; font-family: 'JetBrains Mono', monospace; font-size: 9.5px; color: {'#4edea3' if has_data else '#849495'}; background: #272a32; padding: 2px 6px; border-radius: 4px;">
            <span style="width: 5px; height: 5px; border-radius: 50%; background: {'#4edea3' if has_data else '#849495'};"></span>{'MONITOR' if has_data else 'STANDBY'}
        </span>
    </div>
    <div style="display: flex; align-items: center; justify-content: space-between;">
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #dbfcff; font-weight: 700;">wlan0mon</span>
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #849495;">{'30 dBm' if has_data else '0 dBm'}</span>
    </div>
    <div style="display: flex; align-items: center; justify-content: space-between; font-family: 'JetBrains Mono', monospace; font-size: 9.5px; color: #849495; margin-top: 2px;">
        <span>CH HOP: {'1-165' if has_data else 'IDLE'}</span>
        <span style="color: {'#4edea3' if has_data else '#849495'};">PHY0 802.11ax</span>
    </div>
    <div style="margin-top: 8px; padding-top: 6px; border-top: 1px solid rgba(59, 73, 75, 0.25); display: flex; justify-content: space-between; font-family: 'JetBrains Mono', monospace; font-size: 9px;">
        <span style="color: #00dbe9;">{ap_cnt} APs Observed</span>
        <span style="color: {'#ffb4ab' if th_cnt > 0 else ('#4edea3' if has_data else '#849495')};">{'🚨 ' + str(th_cnt) + ' Rogues' if th_cnt > 0 else ('0 Threats' if has_data else 'STANDBY')}</span>
    </div>
</div>
"""
st.sidebar.markdown(interface_badge_html, unsafe_allow_html=True)

st.sidebar.markdown("---")
navigation = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Wireless Inventory", "PCAP Analyzer", "AI Analyst", 
     "Rogue AP Detector", "Protocol Analysis", "Assessment Workspace", "Reports"]
)

spectral_load_html = f"""
<div style="background: #191b23; border: 1px solid rgba(59, 73, 75, 0.35); border-radius: 10px; padding: 10px 12px; margin-top: 24px;">
    <div style="display: flex; justify-content: space-between; font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #849495;">
        <span>{'RX 28.4 MB/s' if has_data else 'RX 0.0 KB/s'}</span>
        <span>{'TX 1.2 MB/s' if has_data else 'TX 0.0 KB/s'}</span>
    </div>
    <div style="width: 100%; background: #0b0e15; height: 4px; border-radius: 2px; overflow: hidden; margin: 6px 0;">
        <div style="width: {'68%' if has_data else '0%'}; height: 100%; background: #4edea3;"></div>
    </div>
    <div style="display: flex; justify-content: space-between; font-family: 'JetBrains Mono', monospace; font-size: 9.5px; color: #849495;">
        <span>INTERFACE STATUS</span>
        <span style="color: {'#00dbe9' if has_data else '#849495'}; font-weight: 600;">{'ONLINE' if has_data else 'STANDBY'}</span>
    </div>
</div>
"""
st.sidebar.markdown(spectral_load_html, unsafe_allow_html=True)

if has_data:
    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Reset / Clear All Captures", use_container_width=True, help="Clear loaded wireless inventory and PCAP frames to return to standby"):
        st.session_state["inventory_df"] = pd.DataFrame()
        st.session_state["pcap_counts"] = None
        st.session_state["pcap_events"] = pd.DataFrame()
        st.session_state["protocol_summary"] = None
        st.session_state.pop("dashboard_ai_summary", None)
        st.toast("Platform reset to factory standby state! All captures cleared.", icon="🔄")
        st.rerun()

st.sidebar.caption("NWIT 275 - Fall Semester Build")


# =============================================================
# 1. FUNCTIONAL DASHBOARD (CONNECTED TO ALL PROJECT MODULES)
# =============================================================
if navigation == "Dashboard":
    inv_df = st.session_state["inventory_df"]
    baseline_df = st.session_state["baseline_df"]
    findings_df = st.session_state["findings_df"]
    pcap_counts = st.session_state["pcap_counts"]
    pcap_events = st.session_state["pcap_events"]
    scope = st.session_state["scope"]
    proto_summary = st.session_state.get("protocol_summary")
    alerts_df = detect_rogues(inv_df, baseline_df) if not inv_df.empty else pd.DataFrame()
    has_any_data = (not inv_df.empty) or (pcap_counts is not None)

    # Header Banner
    st.markdown(render_page_header(
        title="Mini Wireless SOC & Operations Console",
        subtitle="Real-time 802.11 environment summary, active threat correlation, and verified evidence links.",
        badge_text="SOC ONLINE" if has_any_data else "SOC STANDBY",
        badge_type="cyan" if has_any_data else "warning"
    ), unsafe_allow_html=True)

    # Prominent Evidence Ingestion Uplink (Shown when no data, or as expander when data exists)
    if not has_any_data:
        st.markdown("""
        <div style="background: rgba(0, 240, 255, 0.05); border: 1px dashed rgba(0, 219, 233, 0.4); border-radius: 12px; padding: 18px 22px; margin-bottom: 20px;">
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
                <span style="font-size: 20px;">📥</span>
                <span style="font-family: 'Space Grotesk', sans-serif; font-size: 16px; font-weight: 700; color: #dbfcff;">
                    Telemetry Uplink & Evidence Ingestion
                </span>
            </div>
            <p style="font-size: 13px; color: #b9cacb; margin: 0 0 12px 0;">
                No wireless capture evidence is loaded. Upload your Kismet discovery CSV or wireless packet capture (.pcap) below to initialize real-time RF telemetry, 360° radar detection, and threat matrices.
            </p>
        </div>
        """, unsafe_allow_html=True)

        intake_c1, intake_c2 = st.columns(2)
        up_kismet = intake_c1.file_uploader("Upload Kismet CSV (Inventory & Rogue Detection)", type=["csv"], key="dash_init_csv")
        up_pcap = intake_c2.file_uploader("Upload PCAP Capture (Frame Inspection & Handshakes)", type=["pcap", "pcapng"], key="dash_init_pcap")

        if up_kismet is not None:
            st.session_state["inventory_df"] = load_inventory_data(up_kismet)
            st.success(f"Loaded wireless inventory from {up_kismet.name}!")
            st.rerun()

        if up_pcap is not None:
            counts, events, err = analyze_pcap(up_pcap)
            if not err:
                st.session_state["pcap_counts"] = counts
                st.session_state["pcap_events"] = events
                st.success(f"Parsed PCAP evidence from {up_pcap.name}!")
                st.rerun()
            else:
                st.error(err)
    else:
        with st.expander("📥 Evidence Ingestion & Telemetry Uplink (Upload Additional Captures)", expanded=False):
            intake_c1, intake_c2 = st.columns(2)
            up_kismet = intake_c1.file_uploader("Upload Kismet CSV", type=["csv"], key="dash_exp_csv")
            up_pcap = intake_c2.file_uploader("Upload PCAP Capture", type=["pcap", "pcapng"], key="dash_exp_pcap")

            if up_kismet is not None:
                st.session_state["inventory_df"] = load_inventory_data(up_kismet)
                st.success(f"Updated inventory with {up_kismet.name}!")
                st.rerun()

            if up_pcap is not None:
                counts, events, err = analyze_pcap(up_pcap)
                if not err:
                    st.session_state["pcap_counts"] = counts
                    st.session_state["pcap_events"] = events
                    st.success(f"Updated PCAP telemetry with {up_pcap.name}!")
                    st.rerun()
                else:
                    st.error(err)

    # Band filter and controls
    ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4 = st.columns([1.6, 1.0, 1.0, 1.0])
    with ctrl_col1:
        band_filter = st.radio(
            "RF Band Filter",
            ["All Bands (2.4 & 5 GHz)", "2.4 GHz ISM Band [CH 1-14]", "5 GHz UNII Band [CH 36-165]"],
            horizontal=True,
            label_visibility="collapsed"
        )
    with ctrl_col2:
        run_ai_btn = st.button("🤖 AI Correlation", use_container_width=True, disabled=not has_any_data)
    with ctrl_col3:
        rescan_btn = st.button("🔄 Re-Correlate", use_container_width=True, disabled=inv_df.empty)
    with ctrl_col4:
        if has_any_data:
            if st.button("🗑️ Reset Telemetry", use_container_width=True, help="Clear active Dashboard telemetry and radar"):
                st.session_state["inventory_df"] = pd.DataFrame()
                st.session_state["pcap_counts"] = None
                st.session_state["pcap_events"] = pd.DataFrame()
                st.session_state["protocol_summary"] = None
                st.session_state.pop("dashboard_ai_summary", None)
                st.toast("Dashboard telemetry reset to Standby!", icon="🗑️")
                st.rerun()
        else:
            st.button("🗑️ Reset Telemetry", use_container_width=True, disabled=True)

    if rescan_btn and not inv_df.empty:
        alerts_df = detect_rogues(inv_df, baseline_df)
        st.toast("Baselines re-correlated successfully!", icon="✅")

    # Filter inventory based on band
    if not inv_df.empty:
        if "2.4 GHz" in band_filter:
            view_df = inv_df[inv_df["Channel"].astype(str).str.extract(r"(\d+)")[0].astype(float).fillna(0).between(1, 14)]
        elif "5 GHz" in band_filter:
            view_df = inv_df[inv_df["Channel"].astype(str).str.extract(r"(\d+)")[0].astype(float).fillna(0) > 14]
        else:
            view_df = inv_df
    else:
        view_df = pd.DataFrame()

    # Metric computations
    total_aps = len(view_df)
    wpa_count = len(view_df[view_df["Security"].isin(["WPA2", "WPA3"])]) if not view_df.empty and "Security" in view_df.columns else 0
    weak_count = len(view_df[view_df["Security"].isin(["Open", "WEP"])]) if not view_df.empty and "Security" in view_df.columns else 0

    # Monitored clients
    client_macs = set()
    if pcap_events is not None and not pcap_events.empty:
        for _, row in pcap_events.iterrows():
            src = str(row.get("Source", "")).strip()
            dst = str(row.get("Destination", "")).strip()
            if src and src != "Unknown" and src.lower() != "ff:ff:ff:ff:ff:ff":
                client_macs.add(src)
            if dst and dst != "Unknown" and dst.lower() != "ff:ff:ff:ff:ff:ff":
                client_macs.add(dst)
        ap_bssids = set(inv_df["BSSID"].dropna().astype(str).str.upper().unique()) if not inv_df.empty and "BSSID" in inv_df.columns else set()
        client_macs = client_macs - ap_bssids

    active_clients_count = len(client_macs) if client_macs else (pcap_counts.get("Probe Request", 0) // 15 if pcap_counts else 0)

    # Threats & Risk Posture
    rogue_count = len(alerts_df)
    open_findings = len(findings_df[findings_df["Status"] == "Open"]) if not findings_df.empty else 0
    burst_flag = proto_summary.get("burst_detected", False) if proto_summary else False
    total_threats = rogue_count + (1 if burst_flag else 0) + (1 if weak_count > 0 else 0)

    if not has_any_data:
        env_posture = "STANDBY"
        env_delta = "No Evidence Loaded"
    elif rogue_count > 0 or burst_flag:
        env_posture = "CRITICAL"
        env_delta = f"🚨 {total_threats} Threats Flagged"
    elif weak_count > 0 or open_findings > 0:
        env_posture = "ELEVATED"
        env_delta = f"⚠️ {weak_count} Insecure Networks"
    else:
        env_posture = "NORMAL"
        env_delta = "✅ Baselines Verified"

    # Top 5 Real-Time Hero Metrics
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Access Points", total_aps, f"{wpa_count} WPA2/3 • {weak_count} Weak" if total_aps > 0 else "Awaiting CSV")
    m2.metric("Monitored Clients", f"{active_clients_count} Active" if active_clients_count > 0 else "0 Active", f"{pcap_counts.get('Probe Request', 0)} Probes" if pcap_counts else "Awaiting PCAP")
    m3.metric("Flagged Threats", total_threats, f"{rogue_count} Rogues • {open_findings} Vulns" if has_any_data else "Awaiting Scan")
    m4.metric("Environment Risk", env_posture, env_delta)
    m5.metric("Audit Progress", f"{len(findings_df) - open_findings}/{len(findings_df)} Closed" if not findings_df.empty else "0 Logged", scope.get("Project Name", "NWIT 275")[:12])

    # Live AI Threat Analysis Box (If Triggered)
    if run_ai_btn and has_any_data:
        with st.spinner("AI Copilot analyzing wireless telemetry and baseline evidence..."):
            ai_query = "Provide an executive summary of this wireless environment: explain the overall risk posture, prioritize active threats (rogue APs, deauth bursts, open networks), and specify exact Wireshark display filters to verify each finding."
            st.session_state["dashboard_ai_summary"] = ask_ai_analyst(ai_query, inv_df, pcap_counts or {})

    if "dashboard_ai_summary" in st.session_state and st.session_state["dashboard_ai_summary"]:
        with st.expander("🤖 AI Copilot Environment Risk Assessment & Investigation Guide", expanded=True):
            st.markdown(st.session_state["dashboard_ai_summary"])
            st.caption("⚠️ Evidence-First Rule: Validate all AI conclusions against packet numbers and filters below.")

    # Middle Bento Split (Radar & Spectrum on Left, Threat Matrix on Right)
    st.markdown("")
    left_col, right_col = st.columns([1.1, 1.3])

    with left_col:
        st.markdown("#### 📡 360° Polar Spatial Radar Sweep")
        components.html(get_stitch_radar_scanner_component(inventory_df=view_df, alerts_df=alerts_df, is_scanning=True), height=495, scrolling=False)

        # Dynamic RF Carrier Channel Utilization
        st.markdown("#### 📊 RF Carrier Spectrum Utilization")
        if not view_df.empty:
            ch_counts = view_df["Channel"].value_counts().to_dict() if "Channel" in view_df.columns else {}
            ch1_count = ch_counts.get(1, 0)
            ch6_count = ch_counts.get(6, 0)
            ch11_count = ch_counts.get(11, 0)
            ch5g_count = sum(v for k, v in ch_counts.items() if k not in [1, 6, 11])

            st.markdown(f"""
            <div style="background: #191b23; border: 1px solid rgba(59, 73, 75, 0.35); border-radius: 10px; padding: 12px; margin-top: 6px;">
                <div style="margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; font-family: 'JetBrains Mono', monospace; font-size: 11px; margin-bottom: 3px;">
                        <span style="color: #e1e2ec;">CH 1 [2412 MHz]</span>
                        <span style="color: #00dbe9;">{ch1_count} APs ({min(100, ch1_count * 20)}% load)</span>
                    </div>
                    <div style="width: 100%; background: #0b0e15; height: 6px; border-radius: 3px; overflow: hidden;">
                        <div style="width: {min(100, max(8, ch1_count * 25))}%; height: 100%; background: #00dbe9;"></div>
                    </div>
                </div>
                <div style="margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; font-family: 'JetBrains Mono', monospace; font-size: 11px; margin-bottom: 3px;">
                        <span style="color: {'#ffb4ab' if ch6_count > 1 else '#e1e2ec'};">CH 6 [2437 MHz]</span>
                        <span style="color: {'#ffb4ab' if ch6_count > 1 else '#00dbe9'};">{ch6_count} APs ({min(100, ch6_count * 30)}% load)</span>
                    </div>
                    <div style="width: 100%; background: #0b0e15; height: 6px; border-radius: 3px; overflow: hidden;">
                        <div style="width: {min(100, max(8, ch6_count * 30))}%; height: 100%; background: {'#ffb4ab' if ch6_count > 1 else '#00dbe9'};"></div>
                    </div>
                </div>
                <div style="margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; font-family: 'JetBrains Mono', monospace; font-size: 11px; margin-bottom: 3px;">
                        <span style="color: #e1e2ec;">CH 11 [2462 MHz]</span>
                        <span style="color: #4edea3;">{ch11_count} APs ({min(100, ch11_count * 20)}% load)</span>
                    </div>
                    <div style="width: 100%; background: #0b0e15; height: 6px; border-radius: 3px; overflow: hidden;">
                        <div style="width: {min(100, max(8, ch11_count * 25))}%; height: 100%; background: #4edea3;"></div>
                    </div>
                </div>
                <div>
                    <div style="display: flex; justify-content: space-between; font-family: 'JetBrains Mono', monospace; font-size: 11px; margin-bottom: 3px;">
                        <span style="color: #e1e2ec;">5 GHz Bands [CH 36-165]</span>
                        <span style="color: #4edea3;">{ch5g_count} APs ({min(100, ch5g_count * 15)}% load)</span>
                    </div>
                    <div style="width: 100%; background: #0b0e15; height: 6px; border-radius: 3px; overflow: hidden;">
                        <div style="width: {min(100, max(8, ch5g_count * 20))}%; height: 100%; background: #4edea3;"></div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background: #191b23; border: 1px solid rgba(59, 73, 75, 0.35); border-radius: 10px; padding: 18px; margin-top: 6px; text-align: center;">
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #849495;">
                    No wireless capture loaded. Upload a Kismet CSV to calculate carrier channel loads across 2.4 GHz and 5 GHz.
                </span>
            </div>
            """, unsafe_allow_html=True)

    with right_col:
        st.markdown("#### 🚨 Active Threat Correlation & Evidence Matrix")
        st.caption("Evidence-First Rule: Every security alert connects directly to raw evidence and Wireshark filters.")

        if not has_any_data:
            st.markdown("""
            <div style="background: #191b23; border: 1px solid rgba(59, 73, 75, 0.35); border-radius: 10px; padding: 22px; text-align: center;">
                <div style="font-size: 24px; margin-bottom: 8px;">📡</div>
                <div style="font-family: 'Space Grotesk', sans-serif; font-size: 14px; font-weight: 600; color: #e1e2ec; margin-bottom: 4px;">
                    Standby Mode • Awaiting Telemetry
                </div>
                <div style="font-family: 'Inter', sans-serif; font-size: 12px; color: #849495;">
                    Upload a Kismet CSV or PCAP capture file above to begin automated threat correlation against authorized baselines.
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            has_alerts = False

            # Alert 1: Rogue APs
            if not alerts_df.empty:
                has_alerts = True
                for _, alert in alerts_df.iterrows():
                    target_ssid = alert.get("Target SSID", "Unknown")
                    bssid = alert.get("Suspicious BSSID", "Unknown")
                    sig = alert.get("Signal", "N/A")
                    details = alert.get("Alert Details", "")
                    st.markdown(f"""
                    <div style="background: rgba(147, 0, 10, 0.15); border: 1px solid rgba(255, 180, 171, 0.4); border-radius: 10px; padding: 12px 14px; margin-bottom: 10px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span style="font-family: 'Space Grotesk', sans-serif; font-size: 13.5px; font-weight: 700; color: #ffb4ab;">
                                🚨 Evil Twin / Rogue AP Cloned "{target_ssid}"
                            </span>
                            <span style="padding: 2px 8px; border-radius: 6px; background: rgba(255, 180, 171, 0.2); font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #ffb4ab; font-weight: 700;">
                                CRITICAL
                            </span>
                        </div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #b9cacb; margin-bottom: 4px;">
                            <strong>Target BSSID:</strong> <code style="color: #ffb4ab;">{bssid}</code> &nbsp;|&nbsp; <strong>Signal:</strong> {sig}
                        </div>
                        <div style="font-size: 11.5px; color: #e1e2ec; margin-bottom: 8px;">
                            <strong>Root Cause:</strong> {details}
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; background: #0b0e15; border-radius: 6px; padding: 6px 10px; font-family: 'JetBrains Mono', monospace; font-size: 10.5px;">
                            <span style="color: #849495;">Wireshark Filter:</span>
                            <code style="color: #00dbe9; font-weight: 600;">wlan.bssid == {bssid}</code>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

            # Alert 2: Deauth Attack
            if proto_summary and proto_summary.get("burst_detected", False):
                has_alerts = True
                deauth_cnt = proto_summary.get("deauth_count", 0)
                st.markdown(f"""
                <div style="background: rgba(255, 180, 171, 0.1); border: 1px solid rgba(255, 180, 171, 0.35); border-radius: 10px; padding: 12px 14px; margin-bottom: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-family: 'Space Grotesk', sans-serif; font-size: 13.5px; font-weight: 700; color: #ffb4ab;">
                            ⚠️ Management Frame Flood / Deauth Attack
                        </span>
                        <span style="padding: 2px 8px; border-radius: 6px; background: rgba(255, 180, 171, 0.2); font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #ffb4ab; font-weight: 700;">
                            HIGH
                        </span>
                    </div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #b9cacb; margin-bottom: 4px;">
                        <strong>Burst Count:</strong> <code style="color: #ffb4ab;">{deauth_cnt} Frames</code> &nbsp;|&nbsp; <strong>Subtype:</strong> 0x0c (Deauth)
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; background: #0b0e15; border-radius: 6px; padding: 6px 10px; font-family: 'JetBrains Mono', monospace; font-size: 10.5px;">
                        <span style="color: #849495;">Wireshark Filter:</span>
                        <code style="color: #00dbe9; font-weight: 600;">wlan.fc.type_subtype == 0x0c</code>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Alert 3: Insecure WEP / Open Networks
            if not view_df.empty:
                wep_open = view_df[view_df["Security"].isin(["WEP", "Open"])]
                for _, net in wep_open.iterrows():
                    has_alerts = True
                    ssid_name = net.get("SSID", "Unknown")
                    bssid_val = net.get("BSSID", "Unknown")
                    sec_val = net.get("Security", "Open")
                    st.markdown(f"""
                    <div style="background: rgba(255, 205, 207, 0.08); border: 1px solid rgba(255, 178, 183, 0.25); border-radius: 10px; padding: 12px 14px; margin-bottom: 10px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                            <span style="font-family: 'Space Grotesk', sans-serif; font-size: 13px; font-weight: 600; color: #ffb2b7;">
                                ⚡ Insecure Wireless Protocol: {sec_val}
                            </span>
                            <span style="padding: 2px 8px; border-radius: 6px; background: rgba(255, 178, 183, 0.15); font-family: 'JetBrains Mono', monospace; font-size: 9.5px; color: #ffb2b7; font-weight: 600;">
                                HIGH
                            </span>
                        </div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 10.5px; color: #849495; margin-bottom: 4px;">
                            SSID: <strong style="color: #e1e2ec;">{ssid_name}</strong> | BSSID: <code>{bssid_val}</code>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; background: #0b0e15; border-radius: 6px; padding: 5px 10px; font-family: 'JetBrains Mono', monospace; font-size: 10px;">
                            <span style="color: #849495;">Wireshark Filter:</span>
                            <code style="color: #00dbe9;">wlan.bssid == {bssid_val} && !(wlan.rsn.ie || wlan.wpa.ie)</code>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

            if not has_alerts:
                st.success("✅ No threats flagged in this band scope. Authorized network configurations conform to baseline.")

    # 7. Monitored Live Packet Stream (PCAP Traceability)
    st.markdown("---")
    st.markdown("#### 📡 Monitored Live Packet Stream & Frame Evidence")
    st.caption("Traceable 802.11 management, control, and data frames captured from the wireless medium.")

    if pcap_events is not None and not pcap_events.empty:
        stream_col1, stream_col2 = st.columns([1.5, 3])
        with stream_col1:
            frame_type_filter = st.selectbox(
                "Filter Stream by Frame Type",
                ["All Frames", "Probe Request", "Authentication", "Deauthentication", "EAPOL", "Beacon"],
                key="dash_frame_filter"
            )
        with stream_col2:
            st.write("")
            st.caption(f"Showing live capture events from {len(pcap_events)} verified packet checkpoints.")

        filtered_events = pcap_events.copy()
        if frame_type_filter != "All Frames":
            filtered_events = filtered_events[filtered_events["Type"] == frame_type_filter]
        st.dataframe(filtered_events, use_container_width=True, hide_index=True)
    else:
        st.info("ℹ️ No wireless packet capture (.pcap) loaded. Upload a capture file above to inspect live 802.11 management, control, and data frames.")

    # 8. Scope & Assessment Status Cards
    st.markdown("---")
    scope_col1, scope_col2 = st.columns([1.5, 1])
    with scope_col1:
        st.markdown("#### 🛡️ Authorized Assessment Scope & Rules of Engagement")
        st.markdown(f"""
        <div style="background: #191b23; border: 1px solid rgba(59, 73, 75, 0.35); border-radius: 10px; padding: 12px 16px;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #849495;">ENGAGEMENT:</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #00dbe9; font-weight: 600;">{scope.get('Project Name', 'NWIT 275 Capstone')}</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #849495;">AUTHORIZED TARGETS:</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #4edea3;">{scope.get('In-Scope Targets', 'CorpNet, Guest')}</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #849495;">TESTING WINDOW:</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #e1e2ec;">{scope.get('Authorized Start', '')} to {scope.get('Authorized End', '')}</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #849495;">APPROVED METHODOLOGY:</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #b9cacb;">{scope.get('Approved Tools', 'Wireshark, Kismet, Scapy, Streamlit')}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    with scope_col2:
        st.markdown("#### 📋 Findings & Remediation Summary")
        st.markdown(f"""
        <div style="background: #191b23; border: 1px solid rgba(59, 73, 75, 0.35); border-radius: 10px; padding: 12px 16px;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #849495;">TOTAL FINDINGS:</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #e1e2ec; font-weight: 700;">{len(findings_df)}</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #849495;">OPEN DEFICIENCIES:</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: {'#ffb4ab' if open_findings > 0 else '#849495'}; font-weight: 700;">{open_findings}</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #849495;">REMEDIATION STATUS:</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #4edea3; font-weight: 600;">{len(findings_df) - open_findings} Verified / Remediated</span>
            </div>
        </div>
        """, unsafe_allow_html=True)


# =============================================================
# 2. WIRELESS INVENTORY
# =============================================================
elif navigation == "Wireless Inventory":
    st.markdown(render_page_header(
        title="Target Access Points & Wireless Inventory",
        subtitle="Store, categorize, and filter SSID, BSSID, channel frequency, encryption, and signal strength.",
        badge_text="802.11 INVENTORY",
        badge_type="cyan"
    ), unsafe_allow_html=True)
    
    inv_up_c1, inv_up_c2 = st.columns([3, 1])
    with inv_up_c1:
        uploaded_csv = st.file_uploader("Upload Kismet CSV", type=["csv"], key="inv_csv_uploader")
    with inv_up_c2:
        st.write("")
        st.write("")
        if not st.session_state.get("inventory_df", pd.DataFrame()).empty:
            if st.button("🗑️ Clear Inventory", use_container_width=True, key="inv_top_clear_btn", help="Clear loaded wireless inventory"):
                st.session_state["inventory_df"] = pd.DataFrame()
                st.toast("Wireless inventory cleared!", icon="🗑️")
                st.rerun()

    if uploaded_csv is not None:
        df = load_inventory_data(uploaded_csv)
        st.session_state["inventory_df"] = df
        st.success(f"Loaded {uploaded_csv.name} successfully.")
    else:
        df = st.session_state.get("inventory_df", pd.DataFrame())
    
    if not df.empty:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Access Points", len(df))
        m2.metric("Critical / High Risk", len(df[df["Risk"].isin(["Critical", "High"])]) if "Risk" in df.columns else 0)
        m3.metric("WPA2 / WPA3 Networks", len(df[df["Security"].isin(["WPA2", "WPA3"])]) if "Security" in df.columns else 0)
        m4.metric("Open / WEP Networks", len(df[df["Security"].isin(["Open", "WEP"])]) if "Security" in df.columns else 0)

        st.subheader("Filter Inventory")
        col1, col2 = st.columns(2)
        
        sec_options = sorted(list(df["Security"].dropna().unique())) if "Security" in df.columns else []
        risk_options = sorted(list(df["Risk"].dropna().unique())) if "Risk" in df.columns else []

        security_filter = col1.multiselect("Filter by Security", options=sec_options)
        risk_filter = col2.multiselect("Filter by Risk", options=risk_options)
        
        filtered_df = df.copy()
        if security_filter and "Security" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["Security"].isin(security_filter)]
        if risk_filter and "Risk" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["Risk"].isin(risk_filter)]
            
        st.dataframe(filtered_df, use_container_width=True)
        st.caption(f"Showing {len(filtered_df)} of {len(df)} recorded access points.")

        # Export Insecure Networks (Open / WEP) to Findings
        weak_networks = df[df["Security"].isin(["Open", "WEP"])]
        if not weak_networks.empty:
            if st.button(f"📥 Export {len(weak_networks)} Insecure Networks (Open / WEP) to Assessment Workspace Findings"):
                cur_findings = st.session_state["findings_df"].copy() if not st.session_state["findings_df"].empty else pd.DataFrame(columns=["ID", "Severity", "Title", "Target", "Evidence (Packet/Log)", "Status", "Remediation"])
                existing_targets = set(cur_findings["Target"].dropna().astype(str).unique()) if not cur_findings.empty else set()
                new_rows = []
                start_idx = len(cur_findings) + 1
                for _, row in weak_networks.iterrows():
                    tgt = f"{row.get('BSSID', 'Unknown')} ({row.get('SSID', 'Unknown')})"
                    if tgt in existing_targets:
                        continue
                    sec = str(row.get('Security', 'Open'))
                    sev = "Critical" if "WEP" in sec.upper() else "Medium"
                    ch = row.get('Channel', 'N/A')
                    sig = row.get('Signal', 'N/A')
                    new_rows.append({
                        "ID": f"FIND-0{start_idx}",
                        "Severity": sev,
                        "Title": f"Insecure Wireless Encryption: {row.get('SSID', 'Unknown')} ({sec})",
                        "Target": tgt,
                        "Evidence (Packet/Log)": f"wlan.bssid == {row.get('BSSID', '')} | Security: {sec} | RSSI: {sig} | Channel: {ch}",
                        "Status": "Verified",
                        "Remediation": "Decommission legacy WEP or unencrypted Open configurations; migrate to WPA2-Enterprise (802.1X) or WPA3-SAE with Protected Management Frames (PMF)."
                    })
                    start_idx += 1
                if new_rows:
                    updated = pd.concat([cur_findings, pd.DataFrame(new_rows)], ignore_index=True)
                    st.session_state["findings_df"] = updated
                    st.success(f"Added {len(new_rows)} insecure network findings to the Assessment Workspace!")
                    st.rerun()
                else:
                    st.info("All detected insecure networks are already recorded in your findings log.")
    else:
        st.info("ℹ️ No wireless inventory loaded. Upload a Kismet CSV file above to analyze access points, channels, encryption, and signal strength.")


# =============================================================
# 3. PCAP ANALYZER
# =============================================================
elif navigation == "PCAP Analyzer":
    st.markdown(render_page_header(
        title="Packet Sniffer & Frame Telemetry",
        subtitle="Inspect 802.11 management, control, and data frames with verified Wireshark display filters.",
        badge_text="FRAME INSPECTOR",
        badge_type="cyan"
    ), unsafe_allow_html=True)
    
    pcap_up_c1, pcap_up_c2 = st.columns([3, 1])
    with pcap_up_c1:
        uploaded_file = st.file_uploader("Upload wireless packet capture (.pcap, .pcapng)", type=["pcap", "pcapng"])
    with pcap_up_c2:
        st.write("")
        st.write("")
        if st.session_state.get("pcap_counts") is not None:
            if st.button("🗑️ Clear PCAP", use_container_width=True, key="pcap_top_clear_btn", help="Clear loaded PCAP packet frames"):
                st.session_state["pcap_counts"] = None
                st.session_state["pcap_events"] = pd.DataFrame()
                st.toast("PCAP telemetry cleared!", icon="🗑️")
                st.rerun()

    if uploaded_file is not None:
        counts, events_df, error = analyze_pcap(uploaded_file)
        if error:
            st.error(error)
        else:
            st.session_state["pcap_counts"] = counts
            st.session_state["pcap_events"] = events_df
            st.success(f"Analyzed {uploaded_file.name} successfully.")
    else:
        counts = st.session_state.get("pcap_counts")
        events_df = st.session_state.get("pcap_events")

    if counts:
        st.subheader("802.11 Frame Summary")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Packets", counts["Total Packets"])
        c2.metric("Beacons", counts["Beacon"])
        c3.metric("Probe Requests", counts["Probe Request"])
        c4.metric("Probe Responses", counts["Probe Response"])

        c5, c6, c7 = st.columns(3)
        c5.metric("Authentication", counts["Authentication"])
        c6.metric("Deauthentication", counts["Deauthentication"])
        c7.metric("EAPOL (Handshakes)", counts["EAPOL"])

        if events_df is not None and not events_df.empty:
            st.subheader("Notable Security Events (Packet Traceability)")
            st.dataframe(events_df, use_container_width=True)
    else:
        st.info("ℹ️ No PCAP file loaded. Upload a .pcap or .pcapng file above to extract 802.11 frame summaries and trace security events.")

    st.subheader("Week 5 Checkpoint: Verified Wireshark Filters")
    st.dataframe(get_wireshark_filters(), use_container_width=True)


# =============================================================
# 4. AI ANALYST
# =============================================================
elif navigation == "AI Analyst":
    st.markdown(render_page_header(
        title="AI Wireless Analyst & Verification Copilot",
        subtitle="AI-assisted evidence synthesis paired with student verification and hallucination auditing.",
        badge_text="COPILOT ACTIVE",
        badge_type="cyan"
    ), unsafe_allow_html=True)

    inv_df = st.session_state["inventory_df"]
    pcap_counts = st.session_state["pcap_counts"]
    has_evidence = (not inv_df.empty) or (pcap_counts is not None)

    if not has_evidence:
        st.warning("⚠️ No wireless capture evidence currently loaded. Please upload a Kismet CSV or PCAP in the Dashboard, Wireless Inventory, or PCAP Analyzer. (Per course guidelines: AI is a copilot, not the evidence).")

    api_key = st.text_input("Optional: Enter Gemini API Key (Leave blank to use built-in Offline Analyst)", type="password")

    st.subheader("Week 7: Ask the Analyst")
    preset_question = st.selectbox(
        "Select an investigation prompt or type your own below:",
        [
            "Analyze the deauthentication frames in my capture and suggest Wireshark filters.",
            "Which wireless networks in my inventory pose the highest encryption risk?",
            "How do I verify a WPA2 EAPOL handshake in Wireshark?",
            "Custom Question..."
        ]
    )

    if preset_question == "Custom Question...":
        user_query = st.text_input("Ask the Analyst a custom security question:")
    else:
        user_query = preset_question

    ai_c1, ai_c2 = st.columns([2, 1])
    with ai_c1:
        run_ai = st.button("Analyze Evidence", use_container_width=True)
    with ai_c2:
        if "ai_analyst_response" in st.session_state and st.session_state["ai_analyst_response"]:
            if st.button("🗑️ Clear AI Output", use_container_width=True):
                st.session_state.pop("ai_analyst_response", None)
                st.toast("AI output cleared!", icon="🗑️")
                st.rerun()

    if run_ai:
        if not has_evidence:
            st.error("Cannot analyze without evidence. Please upload a Kismet CSV or PCAP first.")
        else:
            response = ask_ai_analyst(user_query, inv_df, pcap_counts or {}, api_key)
            st.session_state["ai_analyst_response"] = response

    if "ai_analyst_response" in st.session_state and st.session_state["ai_analyst_response"]:
        st.markdown(st.session_state["ai_analyst_response"])

    st.markdown("---")
    st.subheader("Week 8: AI Verification & Hallucination Challenge")
    st.caption("Workflow: AI Finding -> Evidence -> Student Verification -> Conclusion -> Remediation")

    verification_df = get_verification_challenges()
    edited_df = st.data_editor(
        verification_df,
        num_rows="dynamic",
        use_container_width=True
    )


# =============================================================
# 5. ROGUE AP DETECTOR
# =============================================================
elif navigation == "Rogue AP Detector":
    st.markdown(render_page_header(
        title="Rogue AP & Evil Twin Spatial Detector",
        subtitle="Compare live RF emissions against authorized baselines to pinpoint evil twins and unapproved transmitters.",
        badge_text="THREAT RADAR",
        badge_type="crimson"
    ), unsafe_allow_html=True)
    
    baseline_df = st.session_state["baseline_df"]

    # Baseline Configuration & Customizer
    with st.expander("⚙️ Authorized Enterprise Network Baseline (Interactive Customizer)", expanded=False):
        st.caption(
            "Access points matching these corporate SSIDs must conform to authorized vendor OUIs and security profiles. "
            "You can directly edit any cell below, click **+ Add row** to define new authorized networks, or use the quick-add form."
        )
        
        # Interactive Data Editor
        edited_baseline = st.data_editor(
            baseline_df,
            num_rows="dynamic",
            use_container_width=True,
            key="baseline_data_editor",
            column_config={
                "Expected_SSID": st.column_config.TextColumn("Authorized SSID", help="Exact corporate SSID name", required=True),
                "Expected_OUI": st.column_config.TextColumn("Approved Vendor (OUI)", help="e.g. Cisco Systems, Aruba Networks", required=True),
                "Expected_Security": st.column_config.SelectboxColumn("Required Security", help="Approved encryption standard", options=["WPA2", "WPA3", "WPA", "Open", "WEP"], required=True),
                "Expected_Channel": st.column_config.NumberColumn("Expected Channel", help="1-165", min_value=1, max_value=165, step=1, required=True),
            }
        )
        
        col_btn1, col_btn2 = st.columns([1.2, 1.2])
        if col_btn1.button("💾 Apply Baseline Changes & Re-Analyze", use_container_width=True):
            st.session_state["baseline_df"] = edited_baseline
            st.toast("Baseline updated successfully! Re-correlating threat detector...", icon="✅")
            st.rerun()

        if col_btn2.button("↺ Restore Default Corporate Baseline", use_container_width=True):
            st.session_state["baseline_df"] = get_authorized_baseline()
            st.toast("Default baseline restored (CorpWiFi, CorpGuest, CorpNet, Guest)!", icon="ℹ️")
            st.rerun()

        # Quick Add Network Sub-section
        st.markdown("##### ➕ Quick-Add Custom Authorized Network")
        qa_col1, qa_col2, qa_col3, qa_col4, qa_col5 = st.columns([1.5, 1.5, 1.2, 1, 1.2])
        new_ssid = qa_col1.text_input("New SSID", placeholder="e.g. HQ_Internal", key="qa_ssid")
        new_oui = qa_col2.text_input("Hardware Vendor", placeholder="e.g. Cisco Systems", key="qa_oui")
        new_sec = qa_col3.selectbox("Security", ["WPA2", "WPA3", "WPA"], key="qa_sec")
        new_ch = qa_col4.number_input("Channel", min_value=1, max_value=165, value=6, key="qa_ch")
        
        with qa_col5:
            st.write("")
            st.write("")
            if st.button("Add to Baseline", use_container_width=True):
                if new_ssid.strip():
                    new_entry = pd.DataFrame([{
                        "Expected_SSID": new_ssid.strip(),
                        "Expected_OUI": new_oui.strip() or "Cisco Systems",
                        "Expected_Security": new_sec,
                        "Expected_Channel": int(new_ch)
                    }])
                    updated_base = pd.concat([st.session_state["baseline_df"], new_entry], ignore_index=True).drop_duplicates(subset=["Expected_SSID"])
                    st.session_state["baseline_df"] = updated_base
                    st.toast(f"Added '{new_ssid}' to authorized baseline!", icon="✅")
                    st.rerun()
                else:
                    st.warning("Please provide a valid SSID name.")
    
    st.markdown("---")
    st.subheader("Automated Threat Detection")

    # Evidence Uplink
    r_up_col, r_clr_col = st.columns([3, 1])
    with r_up_col:
        uploaded_csv = st.file_uploader("Upload Kismet CSV for Threat Scan", type=["csv"], key="rogue_csv_uploader")
    with r_clr_col:
        st.write("")
        st.write("")
        if not st.session_state.get("inventory_df", pd.DataFrame()).empty:
            if st.button("🗑️ Clear Inventory", use_container_width=True, help="Reset and upload a new Kismet CSV"):
                st.session_state["inventory_df"] = pd.DataFrame()
                st.toast("Wireless inventory cleared! Radar reset to standby.", icon="🗑️")
                st.rerun()
    
    if uploaded_csv is not None:
        inv_df = load_inventory_data(uploaded_csv)
        st.session_state["inventory_df"] = inv_df
    else:
        inv_df = st.session_state.get("inventory_df", pd.DataFrame())

    if inv_df.empty:
        st.info("ℹ️ No wireless inventory loaded. Upload a Kismet CSV above to scan for Rogue APs, Evil Twins, Homoglyphs, and Karma Beacon Floods.")
        st.markdown("#### 📡 RF Radar Standby (No Emitters Plotted)")
        components.html(get_stitch_radar_scanner_component(inventory_df=None, alerts_df=None, is_scanning=True), height=495, scrolling=False)
    else:
        # Automated threat detection runs automatically whenever inventory is present!
        alerts_df = detect_rogues(inv_df, baseline_df)
        
        # Threat breakdown counts
        total_aps = len(inv_df)
        rogue_total = len(alerts_df)
        evil_twins = len(alerts_df[alerts_df["Threat Type"].str.contains("Evil Twin", case=False, na=False)]) if not alerts_df.empty else 0
        homoglyphs = len(alerts_df[alerts_df["Threat Type"].str.contains("Homoglyph", case=False, na=False)]) if not alerts_df.empty else 0
        karma_tools = rogue_total - evil_twins - homoglyphs

        # Hero Telemetry Row
        tm1, tm2, tm3, tm4 = st.columns(4)
        tm1.metric("Monitored APs", total_aps, f"{total_aps} Live Emitters")
        tm2.metric("Flagged Threats", rogue_total, f"🚨 {rogue_total} Rogues" if rogue_total > 0 else "✅ 0 Threats")
        tm3.metric("Evil Twins", evil_twins, "OUI / Sec Downgrade" if evil_twins > 0 else "None")
        tm4.metric("Homoglyphs & Karma", homoglyphs + karma_tools, "Spoofed / Flooding" if (homoglyphs + karma_tools) > 0 else "None")

        st.markdown("")
        radar_col, results_col = st.columns([1.05, 1.25])

        with radar_col:
            st.markdown("#### 📡 360° Polar Spatial Radar Sweep")
            st.caption("Click any emitter blip on the radar to inspect its SSID name, BSSID, Signal dBm, and threat diagnosis below.")
            components.html(get_stitch_radar_scanner_component(inventory_df=inv_df, alerts_df=alerts_df, is_scanning=True), height=495, scrolling=False)

        with results_col:
            st.markdown("#### 🚨 Rogue Threat Matrix & Evidence Verification")
            st.caption("Evidence-First Rule: Every detected rogue correlates to an exact Wireshark display filter.")

            if not alerts_df.empty:
                st.error(f"🚨 {len(alerts_df)} Suspicious Access Point(s) Detected!")
                st.dataframe(alerts_df, use_container_width=True)

                # Export to Findings button
                if st.button("📥 Export Flagged Threats to Assessment Workspace Findings"):
                    cur_findings = st.session_state["findings_df"].copy() if not st.session_state["findings_df"].empty else pd.DataFrame(columns=["ID", "Severity", "Title", "Target", "Evidence (Packet/Log)", "Status", "Remediation"])
                    existing_targets = set(cur_findings["Target"].dropna().astype(str).unique()) if not cur_findings.empty else set()
                    
                    new_rows = []
                    start_idx = len(cur_findings) + 1
                    for _, alert in alerts_df.iterrows():
                        th_type = alert.get("Threat Type", "Rogue AP")
                        tgt = f"{alert.get('Suspicious BSSID', 'Unknown')} ({alert.get('Target SSID', 'Unknown')})"
                        if tgt in existing_targets:
                            continue
                        
                        sev = "Critical" if "Evil Twin" in th_type or "Pineapple" in th_type else ("High" if "Homoglyph" in th_type or "Karma" in th_type else "Medium")
                        filt = alert.get("Wireshark Filter", "")
                        sig = alert.get("Signal", "")
                        details = alert.get("Alert Details", "")
                        
                        new_rows.append({
                            "ID": f"FIND-0{start_idx}",
                            "Severity": sev,
                            "Title": f"{th_type}: {alert.get('Target SSID', 'Unknown')}",
                            "Target": tgt,
                            "Evidence (Packet/Log)": f"{filt} | Signal: {sig} | {details}",
                            "Status": "Open",
                            "Remediation": "Locate rogue AP via directional antenna / RSSI triangulation. Block rogue MAC on switch ports. Enable 802.11w Protected Management Frames (PMF)."
                        })
                        start_idx += 1
                        
                    if new_rows:
                        updated_findings = pd.concat([cur_findings, pd.DataFrame(new_rows)], ignore_index=True)
                        st.session_state["findings_df"] = updated_findings
                        st.success(f"Added {len(new_rows)} rogue findings into Assessment Workspace! View them in Assessment Workspace or Reports.")
                    else:
                        st.info("All detected threats are already logged in the Assessment Workspace.")

                # Evidence Cards
                with st.expander("🔍 Deep Threat Evidence & Wireshark Filter Inspector", expanded=False):
                    for _, alert in alerts_df.iterrows():
                        th_type = alert.get("Threat Type", "Rogue AP")
                        tgt = alert.get("Target SSID", "Unknown")
                        bssid = alert.get("Suspicious BSSID", "Unknown")
                        sig = alert.get("Signal", "N/A")
                        details = alert.get("Alert Details", "")
                        w_filt = alert.get("Wireshark Filter", f"wlan.bssid == {bssid}")

                        st.markdown(f"""
                        <div style="background: rgba(147, 0, 10, 0.12); border: 1px solid rgba(255, 180, 171, 0.35); border-radius: 8px; padding: 10px 12px; margin-bottom: 8px;">
                            <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                                <strong style="color: #ffb4ab; font-size: 12px;">{th_type}: {tgt}</strong>
                                <span style="font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #00dbe9;">{sig}</span>
                            </div>
                            <div style="font-size: 11px; color: #b9cacb; margin-bottom: 4px;">{details}</div>
                            <div style="background: #0b0e15; padding: 4px 8px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #00dbe9;">
                                Wireshark: <code>{w_filt}</code>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
            else:
                st.success("✅ Scan Complete. All detected wireless networks conform to authorized corporate baselines.")


# =============================================================
# 6. PROTOCOL ANALYSIS
# =============================================================
elif navigation == "Protocol Analysis":
    st.markdown(render_page_header(
        title="WPA Handshake & Deauthentication Audit",
        subtitle="Inspect EAPOL 4-way key exchanges and detect malicious deauth/disassociation burst attacks.",
        badge_text="EAPOL / 802.11 MGMT",
        badge_type="cyan"
    ), unsafe_allow_html=True)

    proto_up_c1, proto_up_c2 = st.columns([3, 1])
    with proto_up_c1:
        uploaded_pcap = st.file_uploader(
            "Upload PCAP for Protocol Inspection",
            type=["pcap", "pcapng"],
            key="protocol_pcap"
        )
    with proto_up_c2:
        st.write("")
        st.write("")
        if st.session_state.get("protocol_summary") is not None:
            if st.button("🗑️ Clear Protocol Data", use_container_width=True, key="proto_top_clear_btn", help="Clear protocol analysis summary"):
                st.session_state["protocol_summary"] = None
                st.toast("Protocol analysis cleared!", icon="🗑️")
                st.rerun()

    if uploaded_pcap is not None:
        eapol_df, deauth_df, summary, error = analyze_protocols(uploaded_pcap)
        if error:
            st.error(error)
        elif summary:
            st.session_state["protocol_summary"] = summary
            
            st.subheader("Week 10: WPA/WPA2 4-Way Handshake Analyzer")
            col1, col2 = st.columns(2)
            col1.metric("EAPOL Frames Captured", summary["eapol_count"])
            col2.metric("4-Way Handshake Status", "Complete (4/4)" if summary["handshake_complete"] else "Incomplete / Partial")

            st.markdown(
                "**WPA/WPA2 Handshake Workflow:**\n"
                "1. **Message 1 (AP to Client):** AP sends `ANonce` (Authenticator Nonce) to the client.\n"
                "2. **Message 2 (Client to AP):** Client derives the Pairwise Transient Key (`PTK`) and sends `SNonce` + `MIC`.\n"
                "3. **Message 3 (AP to Client):** AP verifies the `MIC` and delivers the Group Temporal Key (`GTK`).\n"
                "4. **Message 4 (Client to AP):** Client confirms key installation and completes encryption setup."
            )

            if not eapol_df.empty:
                st.dataframe(eapol_df, use_container_width=True)
                st.caption("Verification Filter: Apply `eapol` in Wireshark to confirm packet numbers and message sequence.")
            else:
                st.warning("No EAPOL frames found in this capture.")

            st.markdown("---")

            st.subheader("Week 11: Deauthentication & Disassociation Monitor")
            d1, d2, d3 = st.columns(3)
            d1.metric("Deauthentication Frames (0x0c)", summary["deauth_count"])
            d2.metric("Disassociation Frames (0x0a)", summary["disas_count"])
            d3.metric("Pattern Assessment", "Anomalous Burst" if summary["burst_detected"] else "Normal Baseline")

            if summary["burst_detected"]:
                st.error("⚠️ Unusual management-frame burst detected! Check if EAPOL frames immediately follow this timestamp window.")

            if not deauth_df.empty:
                st.dataframe(deauth_df, use_container_width=True)
                st.caption("Verification Filter: Apply `wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a` in Wireshark.")
            else:
                st.success("No Deauthentication or Disassociation frames observed.")

            # Export Protocol Findings to Assessment Workspace
            if summary and (summary.get("burst_detected") or summary.get("eapol_count", 0) > 0):
                st.markdown("")
                if st.button("📥 Export Handshake & Deauth Findings to Assessment Workspace"):
                    cur_findings = st.session_state["findings_df"].copy() if not st.session_state["findings_df"].empty else pd.DataFrame(columns=["ID", "Severity", "Title", "Target", "Evidence (Packet/Log)", "Status", "Remediation"])
                    existing_titles = set(cur_findings["Title"].dropna().astype(str).unique()) if not cur_findings.empty else set()
                    new_rows = []
                    start_idx = len(cur_findings) + 1
                    
                    if summary.get("burst_detected") and "802.11 Deauthentication Denial-of-Service Attack" not in existing_titles:
                        new_rows.append({
                            "ID": f"FIND-0{start_idx}",
                            "Severity": "High",
                            "Title": "802.11 Deauthentication Denial-of-Service Attack",
                            "Target": "Monitored Wireless Airspace (wlan0mon)",
                            "Evidence (Packet/Log)": f"wlan.fc.type_subtype == 0x0c | Observed anomalous burst of {summary.get('deauth_count', 0)} deauth frames in short time window",
                            "Status": "Verified",
                            "Remediation": "Enable 802.11w Management Frame Protection (MFP / PMF) to prevent spoofed deauthentication frame injection."
                        })
                        start_idx += 1
                        
                    if summary.get("handshake_complete") and "WPA/WPA2 4-Way Handshake Key Exchange Exposure" not in existing_titles:
                        new_rows.append({
                            "ID": f"FIND-0{start_idx}",
                            "Severity": "High",
                            "Title": "WPA/WPA2 4-Way Handshake Key Exchange Exposure",
                            "Target": "Authenticated Wireless Client & AP BSSID",
                            "Evidence (Packet/Log)": f"eapol | Complete 4/4 handshake frames captured ({summary.get('eapol_count', 0)} EAPOL frames). Subject to offline dictionary attacks.",
                            "Status": "Verified",
                            "Remediation": "Transition from WPA2-PSK to WPA3-SAE (Simultaneous Authentication of Equals) to provide forward secrecy and prevent offline dictionary recovery."
                        })
                        
                    if new_rows:
                        updated = pd.concat([cur_findings, pd.DataFrame(new_rows)], ignore_index=True)
                        st.session_state["findings_df"] = updated
                        st.success(f"Added {len(new_rows)} protocol findings to Assessment Workspace!")
                        st.rerun()
                    else:
                        st.info("Protocol findings are already logged in the Assessment Workspace.")
    else:
        st.info("ℹ️ No PCAP loaded. Upload a wireless packet capture (.pcap) above to analyze WPA/WPA2 4-way handshakes and deauthentication management frames.")


# =============================================================
# 7. ASSESSMENT WORKSPACE
# =============================================================
elif navigation == "Assessment Workspace":
    st.markdown(render_page_header(
        title="Authorized Security Assessment Workspace",
        subtitle="Define lab scope, rules of engagement, vulnerability findings log, and remediation tracking.",
        badge_text="SCOPE AUTHORIZED",
        badge_type="emerald"
    ), unsafe_allow_html=True)

    st.subheader("Rules of Engagement & Scope")
    scope = st.session_state["scope"]
    
    col1, col2 = st.columns(2)
    with col1:
        st.text_input("Project Name", value=scope["Project Name"], disabled=True)
        st.text_input("Authorized Start Date", value=scope["Authorized Start"], disabled=True)
        new_in_scope = st.text_area("In-Scope Targets", value=scope["In-Scope Targets"], height=100)
        
    with col2:
        st.text_input("Client / Instructor", value=scope["Client / Instructor"], disabled=True)
        st.text_input("Authorized End Date", value=scope["Authorized End"], disabled=True)
        new_out_scope = st.text_area("Out-of-Scope (DO NOT TEST)", value=scope["Out-of-Scope"], height=100)
        
    new_tools = st.text_input("Approved Tools & Methods", value=scope["Approved Tools"])

    st.markdown("---")

    st.subheader("Findings & Remediation Tracker")
    st.write("Log verified vulnerabilities, attach evidence, and track remediation status.")
    
    findings_df = st.session_state["findings_df"]
    
    if findings_df.empty:
        st.caption("ℹ️ No findings recorded yet. Click '+ Add row' below to document a verified vulnerability from your assessment.")

    edited_findings = st.data_editor(
        findings_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "Severity": st.column_config.SelectboxColumn(
                "Severity",
                options=["Critical", "High", "Medium", "Low", "Informational"],
                required=True
            ),
            "Status": st.column_config.SelectboxColumn(
                "Status",
                options=["Open", "Verified", "Remediated", "False Positive"],
                required=True
            )
        }
    )
    
    w_btn_c1, w_btn_c2 = st.columns([2, 1])
    with w_btn_c1:
        if st.button("💾 Save Updates to Findings", use_container_width=True):
            st.session_state["findings_df"] = edited_findings
            scope["In-Scope Targets"] = new_in_scope
            scope["Out-of-Scope"] = new_out_scope
            scope["Approved Tools"] = new_tools
            st.session_state["scope"] = scope
            st.success("Findings and scope updated successfully! Real-time Dashboard and Reports are now synchronized.")
    with w_btn_c2:
        if not findings_df.empty:
            if st.button("🗑️ Clear All Findings", use_container_width=True, help="Reset findings table to empty"):
                st.session_state["findings_df"] = pd.DataFrame(columns=["ID", "Severity", "Title", "Target", "Evidence (Packet/Log)", "Status", "Remediation"])
                st.toast("Findings log reset to empty!", icon="🗑️")
                st.rerun()


# =============================================================
# 8. REPORTS
# =============================================================
elif navigation == "Reports":
    st.markdown(render_page_header(
        title="Executive Reporting & Security Hardening",
        subtitle="Generate penetration testing deliverables, remediation checklists, and review platform controls.",
        badge_text="EXPORT READY",
        badge_type="emerald"
    ), unsafe_allow_html=True)

    st.subheader("Week 14: Report Generation")
    
    scope = st.session_state["scope"]
    findings_df = st.session_state["findings_df"]
    active_threats = detect_rogues(st.session_state["inventory_df"], st.session_state["baseline_df"]) if not st.session_state["inventory_df"].empty else pd.DataFrame()

    if findings_df.empty:
        if not active_threats.empty:
            st.warning(f"⚠️ You have **{len(active_threats)} detected threats** from your Rogue AP scan that are not yet added to the findings log.")
            if st.button("📥 Auto-Import All Active Scanned Threats into Report"):
                new_rows = []
                for idx, (_, alert) in enumerate(active_threats.iterrows(), 1):
                    th_type = alert.get("Threat Type", "Rogue AP")
                    tgt = f"{alert.get('Suspicious BSSID', 'Unknown')} ({alert.get('Target SSID', 'Unknown')})"
                    sev = "Critical" if "Evil Twin" in th_type or "Pineapple" in th_type else ("High" if "Homoglyph" in th_type or "Karma" in th_type else "Medium")
                    filt = alert.get("Wireshark Filter", "")
                    sig = alert.get("Signal", "")
                    details = alert.get("Alert Details", "")
                    new_rows.append({
                        "ID": f"FIND-0{idx}",
                        "Severity": sev,
                        "Title": f"{th_type}: {alert.get('Target SSID', 'Unknown')}",
                        "Target": tgt,
                        "Evidence (Packet/Log)": f"{filt} | Signal: {sig} | {details}",
                        "Status": "Verified",
                        "Remediation": "Locate rogue AP via directional antenna / RSSI triangulation. Block rogue MAC on switch ports. Enable 802.11w Protected Management Frames (PMF)."
                    })
                st.session_state["findings_df"] = pd.DataFrame(new_rows)
                st.success(f"Imported {len(new_rows)} findings! Generating updated report...")
                st.rerun()
        else:
            st.info("ℹ️ No findings logged in the Assessment Workspace yet. Document and verify findings in the Assessment Workspace before generating the final report.")
    
    r_btn_c1, r_btn_c2 = st.columns([2, 1])
    with r_btn_c1:
        generate_clicked = st.button("📄 Generate Final Report", use_container_width=True)
    with r_btn_c2:
        if "generated_report" in st.session_state and st.session_state["generated_report"]:
            if st.button("🗑️ Clear Report View", use_container_width=True):
                st.session_state.pop("generated_report", None)
                st.toast("Report preview cleared!", icon="🗑️")
                st.rerun()

    if generate_clicked:
        report_markdown = generate_markdown_report(
            scope, 
            findings_df, 
            inv_df=st.session_state.get("inventory_df"), 
            pcap_counts=st.session_state.get("pcap_counts"), 
            proto_summary=st.session_state.get("protocol_summary")
        )
        st.session_state["generated_report"] = report_markdown
        st.success("Report generated successfully!")

    if "generated_report" in st.session_state and st.session_state["generated_report"]:
        st.markdown("---")
        st.markdown(st.session_state["generated_report"])
        st.markdown("---")
        st.download_button(
            label="Download Report (.md)",
            data=st.session_state["generated_report"],
            file_name="AirGuard_Final_Report.md",
            mime="text/markdown"
        )
        
    st.markdown("---")
    st.subheader("Platform Security Hardening")
    st.write("Before the Week 15 final presentation, ensure your platform meets these security requirements:")
    
    checklist_df = get_security_checklist()
    st.data_editor(
        checklist_df,
        hide_index=True,
        use_container_width=True,
        disabled=["Control", "Details"]
    )
