import streamlit as st
import pandas as pd
import os 
from modules.inventory import load_inventory_data
from modules.pcap_analyzer import analyze_pcap, get_sample_pcap_summary, get_wireshark_filters
from modules.ai_analyst import ask_ai_analyst, get_verification_challenges
from modules.inventory import load_inventory_data
from modules.rogue_detector import get_authorized_baseline, detect_rogues
from modules.protocol_analyzer import analyze_protocols
from modules.assessment_workspace import get_assessment_scope, get_findings_log
from modules.assessment_workspace import get_assessment_scope, get_findings_log
from modules.reporter import generate_markdown_report, get_security_checklist

# Configure the page
st.set_page_config(page_title="Project AirGuard", layout="wide", initial_sidebar_state="expanded")

# Sidebar Navigation
st.sidebar.title("🛡️ Project AirGuard")
st.sidebar.markdown("---")
navigation = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Wireless Inventory", "PCAP Analyzer", "AI Analyst", 
     "Rogue AP Detector", "Protocol Analysis", "Assessment Workspace", "Reports"]
)

# Page logic based on navigation selection
if navigation == "Dashboard":
    st.header("Platform Dashboard")
    st.write("Overview of current project status, alerts, and risk levels.")
    # Placeholder for metric cards
    col1, col2, col3 = st.columns(3)
    col1.metric("Access Points Logged", "0")
    col2.metric("Suspicious Events", "0")
    col3.metric("AI Findings Pending Review", "0")

#Main analyzers code
elif navigation == "Wireless Inventory":
    st.header("Wireless Inventory")
    st.write("Store and filter SSID, BSSID, channel, security mode, and signal strength.")
    
    # Load the data using the backend module
    df = load_inventory_data()
    
    if not df.empty:
        st.subheader("Filter Inventory")
        col1, col2 = st.columns(2)
        
        # Create dynamic dropdown filters based on the dataset
        security_filter = col1.multiselect("Filter by Security", options=df["Security"].unique())
        risk_filter = col2.multiselect("Filter by Risk", options=df["Risk"].unique())
        
        # Apply filters if the user selects any options
        filtered_df = df.copy()
        if security_filter:
            filtered_df = filtered_df[filtered_df["Security"].isin(security_filter)]
        if risk_filter:
            filtered_df = filtered_df[filtered_df["Risk"].isin(risk_filter)]
            
        # Render the dataframe in Streamlit
        st.dataframe(filtered_df, use_container_width=True)
    else:
        st.info("No data found. Upload Kismet CSV or scanner data to populate this table.")
    st.header("Wireless Inventory")
    st.write("Store and filter SSID, BSSID, channel, security mode, and signal strength.")
    st.info("Upload Kismet CSV or scanner data to populate this table.")

elif navigation == "PCAP Analyzer":
    st.header("PCAP Analyzer & Wireshark Workflow")
    st.write("Upload wireless packet captures (.pcap) to extract 802.11 frame counts and verify Wireshark filters.")
    
    col_upload, col_demo = st.columns([2, 1])
    uploaded_file = col_upload.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])
    use_sample = col_demo.checkbox("Load Sample Lab Capture (Demo Mode)", value=True)

    counts = None
    events_df = None

    if uploaded_file is not None:
        counts, events_df, error = analyze_pcap(uploaded_file)
        if error:
            st.error(error)
        else:
            st.success(f"Analyzed {uploaded_file.name} successfully.")
    elif use_sample:
        st.info("Showing simulated lab PCAP data. Upload a .pcap file above to analyze real traffic.")
        counts, events_df = get_sample_pcap_summary()

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

    st.subheader("Week 5 Checkpoint: Verified Wireshark Filters")
    st.dataframe(get_wireshark_filters(), use_container_width=True)

elif navigation == "AI Analyst":
    st.header("AI Wireless Analyst & Verification Challenge")
    st.write("AI is a copilot, not the evidence. Validate all AI conclusions against packet numbers and filters.")

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

    if st.button("Analyze Evidence"):
        inv_df = load_inventory_data()
        sample_counts, _ = get_sample_pcap_summary()
        response = ask_ai_analyst(user_query, inv_df, sample_counts, api_key)
        st.markdown(response)

    st.markdown("---")
    st.subheader("Week 8: AI Verification & Hallucination Challenge")
    st.caption("Workflow: AI Finding -> Evidence -> Student Verification -> Conclusion -> Remediation")

    verification_df = get_verification_challenges()
    edited_df = st.data_editor(
        verification_df,
        num_rows="dynamic",
        use_container_width=True
    )

elif navigation == "Rogue AP Detector":
    st.header("Rogue AP & Evil Twin Detector")
    st.write("Compare expected network characteristics against observed evidence to flag suspicious inconsistencies.")
    
    st.subheader("Authorized Network Baseline")
    st.write("These are the known, approved configurations for our corporate networks:")
    baseline_df = get_authorized_baseline()
    st.dataframe(baseline_df, use_container_width=True)
    
    st.markdown("---")
    st.subheader("Automated Threat Detection")
    
    # Added the file uploader directly to this page
    uploaded_csv = st.file_uploader("Upload Kismet CSV for Threat Scan (Optional - defaults to sample data)", type=["csv"])
    
    if st.button("Run Rogue AP Scan"):
        # Pass the uploaded file to your inventory loader
        inv_df = load_inventory_data(uploaded_csv)
        
        if inv_df.empty:
            st.warning("No wireless inventory data available to scan.")
        else:
            alerts_df = detect_rogues(inv_df, baseline_df)
            
            if not alerts_df.empty:
                st.error(f"⚠️ {len(alerts_df)} Suspicious Access Point(s) Detected!")
                st.dataframe(alerts_df, use_container_width=True)
                st.caption("AI Note: Verify the Suspicious BSSID in Wireshark to confirm if it is broadcasting legitimate or malicious management frames.")
            else:
                st.success("✅ Scan Complete. No Rogue APs or Evil Twins detected matching the baseline.")

elif navigation == "Protocol Analysis":
    st.header("WPA Handshake & Deauthentication Analysis")
    st.write("Inspect 802.11 EAPOL authentication flows and detect abnormal management-frame bursts.")

    uploaded_pcap = st.file_uploader(
        "Upload PCAP for Protocol Inspection (Optional - defaults to controlled lab capture)",
        type=["pcap", "pcapng"],
        key="protocol_pcap"
    )

    eapol_df, deauth_df, summary, error = analyze_protocols(uploaded_pcap)

    if error:
        st.error(error)
    elif summary:
        if uploaded_pcap is None:
            st.info("Showing controlled lab capture evidence. Upload a .pcap file above to inspect another capture.")

        # Week 10: WPA / EAPOL Handshake Analyzer
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

        # Week 11: Deauthentication & Disassociation Monitor
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

elif navigation == "Assessment Workspace":
    st.header("Authorized Security Assessment Workspace")
    st.write("Define scope, approved targets, testing window, evidence, findings, and remediation.")
    st.caption("Rule of Engagement: All penetration-testing activity must be limited to instructor-approved lab systems and captures.")

    # Week 12: Scope and Rules of Engagement
    st.subheader("Rules of Engagement & Scope")
    scope = get_assessment_scope()
    
    col1, col2 = st.columns(2)
    with col1:
        st.text_input("Project Name", value=scope["Project Name"], disabled=True)
        st.text_input("Authorized Start Date", value=scope["Authorized Start"], disabled=True)
        st.text_area("In-Scope Targets", value=scope["In-Scope Targets"], height=100)
        
    with col2:
        st.text_input("Client / Instructor", value=scope["Client / Instructor"], disabled=True)
        st.text_input("Authorized End Date", value=scope["Authorized End"], disabled=True)
        st.text_area("Out-of-Scope (DO NOT TEST)", value=scope["Out-of-Scope"], height=100)
        
    st.text_input("Approved Tools & Methods", value=scope["Approved Tools"])

    st.markdown("---")

    # Week 13: Findings and Remediation Tracker
    st.subheader("Findings & Remediation Tracker")
    st.write("Log verified vulnerabilities, attach evidence, and track remediation status.")
    
    findings_df = get_findings_log()
    
    # Use data_editor so you can add/edit findings directly in the UI
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
    
    if st.button("Save Updates to Findings"):
        st.success("Findings saved successfully for the final report.")

elif navigation == "Reports":
    st.header("Reporting & Platform Security")
    st.write("Generate professional technical reports and review platform hardening controls.")

    st.subheader("Week 14: Report Generation")
    
    # Fetch current scope and findings
    scope = get_assessment_scope()
    findings_df = get_findings_log()
    
    if st.button("Generate Final Report"):
        report_markdown = generate_markdown_report(scope, findings_df)
        
        st.success("Report generated successfully!")
        st.markdown("---")
        
        # Display the generated report visually on the page
        st.markdown(report_markdown)
        
        st.markdown("---")
        # Provide a button for the user to download the markdown file
        st.download_button(
            label="Download Report (.md)",
            data=report_markdown,
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
        disabled=["Control", "Details"] # Only let the user edit the Status column
    )

st.sidebar.markdown("---")
st.sidebar.caption("NWIT 275 - Fall Semester Build")