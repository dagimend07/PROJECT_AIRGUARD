import streamlit as st

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

elif navigation == "Wireless Inventory":
    st.header("Wireless Inventory")
    st.write("Store and filter SSID, BSSID, channel, security mode, and signal strength.")
    st.info("Upload Kismet CSV or scanner data to populate this table.")

elif navigation == "PCAP Analyzer":
    st.header("PCAP Analyzer")
    st.write("Upload wireless packet captures (.pcap) for frame extraction.")
    uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])
    if uploaded_file is not None:
        st.success("File uploaded successfully. Awaiting processing module.")

elif navigation == "AI Analyst":
    st.header("AI Copilot")
    st.write("Ask questions about your wireless evidence and generate Wireshark filters.")
    user_query = st.text_input("Ask the Analyst a security question:")
    if st.button("Submit"):
        st.warning("AI integration pending. Please connect API key in settings.")

elif navigation == "Rogue AP Detector":
    st.header("Rogue AP / Evil Twin Detection")
    st.write("Compare expected network characteristics against observed anomalies.")

elif navigation == "Protocol Analysis":
    st.header("WPA & Deauthentication Analysis")
    st.write("Analyze EAPOL handshakes and unusual deauthentication patterns.")

elif navigation == "Assessment Workspace":
    st.header("Authorized Security Workspace")
    st.write("Define scope, approved targets, testing window, and findings.")

elif navigation == "Reports":
    st.header("Reporting & Hardening")
    st.write("Generate executive and technical reports backed by verified evidence.")

st.sidebar.markdown("---")
st.sidebar.caption("NWIT 275 - Fall Semester Build")