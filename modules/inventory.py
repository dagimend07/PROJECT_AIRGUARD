import os
import io
import pandas as pd

# Known OUI prefixes for lab environments and common wireless hardware
OUI_LOOKUP = {
    "00:11:22": "Cisco Systems",
    "00:1A:1E": "Cisco Systems",
    "00:40:96": "Cisco Systems",
    "00:0C:85": "Cisco Systems",
    "11:22:33": "Aruba Networks",
    "00:0B:86": "Aruba Networks",
    "D8:C7:C8": "Aruba Networks",
    "A8:97:CD": "TP-Link",
    "50:C7:BF": "TP-Link",
    "A0:63:91": "Netgear",
    "B8:27:EB": "Raspberry Pi Foundation",
    "00:C0:CA": "Alfa Network / Hak5",
    "00:1D:7E": "Cisco-Linksys",
    "C0:56:27": "Belkin / Linksys",
    "FC:15:B4": "HP Inc.",
    "02:CB:7A": "Locally Administered",
    "02:13:37": "Locally Administered (Spoofed)",
    "02:AA:BB": "Locally Administered (Spoofed)",
    "02:CA:FE": "Locally Administered (Karma AP)",
    "66:77:88": "Legacy Device",
}


def derive_security(encryption_val):
    """Normalizes raw encryption strings (e.g. from Kismet) into standard security levels."""
    if pd.isna(encryption_val):
        return "Open"
    val = str(encryption_val).strip().upper()
    if not val or val in ("NONE", "CLEAR", "OPEN", "NO"):
        return "Open"
    if "WPA3" in val or "SAE" in val:
        return "WPA3"
    if "WPA2" in val:
        return "WPA2"
    if "WPA" in val:
        return "WPA"
    if "WEP" in val:
        return "WEP"
    return val


def derive_risk(security_val):
    """Assigns risk levels based on wireless security mode."""
    sec = str(security_val).strip().upper()
    if "WEP" in sec:
        return "Critical"
    if "OPEN" in sec or "NONE" in sec or "CLEAR" in sec:
        return "High"
    if "WPA" in sec and "WPA2" not in sec and "WPA3" not in sec:
        return "Medium"
    if "WPA2" in sec or "WPA3" in sec:
        return "Low"
    return "Informational"


def derive_oui(bssid_val):
    """Resolves OUI/vendor from BSSID MAC address."""
    if pd.isna(bssid_val):
        return "Unknown"
    mac = str(bssid_val).strip().upper().replace("-", ":")
    prefix = ":".join(mac.split(":")[:3])
    return OUI_LOOKUP.get(prefix, "Unknown")


def derive_signal(row):
    """Extracts signal strength formatting cleanly in dBm, prioritizing true negative dBm."""
    if "Signal" in row and pd.notna(row["Signal"]):
        s = str(row["Signal"]).strip()
        return s if "dBm" in s else f"{s} dBm"
    for col in ["BestSignal", "Signal", "BestQuality"]:
        if col in row and pd.notna(row[col]):
            val = row[col]
            try:
                num = float(val)
                if num < 0:
                    return f"{int(num)} dBm"
                elif num > 0 and col == "BestSignal":
                    return f"-{int(num)} dBm"
                elif num > 0:
                    return f"{int(num)} dBm"
            except (ValueError, TypeError):
                if str(val).strip():
                    return str(val)
    return "N/A" 


def read_raw_csv(source):
    """Safely reads CSV with automatic delimiter detection (semicolon, comma, tab)."""
    text_data = None
    if hasattr(source, "getvalue"):
        val = source.getvalue()
        if isinstance(val, bytes):
            try:
                text_data = val.decode("utf-8")
            except UnicodeDecodeError:
                text_data = val.decode("latin-1")
        else:
            text_data = str(val)
    elif hasattr(source, "read"):
        val = source.read()
        if isinstance(val, bytes):
            try:
                text_data = val.decode("utf-8")
            except UnicodeDecodeError:
                text_data = val.decode("latin-1")
        else:
            text_data = str(val)
    elif isinstance(source, str) and os.path.exists(source):
        with open(source, "r", encoding="utf-8", errors="replace") as f:
            text_data = f.read()
    elif isinstance(source, str):
        text_data = source

    if not text_data or not text_data.strip():
        return pd.DataFrame()

    first_line = text_data.strip().splitlines()[0]
    if ";" in first_line:
        sep = ";"
    elif "\t" in first_line:
        sep = "\t"
    else:
        sep = ","

    try:
        return pd.read_csv(io.StringIO(text_data), sep=sep)
    except Exception:
        try:
            return pd.read_csv(io.StringIO(text_data), sep=None, engine="python")
        except Exception:
            return pd.DataFrame()


def load_inventory_data(uploaded_file=None):
    """
    Loads and normalizes wireless inventory data from an uploaded file.
    Guarantees standard columns: SSID, BSSID, Channel, Security, Risk, Signal, OUI.
    Returns an empty DataFrame if no file is uploaded.
    """
    if uploaded_file is not None:
        df = read_raw_csv(uploaded_file)
    else:
        return pd.DataFrame()

    if df.empty:
        return df

    # Drop trailing unnamed columns (created by trailing semicolons in CSV)
    df = df.loc[:, ~df.columns.str.contains(r"^Unnamed", case=False)]

    # 2. Normalize SSID (ESSID in Kismet)
    if "SSID" not in df.columns:
        if "ESSID" in df.columns:
            df["SSID"] = df["ESSID"].apply(
                lambda x: "<Hidden Network>"
                if pd.isna(x) or not str(x).strip() or str(x).strip().lower() == "nan"
                else str(x).strip()
            )
        else:
            df["SSID"] = "Unknown"
    else:
        df["SSID"] = df["SSID"].apply(
            lambda x: "<Hidden Network>"
            if pd.isna(x) or not str(x).strip() or str(x).strip().lower() == "nan"
            else str(x).strip()
        )

    # 3. Normalize BSSID
    if "BSSID" not in df.columns:
        if "MAC" in df.columns:
            df["BSSID"] = df["MAC"]
        else:
            df["BSSID"] = "00:00:00:00:00:00"

    # 4. Normalize Channel
    if "Channel" not in df.columns:
        df["Channel"] = 0

    # 5. Normalize Security
    if "Security" not in df.columns:
        if "Encryption" in df.columns:
            df["Security"] = df["Encryption"].apply(derive_security)
        else:
            df["Security"] = "Unknown"
    else:
        df["Security"] = df["Security"].fillna("Open").astype(str).str.strip()

    # 6. Normalize Risk
    if "Risk" not in df.columns:
        df["Risk"] = df["Security"].apply(derive_risk)
    else:
        df["Risk"] = df["Risk"].fillna("Low").astype(str).str.strip()

    # 7. Normalize Signal
    if "Signal" not in df.columns:
        df["Signal"] = df.apply(derive_signal, axis=1)

    # 8. Normalize OUI
    if "OUI" not in df.columns:
        if "Manufacturer" in df.columns:
            df["OUI"] = df["Manufacturer"]
        else:
            df["OUI"] = df["BSSID"].apply(derive_oui)

    # Reorder primary columns to the front
    primary_cols = ["SSID", "BSSID", "Channel", "Security", "Risk", "Signal", "OUI"]
    other_cols = [c for c in df.columns if c not in primary_cols]
    df = df[primary_cols + other_cols]

    return df