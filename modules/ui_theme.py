import math
import re
import pandas as pd
"""
Stitch-Inspired Cyber-Tactical Design System & UI Components for Project AirGuard.
Features:
- Dark obsidian & slate theme (#10131a base, #1d1f27 surface containers)
- Electric cyan (#00dbe9) and tactical emerald (#4edea3) accents
- Space Grotesk (headings), Inter (body), JetBrains Mono (metrics & telemetry)
- 360° Polar Spatial Radar Scanner with rotating sweep blade
- RF Carrier Spectrum utilization & spectrogram waterfall
- Monitored live packet stream table with tactical frame badges
"""

def get_custom_css():
    """
    Returns custom CSS that transforms the Streamlit application
    to match the Stitch cyber-tactical design system.
    """
    return """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200');

    /* Global Dark Obsidian Background */
    html, body, [class*="css"], .stApp {
        background-color: #10131a !important;
        color: #e1e2ec !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }

    /* Streamlit Main Container */
    .main .block-container {
        padding-top: 1.25rem !important;
        padding-bottom: 3rem !important;
        max-width: 1440px !important;
    }

    /* Top Header Bar */
    header[data-testid="stHeader"] {
        background: transparent !important;
    }

    /* Typography */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Space Grotesk', sans-serif !important;
        color: #e1e2ec !important;
        font-weight: 600 !important;
        letter-spacing: -0.01em !important;
    }

    h1 { font-size: 26px !important; }
    h2 { font-size: 20px !important; }
    h3 { font-size: 16px !important; }

    code, pre, .stCodeBlock {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background-color: #0b0e15 !important;
        border-right: 1px solid rgba(59, 73, 75, 0.3) !important;
        box-shadow: 0 1px 8px rgba(0, 0, 0, 0.25) !important;
    }

    /* Sidebar Navigation Items */
    [data-testid="stSidebar"] .stRadio > div {
        background: transparent !important;
        gap: 4px !important;
    }

    [data-testid="stSidebar"] .stRadio label {
        background: transparent !important;
        border-radius: 8px !important;
        padding: 8px 14px !important;
        color: #b9cacb !important;
        font-weight: 500 !important;
        font-size: 13.5px !important;
        border: 1px solid transparent !important;
        transition: all 0.15s ease !important;
        cursor: pointer !important;
        display: flex !important;
        align-items: center !important;
    }

    [data-testid="stSidebar"] .stRadio label:hover {
        background: #272a32 !important;
        color: #e1e2ec !important;
    }

    [data-testid="stSidebar"] .stRadio label[data-checked="true"],
    [data-testid="stSidebar"] .stRadio div[aria-checked="true"] {
        background: #1d1f27 !important;
        color: #00dbe9 !important;
        font-weight: 600 !important;
        border: 1px solid rgba(0, 219, 233, 0.25) !important;
        box-shadow: inset 0 0 12px rgba(0, 219, 233, 0.08) !important;
    }

    /* Metric Cards */
    [data-testid="stMetric"] {
        background: rgba(29, 31, 39, 0.6) !important;
        backdrop-filter: blur(16px) !important;
        border: 1px solid rgba(59, 73, 75, 0.3) !important;
        border-radius: 12px !important;
        padding: 16px 20px !important;
        transition: border-color 0.2s ease, transform 0.2s ease !important;
    }

    [data-testid="stMetric"]:hover {
        border-color: rgba(0, 219, 233, 0.4) !important;
        transform: translateY(-1px) !important;
    }

    [data-testid="stMetricLabel"] {
        color: #b9cacb !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 11px !important;
        font-weight: 500 !important;
        letter-spacing: 0.05em !important;
        text-transform: uppercase !important;
    }

    [data-testid="stMetricValue"] {
        font-family: 'Space Grotesk', sans-serif !important;
        color: #e1e2ec !important;
        font-size: 28px !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
    }

    /* Buttons */
    .stButton > button {
        background: #191b23 !important;
        color: #e1e2ec !important;
        border: 1px solid rgba(59, 73, 75, 0.35) !important;
        border-radius: 8px !important;
        padding: 8px 20px !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 13px !important;
        font-weight: 500 !important;
        transition: all 0.2s ease !important;
    }

    .stButton > button:hover {
        background: #272a32 !important;
        border-color: #00dbe9 !important;
        color: #00dbe9 !important;
        box-shadow: 0 0 12px rgba(0, 219, 233, 0.2) !important;
    }

    .stButton > button:active {
        transform: translateY(1px) !important;
    }

    /* Primary Buttons */
    .stButton > button[kind="primary"] {
        background: rgba(0, 240, 255, 0.15) !important;
        color: #00dbe9 !important;
        border: 1px solid rgba(0, 219, 233, 0.4) !important;
        font-weight: 600 !important;
    }

    .stButton > button[kind="primary"]:hover {
        background: rgba(0, 240, 255, 0.25) !important;
        box-shadow: 0 0 16px rgba(0, 219, 233, 0.35) !important;
    }

    /* Input Fields */
    .stTextInput > div > div > input,
    .stSelectbox > div > div,
    .stTextArea > div > div > textarea {
        background-color: rgba(25, 27, 35, 0.8) !important;
        color: #e1e2ec !important;
        border: 1px solid rgba(59, 73, 75, 0.3) !important;
        border-radius: 8px !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 13.5px !important;
    }

    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: #00dbe9 !important;
        box-shadow: 0 0 0 1px rgba(0, 219, 233, 0.3) !important;
    }

    /* File Uploader */
    [data-testid="stFileUploader"] {
        background: rgba(25, 27, 35, 0.6) !important;
        border: 1px dashed rgba(59, 73, 75, 0.6) !important;
        border-radius: 12px !important;
        padding: 16px !important;
        transition: border-color 0.2s ease !important;
    }

    [data-testid="stFileUploader"]:hover {
        border-color: #00dbe9 !important;
    }

    /* Dataframe and Tables */
    [data-testid="stDataFrame"], .stDataFrame {
        background: rgba(25, 27, 35, 0.6) !important;
        border-radius: 12px !important;
        border: 1px solid rgba(59, 73, 75, 0.3) !important;
        overflow: hidden !important;
    }

    /* Alerts */
    .stAlert {
        border-radius: 10px !important;
        border: 1px solid rgba(59, 73, 75, 0.4) !important;
        font-family: 'Inter', sans-serif !important;
    }

    /* Custom Scrollbar */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: #0b0e15;
    }
    ::-webkit-scrollbar-thumb {
        background: #272a32;
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #00dbe9;
    }
    </style>
    """


def get_stitch_dashboard_html(ap_count=42, flagged_count=1, deauth_count=6, pcap_pkts="1.84M"):
    """
    Renders the Stitch cyber-tactical Command Center component:
    - Top live telemetry hero strip
    - RF Channel Utilization spectrogram curves (Ch 1, Ch 6, Ch 11, Ch 36-48, Ch 149-165)
    - Real-time waterfall spectrogram
    - 360° Polar Spatial Radar with rotating sweep blade and interactive plotted APs
    - Top Emitters deck with Rogue AP callout
    - Monitored live packet stream table
    """
    return f"""
    <!DOCTYPE html>
    <html class="dark" lang="en">
    <head>
    <meta charset="utf-8"/>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet"/>
    <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
    tailwind.config = {{
        darkMode: "class",
        theme: {{
            extend: {{
                colors: {{
                    "background": "#10131a",
                    "surface-container-lowest": "#0b0e15",
                    "surface-container-low": "#191b23",
                    "surface-container": "#1d1f27",
                    "surface-container-high": "#272a32",
                    "surface-container-highest": "#32353d",
                    "primary": "#dbfcff",
                    "primary-fixed-dim": "#00dbe9",
                    "secondary": "#4edea3",
                    "secondary-fixed-dim": "#4edea3",
                    "error": "#ffb4ab",
                    "error-container": "#93000a",
                    "on-surface": "#e1e2ec",
                    "on-surface-variant": "#b9cacb",
                    "outline-variant": "#3b494b"
                }},
                fontFamily: {{
                    "headline": ["Space Grotesk", "sans-serif"],
                    "body": ["Inter", "sans-serif"],
                    "mono": ["JetBrains Mono", "monospace"]
                }}
            }}
        }}
    }};
    </script>
    <style>
        * {{ user-select: none; -webkit-user-select: none; }}
        body {{ background: transparent; overflow-x: hidden; font-family: 'Inter', sans-serif; }}
        .polar-sweeper {{
            transform-origin: center center;
            animation: polar-sweep 8s linear infinite;
        }}
        @keyframes polar-sweep {{
            from {{ transform: rotate(0deg); }}
            to {{ transform: rotate(360deg); }}
        }}
        .pulse-ping {{
            animation: ping-wave 1.4s cubic-bezier(0, 0, 0.2, 1) infinite;
        }}
        @keyframes ping-wave {{
            75%, 100% {{ transform: scale(2.2); opacity: 0; }}
        }}
    </style>
    </head>
    <body class="text-on-surface antialiased p-1">

    <div class="flex flex-col w-full gap-5 max-w-7xl mx-auto">
        <!-- TOP LIVE TELEMETRY HERO STRIP -->
        <section class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-3.5 flex flex-col justify-between border border-outline-variant/30 hover:border-outline-variant/60 transition-all">
                <div class="flex items-center justify-between text-on-surface-variant font-mono text-[10px] uppercase tracking-wider">
                    <span>Active Radios</span>
                    <span class="inline-flex w-2 h-2 rounded-full bg-secondary"></span>
                </div>
                <div class="my-2 flex items-baseline gap-2">
                    <span class="font-headline text-2xl font-semibold tracking-tight text-on-surface">3</span>
                    <span class="font-mono text-[11px] text-secondary font-medium">PHY Tri-Band</span>
                </div>
                <div class="flex items-center gap-1.5 font-mono text-[10px] text-on-surface-variant/80">
                    <span>2.4G</span><span class="opacity-40">•</span><span>5G</span><span class="opacity-40">•</span><span>6 GHz</span>
                </div>
            </div>

            <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-3.5 flex flex-col justify-between border border-outline-variant/30 hover:border-outline-variant/60 transition-all">
                <div class="flex items-center justify-between text-on-surface-variant font-mono text-[10px] uppercase tracking-wider">
                    <span>Detected APs</span>
                    <span class="material-symbols-outlined text-xs text-on-surface-variant">router</span>
                </div>
                <div class="my-2 flex items-baseline gap-2">
                    <span class="font-headline text-2xl font-semibold tracking-tight text-on-surface">{ap_count}</span>
                    <span class="font-mono text-[11px] text-on-surface-variant">Targets</span>
                </div>
                <div class="flex items-center justify-between font-mono text-[10px] text-on-surface-variant/80">
                    <span class="text-secondary">{max(0, ap_count - flagged_count)} Secure</span>
                    <span class="text-error font-medium">{flagged_count} Flagged</span>
                </div>
            </div>

            <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-3.5 flex flex-col justify-between border border-outline-variant/30 hover:border-outline-variant/60 transition-all">
                <div class="flex items-center justify-between text-on-surface-variant font-mono text-[10px] uppercase tracking-wider">
                    <span>Probe Ingest</span>
                    <span class="material-symbols-outlined text-xs text-primary-fixed-dim animate-spin" style="animation-duration: 8s;">sync</span>
                </div>
                <div class="my-2 flex items-baseline gap-2">
                    <span class="font-headline text-2xl font-semibold tracking-tight text-on-surface" id="probeCounter">138</span>
                    <span class="font-mono text-[11px] text-on-surface-variant">Req/s</span>
                </div>
                <div class="w-full bg-surface-container-highest/60 h-1 rounded-full overflow-hidden">
                    <div class="bg-primary-fixed-dim/80 h-full w-4/5 rounded-full"></div>
                </div>
            </div>

            <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-3.5 flex flex-col justify-between border border-outline-variant/30 hover:border-outline-variant/60 transition-all">
                <div class="flex items-center justify-between text-on-surface-variant font-mono text-[10px] uppercase tracking-wider">
                    <span>Deauth Events</span>
                    <span class="material-symbols-outlined text-xs text-error">warning</span>
                </div>
                <div class="my-2 flex items-baseline gap-2">
                    <span class="font-headline text-2xl font-semibold tracking-tight text-error">0{deauth_count}</span>
                    <span class="font-mono text-[11px] text-error font-medium">Anomalies</span>
                </div>
                <div class="flex items-center gap-1.5 font-mono text-[10px] text-on-surface-variant/80">
                    <span class="w-1.5 h-1.5 rounded-full bg-error"></span>
                    <span>Burst on Ch 6 & 11</span>
                </div>
            </div>

            <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-3.5 flex flex-col justify-between border border-outline-variant/30 hover:border-outline-variant/60 transition-all">
                <div class="flex items-center justify-between text-on-surface-variant font-mono text-[10px] uppercase tracking-wider">
                    <span>Noise Floor</span>
                    <span class="material-symbols-outlined text-xs text-on-surface-variant">graphic_eq</span>
                </div>
                <div class="my-2 flex items-baseline gap-2">
                    <span class="font-headline text-2xl font-semibold tracking-tight text-on-surface">-96</span>
                    <span class="font-mono text-[11px] text-on-surface-variant">dBm</span>
                </div>
                <div class="flex items-center justify-between font-mono text-[10px] text-on-surface-variant/80">
                    <span>SNR 48.2 dB</span>
                    <span class="text-secondary font-medium">Optimal</span>
                </div>
            </div>

            <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-3.5 flex flex-col justify-between border border-outline-variant/30 hover:border-outline-variant/60 transition-all">
                <div class="flex items-center justify-between text-on-surface-variant font-mono text-[10px] uppercase tracking-wider">
                    <span>Frame Capture</span>
                    <span class="font-mono text-[10px] text-secondary">Live</span>
                </div>
                <div class="my-2 flex items-baseline gap-2">
                    <span class="font-headline text-2xl font-semibold tracking-tight text-on-surface">{pcap_pkts}</span>
                    <span class="font-mono text-[11px] text-on-surface-variant">Packets</span>
                </div>
                <div class="flex items-center justify-between font-mono text-[10px] text-on-surface-variant/80">
                    <span>0.02% Drops</span>
                    <span class="text-primary-fixed-dim">EAPOL 4/4</span>
                </div>
            </div>
        </section>

        <!-- MAIN OPERATIONAL CORE: RF SPECTRUM + 360 RADAR -->
        <section class="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
            <!-- LEFT 8 COLS: RF Channel Utilization & Waterfall -->
            <div class="lg:col-span-8 flex flex-col gap-4">
                <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-4 flex flex-col border border-outline-variant/30">
                    <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
                        <div class="flex items-center gap-2">
                            <span class="material-symbols-outlined text-primary-fixed-dim text-lg">insights</span>
                            <div>
                                <h3 class="font-headline text-base text-on-surface font-medium leading-none">RF Channel Utilization</h3>
                                <span class="font-body text-xs text-on-surface-variant mt-0.5 block">2.4 GHz ISM & 5.0 GHz U-NII Bands Overlay</span>
                            </div>
                        </div>
                        <div class="flex items-center gap-1 p-1 bg-surface-container-low rounded-lg border border-outline-variant/20">
                            <span class="px-2 py-0.5 rounded bg-surface-container-high text-primary font-mono text-[11px]">All Bands</span>
                            <span class="px-2 py-0.5 text-on-surface-variant font-mono text-[11px]">2.4G</span>
                            <span class="px-2 py-0.5 text-on-surface-variant font-mono text-[11px]">5G</span>
                            <span class="px-2 py-0.5 text-on-surface-variant font-mono text-[11px]">6G</span>
                        </div>
                    </div>

                    <!-- SVG Signal Graph with Smooth Bell Curves -->
                    <div class="relative w-full h-56 bg-surface-container-lowest/70 rounded-xl overflow-hidden flex flex-col justify-end p-2 border border-outline-variant/20">
                        <!-- Horizontal Grid Lines -->
                        <div class="absolute inset-0 flex flex-col justify-between p-4 pointer-events-none opacity-10">
                            <div class="w-full h-px bg-outline-variant"></div>
                            <div class="w-full h-px bg-outline-variant"></div>
                            <div class="w-full h-px bg-outline-variant"></div>
                            <div class="w-full h-px bg-outline-variant"></div>
                        </div>

                        <!-- Smooth Curves representing Real Environment Networks -->
                        <svg class="w-full h-44 overflow-visible relative z-10" preserveAspectRatio="none" viewBox="0 0 1000 200">
                            <defs>
                                <linearGradient id="cyanCalm" x1="0%" y1="0%" x2="0%" y2="100%">
                                    <stop offset="0%" stop-color="#00dbe9" stop-opacity="0.25"></stop>
                                    <stop offset="100%" stop-color="#00dbe9" stop-opacity="0.0"></stop>
                                </linearGradient>
                                <linearGradient id="redCalm" x1="0%" y1="0%" x2="0%" y2="100%">
                                    <stop offset="0%" stop-color="#ffb4ab" stop-opacity="0.3"></stop>
                                    <stop offset="100%" stop-color="#ffb4ab" stop-opacity="0.0"></stop>
                                </linearGradient>
                                <linearGradient id="emeraldCalm" x1="0%" y1="0%" x2="0%" y2="100%">
                                    <stop offset="0%" stop-color="#4edea3" stop-opacity="0.25"></stop>
                                    <stop offset="100%" stop-color="#4edea3" stop-opacity="0.0"></stop>
                                </linearGradient>
                            </defs>

                            <!-- Channel 1 (WEP Legacy AP) -->
                            <path d="M 20 200 Q 100 80 180 200 Z" fill="url(#cyanCalm)" stroke="#00dbe9" stroke-width="1.3"></path>
                            <text x="100" y="74" fill="#b9cacb" font-family="'JetBrains Mono', monospace" font-size="9.5" text-anchor="middle">Legacy WEP (-82 dBm)</text>

                            <!-- Channel 6 (CorpNet Authorized vs EVIL TWIN CONGESTION) -->
                            <path d="M 120 200 Q 230 20 340 200 Z" fill="url(#redCalm)" stroke="#ffb4ab" stroke-width="1.6"></path>
                            <text x="230" y="14" fill="#ffb4ab" font-family="'JetBrains Mono', monospace" font-size="10" font-weight="bold" text-anchor="middle">CH 6 ROGUE FLOOD (CorpNet Cloned)</text>

                            <!-- Channel 11 (Ogou Feray External) -->
                            <path d="M 280 200 Q 360 85 440 200 Z" fill="url(#emeraldCalm)" stroke="#4edea3" stroke-width="1.3"></path>
                            <text x="360" y="80" fill="#b9cacb" font-family="'JetBrains Mono', monospace" font-size="9.5" text-anchor="middle">Ogou Feray (-77 dBm)</text>

                            <!-- Channel 36 (CorpNet Authorized WPA2 / Guest WPA3 5GHz) -->
                            <path d="M 460 200 Q 600 40 740 200 Z" fill="url(#cyanCalm)" stroke="#00dbe9" stroke-width="1.5"></path>
                            <text x="600" y="34" fill="#00dbe9" font-family="'JetBrains Mono', monospace" font-size="10" text-anchor="middle">CorpNet Cisco WPA2 (-45 dBm)</text>

                            <!-- Channel 149 (Director Net 5GHz) -->
                            <path d="M 760 200 Q 860 70 960 200 Z" fill="url(#emeraldCalm)" stroke="#4edea3" stroke-width="1.3"></path>
                            <text x="860" y="65" fill="#b9cacb" font-family="'JetBrains Mono', monospace" font-size="9.5" text-anchor="middle">Guest Aruba WPA3 (-62 dBm)</text>
                        </svg>

                        <!-- Frequency Axis Labels -->
                        <div class="flex items-center justify-between pt-1.5 px-2 font-mono text-[10px] text-on-surface-variant/70 border-t border-outline-variant/20 mt-1">
                            <span>CH 1 (2412 MHz)</span>
                            <span class="text-error font-medium">CH 6 (2437 MHz) [CONGESTION]</span>
                            <span>CH 11 (2462 MHz)</span>
                            <span class="text-primary-fixed-dim">CH 36-48 (5180-5240 MHz)</span>
                            <span>CH 149-165 (5745-5825 MHz)</span>
                        </div>
                    </div>

                    <!-- Spectrogram Waterfall -->
                    <div class="mt-3 flex flex-col gap-1.5">
                        <div class="flex items-center justify-between font-mono text-[10px] text-on-surface-variant/80">
                            <span class="flex items-center gap-1.5">
                                <span class="material-symbols-outlined text-xs text-primary-fixed-dim">waterfall_chart</span>
                                Spectrogram Waterfall (T - 60 sec)
                            </span>
                            <span>Resolution: 100 kHz • Sweep: 12.4 ms</span>
                        </div>
                        <div class="h-16 w-full rounded-lg overflow-hidden relative border border-outline-variant/20 bg-surface-container-lowest flex flex-col justify-between">
                            <div class="absolute inset-0 bg-gradient-to-b from-surface-container-lowest/80 via-transparent to-surface-container-lowest/80 pointer-events-none z-10"></div>
                            <div class="h-full w-full opacity-60 flex flex-col">
                                <div class="flex-1 w-full bg-gradient-to-r from-surface-container-lowest via-secondary/15 via-error/35 via-primary-fixed-dim/20 to-surface-container-lowest"></div>
                                <div class="flex-1 w-full bg-gradient-to-r from-surface-container-lowest via-secondary/20 via-error/45 via-primary-fixed-dim/20 to-surface-container-lowest"></div>
                                <div class="flex-1 w-full bg-gradient-to-r from-surface-container-lowest via-primary-fixed-dim/20 via-error/35 via-secondary/20 to-surface-container-lowest"></div>
                            </div>
                            <div class="absolute bottom-1 right-2 z-20 font-mono text-[9px] text-on-surface-variant bg-surface-container-low/90 px-2 py-0.5 rounded border border-outline-variant/30">
                                Active Sweep: 2400.0 - 5875.0 MHz
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 3 Hardware Specs Cards -->
                <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-3 flex flex-col gap-1 border border-outline-variant/30">
                        <div class="flex items-center justify-between text-on-surface-variant font-mono text-[10px] uppercase">
                            <span>DFS Radar Monitor</span>
                            <span class="text-secondary font-medium">Clear</span>
                        </div>
                        <span class="font-headline text-base text-on-surface font-medium">0 Radar Lockouts</span>
                        <p class="font-body text-xs text-on-surface-variant/80">Channels 52-144 zero maritime/weather radar lockouts.</p>
                    </div>

                    <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-3 flex flex-col gap-1 border border-outline-variant/30">
                        <div class="flex items-center justify-between text-on-surface-variant font-mono text-[10px] uppercase">
                            <span>Packet Injection</span>
                            <span class="text-secondary font-medium">Active</span>
                        </div>
                        <span class="font-headline text-base text-on-surface font-medium">0.08 ms Latency</span>
                        <p class="font-body text-xs text-on-surface-variant/80">Raw frame transmission driver ready. Scapy/Pcap ingest active.</p>
                    </div>

                    <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-3 flex flex-col gap-1 border border-outline-variant/30">
                        <div class="flex items-center justify-between text-on-surface-variant font-mono text-[10px] uppercase">
                            <span>Evil Twin Detector</span>
                            <span class="text-error font-medium">1 Detected</span>
                        </div>
                        <span class="font-headline text-base text-error font-medium">CorpNet Cloned</span>
                        <p class="font-body text-xs text-on-surface-variant/80">OUI mismatch on AA:BB:CC:DD:EE:FF (Expected Cisco, observed None).</p>
                    </div>
                </div>
            </div>

            <!-- RIGHT 4 COLS: 360° Polar Spatial Radar & Top Emitters -->
            <div class="lg:col-span-4 flex flex-col gap-4">
                <!-- 360-Degree Polar Radar Container -->
                <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-4 border border-outline-variant/30 flex flex-col gap-3">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-1.5">
                            <span class="material-symbols-outlined text-primary-fixed-dim text-lg">radar</span>
                            <h3 class="font-headline text-base text-on-surface font-medium">Spatial Radar</h3>
                        </div>
                        <span class="px-2 py-0.5 rounded-full bg-surface-container-high font-mono text-[10px] text-on-surface-variant border border-outline-variant/20">Polar 360°</span>
                    </div>

                    <!-- Clean Polar Coordinate Plane -->
                    <div class="relative w-full aspect-square bg-surface-container-lowest/80 rounded-full overflow-hidden flex items-center justify-center border border-outline-variant/30">
                        <!-- Concentric Polar Rings -->
                        <div class="absolute inset-5 rounded-full border border-outline-variant/20"></div>
                        <div class="absolute inset-14 rounded-full border border-outline-variant/20"></div>
                        <div class="absolute inset-24 rounded-full border border-outline-variant/20"></div>
                        <div class="absolute inset-32 rounded-full border border-outline-variant/30"></div>

                        <!-- Crosshairs -->
                        <div class="absolute inset-0 flex items-center justify-center pointer-events-none opacity-15">
                            <div class="w-full h-px bg-outline-variant"></div>
                            <div class="h-full w-px bg-outline-variant absolute"></div>
                        </div>

                        <!-- Rotating Radar Sweeper Blade -->
                        <div class="absolute inset-0 polar-sweeper pointer-events-none opacity-45">
                            <div class="w-1/2 h-1/2 ml-auto origin-bottom-left bg-gradient-to-tr from-transparent to-primary-fixed-dim/30 rounded-tr-full"></div>
                        </div>

                        <!-- Local Receiver Center Beacon -->
                        <div class="w-2.5 h-2.5 rounded-full bg-primary-fixed-dim z-20 shadow-lg shadow-primary-fixed-dim/50"></div>

                        <!-- Target Node 1: Authorized CorpNet (Cisco) -->
                        <div class="absolute top-1/4 left-1/3 z-20 group cursor-pointer" title="CorpNet Authorized (Cisco) -45 dBm • CH 6">
                            <span class="relative flex h-2.5 w-2.5">
                                <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-secondary"></span>
                            </span>
                            <div class="absolute left-4 -top-2 hidden group-hover:flex flex-col bg-surface-container-high px-2 py-1 rounded text-on-surface z-30 shadow-xl border border-outline-variant/40 min-w-[120px] font-mono text-[10px]">
                                <span class="font-bold text-secondary">CorpNet (Cisco)</span>
                                <span>-45 dBm • CH 6</span>
                            </div>
                        </div>

                        <!-- Target Node 2: 🚨 ROGUE AP / EVIL TWIN -->
                        <div class="absolute bottom-1/4 right-1/4 z-20 group cursor-pointer" title="🚨 ROGUE AP: CorpNet Cloned (AA:BB:CC:DD:EE:FF)">
                            <span class="relative flex h-3 w-3">
                                <span class="pulse-ping absolute inline-flex h-full w-full rounded-full bg-error opacity-75"></span>
                                <span class="relative inline-flex rounded-full h-3 w-3 bg-error shadow-lg shadow-error/80"></span>
                            </span>
                            <div class="absolute right-4 -top-2 hidden group-hover:flex flex-col bg-surface-container-high px-2 py-1 rounded text-on-surface z-30 shadow-xl border border-error/40 min-w-[140px] font-mono text-[10px]">
                                <span class="font-bold text-error">⚠️ ROGUE EVIL TWIN</span>
                                <span>-38 dBm • CH 6 (Open)</span>
                            </div>
                        </div>

                        <!-- Target Node 3: Guest Aruba WPA3 -->
                        <div class="absolute top-1/3 right-1/4 z-20 group cursor-pointer" title="Guest WPA3 (Aruba) -62 dBm • CH 36">
                            <div class="w-2 h-2 rounded-full bg-secondary"></div>
                        </div>

                        <!-- Target Node 4: Legacy WEP -->
                        <div class="absolute bottom-12 left-1/4 z-20 group cursor-pointer" title="Legacy WEP AP -82 dBm • CH 1">
                            <div class="w-2 h-2 rounded-full bg-primary-fixed-dim"></div>
                        </div>
                    </div>

                    <div class="flex items-center justify-between font-mono text-[10px] text-on-surface-variant px-1">
                        <div class="flex items-center gap-1.5"><span class="w-2 h-2 rounded-full bg-secondary"></span><span>Secure</span></div>
                        <div class="flex items-center gap-1.5"><span class="w-2 h-2 rounded-full bg-error"></span><span>Rogue</span></div>
                        <div class="flex items-center gap-1.5"><span class="w-2 h-2 rounded-full bg-primary-fixed-dim"></span><span>External</span></div>
                    </div>
                </div>

                <!-- Top Signal Emitters List -->
                <div class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-4 border border-outline-variant/30 flex flex-col gap-2.5">
                    <div class="flex items-center justify-between">
                        <h3 class="font-headline text-sm text-on-surface font-medium">Top Signal Emitters</h3>
                        <span class="font-mono text-[10px] text-on-surface-variant">Sort: RSSI</span>
                    </div>

                    <!-- Emitter 1 -->
                    <div class="p-2 rounded-lg bg-surface-container-low/70 flex flex-col gap-1 border border-outline-variant/20">
                        <div class="flex items-center justify-between">
                            <span class="font-mono text-xs text-on-surface font-medium truncate">CorpNet (Cisco Systems)</span>
                            <span class="font-mono text-[10px] text-secondary font-medium">-45 dBm</span>
                        </div>
                        <div class="flex items-center justify-between font-mono text-[10px] text-on-surface-variant">
                            <span>CH 6 • 00:11:22:33:44:55</span>
                            <span>WPA2-CCMP</span>
                        </div>
                        <div class="w-full bg-surface-container-highest/60 h-1 rounded-full overflow-hidden mt-0.5">
                            <div class="bg-secondary/70 h-full w-[80%]"></div>
                        </div>
                    </div>

                    <!-- Emitter 2: Rogue AP Alert -->
                    <div class="p-2 rounded-lg bg-surface-container-low/70 flex flex-col gap-1 border border-outline-variant/20 border-l-2 border-l-error">
                        <div class="flex items-center justify-between">
                            <span class="font-mono text-xs text-error font-medium truncate">⚠️ CorpNet [ROGUE CLONE]</span>
                            <span class="font-mono text-[10px] text-error font-medium">-38 dBm</span>
                        </div>
                        <div class="flex items-center justify-between font-mono text-[10px] text-on-surface-variant">
                            <span>CH 6 • AA:BB:CC:DD:EE:FF</span>
                            <span class="text-error font-medium">Unencrypted (Open)</span>
                        </div>
                        <div class="w-full bg-surface-container-highest/60 h-1 rounded-full overflow-hidden mt-0.5">
                            <div class="bg-error/70 h-full w-[88%]"></div>
                        </div>
                    </div>

                    <!-- Emitter 3 -->
                    <div class="p-2 rounded-lg bg-surface-container-low/70 flex flex-col gap-1 border border-outline-variant/20">
                        <div class="flex items-center justify-between">
                            <span class="font-mono text-xs text-on-surface font-medium truncate">Guest (Aruba Networks)</span>
                            <span class="font-mono text-[10px] text-primary-fixed-dim font-medium">-62 dBm</span>
                        </div>
                        <div class="flex items-center justify-between font-mono text-[10px] text-on-surface-variant">
                            <span>CH 36 • 11:22:33:44:55:66</span>
                            <span>WPA3-SAE</span>
                        </div>
                        <div class="w-full bg-surface-container-highest/60 h-1 rounded-full overflow-hidden mt-0.5">
                            <div class="bg-primary-fixed-dim/70 h-full w-[65%]"></div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- BOTTOM LIVE PACKET STREAM TABLE -->
        <section class="bg-surface-container/60 backdrop-blur-xl rounded-xl p-4 border border-outline-variant/30 flex flex-col gap-3">
            <div class="flex flex-wrap items-center justify-between gap-3">
                <div class="flex items-center gap-2">
                    <span class="material-symbols-outlined text-secondary text-lg">reorder</span>
                    <div>
                        <h3 class="font-headline text-base text-on-surface font-medium leading-none">Live Monitored Packet Stream</h3>
                        <span class="font-body text-xs text-on-surface-variant mt-0.5 block">Monitored frame capture telemetry & verification filter stream</span>
                    </div>
                </div>
                <div class="flex items-center gap-2 font-mono text-xs">
                    <button id="streamToggleBtn" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-container-low text-on-surface hover:bg-surface-container-high border border-outline-variant/20 transition-colors" type="button">
                        <span class="material-symbols-outlined text-sm">pause</span>
                        <span id="streamLabel">Pause Stream</span>
                    </button>
                    <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-container-high text-primary-fixed-dim border border-outline-variant/30">
                        Promiscuous Monitor Active
                    </span>
                </div>
            </div>

            <!-- Table -->
            <div class="w-full overflow-x-auto rounded-xl bg-surface-container-lowest/60 border border-outline-variant/20">
                <table class="w-full text-left font-mono text-[11px] whitespace-nowrap">
                    <thead class="bg-surface-container-high/40 text-on-surface-variant uppercase tracking-wider">
                        <tr>
                            <th class="py-2.5 px-3 font-medium">Time Offset</th>
                            <th class="py-2.5 px-3 font-medium">Frame Type</th>
                            <th class="py-2.5 px-3 font-medium">Source MAC</th>
                            <th class="py-2.5 px-3 font-medium">Destination MAC</th>
                            <th class="py-2.5 px-3 font-medium">SSID / Target</th>
                            <th class="py-2.5 px-3 font-medium">RSSI</th>
                            <th class="py-2.5 px-3 font-medium">Freq / Ch</th>
                            <th class="py-2.5 px-3 font-medium">Verification Status</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-surface-container-low">
                        <tr class="hover:bg-surface-container-high/40 bg-error-container/10">
                            <td class="py-2.5 px-3 text-error">+0.00124s</td>
                            <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded bg-error-container/30 text-error font-medium">DEAUTH [0x00C0]</span></td>
                            <td class="py-2.5 px-3 text-error">AA:BB:CC:DD:EE:FF</td>
                            <td class="py-2.5 px-3 text-on-surface-variant">FF:FF:FF:FF:FF:FF (Broadcast)</td>
                            <td class="py-2.5 px-3 text-error font-medium">CorpNet (Cloned)</td>
                            <td class="py-2.5 px-3 text-error">-38 dBm</td>
                            <td class="py-2.5 px-3 text-on-surface-variant">2437 MHz [CH 6]</td>
                            <td class="py-2.5 px-3 text-error">⚠️ OUI Mismatch • Flagged</td>
                        </tr>
                        <tr class="hover:bg-surface-container-high/40">
                            <td class="py-2.5 px-3 text-primary-fixed-dim">+0.00318s</td>
                            <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded bg-surface-container-high text-primary-fixed-dim font-medium">EAPOL KEY 1/4</span></td>
                            <td class="py-2.5 px-3">00:11:22:33:44:55</td>
                            <td class="py-2.5 px-3 text-on-surface-variant">84:BA:3B:11:F2:90</td>
                            <td class="py-2.5 px-3">CorpNet (Cisco)</td>
                            <td class="py-2.5 px-3 text-secondary">-45 dBm</td>
                            <td class="py-2.5 px-3 text-on-surface-variant">2437 MHz [CH 6]</td>
                            <td class="py-2.5 px-3 text-secondary">MIC Valid • ANonce Verified</td>
                        </tr>
                        <tr class="hover:bg-surface-container-high/40">
                            <td class="py-2.5 px-3 text-on-surface-variant">+0.00445s</td>
                            <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded bg-surface-container-high text-on-surface-variant">PROBE REQ</span></td>
                            <td class="py-2.5 px-3 text-on-surface-variant">62:7A:B4:9C:18:22</td>
                            <td class="py-2.5 px-3 text-on-surface-variant">FF:FF:FF:FF:FF:FF</td>
                            <td class="py-2.5 px-3 text-on-surface-variant">&lt;Wildcard Broadcast&gt;</td>
                            <td class="py-2.5 px-3 text-on-surface-variant">-76 dBm</td>
                            <td class="py-2.5 px-3 text-on-surface-variant">2412 MHz [CH 1]</td>
                            <td class="py-2.5 px-3 text-on-surface-variant">HT Capable [40MHz]</td>
                        </tr>
                        <tr class="hover:bg-surface-container-high/40">
                            <td class="py-2.5 px-3 text-on-surface-variant">+0.00502s</td>
                            <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded bg-surface-container-high text-on-surface-variant">BEACON [0x0080]</span></td>
                            <td class="py-2.5 px-3 text-on-surface-variant">11:22:33:44:55:66</td>
                            <td class="py-2.5 px-3 text-on-surface-variant">FF:FF:FF:FF:FF:FF</td>
                            <td class="py-2.5 px-3 text-secondary">Guest (Aruba)</td>
                            <td class="py-2.5 px-3 text-secondary">-62 dBm</td>
                            <td class="py-2.5 px-3 text-on-surface-variant">5180 MHz [CH 36]</td>
                            <td class="py-2.5 px-3 text-secondary">WPA3-SAE Valid</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>
    </div>

    <script>
    (function initStitchInteractions() {{
        const probeCounter = document.getElementById('probeCounter');
        if (probeCounter) {{
            setInterval(() => {{
                const jitter = Math.floor(Math.random() * 9) - 4;
                const val = parseInt(probeCounter.innerText, 10);
                probeCounter.innerText = Math.max(115, Math.min(160, val + jitter));
            }}, 1500);
        }}

        const streamBtn = document.getElementById('streamToggleBtn');
        const streamLabel = document.getElementById('streamLabel');
        let streaming = true;
        if (streamBtn && streamLabel) {{
            streamBtn.addEventListener('click', () => {{
                streaming = !streaming;
                streamLabel.innerText = streaming ? 'Pause Stream' : 'Resume Stream';
                streamBtn.querySelector('.material-symbols-outlined').innerText = streaming ? 'pause' : 'play_arrow';
            }});
        }}
    }})();
    </script>
    </body>
    </html>
    """


def render_page_header(title, subtitle, badge_text="ACTIVE", badge_type="cyan"):
    """
    Renders a unified cyber-tactical header banner matching the Stitch design system.
    """
    badge_colors = {
        "cyan": {"bg": "rgba(0, 240, 255, 0.12)", "border": "rgba(0, 219, 233, 0.35)", "text": "#00dbe9", "dot": "#00dbe9"},
        "emerald": {"bg": "rgba(78, 222, 163, 0.12)", "border": "rgba(78, 222, 163, 0.35)", "text": "#4edea3", "dot": "#4edea3"},
        "crimson": {"bg": "rgba(255, 180, 171, 0.12)", "border": "rgba(255, 180, 171, 0.35)", "text": "#ffb4ab", "dot": "#ffb4ab"},
        "warning": {"bg": "rgba(255, 205, 207, 0.12)", "border": "rgba(255, 178, 183, 0.35)", "text": "#ffb2b7", "dot": "#ffb2b7"},
    }
    cfg = badge_colors.get(badge_type, badge_colors["cyan"])
    return f"""
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid rgba(59, 73, 75, 0.25);">
        <div>
            <h1 style="margin: 0; font-size: 24px; font-weight: 700; color: #e1e2ec; font-family: 'Space Grotesk', sans-serif;">{title}</h1>
            <p style="color: #849495; font-size: 13px; margin-top: 3px; font-family: 'Inter', sans-serif;">{subtitle}</p>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
            <span style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; background: {cfg['bg']}; border: 1px solid {cfg['border']}; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: {cfg['text']}; font-weight: 600;">
                <span style="width: 6px; height: 6px; border-radius: 50%; background: {cfg['dot']};"></span>{badge_text}
            </span>
        </div>
    </div>
    """


def generate_radar_targets_html(inventory_df, alerts_df):
    """
    Dynamically maps observed access points and flagged rogue APs onto the 360° radar canvas.
    Signal dBm determines the concentric ring distance (radius), and channel/index determines polar angle.
    Returns ZERO dots when inventory_df is empty.
    """
    if inventory_df is None or inventory_df.empty:
        return """
        <!-- Standby Listening Display -->
        <div class="absolute inset-0 flex items-center justify-center pointer-events-none z-10">
            <span class="font-['JetBrains_Mono'] text-[9px] text-[#849495]/70 uppercase tracking-widest bg-[#0b0e15]/90 px-3 py-1.5 rounded-md border border-[#3b494b]/30">STANDBY • NO RF TARGETS</span>
        </div>
        """

    rogue_bssids = set(alerts_df["Suspicious BSSID"].dropna().astype(str).str.upper().unique()) if alerts_df is not None and not alerts_df.empty else set()
    targets_html = []
    
    for idx, (_, row) in enumerate(inventory_df.iterrows()):
        bssid = str(row.get("BSSID", "Unknown")).strip().upper()
        ssid = str(row.get("SSID", "<Hidden>")).strip()
        sec = str(row.get("Security", "Open")).strip()
        oui = str(row.get("OUI", "Unknown")).strip()
        ch = str(row.get("Channel", "0")).strip()
        sig_str = str(row.get("Signal", "-70 dBm"))
        
        sig_match = re.search(r'(-\d+)', sig_str)
        sig_val = int(sig_match.group(1)) if sig_match else -70
        
        # Radius mapping: -30 dBm is center (12%), -95 dBm is perimeter (43%)
        norm_sig = max(0.0, min(1.0, (abs(sig_val) - 30) / 65.0))
        r_pct = 12.0 + norm_sig * 31.0
        
        angle_deg = (idx * 53.0 + 25.0) % 360.0
        angle_rad = math.radians(angle_deg)
        
        left_pct = round(50.0 + r_pct * math.cos(angle_rad), 1)
        top_pct = round(50.0 - r_pct * math.sin(angle_rad), 1)
        
        is_rogue = bssid in rogue_bssids or any(bssid in str(r) for r in rogue_bssids)
        safe_ssid = ssid.replace("'", "\\'")
        safe_oui = oui.replace("'", "\\'")
        
        if is_rogue:
            targets_html.append(f"""
            <!-- 🚨 ROGUE AP / EVIL TWIN -->
            <div class="absolute z-30 group cursor-pointer" style="top: {top_pct}%; left: {left_pct}%; transform: translate(-50%, -50%);" 
                 title="🚨 CLICK TO INSPECT: {ssid} ({bssid}) {sig_str} • CH {ch}"
                 onclick="selectRadarDot(this, '{safe_ssid}', '{bssid}', '{sig_str}', '{ch}', '{sec}', '{safe_oui}', 'True')">
                <span class="relative flex h-4 w-4">
                    <span class="pulse-ping absolute inline-flex h-full w-full rounded-full bg-[#ffb4ab] opacity-90"></span>
                    <span class="relative inline-flex rounded-full h-4 w-4 bg-[#ffb4ab] shadow-lg shadow-[#ffb4ab] border border-white/40"></span>
                </span>
            </div>
            """)
        elif "WEP" in sec.upper() or "OPEN" in sec.upper():
            targets_html.append(f"""
            <!-- ⚠️ INSECURE AP -->
            <div class="absolute z-20 group cursor-pointer" style="top: {top_pct}%; left: {left_pct}%; transform: translate(-50%, -50%);" 
                 title="⚠️ CLICK TO INSPECT: {ssid} ({bssid}) {sig_str} • CH {ch}"
                 onclick="selectRadarDot(this, '{safe_ssid}', '{bssid}', '{sig_str}', '{ch}', '{sec}', '{safe_oui}', 'False')">
                <div class="w-2.5 h-2.5 rounded-full bg-[#00dbe9] border border-[#00dbe9]/60 shadow-sm shadow-[#00dbe9]"></div>
            </div>
            """)
        else:
            targets_html.append(f"""
            <!-- ✅ AUTHORIZED AP -->
            <div class="absolute z-20 group cursor-pointer" style="top: {top_pct}%; left: {left_pct}%; transform: translate(-50%, -50%);" 
                 title="✅ CLICK TO INSPECT: {ssid} ({oui}) {sig_str} • CH {ch}"
                 onclick="selectRadarDot(this, '{safe_ssid}', '{bssid}', '{sig_str}', '{ch}', '{sec}', '{safe_oui}', 'False')">
                <div class="w-2.5 h-2.5 rounded-full bg-[#4edea3] border border-[#4edea3]/60 shadow-sm shadow-[#4edea3]"></div>
            </div>
            """)
            
    return "\n".join(targets_html)


def get_stitch_radar_scanner_component(inventory_df=None, alerts_df=None, is_scanning=True, **kwargs):
    """
    Renders the dedicated 360° Polar Spatial Radar Scanner for Rogue AP & Evil Twin Detection,
    styled in the Stitch cyber-tactical aesthetic with interactive Target Inspector.
    """
    is_empty = inventory_df is None or inventory_df.empty
    has_rogue = alerts_df is not None and not alerts_df.empty
    rogue_count = len(alerts_df) if has_rogue else 0
    total_aps = len(inventory_df) if not is_empty else 0

    if is_empty:
        badge_text = "STANDBY • NO RF TARGETS"
        badge_class = "text-[#849495] bg-[#191b23] border-[#3b494b]/30"
    elif has_rogue:
        badge_text = f"🚨 {rogue_count} ROGUE AP PINPOINTED"
        badge_class = "text-[#ffb4ab] bg-[#93000a]/30 border-[#ffb4ab]/40 animate-pulse"
    else:
        badge_text = f"● {total_aps} APs MONITORED (SECURE)"
        badge_class = "text-[#4edea3] bg-[#1d1f27] border-[#4edea3]/30"

    radar_targets_html = generate_radar_targets_html(inventory_df, alerts_df)

    return f"""
    <!DOCTYPE html>
    <html class="dark" lang="en">
    <head>
    <meta charset="utf-8"/>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet"/>
    <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        * {{ user-select: none; margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ background: transparent; overflow: hidden; font-family: 'Inter', sans-serif; }}
        .polar-sweeper {{
            transform-origin: center center;
            animation: polar-sweep 5s linear infinite;
        }}
        @keyframes polar-sweep {{
            from {{ transform: rotate(0deg); }}
            to {{ transform: rotate(360deg); }}
        }}
        .pulse-ping {{
            animation: ping-wave 1.2s cubic-bezier(0, 0, 0.2, 1) infinite;
        }}
        @keyframes ping-wave {{
            75%, 100% {{ transform: scale(2.4); opacity: 0; }}
        }}
    </style>
    </head>
    <body class="p-0">
    <div class="bg-[#1d1f27]/90 backdrop-blur-xl rounded-xl p-3 border border-[#3b494b]/35 flex flex-col gap-2 w-full max-w-[390px] mx-auto shadow-2xl">
        <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
                <span class="material-symbols-outlined text-[#00dbe9] text-xl">radar</span>
                <h3 class="font-['Space_Grotesk'] text-sm text-[#e1e2ec] font-semibold tracking-tight">RF Spatial Radar Detector</h3>
            </div>
            <span class="px-2 py-0.5 rounded-full font-['JetBrains_Mono'] text-[9.5px] font-semibold border {badge_class}">{badge_text}</span>
        </div>

        <!-- Radar Display Canvas -->
        <div class="relative w-full max-w-[270px] aspect-square mx-auto bg-[#0b0e15] rounded-full overflow-hidden flex items-center justify-center border border-[#3b494b]/50 shadow-inner">
            <!-- Concentric Range Rings (dBm) -->
            <div class="absolute inset-5 rounded-full border border-[#3b494b]/20 flex items-start justify-center pt-0.5"><span class="font-['JetBrains_Mono'] text-[7px] text-[#b9cacb]/50">-30dBm</span></div>
            <div class="absolute inset-12 rounded-full border border-[#3b494b]/20 flex items-start justify-center pt-0.5"><span class="font-['JetBrains_Mono'] text-[7px] text-[#b9cacb]/50">-50dBm</span></div>
            <div class="absolute inset-20 rounded-full border border-[#3b494b]/25 flex items-start justify-center pt-0.5"><span class="font-['JetBrains_Mono'] text-[7px] text-[#b9cacb]/50">-70dBm</span></div>
            <div class="absolute inset-27 rounded-full border border-[#3b494b]/35 flex items-start justify-center pt-0.5"><span class="font-['JetBrains_Mono'] text-[7px] text-[#b9cacb]/50">-90dBm</span></div>

            <!-- Crosshairs -->
            <div class="absolute inset-0 flex items-center justify-center pointer-events-none opacity-25">
                <div class="w-full h-px bg-[#849495]"></div>
                <div class="h-full w-px bg-[#849495] absolute"></div>
            </div>

            <!-- Rotating Radar Sweeper Blade -->
            <div class="absolute inset-0 polar-sweeper pointer-events-none opacity-60">
                <div class="w-1/2 h-1/2 ml-auto origin-bottom-left bg-gradient-to-tr from-transparent to-[#00dbe9]/40 rounded-tr-full"></div>
            </div>

            <!-- Center Receiver Hub -->
            <div class="w-2.5 h-2.5 rounded-full bg-[#00dbe9] z-20 shadow-lg shadow-[#00dbe9]"></div>

            <!-- Dynamic AP Targets Plotted by Real Signal (dBm) -->
            {radar_targets_html}
        </div>

        <!-- Interactive Target Inspector Card (Updates immediately on click!) -->
        <div id="inspectorCard" class="bg-[#0b0e15] border border-[#3b494b]/40 rounded-lg p-2 font-['JetBrains_Mono'] text-[10.5px] text-[#e1e2ec] transition-all">
            <div class="flex items-center justify-between mb-1">
                <span id="inspectSSID" class="font-bold text-[#00dbe9] text-[11.5px] truncate max-w-[200px]">{'Click dot to inspect telemetry' if not is_empty else 'Radar in Standby'}</span>
                <span id="inspectBadge" class="px-1.5 py-0.2 rounded text-[8.5px] bg-[#191b23] text-[#849495] font-semibold">{'SELECT EMITTER' if not is_empty else 'STANDBY'}</span>
            </div>
            <div id="inspectDetails" class="text-[#849495] text-[9.5px]">
                {'Click any emitter dot above to see its SSID, BSSID, Signal dBm, and threat status.' if not is_empty else 'No capture loaded. Upload a Kismet CSV to plot active APs.'}
            </div>
        </div>

        <div class="flex items-center justify-between font-['JetBrains_Mono'] text-[9px] text-[#b9cacb] px-1 pt-0.5 border-t border-[#3b494b]/20">
            <span class="text-[#4edea3] flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-[#4edea3]"></span>Authorized</span>
            <span class="text-[#ffb4ab] flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-[#ffb4ab]"></span>Rogue AP</span>
            <span class="text-[#849495]">INTERACTIVE 360°</span>
        </div>
    </div>

    <script>
    function selectRadarDot(el, ssid, bssid, signal, channel, security, vendor, isRogue) {{
        const ssidEl = document.getElementById('inspectSSID');
        const badgeEl = document.getElementById('inspectBadge');
        const detailsEl = document.getElementById('inspectDetails');
        
        ssidEl.innerText = ssid;
        if (isRogue === 'True') {{
            ssidEl.className = 'font-bold text-[#ffb4ab] text-[12px] truncate max-w-[200px]';
            badgeEl.innerText = '🚨 ROGUE AP / EVIL TWIN';
            badgeEl.className = 'px-1.5 py-0.5 rounded text-[8.5px] bg-[#93000a]/50 text-[#ffb4ab] border border-[#ffb4ab]/50 font-bold';
        }} else {{
            ssidEl.className = 'font-bold text-[#4edea3] text-[12px] truncate max-w-[200px]';
            badgeEl.innerText = '✅ AUTHORIZED AP';
            badgeEl.className = 'px-1.5 py-0.5 rounded text-[8.5px] bg-[#1d1f27] text-[#4edea3] border border-[#4edea3]/40 font-semibold';
        }}
        
        detailsEl.innerHTML = 
            '<div class="flex justify-between items-center mt-0.5"><span class="text-[#e1e2ec]">BSSID: <code class="text-[#00dbe9]">' + bssid + '</code></span>' +
            '<span class="' + (isRogue === 'True' ? 'text-[#ffb4ab]' : 'text-[#4edea3]') + ' font-bold">' + signal + '</span></div>' +
            '<div class="flex justify-between text-[#849495] mt-0.5"><span>CH ' + channel + ' • ' + security + '</span><span>' + vendor + '</span></div>';
    }}
    </script>
    </body>
    </html>
    """


import base64
import os

def render_team_member_card(m):
    """
    Renders an individual team profile card for the About Us page,
    styled in the Stitch dark cyber-tactical aesthetic.
    Guarantees 0 leading spaces so Markdown never parses it as a code block.
    """
    photo = m.get("photo_path", "")
    init = m.get("initials", "MC")
    m_name = m.get("name", "Team Member")
    m_bio = m.get("bio", "")
    m_email = m.get("email", "#")
    m_in = m.get("linkedin", "#")
    m_gh = m.get("github", "#")
    
    avatar_markup = ""
    if photo and os.path.exists(photo):
        try:
            with open(photo, "rb") as img_f:
                b64_val = base64.b64encode(img_f.read()).decode("utf-8")
            ext = os.path.splitext(photo)[1].lower().replace(".", "")
            if ext == "jpg": ext = "jpeg"
            avatar_markup = f'<div style="width: 86px; height: 86px; margin: 0 auto 14px auto; border-radius: 50%; overflow: hidden; border: 2px solid #00dbe9; box-shadow: 0 0 16px rgba(0, 219, 233, 0.4);"><img src="data:image/{ext};base64,{b64_val}" style="width: 100%; height: 100%; object-fit: cover;" alt="{m_name}" /></div>'
        except Exception:
            avatar_markup = ""
            
    if not avatar_markup:
        avatar_markup = f'<div style="width: 86px; height: 86px; margin: 0 auto 14px auto; border-radius: 50%; background: linear-gradient(135deg, #191b23 0%, #272a32 100%); border: 2px solid rgba(0, 219, 233, 0.5); box-shadow: 0 0 16px rgba(0, 219, 233, 0.2); display: flex; align-items: center; justify-content: center; color: #00dbe9; font-family: sans-serif; font-size: 24px; font-weight: 700; letter-spacing: 0.05em;">{init}</div>'

    card_html = (
        '<div style="background: #191b23; border: 1px solid rgba(59, 73, 75, 0.45); border-radius: 12px; padding: 22px 16px; display: flex; flex-direction: column; justify-content: space-between; text-align: center; min-height: 290px; box-shadow: 0 4px 20px rgba(0,0,0,0.35);">'
        '<div>'
        f'{avatar_markup}'
        f'<h3 style="font-family: sans-serif; font-size: 16.5px; font-weight: 700; color: #dbfcff; margin: 0 0 8px 0;">{m_name}</h3>'
        f'<p style="font-family: sans-serif; font-size: 12px; color: #b9cacb; line-height: 1.5; margin: 0 0 16px 0; min-height: 54px;">{m_bio}</p>'
        '</div>'
        '<div style="display: flex; justify-content: center; gap: 8px; flex-wrap: wrap; padding-top: 12px; border-top: 1px solid rgba(59, 73, 75, 0.3);">'
        f'<a href="mailto:{m_email}" target="_blank" style="text-decoration: none; display: inline-flex; align-items: center; gap: 4px; padding: 5px 9px; border-radius: 6px; background: #272a32; border: 1px solid rgba(59, 73, 75, 0.5); color: #dbfcff; font-family: monospace; font-size: 10.5px; font-weight: 500;">✉️ Email</a>'
        f'<a href="{m_in}" target="_blank" style="text-decoration: none; display: inline-flex; align-items: center; gap: 4px; padding: 5px 9px; border-radius: 6px; background: rgba(0, 119, 181, 0.15); border: 1px solid rgba(0, 119, 181, 0.4); color: #70b5f9; font-family: monospace; font-size: 10.5px; font-weight: 500;">💼 LinkedIn</a>'
        f'<a href="{m_gh}" target="_blank" style="text-decoration: none; display: inline-flex; align-items: center; gap: 4px; padding: 5px 9px; border-radius: 6px; background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.2); color: #e1e2ec; font-family: monospace; font-size: 10.5px; font-weight: 500;">💻 GitHub</a>'
        '</div>'
        '</div>'
    )
    return card_html
