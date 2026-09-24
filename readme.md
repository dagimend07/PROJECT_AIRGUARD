# Project AirGuard
**Mission:** An AI-assisted wireless security assessment platform that analyzes packet evidence, detects suspicious activity, and generates professional reports.

## Product Requirements Document (PRD)
* **Target Users:** Ethical hackers, penetration testers, and security analysts.
* **Core Modules:** Dashboard, Wireless Inventory, PCAP Analyzer, AI Analyst, Rogue AP Detection, Protocol Analysis, Authorized Workspace, and Reporting.
* **Success Criteria:** The platform must successfully ingest raw wireless evidence (PCAPs/CSVs), parse the data, use AI to flag anomalies, and require human validation before generating a final report.
* **Out of Scope (for now):** Active offensive attacks, real-world deployment outside of authorized lab environments, automated remediation.
* **Architecture:** Raw Evidence -> Python Processing Layer -> AI Analysis Layer -> Streamlit Web Dashboard.

