def get_content():
    return {
        "id": "T1041",
        "url_id": "T1041",
        "title": "Exfiltration Over C2 Channel",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.",
        "tags": ["Exfiltration", "C2 Channel", "Data Exfiltration"],
        "tactic": "Exfiltration",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": ["Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used."],
        "data_sources": "Command: Command Execution, File: File Access, Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "File", "source": "File Access", "destination": ""},
            {"type": "Network Traffic", "source": "Network Connection Creation", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Content", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Traffic", "location": "Network Traffic Flow", "identify": "Suspicious data flow over command and control channel"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Network Traffic Content", "identify": "Exfiltrated data over C2 channel"}
        ],
        "detection_methods": ["Monitor for unusual or unrecognized traffic patterns over C2 channels, indicating data exfiltration", "Analyze packet contents for discrepancies in protocol behavior"],
        "apt": ["Pikabot", "Warzone", "Konni", "Lebanese Cedar", "Cyclops Blink", "TA505", "ForSSHe", "Valak", "Higaisa", "Ursnif", "Metador", "Latrodectus", "MuddyWater", "LuminousMoth", "Telebots"],
        "spl_query": [],
        "hunt_steps": ["Search for data exfiltration patterns over established C2 channels", "Inspect network traffic for unusual outgoing data amounts"],
        "expected_outcomes": ["Identification of C2 communication being used to exfiltrate data"],
        "false_positive": "Legitimate communication over C2 channels may occasionally resemble data exfiltration.",
        "clearing_steps": ["Identify and interrupt any malicious C2 channels, ensuring no data is being exfiltrated. Revert to known clean configurations."],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1041", "example": "Data being exfiltrated over an encrypted C2 channel"}
        ],
        "watchlist": ["Monitor for consistent network connections to external C2 servers, indicating potential exfiltration activities"],
        "enhancements": ["Deploy deep packet inspection to detect encoded exfiltrated data over C2 channels"],
        "summary": "Exfiltration over C2 channel leverages existing communication pathways between attacker and victim to transfer stolen data.",
        "remediation": "Implement stronger network traffic analysis tools and behaviors to detect exfiltration patterns over C2 channels.",
        "improvements": "Improve detection by focusing on the characteristics of protocol behavior in relation to known C2 channels.",
        "mitre_version": "16.1"
    }
