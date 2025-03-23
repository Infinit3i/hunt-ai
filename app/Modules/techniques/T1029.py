def get_content():
    return {
        "id": "T1029",
        "url_id": "T1029",
        "title": "Scheduled Transfer",
        "description": "Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability. When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as Exfiltration Over C2 Channel or Exfiltration Over Alternative Protocol.",
        "tags": ["Exfiltration", "Data Exfiltration", "Scheduled Transfer"],
        "tactic": "Exfiltration",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": ["Monitor process file access patterns and network behavior. Unrecognized processes or scripts that appear to be traversing file systems and sending network traffic may be suspicious. Network connections to the same destination that occur at the same time of day for multiple days are suspicious."],
        "data_sources": "Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Network Traffic", "source": "Network Connection Creation", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Traffic", "location": "Network Connection Creation", "identify": "Suspicious traffic patterns related to scheduled transfer"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Network Traffic Flow", "identify": "Data transfer or flow from internal network to external destination"}
        ],
        "detection_methods": ["Monitor for network connections to the same destination at consistent intervals", "Inspect traffic patterns for unusual times or volume"],
        "apt": ["Adwind", "Siamesekitten", "Mofang", "Machete", "ShadowPad", "Kazuar", "Higaisa", "TinyTurla", "ComRAT", "ToddyCat", "Sednit", "MuddyWater", "Gelsemium", "Linfo", "LightNeuron"],
        "spl_query": [],
        "hunt_steps": ["Search for signs of scheduled data exfiltration in network logs, paying attention to recurring network connections"],
        "expected_outcomes": ["Identification of suspicious network traffic that follows a scheduled pattern"],
        "false_positive": "Legitimate scheduled tasks may trigger false positives in network traffic monitoring.",
        "clearing_steps": ["Identify and stop any scheduled tasks related to exfiltration. Restore normal network behavior and ensure no malicious processes are running."],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1041", "example": "Exfiltration over C2 channel used in conjunction with scheduled transfer"},
            {"tactic": "Exfiltration", "technique": "T1048", "example": "Exfiltration over alternative protocols used to complement scheduled transfer"}
        ],
        "watchlist": ["Monitor for unusual or suspicious patterns in network traffic that match typical exfiltration times and intervals"],
        "enhancements": ["Implement behavioral detection rules for recurring network patterns that match scheduled data exfiltration trends"],
        "summary": "Scheduled transfer is used to time the exfiltration of data during specific windows to blend with normal traffic and avoid detection.",
        "remediation": "Ensure regular checks of scheduled tasks and network traffic for any signs of exfiltration. Use advanced network monitoring tools to detect anomalous data transfers.",
        "improvements": "Enhance detection of scheduled exfiltration by analyzing the timing and frequency of network connections to the same external destination.",
        "mitre_version": "16.1"
    }
