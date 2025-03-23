def get_content():
    return {
        "id": "T1568.003",
        "url_id": "T1568/003",
        "title": "Dynamic Resolution: DNS Calculation",
        "description": "Adversaries may perform calculations on addresses returned in DNS results to determine which port and IP address to use for command and control, rather than relying on a predetermined port number or the actual returned IP address.",
        "tags": ["dns", "c2", "dynamic resolution", "port calculation"],
        "tactic": "Command and Control",
        "protocol": "DNS",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Detection requires identifying and reverse-engineering the custom algorithm used to calculate the port or IP.",
            "Analyze DNS response patterns and unusual C2 behaviors."
        ],
        "data_sources": "Network Traffic: Network Traffic Content",
        "log_sources": [
            {"type": "Network Traffic", "source": "Network Traffic", "destination": "Network Traffic"}
        ],
        "source_artifacts": [
            {"type": "DNS Query", "location": "System Resolver Cache", "identify": "DNS name used for C2 resolution"}
        ],
        "destination_artifacts": [
            {"type": "Calculated Port", "location": "Outbound Traffic", "identify": "Derived from DNS response"}
        ],
        "detection_methods": [
            "DNS traffic analysis",
            "Reverse-engineering of known malware families using this technique"
        ],
        "apt": [
            "Numbered Panda"
        ],
        "spl_query": [
            "index=network sourcetype=dns AND query IN ([list of suspected domains])\n| stats count by src_ip, query, answer"
        ],
        "hunt_steps": [
            "Identify uncommon DNS queries followed by connections to non-standard ports.",
            "Analyze malware samples for algorithms used in port/IP derivation."
        ],
        "expected_outcomes": [
            "Uncover obfuscated C2 communication paths",
            "Reveal dynamic behavior triggered via DNS resolution"
        ],
        "false_positive": "Custom DNS resolution logic in legitimate software could trigger similar behavior.",
        "clearing_steps": [
            "Flush DNS cache and remove malware persisting port/IP resolution logic"
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1071.004", "example": "C2 over DNS"},
            {"tactic": "Command and Control", "technique": "T1095", "example": "Non-Application Layer Protocol"}
        ],
        "watchlist": [
            "High entropy DNS responses",
            "Connections to dynamic ports after DNS lookups"
        ],
        "enhancements": [
            "Deploy DNS inspection tools capable of detecting algorithmic C2 derivation",
            "Use threat intel feeds for known dynamic resolution domains"
        ],
        "summary": "DNS Calculation allows adversaries to dynamically compute communication endpoints and ports, making C2 harder to detect and block using static indicators.",
        "remediation": "Deploy network segmentation and apply strict egress filtering. Monitor DNS traffic patterns and analyze new or anomalous domain usage.",
        "improvements": "Integrate deep packet inspection with behavioral modeling to catch dynamic resolution behavior across endpoints and the network."
    }
