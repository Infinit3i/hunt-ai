def get_content():
    return {
        "id": "T1568.002",
        "url_id": "T1568/002",
        "title": "Dynamic Resolution: Domain Generation Algorithms",
        "description": "Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a destination domain for command and control traffic rather than relying on a list of static IP addresses or domains.",
        "tags": ["dga", "dns", "c2", "command and control", "dynamic resolution"],
        "tactic": "Command and Control",
        "protocol": "DNS",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Use machine learning or entropy-based analysis to detect high-randomness domains.",
            "Check for recently registered domains and low-frequency domain access.",
            "Monitor domains that resemble CDN or pseudo-random naming schemes."
        ],
        "data_sources": "Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Network Traffic", "source": "Network Traffic", "destination": "Network Traffic"}
        ],
        "source_artifacts": [
            {"type": "DNS Query", "location": "Malware DGA module", "identify": "Dynamically generated domains queried"}
        ],
        "destination_artifacts": [
            {"type": "Resolved IP", "location": "DNS resolver logs", "identify": "Resolved DGA domain pointing to C2"}
        ],
        "detection_methods": [
            "Domain entropy analysis",
            "N-gram analysis",
            "Markov chain modeling",
            "Deep learning for domain classification"
        ],
        "apt": [
            "APT41", "APT34", "TA551", "GOLD CABIN", "Lyceum", "Sednit", "ShadowPad", "POSHSPY", "Astaroth", "Bazar", "Ursnif", "Grandoreiro", "CostaRicto", "Naikon", "Conficker", "Qakbot", "Ebury", "Doki", "Dukes"
        ],
        "spl_query": [
            "index=dns sourcetype=dns_logs\n| eval entropy=calculate_entropy(domain)\n| where entropy > 3.5"
        ],
        "hunt_steps": [
            "Extract domain names from DNS logs and calculate entropy.",
            "Filter for high-entropy domains not previously seen in baseline traffic.",
            "Correlate with DNS resolution and follow-up traffic behavior."
        ],
        "expected_outcomes": [
            "Detection of malware leveraging DGA for resilient C2 communication.",
            "Enrichment of watchlists with suspicious dynamic domains."
        ],
        "false_positive": "Some CDN or dynamic service domains may mimic pseudo-randomness.",
        "clearing_steps": [
            "Block detected DGA domains and their resolved IPs on firewalls and endpoint DNS resolvers.",
            "Terminate associated malicious processes and remove malware."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1008", "example": "Fallback Channels"},
            {"tactic": "Command and Control", "technique": "T1090.003", "example": "Multiband Communication"}
        ],
        "watchlist": [
            "Unusual or random-looking domain names",
            "Recently registered domains with low traffic history"
        ],
        "enhancements": [
            "Apply ML-based DGA detection on DNS traffic",
            "Use threat intel feeds for known DGA patterns and domains"
        ],
        "summary": "DGAs enable adversaries to avoid static indicators and maintain resilient communication channels with C2 infrastructure through frequently changing domain names.",
        "remediation": "Use DNS sinkholing and reputation-based domain blocking. Enhance visibility into DNS queries and deploy behavioral anomaly detection.",
        "improvements": "Integrate DGA detection into network monitoring tools and use sandboxing to analyze unknown binaries for DGA use."
    }
