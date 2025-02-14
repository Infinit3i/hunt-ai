def get_content():
    return {
        "id": "T1665",
        "url_id": "T1665",
        "title": "Hide Infrastructure",
        "tactic": "Command and Control",
        "data_sources": [
            "Domain Name (Domain Registration)",
            "Internet Scan (Response Content, Response Metadata)",
            "Network Traffic (Network Traffic Content)"
        ],
        "protocol": "Various",
        "os": "Linux, Network, Windows, macOS",
        "objective": "Detect and mitigate adversaries' attempts to hide C2 infrastructure to evade detection and prolong operational effectiveness.",
        "scope": "Monitor network and domain name registration activities to identify obfuscation techniques used to conceal adversary-controlled infrastructure.",
        "threat_model": "Adversaries may manipulate network traffic, filter connections, or use anonymous infrastructure to evade detection and delay discovery.",
        "hypothesis": [
            "Are adversaries using proxy or VPN services to hide C2 origins?",
            "Are there domain registrations mimicking legitimate services?",
            "Is network filtering used to evade detection by security tools?"
        ],
        "log_sources": [
            {"type": "Domain Name", "source": "WHOIS, Passive DNS, Open Source Intelligence (OSINT)"},
            {"type": "Internet Scan", "source": "Shodan, Censys, GreyNoise"},
            {"type": "Network Traffic", "source": "Zeek, Suricata, Firewall Logs"}
        ],
        "detection_methods": [
            "Track newly registered domains for suspicious patterns.",
            "Detect C2 infrastructure using open-source scanning tools.",
            "Monitor traffic patterns for obfuscation techniques like fast-flux DNS, proxies, and VPNs."
        ],
        "spl_query": "index=network sourcetype=firewall_logs | search dest_ip=*vpn* OR dest_ip=*proxy* OR dest_ip=*tor* | stats count by dest_ip",
        "spl_rule": "https://research.splunk.com/detections/tactics/command-and-control/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1665",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1665",
        "hunt_steps": [
            "Run WHOIS and Passive DNS lookups for newly registered domains.",
            "Check for sudden changes in domain resolution behavior.",
            "Identify IPs associated with VPNs, proxies, or TOR networks.",
            "Monitor for known security tool evasion techniques in network traffic.",
            "Correlate with Threat Intelligence Feeds for known C2 indicators."
        ],
        "expected_outcomes": [
            "Identified C2 infrastructure using anonymization techniques.",
            "Blocked adversary-controlled IPs and domains.",
            "Improved detection rules for proxy-based evasion tactics."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1665 (Hide Infrastructure)", "example": "Use of compromised endpoints or bulletproof hosting for C2."}
        ],
        "watchlist": [
            "Flag new domain registrations linked to malicious activity.",
            "Monitor for VPN, proxy, and TOR-based traffic anomalies.",
            "Detect redirection patterns used to hide true C2 locations."
        ],
        "enhancements": [
            "Improve passive DNS monitoring and WHOIS tracking.",
            "Leverage commercial or open-source scanning tools to detect hidden C2.",
            "Enhance network anomaly detection for obfuscated traffic."
        ],
        "summary": "Document identified infrastructure hiding techniques and related threat indicators.",
        "remediation": "Block or disrupt known C2 infrastructure, monitor for future adversary adaptations.",
        "improvements": "Develop better heuristics for detecting hidden infrastructure in real-time."
    }
