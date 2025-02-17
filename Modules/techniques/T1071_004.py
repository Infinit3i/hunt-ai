def get_content():
    return {
        "id": "T1071.004",
        "url_id": "T1071/004",
        "title": "DNS Tunneling",
        "tactic": "Command and Control",
        "data_sources": "DNS Logs, PCAP Logs, Threat Intelligence Feeds",
        "protocol": "DNS",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate DNS tunneling used for data exfiltration or covert C2 channels.",
        "scope": "Monitor DNS query logs for anomalous patterns indicative of tunneling.",
        "threat_model": "Adversaries may use DNS tunneling to bypass restrictions, exfiltrate data, or maintain persistence.",
        "hypothesis": [
            "Are there DNS queries with unusually high entropy in subdomains?",
            "Is a single system generating excessive DNS queries in a short period?",
            "Are large amounts of data being encoded into DNS responses?"
        ],
        "log_sources": [
            {"type": "DNS Logs", "source": "Microsoft DNS, BIND, Cisco Umbrella, OpenDNS, Zeek (Bro)"},
            {"type": "PCAP Logs", "source": "Suricata, Zeek (Bro), Wireshark"},
            {"type": "Threat Intelligence Feeds", "source": "VirusTotal, AbuseIPDB, AlienVault OTX"}
        ],
        "detection_methods": [
            "Monitor DNS queries for long or randomized subdomains.",
            "Detect excessive DNS requests from a single source.",
            "Identify DNS responses with unusually large payloads."
        ],
        "spl_query": [
            "index=dns sourcetype=\"dns_logs\" | eval entropy=len(query)  | stats avg(entropy) as avg_entropy by src_ip, query  | where avg_entropy > 50  | sort - avg_entropy",
            "index=dns sourcetype=\"dns_logs\"  | stats count by src_ip, query  | where count > 500  | sort - count",
            "index=dns sourcetype=\"dns_logs\"  | where len(response) > 200  | stats count by src_ip, query, response"
        ],
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1071.004",
        "hunt_steps": [
            "Run Queries in SIEM to detect high-entropy DNS queries and large DNS response payloads.",
            "Correlate findings with Threat Intelligence Feeds to validate suspicious domains.",
            "Analyze traffic behavior to identify consistent outbound DNS requests to a single domain.",
            "Investigate process execution on endpoints for scripts making outbound DNS requests.",
            "Validate & Escalate: If suspicious activity is detected, escalate to Incident Response."
        ],
        "expected_outcomes": [
            "DNS Tunneling Detected: Block suspicious domains and investigate affected hosts.",
            "No Malicious Activity Found: Improve network monitoring rules for DNS anomalies."
        ],
        "mitre_mapping": [
            {"tactic": "Command & Control", "technique": "T1071.004 (DNS Tunneling)", "example": "Data exfiltration via encoded DNS queries"},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data transmission via DNS tunnels"},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Deleting logs to erase evidence of DNS C2 traffic"}
        ],
        "watchlist": [
            "Flag DNS queries with high-entropy subdomains.",
            "Detect excessive DNS requests from a single host.",
            "Monitor large DNS response payloads."
        ],
        "enhancements": [
            "Deploy DNS monitoring and anomaly detection tools.",
            "Block known malicious domains and unauthorized DNS-over-HTTPS (DoH).",
            "Enable logging and monitoring of all DNS activity."
        ],
        "summary": "Document suspicious DNS tunneling activity and affected systems.",
        "remediation": "Block DNS tunnels, restrict unauthorized DNS-over-HTTPS (DoH), and investigate compromised hosts.",
        "improvements": "Enhance SIEM detection rules, implement AI-based anomaly detection for DNS patterns."
    }
