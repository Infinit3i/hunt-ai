def get_content():
    return {
        "id": "T1133",
        "url_id": "T1133",
        "title": "External Remote Services",
        "tactic": "Persistence",
        "data_sources": "Authentication logs, Netflow/Enclave netflow, Packet capture, Process monitoring, Process use of network, Web logs",
        "protocol": "RDP, SSH, VPN, Citrix, VNC, TeamViewer, Remote Desktop",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate unauthorized access through external remote services, which may indicate persistence or lateral movement.",
        "scope": "Monitor remote access activity for anomalies, such as unauthorized external logins or use of remote access tools.",
        "threat_model": "Adversaries may leverage external remote services for persistence, lateral movement, and maintaining long-term access to compromised networks.",
        "hypothesis": [
            "Are there unauthorized remote logins from external networks?",
            "Is there anomalous activity involving remote access tools like RDP, SSH, or VPN?",
            "Are compromised accounts being used for remote access?"
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Windows Event Logs (Event ID 4624, 4648, 4768, 4776), Linux auth.log"},
            {"type": "Network Logs", "source": "Firewall logs, VPN logs, NetFlow, IDS/IPS alerts"},
            {"type": "Remote Access Logs", "source": "Citrix, TeamViewer, Remote Desktop logs"}
        ],
        "detection_methods": [
            "Monitor external logins for unusual IPs or login times.",
            "Detect high-frequency remote logins from a single account.",
            "Identify accounts accessing multiple remote services simultaneously.",
            "Correlate remote access with threat intelligence feeds to detect known malicious IPs."
        ],
        "spl_query": "index=authentication sourcetype=windows:security EventCode=4624 LogonType=10 OR LogonType=7 | stats count by user, src_ip, dest_ip | sort - count",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1133",
        "hunt_steps": [
            "Analyze remote access logs for anomalous patterns.",
            "Check if remote logins align with typical working hours.",
            "Investigate if the same credentials are used across multiple remote services.",
            "Cross-reference login IPs with known malicious indicators.",
            "Identify unauthorized access attempts and escalate if necessary."
        ],
        "expected_outcomes": [
            "Unauthorized External Access Detected: Disable compromised accounts, block malicious IPs, and escalate to Incident Response.",
            "No Malicious Activity Found: Improve remote access monitoring and enforce stricter authentication controls."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1133 (External Remote Services)", "example": "Adversaries using VPN or RDP for persistent remote access."},
            {"tactic": "Lateral Movement", "technique": "T1021 (Remote Services)", "example": "Using SSH or RDP to pivot across the network."},
            {"tactic": "Credential Access", "technique": "T1110 (Brute Force)", "example": "Adversaries attempting password spraying or credential stuffing."}
        ],
        "watchlist": [
            "Monitor for unusual external IPs accessing remote services.",
            "Detect high-volume remote logins from a single account.",
            "Track remote access tool usage in enterprise environments."
        ],
        "enhancements": [
            "Enforce multi-factor authentication (MFA) on all remote services.",
            "Restrict access to external remote services to known and approved IP addresses.",
            "Enable logging and monitoring of all external remote access attempts."
        ],
        "summary": "Monitor and investigate unauthorized external remote service access attempts.",
        "remediation": "Block unauthorized remote access attempts, revoke compromised credentials, and strengthen authentication controls.",
        "improvements": "Enhance network segmentation, enforce least privilege access, and improve threat intelligence correlation for remote access."
    }
