def get_content():
    return {
        "id": "T1491.002",  # Tactic Technique ID
        "url_id": "1491/002",  # URL segment for technique reference
        "title": "Defacement: External Defacement",  # Name of the attack technique
        "description": "Adversaries may deface externally facing systems, such as public websites, to deliver messaging, intimidate, or mislead users, potentially undermining trust in the organization’s integrity and setting the stage for further attacks.",  # Simple description
        "tags": [
            "External Defacement",
            "Website Defacement",
            "Impact",
            "Hacktivist",
            "Political Message",
            "Propaganda",
            "Kevin Mandia Statement",
            "Anonymous Hackers",
            "Trend Micro",
            "Cadet Blizzard"
        ],
        "tactic": "Impact",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "IaaS, Linux, Windows, macOS",  # Targeted operating systems/environments
        "tips": [
            "Monitor external websites for unplanned content changes",
            "Use deep packet inspection to detect common exploit traffic (e.g., SQL injection)",
            "Review application logs for abnormal activity indicating attempted or successful exploitation"
        ],
        "data_sources": "Application Log: Application Log Content, File: File Creation, File: File Modification, Network Traffic: Network Traffic Content",
        "log_sources": [
            {
                "type": "Application Log",
                "source": "Web/Application Server Logs",
                "destination": "SIEM"
            },
            {
                "type": "File",
                "source": "File System Auditing",
                "destination": "SIEM"
            },
            {
                "type": "Network Traffic",
                "source": "Packet Capture/Flow Data",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Website or Application Content",
                "location": "Public-facing servers or hosting platforms",
                "identify": "HTML pages, scripts, or images that may be altered by adversaries"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Defaced Content",
                "location": "Externally accessible web resources",
                "identify": "Altered pages displaying adversary messaging or propaganda"
            }
        ],
        "detection_methods": [
            "Track modifications to public-facing files or directories",
            "Analyze server logs for suspicious HTTP requests or exploit patterns",
            "Monitor WAF alerts for unusual input or potential code injection attempts"
        ],
        "apt": [
            "Cadet Blizzard"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify newly modified or replaced files in web root directories",
            "Correlate unusual HTTP requests with potential defacement attempts",
            "Review DNS or domain changes that might redirect traffic to adversary-controlled pages"
        ],
        "expected_outcomes": [
            "Detection of unauthorized external content modifications",
            "Identification of possible exploit vectors leading to defacement",
            "Mitigation of adversary propaganda or intimidation campaigns"
        ],
        "false_positive": "Legitimate website updates or maintenance can produce file changes. Validate authorized deployment schedules and version control.",
        "clearing_steps": [
            "Restore defaced content from secure backups",
            "Apply patches or secure configurations to address exploited vulnerabilities",
            "Implement stricter access controls and review credentials for public-facing systems"
        ],
        "mitre_mapping": [
            {
                "tactic": "Impact",
                "technique": "Defacement: External Defacement (T1491.002)",
                "example": "Modifying external web content to display adversary messaging or propaganda"
            }
        ],
        "watchlist": [
            "Unauthorized file changes in public web directories",
            "Abnormal spikes in suspicious WAF or IDS alerts",
            "Sudden changes to site layout, branding, or textual content"
        ],
        "enhancements": [
            "Use a Web Application Firewall (WAF) to block common exploitation attempts",
            "Implement file integrity monitoring for web root directories",
            "Conduct regular vulnerability scans and penetration tests on public-facing sites"
        ],
        "summary": "External defacement involves altering public-facing websites or services to deliver adversary messaging or discredit an organization, potentially serving as a catalyst for further attacks.",
        "remediation": "Restore content from backups, patch and harden public-facing services, and monitor logs for exploit attempts leading to defacement.",
        "improvements": "Restrict file access to authorized users, maintain secure coding practices, and employ continuous monitoring of web resources to detect unplanned modifications."
    }
