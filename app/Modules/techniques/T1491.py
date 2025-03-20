def get_content():
    return {
        "id": "T1491",  # Tactic Technique ID
        "url_id": "1491",  # URL segment for technique reference
        "title": "Defacement",  # Name of the attack technique
        "description": "Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content. They may use defacements to deliver messaging, intimidate users, or claim credit for an intrusion, sometimes employing disturbing or offensive images to pressure compliance.",  # Simple description
        "tags": [
            "Defacement",
            "Website Content Changes",
            "Integrity",
            "Impact",
            "SQL Injection",
            "IaaS",
            "Ready.gov IT DRP",
            "Linux",
            "Windows",
            "macOS"
        ],  # Up to 10 tags
        "tactic": "Impact",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "IaaS, Linux, Windows, macOS",  # Targeted operating systems/environments
        "tips": [
            "Monitor internal and external websites for unplanned content changes",
            "Use deep packet inspection to detect common exploit traffic (e.g., SQL injection)",
            "Monitor application logs for abnormal behavior indicating potential exploitation"
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
                "location": "Web server or CMS file system",
                "identify": "Modified or replaced pages, images, or scripts"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Defaced Content",
                "location": "Publicly visible or internal portal",
                "identify": "Altered text, images, or offensive content"
            }
        ],
        "detection_methods": [
            "Monitor changes to web pages, images, or scripts",
            "Alert on unexpected modifications to files within the web root directory",
            "Analyze web server logs for suspicious requests indicating exploit attempts"
        ],
        "apt": [],  # No specific APT group listed
        "spl_query": [],
        "hunt_steps": [
            "Identify recent file changes in the web root or CMS directories",
            "Correlate unusual HTTP requests with known exploit patterns (SQL injection, etc.)",
            "Review server/application logs for unauthorized user or system account activity"
        ],
        "expected_outcomes": [
            "Detection of website or application content modifications",
            "Identification of potential exploit vectors leading to defacement",
            "Prevention of adversary messaging, intimidation, or disinformation tactics"
        ],
        "false_positive": "Legitimate website updates, content management changes, or web developer activity may mimic suspicious modifications. Validate context and scheduled maintenance.",
        "clearing_steps": [
            "Revert or restore defaced content from secure backups",
            "Apply patches or updates to web applications/CMS to close exploit vectors",
            "Strengthen file permissions and secure credentials used for web content management"
        ],
        "mitre_mapping": [
            {
                "tactic": "Impact",
                "technique": "Defacement (T1491)",
                "example": "Altering website content to display adversary messages or images"
            }
        ],
        "watchlist": [
            "New or unauthorized files in the web root or CMS directories",
            "Abnormal spike in SQL injection or suspicious POST requests",
            "Unexpected changes to HTML, CSS, JS, or image files"
        ],
        "enhancements": [
            "Implement Web Application Firewalls (WAF) to block common exploits",
            "Use file integrity monitoring tools to detect unauthorized file changes",
            "Conduct regular vulnerability scans and penetration tests on web applications"
        ],
        "summary": "Defacement involves modifying web or application content to affect its integrity, often for messaging, intimidation, or credit-claiming purposes. Monitoring for suspicious file changes and exploit attempts can help detect and prevent defacements.",
        "remediation": "Restrict file access to authorized users, patch vulnerabilities, and restore content from secure backups after a defacement event.",
        "improvements": "Regularly audit web server permissions, employ WAF/IDS solutions, and maintain secure coding practices to reduce the likelihood of defacement."
    }
