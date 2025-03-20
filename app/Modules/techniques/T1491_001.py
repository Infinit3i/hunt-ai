def get_content():
    return {
        "id": "T1491.001",  # Tactic Technique ID
        "url_id": "1491/001",  # URL segment for technique reference
        "title": "Defacement: Internal Defacement",  # Name of the attack technique
        "description": "An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users, thus discrediting the integrity of the systems. This may include modifying internal websites or replacing user desktop wallpapers. Offensive images may be used to cause discomfort or pressure compliance with messages. Internal defacements typically occur after other intrusion goals have been met, as they reveal the adversary’s presence.",  # Simple description
        "tags": [
            "Internal Defacement",
            "Defacement",
            "Black Basta",
            "BlackCat",
            "Gamaredon",
            "Novetta Blockbuster",
            "Impact",
            "Integrity",
            "Cybereason INC Ransomware",
            "Ready.gov IT DRP"
        ],  # Up to 10 tags
        "tactic": "Impact",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor internal websites for unplanned content changes",
            "Check for unexpected desktop wallpaper changes or other system modifications",
            "Use deep packet inspection and WAFs to detect SQL injection or exploit attempts"
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
                "type": "Internal Web/Content Files",
                "location": "Intranet portals or user desktop systems",
                "identify": "Altered pages, images, or wallpapers used to intimidate or mislead"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Defaced Content",
                "location": "Internal systems (web portals, desktops)",
                "identify": "Unauthorized changes to content or user interfaces"
            }
        ],
        "detection_methods": [
            "Monitor for sudden or unexpected changes to intranet pages or user desktop wallpapers",
            "Review application logs for abnormal access or exploitation attempts",
            "Use WAF or IDS solutions to detect suspicious or malicious inputs (e.g., SQL injection)"
        ],
        "apt": [
            "Gamaredon",
            "Black Basta",
            "BlackCat"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify recently altered files within intranet portals or shared directories",
            "Correlate suspicious network traffic or exploit patterns with changed content",
            "Check user systems for unauthorized modifications to wallpapers or system settings"
        ],
        "expected_outcomes": [
            "Detection of unauthorized internal defacement attempts",
            "Identification of compromised accounts or processes making disruptive content changes",
            "Prevention of intimidation or messaging campaigns aimed at internal users"
        ],
        "false_positive": "Legitimate updates to internal portals or user desktop themes may appear suspicious. Validate authorized changes and maintenance windows.",
        "clearing_steps": [
            "Restore content from known good backups",
            "Remove or revert unauthorized wallpaper or file changes",
            "Harden and patch systems to prevent further exploit attempts"
        ],
        "mitre_mapping": [
            {
                "tactic": "Impact",
                "technique": "Defacement: Internal Defacement (T1491.001)",
                "example": "Replacing desktop wallpapers or intranet pages to intimidate internal users"
            }
        ],
        "watchlist": [
            "Unplanned modifications to intranet sites or internal file shares",
            "Desktop wallpaper changes pushed out to multiple systems",
            "Abnormal usage of privileged accounts performing content edits"
        ],
        "enhancements": [
            "Implement file integrity monitoring for internal web directories and system settings",
            "Restrict admin privileges and audit privileged user activities",
            "Deploy intrusion detection/prevention systems to detect exploit patterns targeting internal services"
        ],
        "summary": "Internal defacement involves altering content within an organization’s network (e.g., intranet sites, user desktops) to intimidate or mislead users, typically after other malicious objectives have been achieved.",
        "remediation": "Restore defaced content from backups, patch and secure internal services, and monitor for further unauthorized changes. Enforce least privilege to reduce the impact of successful intrusions.",
        "improvements": "Regularly audit internal websites and system configurations, maintain strict change management processes, and use robust monitoring tools to detect unusual file or content modifications."
    }
