def get_content():
    """
    Returns structured content for the Local Group Policy persistence method.
    """
    return {
        "id": "T1484.001",
        "url_id": "T1484/001",
        "title": "Local Group Policy Manipulation",
        "tactic": "Persistence",
        "data_sources": "Windows Registry, Windows Event Logs, File Monitoring",
        "protocol": "N/A",
        "os": "Windows",
        "objective": "Detect and prevent adversaries from modifying Local Group Policy settings to establish persistence.",
        "scope": "Monitor registry changes and modifications to Group Policy files for unauthorized alterations.",
        "threat_model": "Adversaries may manipulate Local Group Policy settings to enforce malicious configurations, disable security features, or establish persistence.",
        "hypothesis": [
            "Are unauthorized changes being made to Group Policy settings?",
            "Are security policies being altered to weaken defenses?",
            "Are Group Policy files being modified outside of administrative control?"
        ],
        "tips": [
            "Regularly audit Group Policy settings for unexpected modifications.",
            "Monitor registry keys related to security policies for suspicious changes.",
            "Enable logging for Group Policy modifications to track potential persistence attempts."
        ],
        "log_sources": [
            {"type": "Windows Event Log", "source": "Event ID 4719", "destination": "System Audit Policy Changed"},
            {"type": "File Monitoring", "source": "C:\\Windows\\System32\\GroupPolicy\\Machine", "destination": "Group Policy Configuration"},
            {"type": "Windows Registry", "source": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\<PolicyKey>", "destination": "Local Group Policy Settings"}
        ],
        "source_artifacts": [
            {"type": "Registry Key", "location": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\<PolicyKey>", "identify": "Tracks policy modifications."}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "C:\\Windows\\System32\\GroupPolicy\\Machine", "identify": "Stores machine-specific Group Policy configurations."}
        ],
        "detection_methods": [
            "Monitor Event ID 4719 in the Security event log to detect policy changes.",
            "Track modifications to Group Policy files in the System32 directory.",
            "Identify unauthorized changes to Local Group Policy registry keys."
        ],
        "apt": ["G0016", "G0032"],
        "spl_query": [
            "index=windows EventCode=4719"
        ],
        "hunt_steps": [
            "Check Windows Event Logs for Group Policy modifications.",
            "Compare registry snapshots to detect unauthorized policy changes.",
            "Investigate if security settings have been altered to weaken defenses."
        ],
        "expected_outcomes": [
            "Unauthorized Group Policy modifications detected and remediated.",
            "No malicious changes found, confirming policy integrity."
        ],
        "false_positive": "Legitimate administrative Group Policy changes may trigger alerts.",
        "clearing_steps": [
            "Restore Group Policy settings to the default secure configuration.",
            "Reapply security baselines using Group Policy Editor.",
            "Audit and revert any unauthorized changes in the registry."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1484.001 (Local Group Policy Manipulation)", "example": "Attackers disable security settings via Local Group Policy."}
        ],
        "watchlist": [
            "Monitor Event ID 4719 for unexpected policy changes.",
            "Track modifications to security-related Group Policy keys.",
            "Investigate changes to Group Policy files in the System32 directory."
        ],
        "enhancements": [
            "Enable logging for Group Policy modifications.",
            "Use security baselines to enforce policy integrity.",
            "Implement alerting for critical Group Policy changes."
        ],
        "summary": "Detect and prevent adversaries from modifying Local Group Policy settings to establish persistence.",
        "remediation": "Restore Group Policy settings, reapply security baselines, and audit unauthorized changes.",
        "improvements": "Enhance monitoring of Group Policy modifications and enforce security policies with stricter controls."
    }
