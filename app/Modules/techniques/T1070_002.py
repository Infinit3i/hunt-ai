def get_content():
    """
    Returns structured content for Log Deletion / Tampering (T1070.002).
    """
    return {
        "id": "T1070.002",
        "url_id": "T1070/002",
        "title": "Log Deletion / Tampering",
        "tactic": "Defense Evasion",
        "data_sources": "Windows Event Logs, Security Logs, System Logs, Audit Logs",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries may delete or alter log entries to evade detection.",
        "scope": "Monitor log integrity and detect tampering activities.",
        "threat_model": "Attackers may remove evidence of their actions by clearing or modifying logs.",
        "hypothesis": [
            "Are security logs being deleted or altered?",
            "Are there unexpected gaps in logging activity?",
            "Are adversaries disabling logging mechanisms?"
        ],
        "tips": [
            "Enable auditing for log deletion and modification.",
            "Monitor Event ID 1102 (Windows Security Log Cleared).",
            "Use centralized logging solutions to maintain copies of logs."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "Linux System Logs", "source": "/var/log/auth.log", "destination": "/var/log/syslog"},
            {"type": "macOS Audit Logs", "source": "/var/log/asl.log", "destination": "/var/log/system.log"}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "C:\\Windows\\System32\\winevt\\Logs", "identify": "Cleared Event Logs"},
            {"type": "Linux Command History", "location": "~/.bash_history", "identify": "Deleted History Entries"}
        ],
        "destination_artifacts": [
            {"type": "Log Files", "location": "/var/log", "identify": "Altered or Missing Logs"}
        ],
        "detection_methods": [
            "Monitor for Event ID 1102 (Windows Log Cleared).",
            "Detect gaps or anomalies in security logs.",
            "Use file integrity monitoring to detect log tampering."
        ],
        "apt": ["G0080", "G0092"],
        "spl_query": [
            "index=windows EventCode=1102 | table _time, host, user, Message",
            "index=linux sourcetype=secure | grep 'log cleared'"
        ],
        "hunt_steps": [
            "Search for log deletion events across all monitored endpoints.",
            "Investigate if any administrative actions preceded log clearing.",
            "Validate if log backups exist and compare with live logs."
        ],
        "expected_outcomes": [
            "Detection of unauthorized log clearing or modifications.",
            "No malicious log tampering detected, improving baseline detection."
        ],
        "false_positive": "System administrators may clear logs as part of routine maintenance.",
        "clearing_steps": [
            "Restore logs from backups.",
            "Investigate and reconfigure security controls to prevent further tampering."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1070.001 (Indicator Removal on Host)", "example": "Attackers may remove artifacts from compromised systems."}
        ],
        "watchlist": [
            "Monitor for frequent log clearing by non-administrators.",
            "Detect unexpected disabling of logging services."
        ],
        "enhancements": [
            "Implement log forwarding to a secure SIEM.",
            "Restrict log deletion permissions to authorized personnel only."
        ],
        "summary": "Adversaries may delete or alter security logs to evade detection and cover their tracks.",
        "remediation": "Reinforce log integrity mechanisms and restrict administrative actions that allow log deletion.",
        "improvements": "Enhance log monitoring capabilities and ensure logs are stored in secure, tamper-proof locations."
    }
