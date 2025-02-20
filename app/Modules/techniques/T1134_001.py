def get_content():
    """
    Returns structured content for the Token Impersonation/Theft technique.
    """
    return {
        "id": "T1134.001",
        "url_id": "T1134/001",
        "title": "Token Impersonation/Theft",
        "tactic": "Privilege Escalation, Defense Evasion",
        "data_sources": "Windows Event Logs, Process Monitoring, Access Tokens",
        "protocol": "N/A",
        "os": "Windows",
        "objective": "Adversaries may steal or impersonate tokens to escalate privileges or evade defenses.",
        "scope": "Monitor token-related events and suspicious process interactions.",
        "threat_model": "Attackers can hijack authentication tokens to execute processes with elevated privileges.",
        "hypothesis": [
            "Are authentication tokens being duplicated or misused?",
            "Are system services executing commands with stolen tokens?",
            "Is there unauthorized lateral movement using token impersonation?"
        ],
        "tips": [
            "Monitor Event ID 4672 (Special privileges assigned to new logon).",
            "Detect processes spawning with inherited or duplicated tokens.",
            "Analyze unusual parent-child process relationships indicative of token theft."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 10", "destination": "Token Impersonation"},
            {"type": "Access Tokens", "source": "Process Access Logs"}
        ],
        "source_artifacts": [
            {"type": "Process Execution", "location": "C:\\Windows\\System32", "identify": "winlogon.exe, lsass.exe"}
        ],
        "destination_artifacts": [
            {"type": "Access Tokens", "location": "Memory", "identify": "Duplicated or stolen tokens"}
        ],
        "detection_methods": [
            "Monitor for suspicious privilege escalation attempts.",
            "Detect unexpected process execution patterns with inherited tokens.",
            "Analyze access token manipulation techniques."
        ],
        "apt": ["G0007", "G0016"],
        "spl_query": [
            "index=windows EventCode=4672 | table Time, User, Privileges",
            "index=windows EventCode=4624 LogonType=2 OR LogonType=9 | table Time, User, Source"
        ],
        "hunt_steps": [
            "Investigate processes executing under stolen tokens.",
            "Analyze parent-child process chains for impersonation activity.",
            "Check for unusual administrative privilege assignments."
        ],
        "expected_outcomes": [
            "Unauthorized token theft detected and mitigated.",
            "No suspicious activity found, improving baseline detection."
        ],
        "false_positive": "Legitimate system processes may reuse tokens during normal operations.",
        "clearing_steps": [
            "Reset compromised accounts and revoke stolen tokens.",
            "Investigate compromised hosts for lateral movement attempts."
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1134.001 (Token Impersonation)", "example": "Attackers use duplicated tokens to execute processes as SYSTEM."}
        ],
        "watchlist": [
            "Monitor for LSASS process access attempts.",
            "Detect unusual privilege escalation through token impersonation."
        ],
        "enhancements": [
            "Enable logging for token manipulation events.",
            "Restrict token duplication privileges to trusted processes."
        ],
        "summary": "Token impersonation allows attackers to execute processes with stolen privileges.",
        "remediation": "Revoke compromised tokens and enforce privilege management policies.",
        "improvements": "Enhance monitoring and alerting on token-based privilege escalations."
    }
