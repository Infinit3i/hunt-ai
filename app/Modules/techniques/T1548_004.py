def get_content():
    return {
        "id": "T1548.004",
        "url_id": "1548/004",
        "title": "Abuse Elevation Control Mechanism: Elevated Execution with Prompt",
        "description": "Adversaries may leverage the AuthorizationExecuteWithPrivileges API to escalate privileges by prompting the user for credentials. This API allows developers to perform operations with root privileges, such as application installation or updates, but does not validate the integrity of the requesting program.",
        "tags": ["Privilege Escalation", "Defense Evasion", "macOS Exploitation"],
        "tactic": "Defense Evasion, Privilege Escalation",
        "protocol": "macOS API",
        "os": "macOS",
        "tips": [
            "Monitor for executions of /usr/libexec/security_authtrampoline.",
            "Detect unauthorized usage of AuthorizationExecuteWithPrivileges API.",
            "Check system logs for unexpected privilege escalation attempts.",
        ],
        "data_sources": "Process: OS API Execution, Process: Process Creation",
        "log_sources": [
            {"type": "Process Execution", "source": "macOS Unified Logs", "destination": "SIEM"},
            {"type": "OS API Execution", "source": "Security Logs", "destination": "Endpoint Monitoring"},
        ],
        "source_artifacts": [
            {"type": "API Call", "location": "AuthorizationExecuteWithPrivileges", "identify": "Abused for privilege escalation"},
        ],
        "destination_artifacts": [
            {"type": "System Process", "location": "/usr/libexec/security_authtrampoline", "identify": "Executed with elevated privileges"},
        ],
        "detection_methods": [
            "Monitor API calls to AuthorizationExecuteWithPrivileges.",
            "Detect executions of security_authtrampoline with unusual parameters.",
            "Analyze process creation logs for suspicious privilege escalation events.",
        ],
        "apt": ["Shlayer", "Coldroot RAT"],
        "spl_query": [
            "index=mac_security_logs sourcetype=macos_unified_logs \n| search process_name='/usr/libexec/security_authtrampoline' \n| stats count by src_ip, user, process_name",
        ],
        "hunt_steps": [
            "Analyze process execution logs for unexpected security_authtrampoline executions.",
            "Monitor system logs for AuthorizationExecuteWithPrivileges API calls.",
            "Investigate anomalies in privilege escalation attempts.",
        ],
        "expected_outcomes": [
            "Privilege Escalation Detected: Investigate potential macOS exploitation attempts.",
            "No Malicious Activity Found: Improve monitoring rules for privilege escalation detection.",
        ],
        "false_positive": "Some legitimate macOS applications may use AuthorizationExecuteWithPrivileges for software installation.",
        "clearing_steps": [
            "Identify and remove malicious applications abusing the AuthorizationExecuteWithPrivileges API.",
            "Restrict execution of security_authtrampoline to authorized users only.",
            "Enhance endpoint monitoring for privilege escalation attempts.",
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1548.004", "example": "Adversaries abusing AuthorizationExecuteWithPrivileges for root access."},
        ],
        "watchlist": [
            "Monitor execution of security_authtrampoline from unknown processes.",
            "Detect suspicious API calls attempting to gain root privileges.",
            "Track modifications to system files that indicate privilege escalation attempts.",
        ],
        "enhancements": [
            "Implement stricter controls on applications using AuthorizationExecuteWithPrivileges.",
            "Enhance behavioral analysis for macOS privilege escalation attempts.",
        ],
        "summary": "Adversaries may exploit the AuthorizationExecuteWithPrivileges API to execute code with root privileges by prompting the user for credentials.",
        "remediation": "Implement system hardening measures, restrict execution of privilege escalation APIs, and monitor system logs for unauthorized escalations.",
        "improvements": "Strengthen endpoint security to detect and block unauthorized privilege escalations on macOS.",
    }
