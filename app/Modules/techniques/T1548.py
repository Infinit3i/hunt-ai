def get_content():
    return {
        "id": "T1548",
        "url_id": "T1548",
        "title": "Abuse Elevation Control Mechanism",
        "description": "Adversaries may circumvent mechanisms designed to control elevation privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk.",
        "tags": ["Privilege Escalation", "Defense Evasion"],
        "tactic": "Defense Evasion, Privilege Escalation",
        "protocol": "System API Calls",
        "os": "Windows, macOS, Linux, IaaS, Identity Provider, Office Suite",
        "tips": [
            "Monitor for modifications to user-accessible Registry settings.",
            "Track executions of elevated processes that are not expected.",
            "Monitor audit logs for changes in user privileges."
        ],
        "data_sources": "Command Execution, File Metadata, File Modification, OS API Execution, Process Creation, Process Metadata, User Account Modification, Windows Registry Key Modification",
        "log_sources": [
            {"type": "Command Execution", "source": "Sysmon, Zeek, Suricata", "destination": "SIEM"},
            {"type": "File Metadata", "source": "Windows Security, Active Directory", "destination": "SIEM"},
            {"type": "Process Creation", "source": "Sysmon, Windows Event Logs", "destination": "SIEM"},
            {"type": "User Account Modification", "source": "Active Directory, Windows Registry", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Registry Modification", "location": "HKCU\\Software\\Classes", "identify": "Unauthorized privilege escalation attempts"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "System32", "identify": "Unexpected high-privileged process execution"}
        ],
        "detection_methods": [
            "Monitor system logs for processes launched with elevated privileges.",
            "Detect unauthorized modifications to sudoers file or Windows Registry keys.",
            "Monitor API calls for behavior indicative of privilege escalation."
        ],
        "apt": ["Raspberry Robin", "UACMe"],
        "spl_query": [
            "index=security_logs sourcetype=windows_security OR sourcetype=process_creation \n| search EventID=4688 OR process_name IN ('sudo', 'runas', 'consent.exe') \n| stats count by src_ip, dest_ip, user, process_name"
        ],
        "hunt_steps": [
            "Analyze security logs for unexpected elevated process executions.",
            "Monitor registry key modifications related to elevation mechanisms.",
            "Correlate privilege escalations with known threat actor techniques."
        ],
        "expected_outcomes": [
            "Unauthorized privilege escalation detected and mitigated.",
            "No suspicious activity found, refining detection methods."
        ],
        "false_positive": "Legitimate administrators executing authorized tasks with elevated privileges.",
        "clearing_steps": [
            "Revoke unauthorized administrative access.",
            "Reset and audit user account permissions.",
            "Restore affected registry keys to their default state."
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1055 (Process Injection)", "example": "Adversaries inject code into legitimate processes to escalate privileges."},
            {"tactic": "Defense Evasion", "technique": "T1574.001 (DLL Search Order Hijacking)", "example": "Adversaries manipulate DLL search paths to gain higher privileges."}
        ],
        "watchlist": [
            "Monitor for repeated privilege escalation attempts.",
            "Detect unauthorized changes to elevation control mechanisms.",
            "Track execution of known privilege escalation exploits."
        ],
        "enhancements": [
            "Implement Just Enough Administration (JEA) to limit privilege escalations.",
            "Deploy behavioral analytics to detect unusual administrative actions.",
            "Increase auditing on privileged command executions."
        ],
        "summary": "Abuse of privilege elevation mechanisms to execute commands with higher-level permissions.",
        "remediation": "Restrict access to elevation mechanisms, implement least privilege policies, and monitor logs for unusual activity.",
        "improvements": "Enhance monitoring of administrative actions and privilege elevation attempts."
    }
