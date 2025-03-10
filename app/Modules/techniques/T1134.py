def get_content():
    return {
        "id": "T1134",
        "url_id": "1134",
        "title": "Access Token Manipulation",
        "description": (
            "Adversaries may modify access tokens to operate under a different user or system security context to perform actions "
            "and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can "
            "manipulate access tokens to make a running process appear as though it is the child of a different process or belongs "
            "to someone other than the user that started the process."
        ),
        "tags": ["Privilege Escalation", "Defense Evasion", "Windows"],
        "tactic": "Defense Evasion, Privilege Escalation",
        "protocol": "Windows API",
        "os": "Windows",
        "tips": [
            "Monitor for abnormal token modification API calls, such as LogonUser, DuplicateTokenEx, and ImpersonateLoggedOnUser.",
            "Enable detailed command-line logging and monitor for suspicious usage of 'runas'.",
            "Analyze user authentication logs for inconsistencies in access patterns.",
            "Correlate token manipulation activity with other suspicious system behavior, such as privilege escalation attempts."
        ],
        "data_sources": "Active Directory: Active Directory Object Modification, Command: Command Execution, Process: OS API Execution, Process: Process Creation, Process: Process Metadata, User Account: User Account Metadata",
        "log_sources": [
            {"type": "Security Event Logs", "source": "Windows Event Log", "destination": "SIEM"},
            {"type": "API Monitoring", "source": "ETW (Event Tracing for Windows)", "destination": "Forensic Analysis"},
        ],
        "source_artifacts": [
            {"type": "Process Token Manipulation", "location": "Security Event Logs", "identify": "Token duplication and impersonation activity"},
            {"type": "Command Execution", "location": "PowerShell Logs", "identify": "Use of 'runas' or token-related API calls"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "Process Logs", "identify": "Processes running under an unexpected security context"},
        ],
        "detection_methods": [
            "Monitor for API calls that indicate token theft or impersonation.",
            "Detect unusual process executions where the security token does not match the expected user.",
            "Analyze authentication logs for users performing actions under different accounts."
        ],
        "apt": ["FIN6", "Ryuk", "Naikon", "Duqu 2.0", "APT41"],
        "spl_query": [
            "index=windows_logs EventCode=4624 \n| search LogonType=3 \n| stats count by Account_Name, Process_ID",
        ],
        "hunt_steps": [
            "Identify processes that have duplicated or modified tokens.",
            "Analyze the timeline of access token manipulations to correlate with other privilege escalation techniques.",
            "Check for suspicious 'runas' usage and unexpected administrator-level actions."
        ],
        "expected_outcomes": [
            "Privilege Escalation Detected: Investigate unauthorized access token modifications.",
            "No Malicious Activity Found: Confirm normal system behavior and log for further analysis."
        ],
        "false_positive": "Some legitimate administrative operations may involve token manipulation; validate against expected administrative activity.",
        "clearing_steps": [
            "Terminate processes running with unauthorized token modifications.",
            "Audit security event logs for unauthorized token duplication attempts.",
            "Restrict access to Windows API functions related to token manipulation for non-administrative users."
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1134", "example": "Token duplication to elevate process privileges."},
        ],
        "watchlist": [
            "Monitor for excessive token impersonation attempts by non-administrator users.",
            "Detect unusual processes running under SYSTEM privileges without direct authentication.",
            "Analyze network authentication logs for anomalous access patterns."
        ],
        "enhancements": [
            "Implement endpoint detection rules for API calls related to token manipulation.",
            "Enable PowerShell logging and script block logging to monitor suspicious activity.",
            "Restrict token-related API functions to authorized administrators only."
        ],
        "summary": "Adversaries may use access token manipulation to operate under a different user security context and bypass access controls.",
        "remediation": "Implement process integrity monitoring, enforce strict user access controls, and audit authentication logs.",
        "improvements": "Enhance API monitoring and forensic analysis of process tokens to detect unauthorized privilege escalations."
    }
