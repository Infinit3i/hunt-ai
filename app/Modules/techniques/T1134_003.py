def get_content():
    return {
        "id": "T1134.003",
        "url_id": "T1134/003",
        "title": "Access Token Manipulation: Make and Impersonate Token",
        "description": (
            "Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls. For example, "
            "if an adversary has a username and password but the user is not logged onto the system, the adversary can create a "
            "logon session for the user using the `LogonUser` function. The function will return a copy of the new session's access token, "
            "and the adversary can use `SetThreadToken` to assign the token to a thread. "
            "This behavior is distinct from [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001), which refers to stealing or duplicating an existing token."
        ),
        "tags": ["Privilege Escalation", "Defense Evasion", "Windows"],
        "tactic": "Defense Evasion, Privilege Escalation",
        "protocol": "Windows API",
        "os": "Windows",
        "tips": [
            "Monitor for suspicious API calls like `LogonUser` and `SetThreadToken`.",
            "Analyze process and thread creation events to detect token manipulation.",
            "Look for unexpected `runas` command executions in command-line logs.",
            "Investigate anomalies in authentication and access control logs."
        ],
        "data_sources": "Command: Command Execution, Process: OS API Execution",
        "log_sources": [
            {"type": "Security Event Logs", "source": "Windows Event Log", "destination": "SIEM"},
            {"type": "API Monitoring", "source": "ETW (Event Tracing for Windows)", "destination": "Forensic Analysis"},
        ],
        "source_artifacts": [
            {"type": "Token Manipulation", "location": "Windows API Calls", "identify": "LogonUser and SetThreadToken usage"},
            {"type": "Command Execution", "location": "Command Line Logs", "identify": "Use of 'runas' with administrative privileges"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "Security Event Logs", "identify": "Processes running with impersonated tokens"},
        ],
        "detection_methods": [
            "Monitor for use of `LogonUser` and `SetThreadToken` API calls.",
            "Correlate token manipulation activity with other suspicious behaviors such as process injection or privilege escalation attempts.",
            "Detect unusual process executions where the security token does not match the expected user."
        ],
        "apt": ["Metador", "Elephant Beetle"],
        "spl_query": [
            "index=windows_logs EventCode=4672 \n| search TokenElevated=True \n| stats count by Account_Name, Process_ID",
        ],
        "hunt_steps": [
            "Identify processes making use of LogonUser and SetThreadToken API calls.",
            "Analyze authentication logs to detect unauthorized logon session creation.",
            "Check for processes running under impersonated accounts without proper authentication."
        ],
        "expected_outcomes": [
            "Privilege Escalation Detected: Investigate unauthorized token creation and usage.",
            "No Malicious Activity Found: Confirm normal system behavior and log for further analysis."
        ],
        "false_positive": "Legitimate administrative scripts and services may use token manipulation; validate against expected usage patterns.",
        "clearing_steps": [
            "Terminate processes using unauthorized impersonated tokens.",
            "Audit authentication logs and remove unauthorized logon sessions.",
            "Restrict access to Windows API functions related to token manipulation for non-administrators."
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1134.003", "example": "Creating and assigning new access tokens to threads."},
        ],
        "watchlist": [
            "Monitor for excessive token impersonation attempts by non-administrator users.",
            "Detect unusual processes running with SYSTEM privileges without direct authentication.",
            "Analyze network authentication logs for anomalous access patterns."
        ],
        "enhancements": [
            "Implement endpoint detection rules for API calls related to token manipulation.",
            "Enable PowerShell logging and script block logging to monitor suspicious activity.",
            "Restrict token-related API functions to authorized administrators only."
        ],
        "summary": "Adversaries may create and impersonate user tokens to gain elevated privileges and bypass access controls.",
        "remediation": "Implement process integrity monitoring, enforce strict user access controls, and audit authentication logs.",
        "improvements": "Enhance API monitoring and forensic analysis of access tokens to detect unauthorized privilege escalations."
    }
