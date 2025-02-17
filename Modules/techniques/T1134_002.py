def get_content():
    """
    Returns structured content for the Create Process with Token technique (T1134.002).
    """
    return {
        "id": "T1134.002",
        "url_id": "T1134/002",
        "title": "Create Process with Token",
        "tactic": "Privilege Escalation, Defense Evasion",
        "data_sources": "Windows Event Logs, Process Monitoring, API Monitoring",
        "protocol": "N/A",
        "os": "Windows",
        "objective": "Adversaries may create a process with a stolen token to escalate privileges or evade detection.",
        "scope": "Monitor process creation and token manipulation activities.",
        "threat_model": "Attackers can use stolen tokens to execute processes under different user contexts, bypassing security controls.",
        "hypothesis": [
            "Are processes being created with suspicious or high-privileged tokens?",
            "Is there a pattern of token manipulation followed by privileged actions?",
            "Are attackers leveraging token duplication for unauthorized access?"
        ],
        "tips": [
            "Monitor Event ID 4688 (process creation) with suspicious parent-child relationships.",
            "Look for Event ID 4673 (sensitive privilege use) associated with process creation.",
            "Detect anomalous use of Windows API functions like `DuplicateTokenEx`, `ImpersonateLoggedOnUser`.",
            "Investigate processes running under SYSTEM or other privileged accounts unexpectedly."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1", "destination": "Process Creation Logs"},
            {"type": "API Monitoring", "source": "ETW Tracing", "destination": "Security Tools"}
        ],
        "source_artifacts": [
            {"type": "Process Execution", "location": "C:\\Windows\\System32", "identify": "cmd.exe, powershell.exe, svchost.exe"}
        ],
        "destination_artifacts": [
            {"type": "Token Manipulation", "location": "N/A", "identify": "Access tokens being duplicated or assigned to new processes"}
        ],
        "detection_methods": [
            "Monitor token duplication and impersonation API calls.",
            "Analyze process execution chains for unexpected privilege escalations.",
            "Look for processes launched with SYSTEM or Administrator tokens without proper authentication."
        ],
        "apt": ["G0007", "G0016"],
        "spl_query": [
            "index=windows EventCode=4688 | search NewProcessName=* | table _time, NewProcessName, ParentProcessName, User" ,
            "index=windows EventCode=4673 | search PrivilegeUse=Sensitive | table _time, SubjectUserName, ObjectName, ProcessName"
        ],
        "hunt_steps": [
            "Identify token manipulation events in security logs.",
            "Correlate with process execution logs to identify privilege escalation.",
            "Investigate the source of token duplication and revoke unauthorized access.",
            "Check if the adversary is using known token theft tools like Mimikatz."
        ],
        "expected_outcomes": [
            "Detection of unauthorized token-based privilege escalation attempts.",
            "No malicious activity found, enhancing detection baselines."
        ],
        "false_positive": "Legitimate IT administrators may use token manipulation for operational tasks.",
        "clearing_steps": [
            "Terminate unauthorized processes using stolen tokens.",
            "Revoke compromised user or service account credentials.",
            "Enhance auditing and logging to detect further token manipulation attempts."
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1134.002 (Create Process with Token)", "example": "Adversaries use token duplication to escalate privileges."}
        ],
        "watchlist": [
            "Monitor process creations with SYSTEM or high-privileged tokens.",
            "Detect abnormal token duplication and impersonation activities."
        ],
        "enhancements": [
            "Implement least privilege principles to limit token abuse.",
            "Use endpoint detection solutions to flag suspicious token manipulation."
        ],
        "summary": "Adversaries may use stolen tokens to create processes under different user contexts, bypassing security controls.",
        "remediation": "Terminate unauthorized token-using processes, revoke compromised accounts, and implement stricter token management policies.",
        "improvements": "Enhance endpoint logging, restrict unnecessary token privileges, and train SOC teams to detect token-based attacks."
    }
