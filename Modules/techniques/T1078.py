def get_content():
    """
    Returns structured content for the Valid Accounts (T1078) persistence method.
    """
    return {
        "id": "T1078",
        "url_id": "T1078",
        "title": "Valid Accounts",
        "tactic": "Persistence, Defense Evasion, Privilege Escalation, Initial Access",
        "data_sources": "Authentication logs, Process monitoring, Windows Event Logs",
        "protocol": "Multiple",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries may use valid credentials to gain access and persist within a network.",
        "scope": "Monitor for unusual account activity and privilege escalations.",
        "threat_model": "Threat actors may leverage stolen credentials to move laterally and escalate privileges.",
        "hypothesis": [
            "Are there unexpected logins from unusual locations?",
            "Are high-privileged accounts being used outside of normal activity hours?",
            "Are there multiple failed login attempts followed by a successful login?"
        ],
        "tips": [
            "Enable multi-factor authentication (MFA) for critical accounts.",
            "Monitor logs for anomalous authentication patterns.",
            "Investigate abnormal account activity, especially for service accounts."
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Windows Security Log Event ID 4624, 4625, 4768, 4769"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1, Windows Event Logs 4688"},
            {"type": "Active Directory", "source": "Domain Controller Authentication Logs"}
        ],
        "source_artifacts": [
            {"type": "Logon Session Tracking", "location": "Windows Event Logs", "identify": "4624, 4625, 4768, 4769"}
        ],
        "destination_artifacts": [
            {"type": "Command Execution", "location": "Process Monitoring", "identify": "Sysmon Event ID 1"}
        ],
        "detection_methods": [
            "Monitor authentication logs for unusual login times or locations.",
            "Detect brute-force attempts by correlating failed and successful logins.",
            "Analyze service account usage patterns for anomalies."
        ],
        "apt": ["G0016", "G0032", "G0096"],
        "spl_query": [
            "index=windows EventCode=4624 OR EventCode=4625 | stats count by Account_Name, Logon_Type, IpAddress",
            "index=windows EventCode=4768 OR EventCode=4769 | table Time, Account_Name, Service_Name, IpAddress"
        ],
        "hunt_steps": [
            "Identify unusual logins or privilege escalations in authentication logs.",
            "Check for recently created accounts with elevated privileges.",
            "Investigate any anomalies in service account usage."
        ],
        "expected_outcomes": [
            "Unauthorized access attempt detected and mitigated.",
            "No suspicious activity found, reinforcing security policies."
        ],
        "false_positive": "Legitimate IT automation or system maintenance accounts may trigger similar logs.",
        "clearing_steps": [
            "Disable compromised accounts and reset credentials.",
            "Audit account permissions and revoke unnecessary privileges."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1078 (Valid Accounts)", "example": "Threat actors use stolen credentials for lateral movement."}
        ],
        "watchlist": [
            "Monitor new accounts with administrative privileges.",
            "Detect login attempts from geolocations outside of the organization's footprint."
        ],
        "enhancements": [
            "Implement strict account lockout policies for failed login attempts.",
            "Use behavioral analytics to detect anomalous authentication activity."
        ],
        "summary": "Adversaries may leverage valid accounts to evade detection and maintain persistent access.",
        "remediation": "Implement least privilege principles and enforce multi-factor authentication.",
        "improvements": "Enhance identity verification mechanisms and real-time anomaly detection."
    }
