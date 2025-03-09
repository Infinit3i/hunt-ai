def get_content():
    return {
        "id": "T1033",
        "url_id": "T1033",
        "title": "Discovery: System Owner/User Discovery",
        "tactic": "Discovery",
        "data_sources": "Process Creation Logs, Authentication Logs, Security Monitoring Tools",
        "protocol": "Windows API, WMI, LDAP, Active Directory",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries gathering information about system users and owners for privilege escalation or lateral movement.",
        "scope": "Identify unauthorized attempts to enumerate user accounts, security groups, or administrative privileges on compromised hosts.",
        "threat_model": "Adversaries query system information to identify privileged accounts, group memberships, and potential targets for escalation or lateral movement.",
        "hypothesis": [
            "Are adversaries enumerating local or domain accounts on the system?",
            "Are unauthorized users attempting to gather information about administrative privileges?",
            "Is there an increase in system owner or user discovery activity from unexpected processes?"
        ],
        "log_sources": [
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs (Event ID 4688)"},
            {"type": "Authentication Logs", "source": "Windows Event Logs (Event ID 4624, 4672, 4768), Linux auth logs"},
            {"type": "Security Monitoring Tools", "source": "SIEM, EDR (CrowdStrike, Defender ATP, Carbon Black)"}
        ],
        "detection_methods": [
            "Monitor for execution of user enumeration commands (e.g., `whoami`, `net user`, `id`).",
            "Detect unauthorized LDAP or WMI queries targeting user or group information.",
            "Identify process anomalies where non-administrative users attempt account discovery."
        ],
        "spl_query": [
            "index=security_logs sourcetype=windows_security OR sourcetype=linux_auth \n| search EventID=4688 OR EventID=4624 OR process_name IN ('whoami', 'net user', 'id') \n| stats count by src_ip, dest_ip, user, process_name"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify user enumeration attempts.",
            "Analyze Process Creation Logs: Detect unauthorized executions of account discovery commands.",
            "Monitor for Unauthorized LDAP Queries: Identify suspicious attempts to enumerate users or groups.",
            "Correlate with Threat Intelligence: Compare with known adversary techniques targeting user discovery.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "System Owner/User Discovery Detected: Block unauthorized enumeration attempts and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for system owner/user discovery techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1033 (System Owner/User Discovery)", "example": "Adversaries querying system users to find privileged accounts for escalation."},
            {"tactic": "Credential Access", "technique": "T1555 (Credentials from Password Stores)", "example": "Attackers targeting stored credentials after discovering administrative users."}
        ],
        "watchlist": [
            "Flag execution of user discovery commands from non-administrative users.",
            "Monitor for anomalies in account enumeration and privilege queries.",
            "Detect unauthorized Active Directory user lookup requests."
        ],
        "enhancements": [
            "Deploy least privilege access control to restrict user enumeration.",
            "Implement behavior-based anomaly detection for privilege escalation attempts.",
            "Improve correlation between user discovery techniques and known threat actor behaviors."
        ],
        "summary": "Document detected malicious system owner/user discovery activity and affected systems.",
        "remediation": "Block unauthorized user enumeration attempts, enforce logging, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of system owner/user discovery techniques."
    }
