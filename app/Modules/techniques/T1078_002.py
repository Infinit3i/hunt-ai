def get_content():
    return {
        "id": "T1078.002",
        "url_id": "T1078/002",
        "title": "Valid Accounts: Domain Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "data_sources": "Authentication logs, Active Directory logs, Network monitoring, Process monitoring",
        "protocol": "LDAP, Kerberos, NTLM, SMB, RDP",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate unauthorized use of domain accounts for persistence and lateral movement.",
        "scope": "Monitor authentication attempts and usage of domain accounts to identify anomalous or unauthorized access.",
        "threat_model": "Adversaries may use compromised domain accounts to bypass authentication mechanisms, escalate privileges, and move laterally within an environment.",
        "hypothesis": [
            "Are there unauthorized domain accounts being used for authentication?",
            "Are there multiple failed login attempts followed by a successful authentication?",
            "Is there suspicious authentication activity from unusual locations or hosts?"
        ],
        "tips": [
            "Monitor authentication logs for failed logins followed by successful attempts.",
            "Detect domain accounts used outside normal working hours or from anomalous locations.",
            "Correlate domain account activity with process execution logs to detect misuse."
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Windows Event ID 4624, 4625, 4776, 4768, 4769", "destination": "Domain Controller"},
            {"type": "Network Monitoring", "source": "Unusual RDP, SMB, or LDAP access", "destination": "Domain Controller"},
            {"type": "Active Directory", "source": "Account usage anomalies and privilege escalations", "destination": "Security Logs"}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Security Logs", "identify": "Unusual login patterns"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "System Logs", "identify": "Unusual child process spawned by domain accounts"}
        ],
        "detection_methods": [
            "Monitor authentication logs for multiple failed attempts followed by success.",
            "Detect domain accounts used outside their typical geographic locations.",
            "Identify privilege escalation activities performed by domain accounts.",
            "Analyze logon events from non-standard or new hosts."
        ],
        "apt": [
            "APT29",
            "APT38",
            "Lazarus Group"
        ],
        "spl_query": [
            "index=security EventCode=4624 OR EventCode=4625 OR EventCode=4768 OR EventCode=4769 Account_Domain!='ExpectedDomain'",
            "index=security EventCode=4624 Logon_Type=10 OR Logon_Type=3 Account_Name!=system_user" 
        ],
        "hunt_steps": [
            "Identify anomalous domain account authentication patterns.",
            "Correlate logins with known attack techniques and behaviors.",
            "Review authentication attempts from suspicious IPs or geolocations.",
            "Analyze privilege escalations tied to domain accounts."
        ],
        "expected_outcomes": [
            "Successful Detection: Unauthorized domain account usage identified and mitigated.",
            "No Malicious Activity: Continue to refine domain account monitoring and detection rules."
        ],
        "false_positive": "Admins using new or temporary domain accounts, service accounts running legitimate processes.",
        "clearing_steps": [
            "Disable compromised domain accounts immediately.",
            "Reset credentials and enforce MFA for all domain accounts.",
            "Conduct forensic analysis on affected accounts to determine scope of compromise." 
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1078.002 (Domain Accounts)", "example": "Adversaries use stolen domain credentials to maintain access."},
            {"tactic": "Privilege Escalation", "technique": "T1078.002 (Domain Accounts)", "example": "Compromised domain accounts used to gain higher privileges."},
            {"tactic": "Lateral Movement", "technique": "T1550.002 (Pass-the-Ticket)", "example": "Attackers use domain credentials to move across systems."}
        ],
        "watchlist": [
            "Monitor newly created or modified domain accounts.",
            "Detect domain accounts logging in from multiple geographic regions.",
            "Alert on domain admin logins occurring outside business hours."
        ],
        "enhancements": [
            "Implement conditional access policies to restrict unauthorized logins.",
            "Enforce MFA on all privileged domain accounts.",
            "Use behavioral analytics to detect abnormal domain account activity."
        ],
        "summary": "Domain accounts are often targeted by adversaries for persistent access, lateral movement, and privilege escalation.",
        "remediation": "Immediately disable suspicious domain accounts, reset credentials, and investigate lateral movement.",
        "improvements": "Enhance SIEM rules to detect abnormal domain authentication behaviors and integrate with threat intelligence feeds."
    }
