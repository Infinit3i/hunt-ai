def get_content():
    return {
        "id": "T1550.003",
        "url_id": "T1550/003",
        "title": "Use Alternate Authentication Material: Pass the Ticket",
        "tactic": "Defense Evasion, Lateral Movement",
        "data_sources": "Active Directory: Active Directory Credential Request, Logon Session: Logon Session Creation, User Account: User Account Authentication",
        "protocol": "Kerberos",
        "os": "Windows",
        "objective": "Detect adversaries using stolen Kerberos tickets to move laterally and bypass authentication controls.",
        "scope": "Identify anomalies in Kerberos ticket use, particularly lateral movement without password-based authentication.",
        "threat_model": "Adversaries capture or forge Kerberos service tickets and TGTs to access services and move within an Active Directory environment without passwords.",
        "hypothesis": [
            "Are there valid Kerberos tickets being reused from unusual hosts or times?",
            "Do service tickets appear in contexts where user authentication hasn’t occurred?",
            "Are forged or overpassed tickets being used in golden or silver ticket attacks?"
        ],
        "log_sources": [
            {"type": "Active Directory", "source": "Domain Controller Security Logs (Event ID 4769, 4624)", "destination": "Event Collector or SIEM"},
            {"type": "Logon Session", "source": "Windows Security Logs (Event ID 4624, 4672)", "destination": "SIEM"},
            {"type": "User Account", "source": "Audit Logs of Privileged Accounts", "destination": "SIEM or Active Directory Audit Tools"}
        ],
        "detection_methods": [
            "Monitor Kerberos ticket usage events (Event ID 4769) for anomalies in host, timestamp, or usage pattern.",
            "Correlate logon sessions (4624) with lack of interactive logins indicating ticket passing.",
            "Alert on mismatches between originating source and expected user behavior."
        ],
        "spl_query": [
            "index=wineventlog sourcetype=WinEventLog:Security EventCode=4769  \n| stats count by Account_Name, Service_Name, Client_Address, Ticket_Encryption_Type"
        ],
        "hunt_steps": [
            "Query SIEM for suspicious Event ID 4769 patterns.",
            "Investigate users with multiple ticket grantings across systems.",
            "Review for forged tickets using golden/silver ticket indicators.",
            "Correlate login events with physical or VPN access.",
            "Isolate endpoints showing repeated misuse."
        ],
        "expected_outcomes": [
            "Detection of Kerberos ticket misuse indicating lateral movement.",
            "Alert on reused TGTs and service tickets across unauthorized systems.",
            "Improved visibility into credential abuse vectors."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1003 (OS Credential Dumping)", "example": "Extracted tickets using Mimikatz from memory."},
            {"tactic": "Lateral Movement", "technique": "T1021.002 (SMB/Windows Admin Shares)", "example": "Accessed administrative shares using stolen ticket."},
            {"tactic": "Defense Evasion", "technique": "T1070.001 (Clear Windows Event Logs)", "example": "Cleared logs after lateral move with forged ticket."}
        ],
        "watchlist": [
            "Unusual Kerberos activity from non-interactive accounts.",
            "Mismatched TGT source and user login location.",
            "Accounts authenticating without corresponding VPN/physical login."
        ],
        "enhancements": [
            "Enable detailed Kerberos auditing on Domain Controllers.",
            "Deploy correlation rules for ticket issuance without credential use.",
            "Incorporate detection rules for silver/golden ticket patterns."
        ],
        "summary": "Pass-the-Ticket attacks use valid Kerberos tickets stolen from memory or forged to move laterally, access resources, and evade password checks.",
        "remediation": "Reset the KRBTGT password twice, investigate all lateral movement from affected accounts, and revoke/rotate associated credentials.",
        "improvements": "Enhance behavioral detections around ticket granting, enforce tiered access controls, and train incident response teams on Kerberos misuse forensics.",
        "mitre_version": "16.1"
    }
