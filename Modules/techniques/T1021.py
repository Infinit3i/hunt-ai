def get_content():
    return {
        "id": "T1021",
        "url_id": "T1021",
        "title": "Remote Services",
        "tactic": "Lateral Movement",
        "data_sources": "Windows Event, Sysmon, VPN Logs, Remote Access Logs, Firewall",
        "protocol": "RDP, SSH, VNC, SMB",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate unauthorized or anomalous remote service access, which may indicate compromised credentials, lateral movement, or persistence mechanisms used by attackers.",
        "scope": "Monitor remote login attempts for anomalies, such as unusual IP addresses, off-hours access, or logins from unapproved geographic locations.",
        "threat_model": "Adversaries exploit remote services to gain unauthorized access, move laterally, and establish persistence using RDP, SSH, or VNC.",
        "hypothesis": [
            "Are there repeated remote login attempts from unknown or blacklisted IPs?",
            "Is there unusual remote access activity outside business hours?",
            "Are legitimate remote access tools being used in unexpected ways?"
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Windows Security Logs (Event ID 4624, 4648), Linux SSH Logs"},
            {"type": "Remote Access Logs", "source": "VPN Logs, RDP, SSH, VNC, SMB"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Threat Intelligence Feeds", "source": "VirusTotal, AlienVault OTX, AbuseIPDB"}
        ],
        "detection_methods": [
            "Monitor remote access attempts with unusual geolocation or IP address.",
            "Detect excessive failed logins that may indicate brute-force attempts.",
            "Identify patterns of remote access outside normal business hours."
        ],
        "spl_query": {
            "index=windows sourcetype=WinEventLog:Security EventCode=4624 LogonType=10 \n| stats count by user, src_ip, host \n| where count > 5",
            "index=windows sourcetype=WinEventLog:Security EventCode=4625 LogonType=10 \n| stats count by src_ip, user \n| where count > 10",
            "index=windows sourcetype=WinEventLog:Security EventCode=4624 LogonType=10 \n| eval hour=strftime(_time, '%H') \n| where hour < 6 OR hour > 22 \n| stats count by user, src_ip, host"
        },
        "hunt_steps": [
            "Run Queries in SIEM: Detect unusual remote login patterns and failed authentication attempts.",
            "Correlate with Threat Intelligence Feeds: Validate suspicious IPs against known threat actor infrastructure.",
            "Analyze User Behavior: Identify whether the user has a history of remote logins from the detected IP.",
            "Monitor for Privilege Escalation or Lateral Movement: Check for additional activity following the remote access.",
            "Validate & Escalate: If unauthorized remote access is detected → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Unauthorized Remote Access Detected: Block the external IP and disable the compromised account.",
            "No Malicious Activity Found: Improve baseline monitoring for remote access behaviors."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Remote command execution via PowerShell or Bash to control target systems."},
            {"tactic": "Initial Access", "technique": "T1190", "example": "Exploitation of vulnerabilities in public-facing remote services to gain initial access"},
            {"tactic": "Credential Access", "technique": "T1003", "example": "Dumping credentials from LSASS memory to escalate privileges after remote access is achieved."},
            {"tactic": "Defense Evasion", "technique": "T1036", "example": "Masquerading malicious files as legitimate system processes to avoid detection during remote sessions."},      
        ],
        "watchlist": [
            "Flag unusual remote login attempts from unapproved IPs.",
            "Detect failed login attempts exceeding normal thresholds.",
            "Monitor lateral movement attempts post-authentication."
        ],
        "enhancements": [
            "Implement MFA for all remote access services.",
            "Restrict remote login access to known and approved IP ranges.",
            "Enable logging and monitoring for all remote access sessions."
        ],
        "summary": "Monitor and detect unauthorized remote service access attempts to prevent lateral movement and persistence.",
        "remediation": "Block unauthorized access attempts, enforce MFA, and restrict remote logins to approved networks.",
        "improvements": "Enhance SIEM detection rules for anomalous remote access behaviors and brute-force attempts."
    }