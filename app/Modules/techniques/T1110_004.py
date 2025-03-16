def get_content():
    return {
        "id": "T1110.004",  # Tactic Technique ID
        "url_id": "1110/004",  # URL segment for technique reference
        "title": "Brute Force: Credential Stuffing",  # Name of the attack technique
        "description": "Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, large numbers of username and password pairs are dumped online when a website or service is compromised and the user account credentials accessed. The information may be useful to an adversary attempting to compromise accounts by taking advantage of the tendency for users to use the same passwords across personal and business accounts. Credential stuffing is a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. Typically, management services over commonly used ports are used when stuffing credentials, including SSH, Telnet, FTP, NetBIOS, SMB, LDAP, Kerberos, RDP, HTTP management services, MSSQL, Oracle, MySQL, and VNC. In addition to management services, adversaries may target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols, as well as externally facing email applications, such as Office 365.",  
        "tags": [],  
        "tactic": "Credential Access",  
        "protocol": "Containers, IaaS, Identity Provider, Linux, Network, Office Suite, SaaS, Windows, macOS",  
        "os": "Linux, Windows, macOS",  
        "tips": [
            "Monitor authentication logs for system and application login failures of Valid Accounts.",
            "If authentication failures are high, then there may be a brute force attempt to gain access using legitimate credentials.",
            "Monitor for many failed authentication attempts across various accounts that may result from credential stuffing attempts.",
            "Enable account lockout mechanisms and enforce multi-factor authentication (MFA) to mitigate risks."
        ],  
        "data_sources": "Application Log: Application Log Content, User Account: User Account Authentication",  
        "log_sources": [  
            {"type": "Authentication Logs", "source": "Failed Login Attempts", "destination": "Security Logs"}  
        ],  
        "source_artifacts": [  
            {"type": "Compromised Credentials", "location": "Dark Web Breach Dumps", "identify": "Leaked Usernames and Passwords"},  
            {"type": "Login Attempts", "location": "/var/log/auth.log", "identify": "Authentication Failure Logs"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "identify": "Windows Security Event Logs"}  
        ],  
        "detection_methods": ["Failed Authentication Monitoring", "User Behavior Analytics"],  
        "apt": ["Chimera", "Trickbot"],  
        "spl_query": ["index=auth_logs | search credential_stuffing_attempts"],  
        "hunt_steps": ["Check for high volumes of failed login attempts.", "Analyze patterns of login attempts across multiple accounts and services."],  
        "expected_outcomes": ["Detection of credential stuffing attacks attempting to gain unauthorized access."],  
        "false_positive": "Legitimate users may trigger failed logins due to forgotten passwords.",  
        "clearing_steps": ["Enforce strong password policies and lockout mechanisms.", "Reset affected accounts and investigate potential breaches."],  
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1110.004", "example": "Credential stuffing attacks used to gain unauthorized access to multiple accounts."}
        ],  
        "watchlist": ["Multiple failed authentication attempts", "Unusual login attempts from different IP addresses"],  
        "enhancements": ["Implement multi-factor authentication (MFA).", "Monitor for patterns of automated login attempts and block repeated failed attempts."],  
        "summary": "Credential stuffing allows adversaries to use leaked credentials from unrelated breaches to gain unauthorized access to target accounts.",  
        "remediation": "Monitor authentication logs and enforce strong password policies to prevent credential stuffing attacks.",  
        "improvements": "Enhance detection rules for abnormal login activity and implement IP-based throttling for authentication attempts."  
    }
