def get_content():
    return {
        "id": "T1110.003",  # Tactic Technique ID
        "url_id": "T1110/003",  # URL segment for technique reference
        "title": "Brute Force: Password Spraying",  # Name of the attack technique
        "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. Typically, management services over commonly used ports are used when password spraying, such as SSH, Telnet, FTP, NetBIOS, SMB, LDAP, Kerberos, RDP, HTTP management services, MSSQL, Oracle, MySQL, and VNC. In addition to management services, adversaries may target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols, as well as externally facing email applications, such as Office 365.",  
        "tags": [],  
        "tactic": "Credential Access",  
        "protocol": "Containers, IaaS, Identity Provider, Linux, Network, Office Suite, SaaS, Windows, macOS",  
        "os": "Linux, Windows, macOS",  
        "tips": [
            "Monitor authentication logs for system and application login failures of Valid Accounts.",
            "Specifically, monitor for many failed authentication attempts across various accounts that may result from password spraying attempts.",
            "Enable account lockout mechanisms and enforce multi-factor authentication (MFA) to mitigate risks.",
            "Consider monitoring for repeated failed authentication attempts on multiple accounts from a single IP address."
        ],  
        "data_sources": "Application Log: Application Log Content, User Account: User Account Authentication",  
        "log_sources": [  
            {"type": "Authentication Logs", "source": "Failed Login Attempts", "destination": "Security Logs"}  
        ],  
        "source_artifacts": [  
            {"type": "Login Attempts", "location": "/var/log/auth.log", "identify": "Linux Authentication Logs"},  
            {"type": "Credential Store", "location": "HKEY_LOCAL_MACHINE\\SAM", "identify": "Windows SAM Database"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "identify": "Windows Security Event Logs"}  
        ],  
        "detection_methods": ["Failed Authentication Monitoring", "User Behavior Analytics"],  
        "apt": ["Nobelium", "APT29", "Agrius", "Leafminer", "Chimera"],  
        "spl_query": ["index=auth_logs | search password_spraying_attempts"],  
        "hunt_steps": ["Check for repeated failed login attempts across multiple accounts.", "Analyze patterns of login attempts originating from a single IP."],  
        "expected_outcomes": ["Detection of password spraying attacks attempting to gain unauthorized access."],  
        "false_positive": "Legitimate users may trigger failed logins due to forgotten passwords.",  
        "clearing_steps": ["Enforce strong password policies and lockout mechanisms.", "Reset affected accounts and investigate potential breaches."],  
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1110.003", "example": "Password spraying attacks used to gain unauthorized access to multiple accounts."}
        ],  
        "watchlist": ["Multiple failed authentication attempts", "Login attempts from unusual locations or multiple services"],  
        "enhancements": ["Implement multi-factor authentication (MFA).", "Monitor for patterns of automated login attempts and block repeated failed attempts."],  
        "summary": "Password spraying allows adversaries to systematically attempt to access accounts using common passwords while avoiding account lockouts.",  
        "remediation": "Monitor authentication logs and enforce strong password policies to prevent password spraying attacks.",  
        "improvements": "Enhance detection rules for unusual login activity and implement IP-based throttling for authentication attempts."  
    }
