def get_content():
    return {
        "id": "T1110.001",  # Tactic Technique ID
        "url_id": "1110/001",  # URL segment for technique reference
        "title": "Brute Force: Password Guessing",  # Name of the attack technique
        "description": "Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts. Guessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. Typically, management services over commonly used ports are used when guessing passwords, such as SSH, Telnet, FTP, NetBIOS, SMB, LDAP, Kerberos, RDP, HTTP management services, MSSQL, Oracle, MySQL, VNC, and SNMP. In addition to management services, adversaries may target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols, as well as externally facing email applications, such as Office 365. Further, adversaries may abuse network device interfaces (such as `wlanAPI`) to brute force accessible WiFi routers via wireless authentication protocols.",  
        "tags": [],  
        "tactic": "Credential Access",  
        "protocol": "Containers, IaaS, Identity Provider, Linux, Network, Office Suite, SaaS, Windows, macOS",  
        "os": "Linux, Windows, macOS",  
        "tips": [
            "Monitor authentication logs for system and application login failures of Valid Accounts.",
            "If authentication failures are high, then there may be a brute force attempt to gain access to a system using legitimate credentials.",
            "Monitor login attempts on critical management services and cloud-based applications.",
            "Enable account lockout mechanisms and enforce multi-factor authentication (MFA) to mitigate risks."
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
        "apt": ["APT29", "Emotet", "Xbash", "Lucifer", "Hermetic Wizard"],  
        "spl_query": ["index=auth_logs | search password_guessing_attempts"],  
        "hunt_steps": ["Check for high volumes of failed login attempts.", "Analyze patterns of login attempts across multiple accounts and services."],  
        "expected_outcomes": ["Detection of password guessing attacks attempting to gain unauthorized access."],  
        "false_positive": "Legitimate users may trigger failed logins due to forgotten passwords.",  
        "clearing_steps": ["Enforce strong password policies and lockout mechanisms.", "Reset affected accounts and investigate potential breaches."],  
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1110.001", "example": "Password guessing attacks used to gain unauthorized access to accounts."}
        ],  
        "watchlist": ["Multiple failed authentication attempts", "Login attempts from unusual locations or multiple services"],  
        "enhancements": ["Implement multi-factor authentication (MFA).", "Monitor for patterns of automated login attempts and block repeated failed attempts."],  
        "summary": "Password guessing allows adversaries to systematically attempt to access accounts using common passwords, potentially leading to unauthorized access.",  
        "remediation": "Monitor authentication logs and enforce strong password policies to prevent password guessing attacks.",  
        "improvements": "Enhance detection rules for unusual login activity and implement IP-based throttling for authentication attempts."  
    }
