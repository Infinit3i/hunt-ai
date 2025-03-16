def get_content():
    return {
        "id": "T1110",  # Tactic Technique ID
        "url_id": "1110",  # URL segment for technique reference
        "title": "Brute Force",  # Name of the attack technique
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes. Brute forcing credentials may take place at various points during a breach. For example, adversaries may attempt to brute force access to Valid Accounts within a victim environment leveraging knowledge gathered from other post-compromise behaviors such as OS Credential Dumping, Account Discovery, or Password Policy Discovery. Adversaries may also combine brute forcing activity with behaviors such as External Remote Services as part of Initial Access.",  
        "tags": [],  
        "tactic": "Credential Access",  
        "protocol": "Containers, IaaS, Identity Provider, Linux, Network, Office Suite, SaaS, Windows, macOS",  
        "os": "Linux, Windows, macOS",  
        "tips": [
            "Monitor authentication logs for system and application login failures of Valid Accounts.",
            "If authentication failures are high, then there may be a brute force attempt to gain access using legitimate credentials.",
            "Monitor for many failed authentication attempts across various accounts that may result from password spraying attempts.",
            "It is difficult to detect when hashes are cracked, since this is generally done outside the scope of the target network."
        ],  
        "data_sources": "Application Log: Application Log Content, Command: Command Execution, User Account: User Account Authentication",  
        "log_sources": [  
            {"type": "Authentication Logs", "source": "Failed Login Attempts", "destination": "Security Logs"}  
        ],  
        "source_artifacts": [  
            {"type": "Password Hash", "location": "/etc/shadow", "identify": "Linux Password Hashes"},  
            {"type": "Credential Store", "location": "HKEY_LOCAL_MACHINE\\SAM", "identify": "Windows SAM Database"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "/var/log/auth.log", "identify": "Linux Authentication Logs"}  
        ],  
        "detection_methods": ["Failed Authentication Monitoring", "User Behavior Analytics"],  
        "apt": ["APT39", "Lebanese Cedar", "Lazarus", "Qakbot", "FIN5"],  
        "spl_query": ["index=auth_logs | search brute_force_attempts"],  
        "hunt_steps": ["Check for high volumes of failed login attempts.", "Analyze patterns of login attempts across multiple accounts."],  
        "expected_outcomes": ["Detection of brute force attacks attempting to gain unauthorized access."],  
        "false_positive": "Legitimate users may trigger failed logins due to forgotten passwords.",  
        "clearing_steps": ["Enforce strong password policies and lockout mechanisms.", "Reset affected accounts and investigate potential breaches."],  
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1110", "example": "Brute force attacks used to gain unauthorized access to valid accounts."}
        ],  
        "watchlist": ["Multiple failed authentication attempts", "Unusual login attempts from different IP addresses"],  
        "enhancements": ["Implement multi-factor authentication (MFA).", "Monitor for patterns of automated login attempts."],  
        "summary": "Brute force attacks allow adversaries to systematically guess passwords or crack password hashes to gain unauthorized access to accounts.",  
        "remediation": "Monitor authentication logs and enforce strong password policies to prevent brute force attacks.",  
        "improvements": "Enhance detection rules for abnormal login activity and implement account lockout mechanisms."  
    }
