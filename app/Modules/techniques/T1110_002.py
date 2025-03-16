def get_content():
    return {
        "id": "T1110.002",  # Tactic Technique ID
        "url_id": "1110/002",  # URL segment for technique reference
        "title": "Brute Force: Password Cracking",  # Name of the attack technique
        "description": "Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. OS Credential Dumping can be used to obtain password hashes, but this may only get an adversary so far when Pass the Hash is not an option. Further, adversaries may leverage Data from Configuration Repository in order to obtain hashed credentials for network devices. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network. The resulting plaintext password resulting from a successfully cracked hash may be used to log into systems, resources, and services in which the account has access.",  
        "tags": [],  
        "tactic": "Credential Access",  
        "protocol": "Identity Provider, Linux, Network, Office Suite, Windows, macOS",  
        "os": "Linux, Windows, macOS",  
        "tips": [
            "It is difficult to detect when hashes are cracked, since this is generally done outside the scope of the target network.",
            "Consider focusing efforts on detecting other adversary behavior used to acquire credential materials, such as OS Credential Dumping or Kerberoasting.",
            "Monitor for suspicious access to password hash storage locations.",
            "Use strong hashing algorithms and salting to make cracking more difficult."
        ],  
        "data_sources": "Application Log: Application Log Content, User Account: User Account Authentication",  
        "log_sources": [  
            {"type": "Security Logs", "source": "Access to Hash Files", "destination": "Authentication Logs"}  
        ],  
        "source_artifacts": [  
            {"type": "Password Hash", "location": "/etc/shadow", "identify": "Linux Password Hashes"},  
            {"type": "Credential Store", "location": "HKEY_LOCAL_MACHINE\\SAM", "identify": "Windows SAM Database"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "/var/log/auth.log", "identify": "Linux Authentication Logs"}  
        ],  
        "detection_methods": ["Monitoring Access to Hash Files", "Detecting Credential Dumping Techniques"],  
        "apt": ["APT3", "FIN6", "Night Dragon", "Cleaver"],  
        "spl_query": ["index=auth_logs | search password_cracking_attempts"],  
        "hunt_steps": ["Check for unauthorized access to password hash files.", "Analyze unusual access patterns to authentication logs."],  
        "expected_outcomes": ["Detection of password cracking attempts used to recover plaintext passwords."],  
        "false_positive": "Legitimate system administrators may access hash files for security audits.",  
       
