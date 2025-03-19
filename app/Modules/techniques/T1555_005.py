def get_content():
    return {
        "id": "T1555.005",
        "url_id": "1555/005",
        "title": "Credentials from Password Stores: Password Managers",
        "description": "Adversaries may acquire user credentials from third-party password managers. Password managers store credentials in encrypted databases, which are typically accessible after providing a master password. Once unlocked, credentials may be stored in memory or as files on disk, making them potential targets for credential theft.",
        "tags": ["Credential Access", "Password Managers", "Memory Extraction"],
        "tactic": "Credential Access",
        "protocol": "Local File Access, OS API Calls, Memory Analysis",
        "os": ["Windows", "Linux", "macOS"],
        "tips": [
            "Monitor access to known password manager storage locations.",
            "Detect unauthorized processes scanning memory for password manager credentials.",
            "Restrict access to password manager files and enforce strong master password policies."
        ],
        "data_sources": "File Access, Process Execution, OS API Calls, Memory Analysis",
        "log_sources": [
            {"type": "File", "source": "Password Manager Database Locations", "destination": "File Access Logs"},
            {"type": "Process", "source": "Memory Access Attempts", "destination": "System Logs"},
            {"type": "Command", "source": "Credential Dumping Commands", "destination": "Audit Logs"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "Password Manager Storage", "identify": "Extracted Credential Database"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Memory", "identify": "Dumped Password Manager Credentials"}
        ],
        "detection_methods": [
            "Monitor file access logs for unauthorized access to password manager databases.",
            "Detect memory scanning techniques used to extract credentials.",
            "Analyze process execution logs for suspicious access to password manager applications."
        ],
        "apt": ["Wocao", "LAPSUS", "Ferocious Kitten", "DRBControl", "Anchor"],
        "spl_query": [
            "index=security (file_path=*password_manager* OR process_name=*keepass* OR process_name=*lastpass*) | table _time, file_path, process_name, user"
        ],
        "hunt_steps": [
            "Review access logs for attempts to read password manager storage files.",
            "Analyze execution history for credential dumping tools targeting password managers.",
            "Monitor memory scanning techniques attempting to extract stored credentials."
        ],
        "expected_outcomes": [
            "Detection of unauthorized attempts to extract stored password manager credentials.",
            "Identification of processes attempting credential theft from password managers."
        ],
        "false_positive": "Legitimate user access to stored password manager credentials.",
        "clearing_steps": [
            "Investigate unauthorized access to password manager storage.",
            "Revoke compromised credentials and enforce password rotation.",
            "Implement additional security controls on password manager access."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "Extract Credentials from Password Managers", "example": "An attacker retrieves stored credentials from a KeePass database."}
        ],
        "watchlist": ["Processes accessing multiple password manager storage locations in a short timeframe."],
        "enhancements": ["Enable logging and alerting on unauthorized password manager access attempts."],
        "summary": "Attackers may extract credentials from password managers to gain unauthorized access. Monitoring file access and memory analysis can help detect this activity.",
        "remediation": "Restrict access to password manager-stored credentials and enforce strong authentication measures.",
        "improvements": "Enhance monitoring for password manager-related file access and system calls."
    }