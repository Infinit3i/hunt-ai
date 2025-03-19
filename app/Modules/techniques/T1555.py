def get_content():
    return {
        "id": "T1555",
        "url_id": "1555",
        "title": "Credentials from Password Stores",
        "description": "Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in various places depending on the operating system or application, including password managers and cloud secrets vaults. Once credentials are obtained, they can be used for lateral movement and unauthorized access to sensitive information.",
        "tags": ["Credential Access", "Password Stores", "Cloud Secrets Vaults"],
        "tactic": "Credential Access",
        "protocol": "Local File Access, API Calls, System Calls",
        "os": ["Windows", "Linux", "macOS", "IaaS"],
        "tips": [
            "Monitor system calls and file read events for signs of password store access.",
            "Detect processes searching for credentials using keywords like 'password', 'pwd', 'login', 'secure'.",
            "Implement application control to prevent unauthorized access to password storage locations."
        ],
        "data_sources": "File Access, Process Execution, OS API Calls, Cloud Service Enumeration",
        "log_sources": [
            {"type": "File", "source": "Password Storage Locations", "destination": "File Access Logs"},
            {"type": "Process", "source": "OS API Execution", "destination": "System Logs"},
            {"type": "Cloud Service", "source": "Credential Access Logs", "destination": "Audit Logs"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "Local Password Stores", "identify": "Extracted Password Files"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "System Memory", "identify": "Dumped Credentials"}
        ],
        "detection_methods": [
            "Monitor for unauthorized file access in known password storage locations.",
            "Analyze process memory for credential dumping attempts.",
            "Detect unusual API calls to credential management systems."
        ],
        "apt": ["MuddyWater", "Chafer", "The Dukes", "Pupy", "Mimikatz", "EvilNum", "APT41", "Daggerfly", "APT35", "Malteiro", "Operation Groundbait", "APT34", "LaZagne", "Kimsuky", "Volt Typhoon"],
        "spl_query": [
            "index=security (process_name=mimikatz OR file_path=*password*) | table _time, process_name, file_path, user"
        ],
        "hunt_steps": [
            "Review file access logs for attempts to read password storage locations.",
            "Analyze execution history for credential dumping tools.",
            "Monitor for suspicious API calls targeting credential vaults."
        ],
        "expected_outcomes": [
            "Detection of unauthorized attempts to extract stored credentials.",
            "Identification of processes attempting credential theft."
        ],
        "false_positive": "Legitimate administrative access to credential stores.",
        "clearing_steps": [
            "Investigate unauthorized access to password stores.",
            "Revoke compromised credentials and enforce password rotation.",
            "Implement additional security controls on credential storage locations."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "Obtain Credentials from Password Stores", "example": "An attacker extracts stored passwords from a local vault."}
        ],
        "watchlist": ["Processes accessing multiple credential storage locations in a short time frame."],
        "enhancements": ["Enable logging and alerting on unauthorized access to credential storage locations."],
        "summary": "Attackers may extract credentials from stored password locations to gain unauthorized access. Monitoring file access and process execution can help detect this activity.",
        "remediation": "Restrict access to password stores and enforce strong authentication mechanisms.",
        "improvements": "Enhance monitoring for credential-related file access and system calls."
    }
