def get_content():
    return {
        "id": "T1555.003",
        "url_id": "1555/003",
        "title": "Credentials from Password Stores: Credentials from Web Browsers",
        "description": "Adversaries may acquire credentials from web browsers by extracting data from browser-specific storage locations. Web browsers commonly store credentials such as usernames and passwords in encrypted databases or credential stores. Attackers can extract these credentials by accessing local storage files, querying databases, or decrypting password data using OS-specific functions.",
        "tags": ["Credential Access", "Web Browsers", "Password Extraction"],
        "tactic": "Credential Access",
        "protocol": "Local File Access, OS API Calls, Process Memory Scanning",
        "os": ["Windows", "Linux", "macOS"],
        "tips": [
            "Monitor access to browser credential storage files.",
            "Detect processes querying browser credential databases.",
            "Restrict access to browser-stored passwords through policy enforcement."
        ],
        "data_sources": "File Access, Process Execution, OS API Calls",
        "log_sources": [
            {"type": "File", "source": "Browser Storage Locations", "destination": "File Access Logs"},
            {"type": "Process", "source": "OS API Execution", "destination": "System Logs"},
            {"type": "Command", "source": "Credential Dumping Commands", "destination": "Audit Logs"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "Browser Credential Storage", "identify": "Extracted Password Databases"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Memory", "identify": "Dumped Browser Credentials"}
        ],
        "detection_methods": [
            "Monitor file access logs for unauthorized access to browser storage files.",
            "Detect unexpected execution of SQL queries on browser credential databases.",
            "Analyze process memory dumps for credential data patterns."
        ],
        "apt": ["MuddyWater", "Konni", "Inception Framework", "Kimsuky", "Lizar", "QakBot", "OilRig", "Lyceum", "Mimikittenz", "APT41", "Daggerfly", "NETWIRE", "Grandoreiro", "APT35"],
        "spl_query": [
            "index=security (file_path=*Login Data* OR process_name=*sqlite3* OR process_name=*chrome*) | table _time, file_path, process_name, user"
        ],
        "hunt_steps": [
            "Review file access logs for attempts to read browser credential storage.",
            "Analyze execution history for credential dumping tools.",
            "Monitor process memory for suspicious access to web browser credentials."
        ],
        "expected_outcomes": [
            "Detection of unauthorized attempts to extract stored browser credentials.",
            "Identification of processes attempting credential theft from web browsers."
        ],
        "false_positive": "Legitimate user access to stored browser credentials.",
        "clearing_steps": [
            "Investigate unauthorized access to browser credential storage.",
            "Revoke compromised credentials and enforce password rotation.",
            "Implement additional security controls on browser-stored passwords."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "Extract Credentials from Web Browsers", "example": "An attacker retrieves stored credentials from Chrome's Login Data database."}
        ],
        "watchlist": ["Processes accessing multiple browser credential storage locations in a short timeframe."],
        "enhancements": ["Enable logging and alerting on unauthorized access to browser credential storage locations."],
        "summary": "Attackers may extract credentials from web browsers to gain unauthorized access. Monitoring file access and process execution can help detect this activity.",
        "remediation": "Restrict access to browser-stored credentials and enforce secure password management policies.",
        "improvements": "Enhance monitoring for credential-related file access and system calls."
    }
