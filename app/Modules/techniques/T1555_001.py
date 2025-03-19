def get_content():
    return {
        "id": "T1555.001",
        "url_id": "1555/001",
        "title": "Credentials from Password Stores: Keychain",
        "description": "Adversaries may acquire credentials from Keychain, the macOS credential management system that stores passwords, private keys, certificates, and secure application data. Attackers can access stored credentials via the Keychain Access application or the 'security' command-line utility, potentially decrypting and extracting sensitive information.",
        "tags": ["Credential Access", "Keychain", "macOS Security"],
        "tactic": "Credential Access",
        "protocol": "Local File Access, OS API Calls, System Authentication",
        "os": ["macOS"],
        "tips": [
            "Monitor access to Keychain storage locations.",
            "Detect unauthorized usage of the 'security' command-line utility.",
            "Restrict access to Keychain credentials using strong authentication policies."
        ],
        "data_sources": "File Access, Process Execution, OS API Calls",
        "log_sources": [
            {"type": "File", "source": "Keychain Database Locations", "destination": "File Access Logs"},
            {"type": "Process", "source": "OS API Execution", "destination": "System Logs"},
            {"type": "Command", "source": "Keychain CLI Usage", "destination": "Audit Logs"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "~/Library/Keychains/", "identify": "Extracted Keychain Database"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Memory", "identify": "Decrypted Keychain Credentials"}
        ],
        "detection_methods": [
            "Monitor system calls to Keychain to detect unauthorized access attempts.",
            "Analyze process execution logs for unusual Keychain interactions.",
            "Detect unauthorized execution of 'security dump-keychain' commands."
        ],
        "apt": ["DazzleSpy", "Calisto", "Green Lambert", "Cuckoo"],
        "spl_query": [
            "index=macos (process_name=security OR file_path=~/Library/Keychains/*) | table _time, process_name, file_path, user"
        ],
        "hunt_steps": [
            "Review access logs for unauthorized Keychain access.",
            "Analyze execution history for Keychain credential dumping attempts.",
            "Monitor for suspicious process activity targeting Keychain storage."
        ],
        "expected_outcomes": [
            "Detection of unauthorized attempts to extract Keychain credentials.",
            "Identification of processes attempting credential theft from Keychain."
        ],
        "false_positive": "Legitimate access to Keychain by authorized applications.",
        "clearing_steps": [
            "Investigate unauthorized Keychain access attempts.",
            "Revoke compromised credentials and enforce password rotation.",
            "Implement additional security controls on Keychain access."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "Extract Credentials from macOS Keychain", "example": "An attacker retrieves stored credentials from Keychain via the 'security' CLI."}
        ],
        "watchlist": ["Processes accessing multiple Keychain storage locations in a short timeframe."],
        "enhancements": ["Enable logging and alerting on unauthorized Keychain access attempts."],
        "summary": "Attackers may extract credentials from macOS Keychain to gain unauthorized access. Monitoring file access and process execution can help detect this activity.",
        "remediation": "Restrict access to Keychain-stored credentials and enforce strong authentication measures.",
        "improvements": "Enhance monitoring for Keychain-related file access and system calls."
    }
