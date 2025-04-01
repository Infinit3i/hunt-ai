def get_content():
    return {
        "id": "T1552.004",
        "url_id": "T1552/004",
        "title": "Unsecured Credentials: Private Keys",
        "description": "Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials.",
        "tags": ["credentials", "private keys", "ssh", "certificates", "crypto", "infostealer"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Store private keys in secure containers or vaults with proper permissions.",
            "Implement file access monitoring for key file extensions.",
            "Use multi-factor authentication instead of key-only authentication when possible."
        ],
        "data_sources": "Command, File",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "~/.ssh/, C:\\Users\\<user>\\.ssh\\", "identify": "Access to private key files"},
            {"type": "Windows Defender Logs", "location": "Microsoft-Windows-Windows Defender/Operational", "identify": "Detection of file collection tools or suspicious access"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "SSH, SFTP logs", "identify": "Use of stolen keys for remote authentication"},
            {"type": "Sysmon Logs", "location": "Event ID 11", "identify": "Remote file access of private key file extensions"}
        ],
        "detection_methods": [
            "File access monitoring for `.key`, `.pem`, `.ppk`, and related file extensions",
            "Command-line monitoring for keyword searches like `find`, `cat`, `scp` on key paths",
            "Monitor network devices for `crypto pki export` or similar commands"
        ],
        "apt": [
            "Hildegard", "Adwind", "PowerShell Empire", "Kinsing", "Rocke", "Wocao", "FoggyWeb", "TeamTNT",
            "Metador", "Solorigate", "Machete", "Ebury", "Scattered Spider"
        ],
        "spl_query": [
            'index=* process_name IN ("cat", "find", "scp") file_path="*.pem" OR file_path="*.key" OR file_path="*.ppk"\n| stats count by host, user, file_path, process_name',
            'index=* file_path IN ("*.pem", "*.key", "*.ppk", "*.pfx", "*.asc") action=read\n| stats count by file_path, host, user'
        ],
        "hunt_steps": [
            "Hunt for use of `find` or `cat` commands targeting key directories or extensions.",
            "Check for abnormal access patterns to `.ssh`, `.pfx`, or `.pem` files.",
            "Review AAA logs on network devices for key export attempts."
        ],
        "expected_outcomes": [
            "Detection of adversary accessing or copying private key material",
            "Identification of key-based lateral movement or external authentication"
        ],
        "false_positive": "Backup operations or admin scripts may touch key files; confirm via user behavior and context.",
        "clearing_steps": [
            "Rotate all private keys that may have been accessed.",
            "Invalidate any active sessions or tokens using the compromised keys.",
            "Audit and remove improper key storage across the environment."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1021.004", "example": "Using stolen SSH private keys for access"},
            {"tactic": "Collection", "technique": "T1119", "example": "Collecting private key files for later use or exfiltration"}
        ],
        "watchlist": [
            "*.pem", "*.ppk", "*.pfx", "*.key", "crypto pki export", "~/.ssh/id_rsa", "C:\\Users\\*\\.ssh\\id_rsa"
        ],
        "enhancements": [
            "Use full-disk encryption and enforce strong ACLs on sensitive key files",
            "Alert on access to private keys outside of approved automation accounts"
        ],
        "summary": "Adversaries may collect improperly stored private keys and use them for authentication, decryption, or digital signatures.",
        "remediation": "Secure all private keys using vaults or encrypted containers and monitor file access logs to detect misuse.",
        "improvements": "Implement agent-based monitoring to flag key file access and correlate with suspicious remote logins.",
        "mitre_version": "16.1"
    }
