def get_content():
    return {
        "id": "T1003.008",
        "url_id": "T1003/008",
        "title": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "description": "Adversaries may dump the contents of /etc/passwd and /etc/shadow files to retrieve user and password hash information for offline cracking.",
        "tags": ["linux", "passwd", "shadow", "unshadow", "offline cracking", "john the ripper"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Linux",
        "tips": [
            "Use AuditD to monitor access to /etc/passwd and /etc/shadow",
            "Alert on usage of tools like unshadow or john",
            "Restrict file permissions and ensure /etc/shadow is only accessible by root"
        ],
        "data_sources": "Sysmon, Command, File",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "/etc/passwd", "identify": "Contains usernames and UID mappings"},
            {"type": "File", "location": "/etc/shadow", "identify": "Contains password hashes for local user accounts"},
            {"type": "File", "location": "/tmp/crack.password.db", "identify": "Generated output for password cracking tools"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect access to /etc/shadow by non-root users",
            "Monitor for use of unshadow or file creation in /tmp that resembles cracking databases",
            "Identify use of cracking tools such as John the Ripper"
        ],
        "apt": [
            "APT33", "LaZagne"
        ],
        "spl_query": [
            'index=linux_logs file_path="/etc/shadow" OR file_path="/etc/passwd" AND user!="root"',
            'index=linux_logs command_line="*unshadow*" OR command_line="*john*"'
        ],
        "hunt_steps": [
            "Identify access to /etc/shadow and /etc/passwd outside normal authentication routines",
            "Search for cracking file output like /tmp/crack.password.db",
            "Correlate with usage of password cracking utilities"
        ],
        "expected_outcomes": [
            "Detection of attempts to harvest and crack local Linux account credentials",
            "Alert on suspicious access to restricted files"
        ],
        "false_positive": "Legitimate system processes read /etc/passwd. False positives are rare for /etc/shadow unless misconfigured or root script runs.",
        "clearing_steps": [
            "Delete any dumped or unshadowed files containing password hashes",
            "Rotate passwords of any accounts suspected to be compromised",
            "Review file permission settings on /etc/shadow"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1110.002", "example": "Cracking password hashes from /etc/shadow using John the Ripper"}
        ],
        "watchlist": [
            "Access to /etc/shadow",
            "Use of unshadow or creation of cracking input files in temp directories",
            "Presence of password cracking tools like john"
        ],
        "enhancements": [
            "Harden file permissions and audit access to sensitive files",
            "Use AppArmor or SELinux to restrict file access to critical system files",
            "Deploy password hash cracking detection logic in EDR or SIEM"
        ],
        "summary": "Adversaries may read /etc/passwd and /etc/shadow files to gather password hashes and perform offline cracking using tools like unshadow and john.",
        "remediation": "Re-secure permissions, rotate compromised credentials, and clean up any password cracking artifacts.",
        "improvements": "Enforce stricter privilege separation, monitor for file access anomalies, and deploy alerts for cracking activity.",
        "mitre_version": "16.1"
    }
