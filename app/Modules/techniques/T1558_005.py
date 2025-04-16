def get_content():
    return {
        "id": "T1558.005",
        "url_id": "T1558/005",
        "title": "Steal or Forge Kerberos Tickets: Ccache Files",
        "description": "Adversaries may steal Kerberos tickets stored in credential cache (ccache) files, which hold short-term session credentials. These files enable service access without re-authentication and can be exploited to impersonate users, escalate privileges, or move laterally within a network.",
        "tags": ["ccache", "kerberos", "ticket theft", "pass-the-ticket", "linux", "macos", "privilege escalation"],
        "tactic": "Credential Access",
        "protocol": "Kerberos",
        "os": "Linux, macOS",
        "tips": [
            "Monitor access to sensitive files such as krb5cc_* under /tmp.",
            "Track use of tools like klist, kinit, and custom scripts interacting with credential caches.",
            "Detect unusual exports of KRB5CCNAME environment variable or access by root where not expected."
        ],
        "data_sources": "File",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "/tmp/krb5cc_*", "identify": "Timestamps showing unauthorized access"},
            {"type": "Environment Variables", "location": "/proc/<pid>/environ", "identify": "KRB5CCNAME variable set to unusual file paths"},
            {"type": "Process List", "location": "Memory", "identify": "Suspicious processes like `linikatz` or `klist`"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "/tmp or /var/tmp", "identify": "Credential cache files copied to attacker-controlled paths"},
            {"type": "Memory Dumps", "location": "/dev/shm or tmpfs", "identify": "Stolen ticket artifacts loaded into memory"}
        ],
        "detection_methods": [
            "Monitor file access to `/tmp/krb5cc_*`, especially by unexpected users",
            "Detect execution of binaries like `klist`, `kinit`, or `linikatz` by non-interactive shells",
            "Alert on export of `KRB5CCNAME` with external file paths or strange process ancestry"
        ],
        "apt": ["APT28", "UNC1945"],
        "spl_query": [
            "index=linux_logs sourcetype=syslog \"krb5cc\" \n| stats count by user, process, path",
            "index=linux_logs command=\"*klist*\" OR command=\"*kinit*\" OR command=\"*linikatz*\" \n| stats count by user, command"
        ],
        "hunt_steps": [
            "List all krb5cc_* files in /tmp and correlate access timestamps",
            "Enumerate active processes with access to credential caches",
            "Check for KRB5CCNAME environment variable abuse in /proc/<pid>/environ"
        ],
        "expected_outcomes": [
            "Discovery of stolen Kerberos tickets stored in ccache",
            "Detection of privilege escalation or lateral movement using pass-the-ticket"
        ],
        "false_positive": "Legitimate users and system daemons may access ccache files. Use process ancestry and user context for validation.",
        "clearing_steps": [
            "Purge all krb5cc_* files using `kdestroy` or manual deletion",
            "Reboot impacted hosts to clear memory-resident credentials",
            "Rotate associated Kerberos credentials and monitor for reuse"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1550.003", "example": "Use of stolen ccache in pass-the-ticket attacks"},
            {"tactic": "Lateral Movement", "technique": "T1550.003", "example": "Kerberos ticket reuse across hosts"},
            {"tactic": "Privilege Escalation", "technique": "T1548.003", "example": "Impersonation of privileged users via cached tickets"}
        ],
        "watchlist": [
            "Unexpected access to krb5cc_* or krb5.ccache",
            "Environment variable KRB5CCNAME set to external or suspicious values"
        ],
        "enhancements": [
            "Apply filesystem auditing on /tmp and /var/tmp",
            "Enforce Kerberos ticket expiration with short TTL policies",
            "Limit access to credential cache files via system hardening"
        ],
        "summary": "Ccache files store Kerberos tickets in plaintext on disk or memory. Adversaries who gain access can extract or reuse these tickets to impersonate users or escalate privileges, especially in Linux/macOS environments.",
        "remediation": "Regularly purge expired Kerberos tickets, apply strict file access controls, and monitor high-value directories like `/tmp`.",
        "improvements": "Automate rotation of Kerberos tickets and enforce use of secure memory-only credential caches when possible.",
        "mitre_version": "16.1"
    }
