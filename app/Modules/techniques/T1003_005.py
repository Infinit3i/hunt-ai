def get_content():
    return {
        "id": "T1003.005",
        "url_id": "T1003/005",
        "title": "OS Credential Dumping: Cached Domain Credentials",
        "description": "Adversaries may extract cached domain credentials stored on endpoints for offline password cracking.",
        "tags": ["cached credentials", "mimikatz", "dcc2", "sssd", "vas", "tdbdump", "offline cracking"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Linux, Windows",
        "tips": [
            "Limit cached logon credentials via GPO to reduce exposure",
            "Use protected user security groups to prevent caching",
            "Monitor for access to SSSD or VAS caches on Linux endpoints"
        ],
        "data_sources": "Command",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "/var/lib/sss/db/cache.[domain].ldb", "identify": "SSSD credential cache (Linux)"},
            {"type": "File", "location": "/var/opt/quest/vas/authcache/vas_auth.vdb", "identify": "Quest VAS credential cache (Linux)"},
            {"type": "File", "location": "HKLM\\SECURITY\\Cache", "identify": "Cached logon entries on Windows (DCC2 hashes)"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect use of tools like Mimikatz, secretsdump.py, Linikatz, or tdbdump",
            "Monitor access or export of registry keys under HKLM\\SECURITY\\Cache",
            "Track file access to SSSD or VAS cache files on Linux systems"
        ],
        "apt": [
            "APT1", "APT33", "APT34", "APT35", "Elfin", "Leafminer", "MuddyWater", "Okrum", "OilRig"
        ],
        "spl_query": [
            'index=windows_logs sourcetype=WinRegistry registry_path="HKLM\\\\SECURITY\\\\Cache"',
            'index=linux_logs process_name="tdbdump" OR file_path="*/cache.*.ldb"',
            'index=windows_logs command_line="*Invoke-Mimikatz*" OR command_line="*secretsdump.py*"'
        ],
        "hunt_steps": [
            "Identify usage of credential dumping tools targeting cached creds",
            "Check registry access to HKLM\\SECURITY\\Cache on Windows systems",
            "Review Linux auth cache file access under /var/lib/sss or /var/opt/quest"
        ],
        "expected_outcomes": [
            "Detection of cached credential dumping activity",
            "Identification of files targeted for offline password cracking",
            "Increased risk of credential reuse and privilege escalation"
        ],
        "false_positive": "Legitimate backup or forensic activity may touch auth cache files. Validate via user and execution context.",
        "clearing_steps": [
            "Delete unauthorized dumps or tools",
            "Purge cached credentials using `secpol.msc` or group policies (Windows)",
            "Rotate domain account passwords potentially exposed"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1110.002", "example": "Offline cracking of dumped DCC2 hashes from HKLM\\SECURITY\\Cache"}
        ],
        "watchlist": [
            "Access to HKLM\\SECURITY\\Cache",
            "File access to /var/lib/sss/db/cache.*.ldb or /var/opt/quest/vas/authcache",
            "Execution of tdbdump, mimikatz, Linikatz, or secretsdump"
        ],
        "enhancements": [
            "Limit cached credentials to 1 or 0 using GPO",
            "Deploy monitoring on registry access to credential storage keys",
            "Disable unused SSSD or VAS modules in Linux environments"
        ],
        "summary": "Cached domain credentials allow authentication during DC unavailability, but adversaries can dump them and crack hashes offline for credential theft.",
        "remediation": "Purge cached credentials, rotate exposed passwords, and reduce caching via GPO or Linux configuration changes.",
        "improvements": "Enable protected user group policy and reduce the number of stored credentials. Implement Linux hardening to restrict auth cache access.",
        "mitre_version": "16.1"
    }
