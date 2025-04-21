def get_content():
    return {
        "id": "T1564.012",
        "url_id": "T1564/012",
        "title": "Hide Artifacts: File/Path Exclusions",
        "description": "Adversaries may hide malicious files in paths or filenames that are excluded from scanning by antivirus (AV) or other security tools. These exclusions are often configured to reduce performance impact or to avoid false positives in known trusted directories. Instead of modifying tool settings to add new exclusions, adversaries can drop payloads into directories that are already whitelisted. These paths may include locations like update folders, logging directories, or tool-specific cache areas. Using [Security Software Discovery](https://attack.mitre.org/techniques/T1518/001), adversaries may identify exclusions and verify which folders avoid inspection.",
        "tags": ["AV exclusions", "default exclusion abuse", "file hiding", "Evasion", "payload placement"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Identify folders known to be excluded from scans (e.g., AV log/cache directories)",
            "Use file integrity monitoring to track high-value or ignored paths",
            "Alert on suspicious binaries created in common exclusion directories"
        ],
        "data_sources": "File: File Creation",
        "log_sources": [
            {"type": "File", "source": "EDR or File Integrity Logs", "destination": ""},
            {"type": "Command", "source": "Security tool config audit", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "AV exclusion directory", "identify": "Suspicious executables or scripts"},
            {"type": "Command", "location": "Security audit logs", "identify": "Discovery of exclusion policy via tool queries"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "AV scan exclusion paths", "identify": "Dropped malware or payload"},
            {"type": "Log", "location": "Security tool audit trail", "identify": "No alert despite file creation in excluded path"}
        ],
        "detection_methods": [
            "Track file creation in known excluded directories",
            "Audit known exclusion settings across endpoint security tools",
            "Detect unusual binaries or script execution from otherwise trusted directories"
        ],
        "apt": [
            "Turla (Lunar toolset)"
        ],
        "spl_query": [
            "index=sysmon EventCode=11 \n| search TargetFilename=\"*\\ProgramData\\*\" OR TargetFilename=\"*\\Temp\\*\" OR TargetFilename=\"*\\AVExcluded\\*\" \n| stats count by TargetFilename, User, Image",
            "index=edr_logs event_type=write_file \n| lookup exclusion_paths path AS file_path OUTPUT exclusion_reason \n| where isnotnull(exclusion_reason) \n| stats count by file_path, process_name"
        ],
        "hunt_steps": [
            "List all folders commonly excluded by AV or EDR tools (via config inspection)",
            "Scan these folders for executable content and recent file creation timestamps",
            "Compare access and modification patterns against expected software behaviors"
        ],
        "expected_outcomes": [
            "Malicious files discovered in AV exclusion paths",
            "File creation in paths normally exempt from security scans",
            "No alerts triggered despite high-risk file activity"
        ],
        "false_positive": "Backup agents, legitimate software updaters, and admin scripts may write to excluded folders. Contextual analysis is required.",
        "clearing_steps": [
            "Remove malware from exclusion path and restore file integrity",
            "Temporarily disable exclusion to run a full scan of the directory",
            "Reassess and update exclusion policies"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-exclusions-microsoft-defender-antivirus"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.001", "example": "Avoiding detection via default AV exclusion abuse"},
            {"tactic": "Discovery", "technique": "T1518.001", "example": "Identifying security software exclusions on the system"}
        ],
        "watchlist": [
            "File creation or execution from AV exclusion paths",
            "Audit events showing discovery of tool configuration",
            "Repeated writes to trusted folders from untrusted sources"
        ],
        "enhancements": [
            "Use FIM (File Integrity Monitoring) tools on exclusion directories",
            "Add decoy or honeyfiles to common exclusions to catch misuse",
            "Enforce AV scans even on excluded paths during incident response"
        ],
        "summary": "Adversaries can bypass detection by placing payloads in known AV or EDR scan exclusion directories. This allows execution and persistence with minimal risk of triggering alerts. The abuse of pre-existing trusted paths avoids the need for direct tool modification.",
        "remediation": "Review and validate all exclusion lists regularly. Eliminate unnecessary exclusions and monitor allowed folders for high-privilege access or unauthorized writes.",
        "improvements": "Use anomaly-based detection to flag new files or executables in historically benign paths. Enhance threat models to include abuse of default exclusions.",
        "mitre_version": "16.1"
    }
