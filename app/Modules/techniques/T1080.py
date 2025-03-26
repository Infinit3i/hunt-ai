def get_content():
    return {
        "id": "T1080",
        "url_id": "T1080",
        "title": "Taint Shared Content",
        "description": "Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system.",
        "tags": ["lateral movement", "shared content", "tainted binaries", "shortcut modification", "directory pivot"],
        "tactic": "lateral-movement",
        "protocol": "SMB",
        "os": "Linux, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Scan network shares for abnormal file types (.lnk, .vbs, .scr, etc.)",
            "Enable logging for file creation and process execution from shared locations",
            "Use file integrity monitoring on shared folders"
        ],
        "data_sources": "File, Network Share, Process",
        "log_sources": [
            {"type": "File", "source": "source machine", "destination": "destination share"},
            {"type": "Network Share", "source": "", "destination": ""},
            {"type": "Process", "source": "endpoint", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "identify": "Event ID 1, 11, 15, 17"},
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch\\", "identify": ".pf entries of tainted files"},
            {"type": "Amcache", "location": "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "identify": "Execution of malicious binaries"}
        ],
        "destination_artifacts": [
            {"type": "File Access Times", "location": "\\\\SharedDrive\\InfectedFiles\\", "identify": "Recent modification timestamps"},
            {"type": "Shortcut Files (.lnk)", "location": "\\\\SharedDrive\\", "identify": "Suspicious shortcut redirection"},
            {"type": "Registry Hives", "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", "identify": "Recently executed file from share"}
        ],
        "detection_methods": [
            "Detect creation/modification of .lnk files in shared directories",
            "Monitor execution of binaries from shared folders",
            "Behavioral analysis of processes spawned from network drives"
        ],
        "apt": [
            "BRONZE BUTLER", "Gamaredon", "InvisiMole", "RedCurl", "Darkhotel", "Conti"
        ],
        "spl_query": [
            'index=sysmon EventCode=11 \n| where TargetFilename like "\\\\%" AND (TargetFilename like "%.lnk" OR TargetFilename like "%.vbs" OR TargetFilename like "%.exe")',
            'index=sysmon EventCode=1 \n| where Image like "\\\\%" AND (Image like "%.exe" OR Image like "%.bat")',
            'index=wineventlog EventCode=5145 \n| where ShareName="\\\\SharedDrive" AND RelativeTargetName like "%.lnk"'
        ],
        "hunt_steps": [
            "Search for .lnk, .scr, .vbs files in shared network directories",
            "Identify binaries with unusual compile times or entry point modifications",
            "Trace execution chains from files opened on shared drives"
        ],
        "expected_outcomes": [
            "Detection of lateral movement via tainted shared content",
            "Identification of compromised .lnk or executable files",
            "Visibility into which users accessed and executed the malicious content"
        ],
        "false_positive": "Administrators or developers legitimately using shared drives to distribute scripts or tools. Validate file origin and verify digital signatures when applicable.",
        "clearing_steps": [
            "Delete tainted files from shared drives",
            "Restore clean versions from backup",
            "Revoke access permissions to shared content temporarily",
            "Run AV or EDR scans on all machines that accessed the share"
        ],
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1059.001", "example": "Execution of tainted .bat or .vbs file"},
            {"tactic": "defense-evasion", "technique": "T1036", "example": "Masquerading as a legitimate directory or file"},
            {"tactic": "persistence", "technique": "T1547.009", "example": "Shortcut Modification in shared folder"}
        ],
        "watchlist": [
            "Executables in shared folders with recent timestamp changes",
            "Non-standard file extensions in shared directories",
            "Execution of processes from network paths"
        ],
        "enhancements": [
            "Integrate YARA rule scanning of shared folders",
            "Implement application whitelisting for execution from mapped drives",
            "Block execution from network shares unless explicitly allowed"
        ],
        "summary": "Tainting shared content allows adversaries to pivot laterally by planting malware in shared directories that users routinely access, enabling stealthy and automated spread across an enterprise.",
        "remediation": "Limit write permissions to shared folders. Educate users on safe file handling. Use threat detection tools to flag and quarantine modified content in shares.",
        "improvements": "Deploy honeypot shares to attract and detect suspicious activity. Use DLP and behavioral monitoring to detect abnormal file access and modifications.",
        "mitre_version": "16.1"
    }
