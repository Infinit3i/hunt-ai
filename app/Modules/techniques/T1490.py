def get_content():
    return {
        "id": "T1490",
        "url_id": "T1490",
        "title": "Inhibit System Recovery",
        "description": "Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery. This may deny access to available backups and recovery options. Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features. Adversaries may disable or delete system recovery features to augment the effects of data destruction and encryption. They may also disable recovery notifications and corrupt backups.",
        "tags": ["system recovery", "ransomware", "backup deletion"],
        "tactic": "Impact",
        "protocol": "",
        "os": "Containers, IaaS, Linux, Network, Windows, macOS",
        "tips": [
            "Monitor for execution of utilities like vssadmin, wbadmin, and diskshadow.",
            "Audit registry keys related to recovery and backup settings.",
            "Alert on backup deletions or snapshot removals in cloud environments."
        ],
        "data_sources": "Cloud Storage, Command, File, Process, Service, Snapshot, Windows Registry",
        "log_sources": [
            {"type": "Process", "source": "Sysmon", "destination": ""},
            {"type": "Snapshot", "source": "Cloud Storage", "destination": ""},
            {"type": "Windows Registry", "source": "Windows Security", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Event Logs", "location": "System", "identify": "Event ID 524 - catalog deletion"},
            {"type": "Registry Hives", "location": "HKCU\\Software\\Policies\\Microsoft\\PreviousVersions", "identify": "Recovery feature flags"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Track command-line activity of recovery utilities.",
            "Monitor snapshot and backup deletions in IaaS/cloud environments.",
            "Audit registry and policy changes affecting backup and restore."
        ],
        "apt": [
            "WannaCry", "Avaddon", "Black Basta", "Ryuk", "EKANS", "REvil", "Babuk", "Hermetic Wiper", "DarkWatchman"
        ],
        "spl_query": [
            "index=win_logs Image=*\\vssadmin.exe* OR *\\wbadmin.exe* OR *\\diskshadow.exe* CommandLine=*delete*\n| stats count by Image, CommandLine, host",
            "index=cloud_logs event_type=snapshot_deletion\n| stats count by user, resource, region"
        ],
        "hunt_steps": [
            "Search for execution of recovery-disabling utilities.",
            "Check cloud logs for snapshot or backup deletion actions.",
            "Review policy/configuration changes affecting restore mechanisms."
        ],
        "expected_outcomes": [
            "Backups and shadow copies are deleted.",
            "Recovery environment is disabled, preventing system recovery.",
            "Snapshots or cloud recovery images removed."
        ],
        "false_positive": "System administrators may run backup maintenance tasks—correlate with change records or expected admin behavior.",
        "clearing_steps": [
            "Re-enable system recovery settings via registry or command-line tools.",
            "Restore lost backups from secure offsite locations.",
            "Audit and clean up malicious tools/scripts that altered recovery settings."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-ransomware"
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1486", "example": "Deleting backups before ransomware encryption."},
            {"tactic": "Defense Evasion", "technique": "T1562", "example": "Disabling shadow copy service."}
        ],
        "watchlist": [
            "Execution of vssadmin, wbadmin, diskshadow with delete parameters.",
            "Cloud user actions deleting backups or snapshots.",
            "Registry entries that disable recovery UI or options."
        ],
        "enhancements": [
            "Implement role-based controls and alerts for snapshot management.",
            "Cross-correlate backup deletion with malware alerts or ransom notes."
        ],
        "summary": "Disabling recovery tools and deleting backups prevents organizations from restoring affected systems, increasing the damage inflicted by ransomware or destructive malware.",
        "remediation": "Reconfigure recovery settings, restore valid backups, and deploy monitoring to prevent unauthorized deletion of recovery data.",
        "improvements": "Harden backup infrastructure, replicate backups offsite/offline, and monitor for system utility misuse.",
        "mitre_version": "16.1"
    }
