def get_content():
    return {
        "id": "T1070.007",
        "url_id": "T1070/007",
        "title": "Indicator Removal: Clear Network Connection History and Configurations",
        "description": "Adversaries may clear or remove evidence of malicious network connections in order to clean up traces of their operations. Configuration settings as well as various artifacts that highlight connection history may be created on a system and/or in application logs from behaviors that require network connections, such as Remote Services or External Remote Services.",
        "tags": ["defense evasion", "network history", "rdp", "firewall", "registry", "macOS", "linux", "windows"],
        "tactic": "defense-evasion",
        "protocol": "",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor deletion or modification of known RDP registry keys",
            "Alert on deletion of Default.rdp or cache folder files",
            "Detect abnormal firewall configuration changes or clearing"
        ],
        "data_sources": "Windows Registry, File, Firewall, Command, Process",
        "log_sources": [
            {"type": "Windows Registry", "source": "source", "destination": ""},
            {"type": "File", "source": "source", "destination": ""},
            {"type": "Firewall", "source": "source", "destination": ""},
            {"type": "Command", "source": "source", "destination": ""},
            {"type": "Process", "source": "source", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Registry", "location": "HKCU\\Software\\Microsoft\\Terminal Server Client", "identify": "RDP connection history"},
            {"type": "File", "location": "C:\\Users\\%username%\\Documents\\Default.rdp", "identify": "RDP connection history"},
            {"type": "File", "location": "C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\", "identify": "RDP cache files"},
            {"type": "File", "location": "/var/log/", "identify": "SSH or remote login history on Linux"},
            {"type": "File", "location": "/Library/Logs/", "identify": "Remote login history on macOS"}
        ],
        "destination_artifacts": [
            {"type": "", "location": "", "identify": ""}
        ],
        "detection_methods": [
            "Monitor for deletion of known RDP files and registry keys",
            "Alert on cleared system logs relating to remote connections",
            "Detect use of firewall or proxy modifications shortly after remote access"
        ],
        "apt": ["BRONZE SILHOUETTE", "Nobelium"],
        "spl_query": [
            "index=win_logs EventCode=4663 Object_Name=\"*Default.rdp\" Accesses=\"DELETE\" \n| stats count by Account_Name, Object_Name, Accesses",
            "index=win_registry registry_path=\"*Terminal Server Client*\" action=deleted \n| stats count by user, registry_path",
            "index=firewall_logs rule_deleted=true \n| stats count by host, user, rule_name"
        ],
        "hunt_steps": [
            "Review logs for deletion of Default.rdp and RDP registry keys",
            "Hunt for abnormal firewall changes not tied to admin activity",
            "Check for script activity altering or clearing remote login logs"
        ],
        "expected_outcomes": [
            "Deletion or absence of RDP history where previously existed",
            "Firewall rules reset or cleared with no corresponding policy change",
            "Modification of remote login history logs"
        ],
        "false_positive": "System cleanup utilities or scripts may trigger similar deletions. Verify with IT operations or maintenance logs.",
        "clearing_steps": [
            "reg delete \"HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers\" /f",
            "del C:\\Users\\%username%\\Documents\\Default.rdp",
            "del /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\*"
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1562.004", "example": "Disabling system firewall after clearing remote traces"},
            {"tactic": "lateral-movement", "technique": "T1021.001", "example": "Remote desktop connections used prior to indicator removal"},
            {"tactic": "persistence", "technique": "T1090", "example": "Use of proxy to redirect or hide further traffic"}
        ],
        "watchlist": [
            "Repeated deletions of RDP registry keys",
            "Firewall rule changes without admin context",
            "Absence of expected remote connection logs"
        ],
        "enhancements": [
            "Enable auditing on RDP-related registry keys",
            "Create honeypot entries for Default.rdp to alert on deletion",
            "Implement GPO alerts for firewall configuration changes"
        ],
        "summary": "Technique involves adversaries removing network connection history and configuration traces to hide activity. Artifacts targeted include RDP history files, registry keys, system logs, and firewall settings.",
        "remediation": "Reinstate secure firewall policies, restore registry values from backups if applicable, and enable enhanced logging on remote access points.",
        "improvements": "Deploy EDR rules for detection of artifact deletion tied to remote access, implement regular backups and snapshots of user profile artifacts.",
        "mitre_version": "16.1"
    }
