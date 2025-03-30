def get_content():
    return {
        "id": "T1505",
        "url_id": "T1505",
        "title": "Server Software Component",
        "description": "Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application.",
        "tags": ["persistence", "server abuse", "plugin", "web shell", "extensibility", "component injection"],
        "tactic": "Persistence",
        "protocol": "",
        "os": "Windows, Linux, macOS, Network",
        "tips": [
            "Monitor for installation or loading of non-standard application plugins or extensions.",
            "Restrict write access to directories used for server extensibility.",
            "Audit server-side code repositories and config files for unauthorized changes.",
            "Consider application whitelisting for known-good server-side components."
        ],
        "data_sources": "Application Log, File, Network Traffic, Process",
        "log_sources": [
            {"type": "Application Log", "source": "Application Log Content", "destination": ""},
            {"type": "File", "source": "File Creation", "destination": ""},
            {"type": "File", "source": "File Modification", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Content", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "Web server root or plugin folders", "identify": "Unexpected modification timestamps"},
            {"type": "Process List", "location": "Server runtime environment", "identify": "Unexpected child processes (e.g., cmd.exe from a server binary)"},
            {"type": "Registry Hives (NTUSER.DAT, SYSTEM, SOFTWARE, etc.)", "location": "Windows servers", "identify": "Persistence registry keys for custom modules"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "/var/www, /opt/plugins, Program Files\\Web\\Plugins", "identify": "Malicious plugin or web shell dropped"},
            {"type": "Network Connections", "location": "Web application traffic logs", "identify": "Out-of-pattern C2 callbacks from server"},
            {"type": "Windows Defender Logs", "location": "Event Viewer", "identify": "Detection of suspicious DLLs or scripts in server folders"}
        ],
        "detection_methods": [
            "Monitor plugin directories for unauthorized changes or suspicious file additions.",
            "Use file integrity monitoring to detect unauthorized modification to server application files.",
            "Detect suspicious child processes spawned by server binaries (e.g., cmd, powershell, bash).",
            "Inspect server logs for authentication anomalies or plugin initialization from external sources."
        ],
        "apt": ["UNC2447", "APT28", "OceanLotus"],
        "spl_query": [
            'index=app_logs sourcetype=application\n| search "plugin loaded" OR "component initialized"\n| stats count by component_name, user\n| where count > 5',
            'index=os_logs sourcetype=process_creation\n| search parent_process_name IN ("httpd", "nginx", "java", "tomcat") AND process_name IN ("cmd.exe", "powershell.exe", "bash")\n| stats count by host, parent_process_name, process_name',
            'index=network_traffic sourcetype=flow\n| search dest_port=443 OR dest_port=80\n| stats count by dest_ip, uri_path\n| where uri_path IN ("/plugin/update", "/admin/shell")'
        ],
        "hunt_steps": [
            "Check for recently installed or modified plugins across all server endpoints.",
            "Scan plugin directories and web root folders for web shells or backdoors.",
            "Validate hashes of all installed components against known-good baselines.",
            "Review all processes spawned by server applications for suspicious behavior."
        ],
        "expected_outcomes": [
            "Discovery of unauthorized plugins or modules injected into production servers.",
            "Detection of persistent access via extensible server-side interfaces.",
            "Identification of attacker-controlled web shells or malicious server-side scripts."
        ],
        "false_positive": "Legitimate administrator tasks such as plugin updates or server patching can mimic indicators. Validate via change control records and known hashes.",
        "clearing_steps": [
            "Remove unauthorized components from server directories.",
            "Restart impacted services to clear memory-resident payloads.",
            "Review and roll back recent changes or deployments to affected server.",
            "Rebuild server with verified, clean images if full compromise is suspected."
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-web-shell"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Malicious script executed through plugin"},
            {"tactic": "Persistence", "technique": "T1505.003", "example": "Web server components abused for long-term access"},
            {"tactic": "Defense Evasion", "technique": "T1036.005", "example": "Malicious DLL masquerading as legitimate plugin"}
        ],
        "watchlist": [
            "New files in server plugin or module directories",
            "Server processes spawning shells or scripting interpreters",
            "Unusual outbound connections from server binaries",
            "Frequent loading of unknown plugin components"
        ],
        "enhancements": [
            "Whitelist approved plugins and monitor installation paths.",
            "Use endpoint detection and response (EDR) to correlate process trees.",
            "Deploy host-based firewalls to block unauthorized outbound traffic from servers."
        ],
        "summary": "Server Software Component techniques exploit extensible features in enterprise software to maintain access, execute payloads, or establish persistence. Attackers leverage these vectors because they blend in with legitimate application behavior.",
        "remediation": "Remove rogue server extensions, perform a security audit on server configuration, and enforce change management controls for plugins.",
        "improvements": "Automate integrity checks of plugin directories, correlate plugin loading with known threat signatures, and isolate extensible components in sandboxed environments.",
        "mitre_version": "16.1"
    }
