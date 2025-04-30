def get_content():
    return {
        "id": "T1176.002",
        "url_id": "T1176/002",
        "title": "IDE Extensions",
        "description": "Adversaries may abuse an integrated development environment (IDE) extension to establish persistent access to victim systems.",
        "tags": ["persistence", "IDE", "vscode", "jetbrains", "eclipse", "plugin", "malicious extension"],
        "tactic": "persistence",
        "protocol": "",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Restrict IDE extension use to trusted, verified sources.",
            "Audit IDE binaries executed on production systems.",
            "Inspect extension directories for unexpected or recently added plugins."
        ],
        "data_sources": "Process, Network Traffic",
        "log_sources": [
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "%USERPROFILE%\\.vscode\\extensions", "identify": "Suspicious or newly dropped extension folders"},
            {"type": "Process List", "location": "RAM", "identify": "Unexpected IDE launches (e.g., code.exe, idea64.exe)"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall or Proxy Logs", "identify": "Connections to tunneling endpoints or JetBrains cloud APIs"}
        ],
        "detection_methods": [
            "Monitor IDE processes launched on non-development endpoints.",
            "Inspect extension install flags and parent process relationships.",
            "Detect traffic to known tunneling APIs from production zones."
        ],
        "apt": [],
        "spl_query": [
            "sourcetype=zeek:conn_log OR sourcetype=zeek:http_log OR sourcetype=suricata_flow(host=\".tunnels.api.visualstudio.com\" OR host=\".jetbrains.com\")\n| lookup endpoint_asset_zones ip AS src_ip OUTPUT zone\n| where zone=\"prod\" OR zone=\"non-dev\"\n| stats count by src_ip, dest_ip, host, uri_path, http_method, zone, _time\n| sort -_time",
            "sourcetype=WinEventLog:Sysmon EventCode=1(Image=\"\\code.exe\" OR Image=\"\\idea64.exe\" OR Image=\"\\eclipse.exe\" OR Image=\"\\jetbrains-gateway.exe\")\n| eval is_unexpected_host=if(like(Computer, \"%server%\") OR like(Computer, \"%prod%\"), \"yes\", \"no\")\n| stats count by Image, CommandLine, ParentImage, User, Computer, is_unexpected_host, _time\n| where is_unexpected_host=\"yes\"\n| sort -_time"
        ],
        "hunt_steps": [
            "Scan for IDE installations or launches on servers and production systems.",
            "Correlate extension folder creation with binary execution logs.",
            "Check for SSH tunnels or reverse shells invoked by IDE extensions."
        ],
        "expected_outcomes": [
            "Detection of misuse of IDE plugins for persistence or tunneling."
        ],
        "false_positive": "Legitimate developers may use extensions across multiple IDEs. Validate via user role and machine context.",
        "clearing_steps": [
            "Remove malicious plugin folders manually or via IDE extension manager.",
            "Block outbound traffic to suspicious tunnel domains.",
            "Audit IDE installs across endpoint fleet."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "persistence", "technique": "T1176", "example": "Software Extensions"},
            {"tactic": "command-and-control", "technique": "T1572", "example": "Protocol Tunneling"}
        ],
        "watchlist": [
            "Extension installations on non-dev endpoints",
            "IDE binaries launched by cmd.exe or PowerShell"
        ],
        "enhancements": [
            "Monitor extension folder integrity hashes.",
            "Use developer endpoint tagging to separate alerts from prod usage."
        ],
        "summary": "IDE extensions offer attackers a covert route for persistence and tunneling, particularly when installed outside developer environments.",
        "remediation": "Restrict plugin usage through allowlists and monitor network traffic to known IDE services.",
        "improvements": "Baseline extension usage in development environments to detect anomalies elsewhere.",
        "mitre_version": "17.0"
    }
