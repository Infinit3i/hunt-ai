def get_content():
    return {
        "id": "T1219.001",
        "url_id": "T1219/001",
        "title": "IDE Tunneling",
        "description": "Adversaries may abuse Integrated Development Environment (IDE) software with remote development features to establish an interactive command and control channel on target systems within a network.",
        "tags": ["c2", "persistence", "vscode", "tunnel", "devtunnel", "remote access", "ssh", "ide"],
        "tactic": "command-and-control",
        "protocol": "HTTPS, SSH",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Restrict tunnel creation to approved users and devices via group policies.",
            "Monitor file creation within .vscode-cli or equivalent directories.",
            "Review use of CLI tunnel commands on endpoints outside developer environments."
        ],
        "data_sources": "File, Network Traffic, Process",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "%USERPROFILE%\\.vscode-cli\\code_tunnel.json", "identify": "Tunnel configuration file indicating persistent remote session"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall/Proxy", "identify": "Outbound traffic to *.tunnels.api.visualstudio.com or *.devtunnels.ms"}
        ],
        "detection_methods": [
            "Monitor for code_tunnel.json creation events.",
            "Track process execution involving code.exe or jetbrains-gateway with tunnel arguments.",
            "Detect network traffic to known Visual Studio Dev Tunnel domains."
        ],
        "apt": [],
        "spl_query": [
            "sourcetype=\"WinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=11(file_path=\"\\.vscode-cli\\code_tunnel.json\" OR file_path=\"/.vscode-cli/code_tunnel.json\")\n| stats min(_time) as creation_time by host, user, file_path\n| sort creation_time",
            "sourcetype=\"stream:http\" OR sourcetype=\"stream:tcp\"(dest_domain=\".tunnels.api.visualstudio.com\" OR dest_domain=\".devtunnels.ms\")\n| stats count by _time, src_ip, dest_ip, dest_domain, uri_path\n| sort _time desc",
            "sourcetype=\"WinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1(Image=\"\\code.exe\" OR Image=\"/code\" OR Image=\"/jetbrains-gateway\" OR Image=\"/ssh\")(CommandLine=\"tunnel\" OR CommandLine=\"--remote\" OR CommandLine=\"-R\" OR CommandLine=\"-L\" OR CommandLine=\"-D*\")\n| table _time, host, user, Image, CommandLine, ParentImage\n| sort _time desc"
        ],
        "hunt_steps": [
            "Search for tunnel-related CLI commands executed by code or ssh.",
            "Monitor file system for persistent tunneling configuration artifacts.",
            "Flag outbound connections to Visual Studio or JetBrains tunneling endpoints."
        ],
        "expected_outcomes": [
            "Detection of tunneled sessions initiated via IDEs for remote access or lateral movement."
        ],
        "false_positive": "Legitimate developers may use tunneling features for remote coding. Validate by user role and endpoint context.",
        "clearing_steps": [
            "Delete the .vscode-cli directory and code_tunnel.json file.",
            "Block tunneling traffic using domain and IP filtering.",
            "Restrict or remove dev tunnel feature via group policy."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "command-and-control", "technique": "T1219", "example": "Remote Access Tools"},
            {"tactic": "persistence", "technique": "T1176.002", "example": "IDE Extensions"}
        ],
        "watchlist": [
            "Outbound connections to *.devtunnels.ms or *.tunnels.api.visualstudio.com",
            "code.exe with 'tunnel' arguments launched outside development work hours"
        ],
        "enhancements": [
            "Log Visual Studio Dev Tunnel settings and use policy-based controls.",
            "Monitor extension installation events for auto-tunneling plugins."
        ],
        "summary": "IDE Tunneling enables attackers to establish covert remote sessions through development tools like VSCode, often evading traditional detection mechanisms.",
        "remediation": "Restrict IDE tunnel creation to approved users and tenants. Monitor for config artifacts and tunnel traffic.",
        "improvements": "Improve telemetry collection around IDE execution, CLI flags, and associated network destinations.",
        "mitre_version": "17.0"
    }
