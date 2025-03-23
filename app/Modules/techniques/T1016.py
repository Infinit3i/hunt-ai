def get_content():
    return {
        "id": "T1016",
        "url_id": "T1016",
        "title": "System Network Configuration Discovery",
        "description": "Adversaries may gather information about the network configuration and settings of systems to inform later actions.",
        "tags": ["network discovery", "ipconfig", "route", "nbtstat", "arp", "network enumeration", "discovery"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Baseline normal use of network configuration commands.",
            "Alert on execution of networking tools by unusual users or paths.",
            "Use script block logging to capture PowerShell-based reconnaissance."
        ],
        "data_sources": "Command, Process, Script",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Script", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "~/.bash_history", "identify": "Use of ifconfig, ip a, or route"},
            {"type": "Script", "location": "C:\\Users\\<User>\\AppData\\Local\\Temp", "identify": "Custom scripts containing netstat, ipconfig"},
            {"type": "PowerShell Logs", "location": "Event ID 4104", "identify": "Network-related discovery commands"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "Windows Security/Event Logs", "identify": "Newly spawned cmd.exe or PowerShell processes"},
            {"type": "Network Connections", "location": "/proc/net/route or netstat", "identify": "Exposed routing or interface data"},
            {"type": "Process List", "location": "tasklist or ps", "identify": "Suspicious parent-child relationships for discovery commands"}
        ],
        "detection_methods": [
            "Monitor execution of commands like ipconfig, ifconfig, netstat, arp, nbtstat",
            "Detect command line flags used for advanced or verbose output",
            "Alert on PowerShell script execution that includes networking modules or net adapter enumeration",
            "Monitor usage of network CLI tools on non-network device endpoints"
        ],
        "apt": ["APT10", "APT34", "Turla", "MuddyWater", "APT41", "APT28", "Kimsuky"],
        "spl_query": [
            'index=windows_logs source="WinEventLog:Security" EventCode=4688 \n| search CommandLine="*ipconfig*" OR CommandLine="*nbtstat*" OR CommandLine="*netstat*"',
            'index=sysmon EventCode=1 \n| search CommandLine="*ifconfig*" OR CommandLine="*ip addr*"',
            'index=powershell EventCode=4104 \n| search ScriptBlockText="*Get-NetIPAddress*" OR ScriptBlockText="*Get-NetAdapter*"'
        ],
        "hunt_steps": [
            "Search logs for repeated execution of discovery tools across multiple hosts",
            "Hunt for use of admin or service accounts running interactive network commands",
            "Look for staging or output redirection of network data to disk",
            "Identify commands run via remote tools like PsExec or WMI"
        ],
        "expected_outcomes": [
            "Evidence of network enumeration activity",
            "Presence of output files containing network interface or route info",
            "Execution of discovery commands by suspicious or elevated users"
        ],
        "false_positive": "Network administrators or IT staff may regularly run these commands as part of diagnostics.",
        "clearing_steps": [
            "Delete any script or batch files containing discovery commands",
            "Clear PowerShell history and command history files",
            "Review and reset compromised accounts if used to run enumeration commands"
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1021.002", "example": "Adversaries use gathered IP ranges to RDP into new systems"},
            {"tactic": "Credential Access", "technique": "T1555", "example": "IP ranges used to target systems with credential dumping"}
        ],
        "watchlist": [
            "Use of ipconfig/ifconfig by service accounts",
            "Command line processes with redirected output to .txt or .csv",
            "Execution of discovery tools by parent processes like mshta.exe or wscript.exe"
        ],
        "enhancements": [
            "Enable command line process logging with full arguments",
            "Set alerts for uncommon CLI usage patterns on endpoints",
            "Integrate DNS and ARP logs with process execution context"
        ],
        "summary": "System Network Configuration Discovery allows adversaries to identify key network information, such as IP addresses and routing details, which can aid lateral movement and targeting.",
        "remediation": "Restrict use of discovery tools to authorized users. Monitor and control CLI tool usage through Group Policy or application control solutions.",
        "improvements": "Correlate process execution with user context and network interface changes. Regularly review audit logs for reconnaissance patterns.",
        "mitre_version": "16.1"
    }
