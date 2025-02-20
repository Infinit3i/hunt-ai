def get_content():
    """
    Returns structured content for the Remote Access Software technique.
    """
    return {
        "id": "T1219",
        "url_id": "T1219",
        "title": "Remote Access Software",
        "tactic": "Command and Control, Persistence",
        "data_sources": "Process Monitoring, Network Traffic, Registry, Windows Event Logs",
        "protocol": "Multiple (RDP, VNC, SSH, etc.)",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries may install and use remote access software to control compromised systems.",
        "scope": "Monitor for unauthorized remote access tools and unexpected outbound network connections.",
        "threat_model": "Attackers often install remote access software to maintain persistent access and execute commands on compromised hosts.",
        "hypothesis": [
            "Is unauthorized remote access software installed on the system?",
            "Are there unexpected network connections to remote hosts?",
            "Is there abnormal user activity suggesting remote control?"
        ],
        "tips": [
            "Monitor process creation for common remote access tools (e.g., AnyDesk, TeamViewer, RDP, VNC, SSH).",
            "Analyze network traffic for unexpected remote connections.",
            "Review startup programs and scheduled tasks for unauthorized remote access applications."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1, 3", "destination": "N/A"},
            {"type": "Network Traffic", "source": "Firewall Logs, Proxy Logs", "destination": "SIEM"},
            {"type": "Registry", "source": "HKLM\\Software\\RemoteAccess", "destination": "N/A"}
        ],
        "source_artifacts": [
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch", "identify": "TeamViewer.exe, AnyDesk.exe"},
            {"type": "Scheduled Tasks", "location": "C:\\Windows\\System32\\Tasks", "identify": "RemoteAccessTask"}
        ],
        "destination_artifacts": [
            {"type": "Log Files", "location": "/var/log/auth.log", "identify": "SSH remote access logs"},
            {"type": "Configuration Files", "location": "/etc/ssh/sshd_config", "identify": "Modified SSH settings"}
        ],
        "detection_methods": [
            "Monitor for execution of known remote access software binaries.",
            "Analyze process and network behavior for unusual remote access activity.",
            "Check for unauthorized changes to system policies allowing remote access."
        ],
        "apt": ["G0016", "G0032"],
        "spl_query": [
            "index=windows EventCode=4688 NewProcessName IN (\"*TeamViewer.exe*\", \"*AnyDesk.exe*\", \"*VNC.exe*\")",
            "index=network dest_port IN (3389, 5900, 22) | table src_ip, dest_ip, dest_port"
        ],
        "hunt_steps": [
            "Identify unauthorized remote access software installed on endpoints.",
            "Check for unexpected remote login activity in system logs.",
            "Analyze network traffic for unauthorized remote desktop connections."
        ],
        "expected_outcomes": [
            "Unauthorized remote access software detected and mitigated.",
            "No suspicious activity found, improving baseline detection."
        ],
        "false_positive": "Legitimate IT and support teams may use remote access software for troubleshooting.",
        "clearing_steps": [
            "Uninstall unauthorized remote access software using system management tools.",
            "Block known remote access software in enterprise firewall policies.",
            "Revoke compromised user credentials used for remote access."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1071.001 (Web Protocols)", "example": "Attackers may use web-based remote access software."}
        ],
        "watchlist": [
            "Monitor for installation of unauthorized remote access tools.",
            "Detect unexpected network traffic to known remote access domains."
        ],
        "enhancements": [
            "Restrict installation of remote access software using application control policies.",
            "Require multi-factor authentication for all remote access connections."
        ],
        "summary": "Adversaries may install and use remote access software to control compromised systems.",
        "remediation": "Uninstall unauthorized remote access tools, block known remote access software, and review firewall rules.",
        "improvements": "Enhance logging and monitoring of remote access connections and enforce strong authentication mechanisms."
    }
