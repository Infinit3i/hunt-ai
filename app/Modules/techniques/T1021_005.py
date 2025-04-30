def get_content():
    return {
        "id": "T1021.005",
        "url_id": "T1021/005",
        "title": "Remote Services: VNC",
        "description": "Adversaries may use Virtual Network Computing (VNC) to remotely control a system using valid credentials.",
        "tags": ["vnc", "lateral movement", "remote access", "rfb protocol", "valid accounts"],
        "tactic": "Lateral Movement",
        "protocol": "RFB",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Look for VNC usage outside of normal business hours or from unexpected IPs.",
            "Alert on VNC connections where default/test credentials are used.",
            "Hunt for unusual mouse/keyboard activity from headless systems or during screen lock."
        ],
        "data_sources": "Sysmon, Logon Session, Network Traffic, Process",
        "log_sources": [
            {"type": "Logon Session", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "Sysmon Event ID 1", "identify": "vncviewer.exe, tightvnc.exe, ultravnc.exe"},
            {"type": "Network Connections", "location": "Sysmon Event ID 3", "identify": "outbound TCP to port 5900"},
            {"type": "Clipboard Data", "location": "Windows Clipboard or session logs", "identify": "copied credentials or exfiltrated data"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "/var/log/auth.log (Linux) or Unified Logs (macOS)", "identify": "screensharingd authentication or VNC access"},
            {"type": "Memory Dumps", "location": "Dumped from compromised system", "identify": "RFB session or authentication credentials"},
            {"type": "Services", "location": "systemctl or Task Manager", "identify": "VNC service running (tightvncserver, winvnc.exe, etc.)"}
        ],
        "detection_methods": [
            "Detect VNC-specific processes and command-line arguments",
            "Analyze network connections to TCP port 5900 and correlate with authentication attempts",
            "On macOS, monitor `screensharingd` process logs for VNC sessions"
        ],
        "apt": ["TrickBot", "Gamaredon", "Shuckworm", "Actinium", "Siamesekitten", "GCMAN", "Carbon Spider"],
        "spl_query": [
            'index=sysmon EventCode=1 \n| search Image="*vnc*" OR CommandLine="*vncviewer*"',
            'index=sysmon EventCode=3 \n| search DestinationPort=5900',
            'index=unified_logs sourcetype=macos_logs \n| search process="screensharingd" AND eventMessage="Authentication:"'
        ],
        "hunt_steps": [
            "Hunt for use of VNC clients or services in endpoints outside of IT-managed systems",
            "Identify systems with VNC servers running without a valid business need",
            "Correlate use of VNC with file transfers, clipboard activity, or process execution"
        ],
        "expected_outcomes": [
            "Detection of VNC-based lateral movement attempts",
            "Uncover compromised credentials used for unauthorized remote control",
            "Confirmation of malicious VNC sessions used for screen interaction or command execution"
        ],
        "false_positive": "Legitimate IT remote support tools may use VNC. Validate with user department or asset ownership.",
        "clearing_steps": [
            "Stop and uninstall any unauthorized VNC servers: `taskkill /F /IM winvnc.exe` or `systemctl stop vncserver@:<display>.service`",
            "Delete configuration files or registry keys: `HKLM\\Software\\ORL\\WinVNC4`",
            "Reset credentials used during VNC compromise and audit account usage"
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1219", "example": "Interactive remote session using VNC to issue commands"},
            {"tactic": "Collection", "technique": "T1113", "example": "Screen capture and data exfiltration through shared display"}
        ],
        "watchlist": [
            "Outbound traffic to TCP 5900 from non-admin systems",
            "Execution of VNC viewer binaries by non-IT users",
            "Logon activity immediately followed by VNC screen sharing or clipboard use"
        ],
        "enhancements": [
            "Apply firewall rules to restrict outbound VNC access",
            "Alert on the installation or startup of VNC server processes",
            "Baseline authorized VNC usage and alert on deviations"
        ],
        "summary": "Adversaries may abuse VNC to gain remote desktop control using stolen credentials, allowing them to mimic user activity, extract data, or pivot further into the network.",
        "remediation": "Audit and disable unauthorized VNC software. Enforce MFA and unique credentials for remote access solutions.",
        "improvements": "Deploy host-based firewalls to block incoming VNC traffic. Log and alert on all remote access sessions.",
        "mitre_version": "16.1"
    }
