def get_content():
    return {
        "id": "T1563",
        "url_id": "T1563",
        "title": "Remote Service Session Hijacking",
        "description": "Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service. Adversaries may commandeer these sessions to carry out actions on remote systems.",
        "tags": ["lateral movement", "session hijacking", "RDP", "SSH", "telnet"],
        "tactic": "Lateral Movement",
        "protocol": "RDP, SSH, Telnet",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor for access to systems outside of normal user behavior.",
            "Audit tools like TScon and manipulation of session handles in Windows.",
            "Review logs for abrupt session changes or privilege escalation patterns."
        ],
        "data_sources": "Command, Logon Session, Network Traffic, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Logon Session", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Windows Event Viewer", "identify": "Logon ID reuse, RDP connection established"},
            {"type": "Process List", "location": "Task Manager or Sysmon", "identify": "tscon.exe used"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "Windows Event Viewer", "identify": "Session connected from known system"},
            {"type": "Network Connections", "location": "Netstat or Zeek", "identify": "Ongoing session over port 3389 or 22"}
        ],
        "detection_methods": [
            "Monitor for tscon.exe usage in Windows systems",
            "Detect reuse of existing Logon Sessions",
            "Monitor network connections for lateral movement patterns"
        ],
        "apt": ["APT29", "Lazarus Group"],
        "spl_query": [
            "index=sysmon EventCode=1 Image=*\\tscon.exe\n| stats count by User, Computer, Image",
            "index=wineventlog EventCode=4624 LogonType=10\n| stats count by Account_Name, Source_Network_Address"
        ],
        "hunt_steps": [
            "Query session hijack indicators (e.g., tscon.exe)",
            "Correlate Logon IDs across multiple systems",
            "Examine PowerShell logs for unauthorized manipulation of sessions"
        ],
        "expected_outcomes": [
            "Identification of suspicious session control tools like tscon",
            "Detection of reused Logon Sessions",
            "Flagging of atypical RDP behavior or timing"
        ],
        "false_positive": "Legitimate administrators using session tools such as tscon for helpdesk or support tasks.",
        "clearing_steps": [
            "Clear security logs: wevtutil cl security",
            "Delete PowerShell history: Remove-Item (Get-PSReadlineOption).HistorySavePath",
            "Clear bash history: > ~/.bash_history; history -c"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-rdp"],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1078", "example": "Use of Valid Accounts"},
            {"tactic": "Defense Evasion", "technique": "T1027", "example": "Obfuscated tools to control session"}
        ],
        "watchlist": [
            "tscon.exe execution",
            "LogonType 10 (RDP) in Event ID 4624",
            "Multiple session connections from same user in short time"
        ],
        "enhancements": [
            "Alert when tscon is used without corresponding session logoff",
            "Ingest session data with EDR integration"
        ],
        "summary": "Remote Service Session Hijacking involves taking over existing authenticated remote sessions (e.g., RDP, SSH) to gain lateral movement across systems. It allows attackers to bypass some authentication controls and perform malicious activity under the guise of an already authenticated user.",
        "remediation": "Restrict use of session management tools. Enforce session timeout and reauthentication policies. Audit and monitor session activity frequently.",
        "improvements": "Implement session monitoring via EDR. Create baselines for session behavior. Enhance alerts for tscon, SSH hijacking tools, or lateral RDP jumps.",
        "mitre_version": "16.1"
    }
