def get_content():
    return {
        "id": "T1563.002",
        "url_id": "T1563/002",
        "title": "Remote Service Session Hijacking: RDP Hijacking",
        "description": "Adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment. This is often achieved using tscon.exe to hijack sessions without prompting the legitimate user. The attacker can inherit session privileges, including those of Domain Admins, without needing authentication.",
        "tags": ["rdp", "lateral movement", "session hijacking", "tscon", "windows"],
        "tactic": "Lateral Movement",
        "protocol": "RDP",
        "os": "Windows",
        "tips": [
            "Audit tscon.exe usage especially outside of standard IT support hours.",
            "Alert on cmd.exe processes with /k or /c parameters used for service creation.",
            "Cross-check sessions with high-privilege accounts against unexpected hosts."
        ],
        "data_sources": "Command, Logon Session, Network Traffic, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Logon Session", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "Sysmon or Task Manager", "identify": "tscon.exe"},
            {"type": "Event Logs", "location": "Windows Event Viewer", "identify": "Event ID 4624 with LogonType 10"},
            {"type": "Registry Hives", "location": "HKLM\\SOFTWARE\\Microsoft\\Terminal Server", "identify": "RDP session policy entries"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "netstat or Sysmon ID 3", "identify": "Inbound RDP over TCP 3389"},
            {"type": "Event Logs", "location": "Security.evtx", "identify": "tscon.exe execution without corresponding logoff"},
            {"type": "Process List", "location": "Sysinternals Procmon", "identify": "tscon.exe without user interaction"}
        ],
        "detection_methods": [
            "Alert on use of tscon.exe with suspicious session IDs",
            "Detect use of cmd.exe /c or /k in service creation",
            "Identify orphaned or hijacked sessions with privilege escalation traces"
        ],
        "apt": ["APT29", "Wizard Spider", "Cobalt Group"],
        "spl_query": [
            "index=wineventlog EventCode=4624 LogonType=10\n| stats count by Account_Name, Source_Network_Address",
            "index=sysmon EventCode=1 Image=*\\tscon.exe\n| stats count by ParentImage, CommandLine, User"
        ],
        "hunt_steps": [
            "Hunt for tscon.exe executions tied to unexpected sessions",
            "Correlate session activity against user access logs and privilege levels",
            "Search for service creations with embedded commands (cmd.exe /c/k)"
        ],
        "expected_outcomes": [
            "Detection of lateral movement via RDP hijacking",
            "Correlation of session inheritance with elevated privilege access",
            "Identification of session theft without credential use"
        ],
        "false_positive": "Helpdesk or IT administrators using tscon.exe for legitimate session management.",
        "clearing_steps": [
            "Clear tscon usage artifacts: del /f /q %windir%\\System32\\tscon.exe (if malicious copy)",
            "Delete related logs (admin abuse): wevtutil cl security",
            "Remove RDP session history: reg delete \"HKCU\\Software\\Microsoft\\Terminal Server Client\\Default\" /f"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-privilege-escalation"],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1078", "example": "Session hijacked from Domain Admin"},
            {"tactic": "Discovery", "technique": "T1018", "example": "Remote System Discovery after hijack"}
        ],
        "watchlist": [
            "tscon.exe launched by SYSTEM or from unexpected parent process",
            "cmd.exe /c or /k used in service creation context",
            "Event ID 4778 (session reconnection) with unknown origin"
        ],
        "enhancements": [
            "Integrate tscon monitoring with EDR solutions",
            "Baseline service usage of RDP and flag non-baseline session hijack activity",
            "Deploy session isolation controls to prevent cross-user session hijacking"
        ],
        "summary": "RDP Hijacking allows adversaries to inherit interactive sessions on Windows systems without credentials. This tactic is especially dangerous when privileged sessions are hijacked, allowing silent lateral movement and privilege escalation.",
        "remediation": "Restrict RDP access, monitor session control tools, and enforce least privilege. Disable tscon.exe if not needed in your environment.",
        "improvements": "Alert on unusual session ID switches, integrate with session telemetry tools, and maintain session state audits.",
        "mitre_version": "16.1"
    }
