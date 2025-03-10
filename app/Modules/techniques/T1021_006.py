def get_content():
    return {
        "id": "T1021.006",
        "url_id": "T1021/006",
        "title": "Remote Services: PowerShell Remoting",
        "tactic": "Lateral Movement",
        "data_sources": "Windows System, Windows PowerShell, Windows Registry",
        "protocol": "WinRM, PowerShell Remoting",
        "os": "Windows",
        "description": "Adversaries may use PowerShell Remoting to execute commands on remote systems. PowerShell Remoting is a powerful tool for system administrators, but adversaries can abuse it for lateral movement and remote",
        "tips": [
            "Enable PowerShell Script Block Logging (Event ID 4104) for deeper visibility.",
            "Restrict PowerShell execution policy to prevent unauthorized scripts.",
            "Monitor WinRM logs for abnormal session creation (Event ID 91, 142)."
        ],
        "log_sources": [
            {"type": "Authentication", "source": "Windows Security Logs (Event ID 4648, 4624, 4672)", "destination": "SIEM"},
            {"type": "Process Execution", "source": "PowerShell Operational Logs (Event ID 40961, 40962, 8193, 8194)", "destination": "SIEM"},
            {"type": "Windows System", "source": "WinRM Operational Logs (Event ID 161, 6, 8, 15, 16, 33)", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "C:\\Users\\<Username>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt", "identify": "Tracks PowerShell commands used by an attacker."},
            {"type": "File Execution", "location": "C:\\Windows\\Prefetch\\powershell.exe-{hash}.pf", "identify": "Identifies execution of PowerShell scripts."}
        ],
        "destination_artifacts": [
            {"type": "WinRM Execution", "location": "C:\\Windows\\Prefetch\\wsmprovhost.exe-{hash}.pf", "identify": "Execution of remote commands via PowerShell Remoting."},
            {"type": "Process Execution", "location": "Windows Event Logs (Event ID 4103, 4104, 53504)", "identify": "Detects script execution via PowerShell Remoting."}
        ],
        "detection_methods": [
            "Monitor PowerShell Script Block Logging (Event ID 4104) for suspicious activity.",
            "Analyze WinRM session logs (Event ID 91, 142) for unauthorized remote command execution.",
            "Track security log events (Event ID 4648, 4624, 4672) for unusual PowerShell remoting connections."
        ],
        "apt": [
            "G0046 - APT29: Known to leverage PowerShell Remoting for lateral movement."
        ],
        "spl_query": [
            "index=windows EventCode=4648 | stats count by user, src_ip, dest_ip\n|",
            "index=windows EventCode=4104 | search scriptblock_text=*Invoke-Command* | stats count by user, host\n|",
            "index=windows EventCode=91 OR EventCode=142 | stats count by user, dest_ip"
        ],
        "hunt_steps": [
            "Identify unauthorized PowerShell remoting sessions in event logs.",
            "Correlate logs between source and destination systems for lateral movement.",
            "Investigate whether execution policies were modified to allow script execution.",
            "Analyze parent-child process relationships to detect malicious PowerShell usage."
        ],
        "expected_outcomes": [
            "Unauthorized remote execution detected: Containment and mitigation actions initiated.",
            "Legitimate administrative activity confirmed: No action needed."
        ],
        "false_positive": "Legitimate system administrators may use PowerShell Remoting for IT automation, requiring baseline monitoring.",
        "clearing_steps": [
            "Disable PowerShell Remoting using Group Policy: `Disable-PSRemoting -Force`.",
            "Restrict WinRM execution policy using registry modifications.",
            "Review and reset PowerShell Execution Policy to `Restricted`."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1552 (Unsecured Credentials)", "example": "Attackers may retrieve stored credentials via PowerShell."},
            {"tactic": "Persistence", "technique": "T1053.005 (Scheduled Task - At Job)", "example": "Adversaries may use scheduled tasks to re-enable PowerShell Remoting."}
        ],
        "watchlist": [
            "Monitor for new PowerShell remoting sessions with unknown user accounts.",
            "Track execution of `Invoke-Command` and `Enter-PSSession` in logs.",
            "Identify attempts to modify PowerShell execution policies."
        ],
        "enhancements": [
            "Enable enhanced PowerShell logging to capture command execution details.",
            "Restrict WinRM service to authorized administrators only.",
            "Enforce application whitelisting to prevent execution of unauthorized scripts."
        ],
        "summary": "PowerShell Remoting is a powerful tool for system administration, but adversaries can abuse it for lateral movement and remote execution.",
        "remediation": "Disable PowerShell Remoting if not required, monitor script execution logs, and enforce least privilege principles.",
        "improvements": "Implement least privilege access controls for remote command execution and deploy behavioral-based anomaly detection for PowerShell usage."
    }


'''

    return [
        {
            "title": "PowerShell Remoting Source Event Logs",
            "content": """
### Source Event Logs
- **security.evtx**
    - `4648` - Logon specifying alternate credentials
        - Current logged-on User Name
        - Alternate User Name
        - Destination Host Name/IP
        - Process Name
- **Microsoft-Windows-WinRM/Operational.evtx**
    - `161` - Remote Authentication Error
    - `6` - WSMan Session initialize
        - Session created
        - Destination Host Name or IP
        - Current logged-on User Name
    - `8`, `15`, `16`, `33` - WSMan Session deinitialization
        - Closing of WSMan session
        - Current logged-on User Name
- **Microsoft-Windows-PowerShell/Operational.evtx**
    - `40961`, `40962`
        - Records the local initiation of powershell.exe and associated user account
    - `8193` & `8194` - Session created
    - `8197` - Connect
        - Session closed
            """
        },
        {
            "title": "PowerShell Remoting Source Registry",
            "content": """
### Source Registry
- **ShimCache** – SYSTEM
    - powershell.exe
- **BAM_DAM** – SYSTEM – Last Time Executed
    - powershell.exe
- **AmCache.hve** – First Time Executed
    - powershell.exe
            """
        },
        {
            "title": "PowerShell Remoting Source File System Artifacts",
            "content": """
### Source File System Artifacts
- **Prefetch** – C:\\Windows\\Prefetch\\
    - powershell.exe-{hash}.pf
    - PowerShell scripts (.ps1 files) that run within 10 seconds of powershell.exe launching will be tracked in powershell.exe prefetch file
- **Command history**
    - C:\\Users\\<Username>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt
        - With PS v5+, a history file with previous 4096 commands is maintained per user
            """
        },
        {
            "title": "PowerShell Remoting Destination Event Logs",
            "content": """
### Destination Event Logs
- **security.evtx**
    - `4624` – Logon Type 3
        - Source IP/Logon User Name
    - `4672`
        - Logon User Name
        - Logon by a user with administrative rights
- **Microsoft-Windows-PowerShell%4Operational.evtx**
    - `4103`, `4104` – Script Block logging
        - Logs suspicious scripts by default in PS v5
        - Logs all scripts if configured
    - `53504` - Records the authenticating user
- **Windows PowerShell.evtx**
    - `400/403` - "ServerRemoteHost" indicates start/end of remoting session
    - `800` - Includes partial script code
- **Microsoft-Windows-WinRM/Operational.evtx**
    - `91` – Session creation
    - `142` – WSMan Operation Failure
    - `169` – Records the authenticating user
            """
        },
        {
            "title": "PowerShell Remoting Destination Registry",
            "content": """
### Destination Registry
- **ShimCache** – SYSTEM
    - wsmprovhost.exe
    - evil.exe
- **SOFTWARE**
    - Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy
        - Attacker may change execution policy to a less restrictive setting, such as "bypass"
- **AmCache.hve** – First Time Executed
    - wsmprovhost.exe
    - evil.exe
            """
        },
        {
            "title": "PowerShell Remoting Destination File System Artifacts",
            "content": """
### Destination File System Artifacts
- **File Creation**
    - evil.exe
    - With Enter-PSSession, a user profile directory may be created
- **Prefetch** – C:\\Windows\\Prefetch\\
    - evil.exe-{hash}.pf
    - wsmprovhost.exe-{hash}.pf
            """
        }
    ]


'''