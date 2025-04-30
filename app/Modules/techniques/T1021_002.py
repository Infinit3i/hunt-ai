def get_content():
    return {
        "id": "T1021.002",
        "url_id": "T1021/002",
        "title": "Remote Services: SMBExec",
        "tactic": "Lateral Movement",
        "protocol": "SMB",
        "os": "Windows",
        "description": "Adversaries may use SMBExec to execute commands remotely over SMB without writing files to disk, making it a stealthy lateral movement technique.",
        "tips": [
            "Monitor Event ID 7045 for unusual service installations.",
            "Analyze ADMIN$ access logs to detect suspicious SMB connections.",
            "Detect and investigate the execution of execute.bat in TEMP directories."
        ],
        "data_sources": "Sysmon, Windows Event, Registry, File Monitoring, Network Traffic Analysis",
        "log_sources": [
            {"type": "Sysmon", "source": "", "destination": ""},
            {"type": "Windows Security", "source": "", "destination": ""},
            {"type": "Windows System", "source": "", "destination": ""},
            {"type": "File Monitoring", "source": "C:\\Windows\\Prefetch\\", "destination": "EDR"},
            {"type": "Network Monitoring", "source": "NetFlow, SMB Traffic", "destination": "Network Security Tools"}
        ],
        "source_artifacts": [
            {"type": "Registry", "location": "NTUSER.DAT\\Software\\SysInternals\\SMBExec", "identify": "EulaAccepted"},
            {"type": "File", "location": "C:\\Windows\\Prefetch\\smbexec.exe-{hash}.pf", "identify": "SMBExec execution evidence"}
        ],
        "destination_artifacts": [
            {"type": "Registry", "location": "SYSTEM\\CurrentControlSet\\Services\\<ServiceName>", "identify": "Service persistence evidence"},
            {"type": "File", "location": "C:\\Windows\\TEMP\\execute.bat", "identify": "Temporary execution batch file"}
        ],
        "detection_methods": [
            "Monitor Event ID 7045 for unexpected service installations.",
            "Detect logon attempts via SMB (Event ID 4624, 4672, 4776).",
            "Analyze network traffic for ADMIN$ share access."
        ],
        "apt": [
            "G0016 - APT29: Uses SMBExec for lateral movement.",
            "G0032 - Lazarus Group: Known to abuse SMBExec for remote execution."
        ],
        "spl_query": [
            "index=windows EventCode=7045 \n| search ServiceName=BTOBTO",
            "index=windows EventCode=4688 CommandLine=\\Windows\\TEMP\\execute.bat",
            "index=network protocol=SMB AND dest_port=445 \n| stats count by src_ip dest_ip"
        ],
        "hunt_steps": [
            "Query SIEM for Event ID 7045 to identify unexpected service installations.",
            "Analyze Prefetch files for execution of smbexec.exe and execute.bat.",
            "Monitor SMB network traffic for unauthorized lateral movement."
        ],
        "expected_outcomes": [
            "Detection of SMBExec activity through event logs and network monitoring.",
            "Identification of unauthorized service installations and suspicious SMB traffic."
        ],
        "false_positive": "Legitimate administrative SMB-based service installations.",
        "clearing_steps": [
            "Remove unauthorized services created via SMBExec.",
            "Delete execute.bat files from TEMP directories.",
            "Audit and restrict ADMIN$ share access to limit misuse."
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1021.002 (SMB/Windows Admin Shares)", "example": "Attackers use SMBExec to execute commands remotely."},
            {"tactic": "Persistence", "technique": "T1543.003 (Create or Modify System Process: Windows Service)", "example": "Adversaries create services for execution via SMBExec."}
        ],
        "watchlist": [
            "Monitor unexpected SMB-based logon attempts.",
            "Detect abnormal service creation events linked to SMBExec.",
            "Flag ADMIN$ access from non-standard administrative hosts."
        ],
        "enhancements": [
            "Disable SMBv1 to reduce attack surface.",
            "Implement strict firewall rules limiting SMB access.",
            "Use endpoint detection tools to flag unauthorized service creation."
        ],
        "summary": "SMBExec is used by adversaries to execute commands remotely over SMB without writing files to disk, making it a stealthy lateral movement technique.",
        "remediation": "Restrict SMB traffic, monitor service installations, and audit network shares for unusual activity.",
        "improvements": "Enhance SMB security by enforcing authentication restrictions, using SIEM rules for detection, and implementing endpoint logging solutions."
    }


'''

        {
            "title": "SMBExec Source Event Logs",
            "content": """
### Source Event Logs
- **security.evtx**
    - `4776` - Logon specifying alternate credentials
        - Current logged-on User Name
        - Alternate User Name
        - Destination Host Name/IP
        - Process Name
            """
        },
        {
            "title": "SMBExec Destination Event Logs",
            "content": """
### Destination Event Logs
- **security.evtx**
    - `4776` - Logon specifying alternate credentials
        - Connecting User Name
        - Process Name
    - `4624` Logon Type 3
        - Source IP/Logon User Name
    - `4672`
        - Logon User Name
        - Logon by a user with administrative rights
    - `4634` Type 3 (session end)
- **system.evtx**
    - `7045` - Service installation
        - Default service name: "BTOBTO" or a random 8-character mixed-case string.
    - `7036` Service start/stop events
            """
        },
        {
            "title": "SMBExec Source Registry",
            "content": """
### Source Registry
- **NTUSER.DAT**
    - Software\\SysInternals\\SMBExec\\EulaAccepted
- **ShimCache** – SYSTEM
    - smbexec.exe
- **BAM_DAM** – SYSTEM – Last Time Executed
    - smbexec.exe
- **AmCache.hve** – First Time Executed
    - smbexec.exe
            """
        },
        {
            "title": "SMBExec Destination Registry",
            "content": """
### Destination Registry
- SYSTEM\\CurrentControlSet\\Services\\<ServiceName>
    - Default: "BTOBTO" or random 8-character string.
- **ShimCache** – SYSTEM
    - smbexecsvc.exe
- **AmCache.hve**
    - First Time Executed
        - smbexecsvc.exe
            """
        },
        {
            "title": "SMBExec Source File System",
            "content": """
### Source File System
- **Prefetch** – C:\\Windows\\Prefetch\\
    - smbexec.exe-{hash}.pf
- **File Creation**
    - smbexec.exe file downloaded and created on the local host.
            """
        },
        {
            "title": "SMBExec Destination File System",
            "content": """
### Destination File System
- **Prefetch** – C:\\Windows\\Prefetch\\
    - smbexecsvc.exe-{hash}.pf
    - execute.bat-{hash}.pf
- **File Creation**
    - `execute.bat` created in C:\\Windows\\TEMP\\
    - User-specified commands echoed to `execute.bat`.
    - Temporary batch file removed after execution.
            """
        },
        {
            "title": "SMBExec Service Creation Details",
            "content": """
### Service Creation Details
- Service Name:
    - Default: "BTOBTO"
    - Updated to a random 8-character mixed-case string in May 2023.
- Executable: `execute.bat` created for every command.
- Event Log Evidence:
    - `7045` in `system.evtx` logs service creation.
    - Command executed via:
        - `%COMSPEC% /Q /c echo cd ^> \\127.0.0.1\\C$\\__output 2^>^&1 > %TEMP%\\execute.bat`.
            """
        },
        {
            "title": "SMBExec Network Artifacts",
            "content": """
### Network Artifacts
- **Network Connections**:
    - SMB protocol communication with the target.
    - Evidence of ADMIN$ share access.
- **Network Traffic Analysis**:
    - Monitor for suspicious SMB traffic to/from servers.
    - Detect repeated connections with new service creation.
            """
        },
        {
            "title": "SMBExec Eviction Techniques",
            "content": """
### Eviction Techniques
- Remove temporary files:
    - `execute.bat` is deleted after execution.
- Service cleanup:
    - Services created for each command are removed after execution.
            """
        },
        {
            "title": "SMBExec Malware Case Study",
            "content": """
### Malware Case Study
- **Case Study**:
    - Malware using SMBExec for lateral movement.
    - Leveraged temporary service creation for executing commands.
    - Indicators:
        - Random service names.
        - Temporary batch files in `C:\\Windows\\TEMP`.
- **Detection**:
    - Monitor Event ID 7045 for abnormal service names.
    - Correlate with batch file creation and execution in `TEMP` directory.
            """
        }
    ]

'''