def get_content():
    """
    Returns structured content for the SMBExec persistence method.
    """
    return [
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
