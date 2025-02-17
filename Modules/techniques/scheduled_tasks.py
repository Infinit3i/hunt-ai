def get_content():
    """
    Returns structured content for the Scheduled Tasks persistence method.
    """
    return [
        {
            "title": "Scheduled Tasks Source Event Logs",
            "content": """
### Source Event Logs
- `security.evtx`
    - `4648` - Logon specifying alternate credentials
        - Current logged-on User Name
        - Alternate User Name
        - Destination Host Name/IP
        - Process Name
            """
        },
        {
            "title": "Scheduled Tasks Destination Event Logs",
            "content": """
### Destination Event Logs
- `security.evtx`
    - `4624` Logon Type 3
        - Source IP/Logon User Name
    - `4672`
        - Logon User Name
        - Logon by a user with administrative rights
        - Requirement for accessing default shares such as **C$** and **ADMIN$**
    - `4698` - Scheduled task created
    - `4702` - Scheduled task updated
    - `4699` - Scheduled task deleted
    - `4700/4701` - Scheduled task enabled/disabled
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`
    - `106` - Scheduled task created
    - `140` - Scheduled task updated
    - `141` - Scheduled task deleted
    - `200/201` - Scheduled task executed/completed
            """
        },
        {
            "title": "Scheduled Tasks Source Registry",
            "content": """
### Source Registry
- **ShimCache** – SYSTEM
    - at.exe
    - schtasks.exe
- **BAM/DAM** – SYSTEM – Last Time Executed
    - at.exe
    - schtasks.exe
- **AmCache.hve** – First Time Executed
    - at.exe
    - schtasks.exe
            """
        },
        {
            "title": "Scheduled Tasks Destination Registry",
            "content": """
### Destination Registry
- SOFTWARE
    - `Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks`
    - `Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\`
- **ShimCache** – SYSTEM
    - evil.exe
- **AmCache.hve** – First Time Executed
    - evil.exe
            """
        },
        {
            "title": "Scheduled Tasks Source File System Artifacts",
            "content": """
### Source File System Artifacts
- **Prefetch** – `C:\\Windows\\Prefetch\\`
    - at.exe-{hash}.pf
    - schtasks.exe-{hash}.pf
            """
        },
        {
            "title": "Scheduled Tasks Destination File System Artifacts",
            "content": """
### Destination File System Artifacts
- **File Creation**
    - evil.exe
- Job files created in
    - `C:\\Windows\\Tasks`
- XML task files created in
    - `C:\\Windows\\System32\\Tasks`
    - `C:\\Windows\\SysWOW64\\Tasks`
    - **Author tag** can identify:
        - Source system name
        - Creator username
- **Prefetch** – `C:\\Windows\\Prefetch\\`
    - evil.exe-{hash}.pf
            """
        },
        {
            "title": "Atexec Analysis",
            "content": """
### Atexec Analysis
#### Command Syntax:
- `atexec.py domain/username:password@[hostname | IP] command`

#### Characteristics:
- Executes commands remotely but does not provide shell access.
- Creates a Scheduled Task with a random 8-character mixed-case alpha string.
- Uses `cmd.exe /C` to run commands, outputting results to `C:\\Windows\\Temp\\<random>.tmp` before deleting the file.
- **NOT detected and blocked by Windows Defender by default**.

#### Windows Event Log Residue:
1. Event IDs in `Security.evtx`:
    - `4776` - NTLM Authentication
    - `4672` - Special privileges assigned to logon.
    - `4624` - Successful logon (Type 3).
2. `Microsoft-Windows-TaskScheduler/Operational`:
    - `106`, `325`, `129`, `100`, `200`, `110`, `141`, `111`, `201`, `102` (Task lifecycle).
3. **IF ENABLED**:
    - `4688` - Process creation (`cmd.exe` spawning tasks or executing commands).
    - `4698` - Scheduled task created.
    - `4699` - Scheduled task deleted.

#### Example Detection Indicators:
- Multiple rounds of Event IDs (`4776`, `4672`, `4624`).
- Temporary `.tmp` files in `C:\\Windows\\Temp` with scheduled task output.
            """
        },
        {
            "title": "Scheduled Tasks Extra Information",
            "content": """
### Scheduled Tasks Commands
- `at \\\\host 13:00 "c:\\temp\\evil.exe"`
- `schtasks /CREATE /TN taskname /TR c:\\temp\\evil.exe /SC once /RU “SYSTEM” /ST 13:00 /S host /U username`
            """
        }
    ]
