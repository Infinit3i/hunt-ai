def get_content():
    """
    Returns structured content for the WMI persistence method.
    """
    return [
        {
            "title": "WMI Source Event Logs",
            "content": """
### Source Event Logs
`security.evtx`:
- `4648` – Logon specifying alternate credentials
    - Current logged-on User Name
    - Alternate User Name
    - Destination Host Name/IP
    - Process Name
            """
        },
        {
            "title": "WMI Destination Event Logs",
            "content": """
### Destination Event Logs
`security.evtx`:
- `4624` Logon Type 3
    - Source IP/Logon User Name
- `4672`
    - Logon User Name
    - Logon by a user with administrative rights

`Microsoft-Windows-WMI-Activity/Operational.evtx`:
- `5857`
    - Indicates time of wmiprvse execution and path to provider DLL – attackers sometimes install malicious WMI provider DLLs.
- `5860`, `5861`
    - Registration of Temporary (5860) and Permanent (5861) Event Consumers.
    - Typically used for persistence, but can also be used for remote execution.
            """
        },
        {
            "title": "WMI Source Registry",
            "content": """
### Source Registry
- **ShimCache** – SYSTEM
    - `wmic.exe`
- **BAM_DAM** – SYSTEM – Last Time Executed
    - `wmic.exe`
- **AmCache.hve** – First Time Executed
    - `wmic.exe`
            """
        },
        {
            "title": "WMI Destination Registry",
            "content": """
### Destination Registry
- **ShimCache** – SYSTEM
    - `scrcons.exe`
    - `mofcomp.exe`
    - `wmiprvse.exe`
    - `evil.exe`
- **AmCache.hve** – First Time Executed
    - `scrcons.exe`
    - `mofcomp.exe`
    - `wmiprvse.exe`
    - `evil.exe`
            """
        },
        {
            "title": "WMI Source File System",
            "content": """
### Source File System
- **Prefetch**:
    - `C:\\Windows\\Prefetch\\wmic.exe-{hash}.pf`
            """
        },
        {
            "title": "WMI Destination File System",
            "content": """
### Destination File System
- **File Creation**:
    - `evil.exe`
    - `evil.mof` - .mof files can be used to manage the WMI Repository.

- **Prefetch**:
    - `C:\\Windows\\Prefetch\\scrcons.exe-{hash}.pf`
    - `C:\\Windows\\Prefetch\\mofcomp.exe-{hash}.pf`
    - `C:\\Windows\\Prefetch\\wmiprvse.exe-{hash}.pf`
    - `C:\\Windows\\Prefetch\\evil.exe-{hash}.pf`

- **Unauthorized changes to the WMI Repository**:
    - `C:\\Windows\\System32\\wbem\\Repository`
            """
        },
        {
            "title": "WMI Event Consumer Backdoors",
            "content": """
### WMI Event Consumer Backdoors
- **Event Filters**: Define conditions under which events trigger (e.g., process starts).
- **Event Consumers**: Define actions for triggered events (e.g., execute a script).
- **Event Bindings**: Link filters and consumers.
            """
        },
        {
            "title": "WMIEXEC Analysis",
            "content": """
### WMIEXEC Analysis
- **Command Example**: `wmiexec.py domain/username:password@[hostname | IP] command`
- **Logs**:
    - Event ID `4648`, `4624`, `4672`, `5857`, `5861` indicate WMI activity.
- **Detection**:
    - Monitor commands triggering `wmiprvse.exe` and subsequent processes.
            """
        },
        {
            "title": "Additional WMI Detection Tips",
            "content": """
### Additional Detection Tips
- Enable verbose WMI logging in the `Microsoft-Windows-WMI-Activity` log.
- Correlate WMI activity with file system or registry changes.
- Research WMI use by known APTs or malware families.
            """
        }
    ]
