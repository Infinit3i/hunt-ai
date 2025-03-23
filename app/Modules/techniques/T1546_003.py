def get_content():
    """
    Returns structured content for the WMI persistence method.
    """
    return {
        "id": "T1546.003",
        "url_id": "1546/003",
        "title": "Event Triggered Execution: Windows Management Instrumentation (WMI)",
        "tactic": "Persistence, Execution",
        "description": "Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a WMI event subscription.",
        "tags": ["wmi", "event subscription", "mof", "WmiPrvSe.exe", "persistence", "privilege escalation"],
        "tactic": "Persistence",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for creation of WMI EventFilter, EventConsumer, and FilterToConsumerBinding entries",
            "Use Autoruns and PowerShell to inspect WMI subscriptions",
            "Monitor execution from WmiPrvSe.exe as an indicator of malicious WMI event triggers"
        ],
        "data_sources": "Command, File, Process, WMI",
        "tips": [
            "Monitor Event ID 5857, 5860, and 5861 for suspicious WMI event consumer registrations.",
            "Analyze process executions triggered by `wmiprvse.exe`.",
            "Audit the WMI repository (`C:\\Windows\\System32\\wbem\\Repository`) for unauthorized modifications."
        ],
        "log_sources": [
            {"type": "Security Event Log", "source": "Event ID 4648, 4624, 4672", "destination": "Indicates authentication and privilege escalation via WMI"},
            {"type": "WMI Operational Log", "source": "Event ID 5857, 5860, 5861", "destination": "Tracks WMI event consumer activity"},
            {"type": "System Event Log", "source": "Process execution logs", "destination": "Detects commands executed through WMI"}
        ],
        "source_artifacts": [
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch\\", "identify": "wmic.exe-{hash}.pf"},
            {"type": "Registry", "location": "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", "identify": "Tracks execution of remote WMI commands"}
        ],
        "destination_artifacts": [
            {"type": "File System", "location": "C:\\Windows\\System32\\wbem\\Repository", "identify": "WMI repository modifications"},
            {"type": "Registry", "location": "SYSTEM\\CurrentControlSet\\Services\\WmiApSrv", "identify": "WMI service backdoors"}
        ],
        "detection_methods": [
            "Monitor WMI event consumer registrations via Event ID 5861.",
            "Detect unauthorized modifications to the WMI repository.",
            "Analyze process executions triggered by `wmiprvse.exe`."
        ],
        "apt": ["G0045", "G0096"],  # Example APT groups known to use WMI for persistence
        "spl_query": [
            "index=windows EventCode=5857 OR EventCode=5861 OR EventCode=4688 ProcessName='wmiprvse.exe' \n| stats count by host, user",
            "index=windows EventCode=5857 EventConsumer='evil.exe' \n| stats count by host, user"
        ],
        "hunt_steps": [
            "Identify Event ID 5861 in WMI logs for unauthorized event consumers.",
            "Check process execution logs for suspicious `wmiprvse.exe` activity.",
            "Analyze registry modifications in SYSTEM\\CurrentControlSet\\Services\\WmiApSrv."
        ],
        "expected_outcomes": [
            "Unauthorized WMI persistence detected and mitigated.",
            "No malicious activity found, improving detection baselines."
        ],
        "false_positive": "Legitimate IT administration may use WMI for remote management.",
        "clearing_steps": [
            "Remove unauthorized WMI event consumers using `wmic /namespace:\\\\root\\subscription PATH __EventConsumer DELETE`.",
            "Delete malicious MOF files from `C:\\Windows\\System32\\wbem\\`.",
            "Audit and reset WMI repository to remove backdoors."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1546.003 (WMI Event Subscription)", "example": "Attackers register a WMI event consumer for persistence."},
            {"tactic": "Execution", "technique": "T1059.001 (PowerShell)", "example": "WMI event triggers PowerShell scripts for execution."}
        ],
        "watchlist": [
            "Detect unauthorized WMI event consumer registrations (Event ID 5861).",
            "Monitor unexpected process executions via `wmiprvse.exe`.",
            "Investigate WMI repository modifications."
        ],
        "enhancements": [
            "Restrict WMI event consumer registrations to authorized administrators.",
            "Enable advanced logging for WMI activity.",
            "Regularly audit the WMI repository for unauthorized modifications."
        ],
        "summary": "Detect unauthorized WMI event consumer registrations used for stealthy persistence and execution.",
        "remediation": "Remove unauthorized WMI subscriptions, audit process execution, and secure WMI repository access.",
        "improvements": "Enhance endpoint logging for WMI activity and limit execution permissions to authorized users only."
    }



'''

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


'''