def get_content():
    """
    Returns structured content for the Scheduled Tasks (T1053.005) persistence method.
    """
    return {
        "id": "T1053.005",
        "url_id": "T1053/005",
        "title": "Scheduled Task / Job: Scheduled Task",
        "tactic": "Persistence, Execution",
        "data_sources": "Windows Event Logs, File Monitoring, Process Execution",
        "protocol": "N/A",
        "os": "Windows",
        "objective": "Detect and mitigate adversaries leveraging scheduled tasks for persistence or execution.",
        "scope": "Monitor scheduled task creation, modification, and execution for unauthorized activities.",
        "threat_model": "Attackers may use scheduled tasks to execute commands or payloads at specific intervals, ensuring persistence.",
        "hypothesis": [
            "Are unauthorized scheduled tasks being created or modified?",
            "Are scheduled tasks executing suspicious processes?",
            "Are scheduled tasks being used for lateral movement or persistence?"
        ],
        "tips": [
            "Monitor scheduled tasks regularly and investigate unknown or suspicious tasks.",
            "Check for scheduled tasks executing scripts or binaries in non-standard locations.",
            "Use Group Policy to restrict who can create and modify scheduled tasks."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security Event ID 4698, 4702, 4699", "destination": "System Event Logs"},
            {"type": "Task Scheduler Logs", "source": "Microsoft-Windows-TaskScheduler%4Operational.evtx", "destination": "Task Execution Logs"},
            {"type": "Process Execution", "source": "Sysmon Event ID 1", "destination": "Process Logs"}
        ],
        "source_artifacts": [
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch\\", "identify": "schtasks.exe-{hash}.pf"},
            {"type": "Command History", "location": "C:\\Windows\\System32\\Tasks\\", "identify": "Suspicious scheduled task XML files"}
        ],
        "destination_artifacts": [
            {"type": "Scheduled Task Files", "location": "C:\\Windows\\Tasks", "identify": "Job files created for execution"},
            {"type": "System Registry", "location": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache", "identify": "Task cache registry entries"}
        ],
        "detection_methods": [
            "Monitor event logs for scheduled task creation (Event ID 4698).",
            "Detect scheduled tasks executing unauthorized scripts or executables.",
            "Analyze XML files in Task Scheduler directories for anomalies."
        ],
        "apt": ["G0096", "G0016"],
        "spl_query": [
            "index=windows EventCode=4698 OR EventCode=4702 OR EventCode=4699",
            "index=windows sourcetype=WinEventLog:Microsoft-Windows-TaskScheduler/Operational \n| stats count by TaskName"
        ],
        "hunt_steps": [
            "Review all scheduled tasks using Task Scheduler or PowerShell (Get-ScheduledTask).",
            "Analyze event logs for new or modified scheduled tasks.",
            "Correlate scheduled task execution with process creation logs."
        ],
        "expected_outcomes": [
            "Malicious scheduled task detected and removed.",
            "No unauthorized scheduled tasks identified."
        ],
        "false_positive": "Administrators may create legitimate scheduled tasks for system maintenance.",
        "clearing_steps": [
            "schtasks /Delete /TN \"malicious_task\" /F",
            "Remove corresponding task XML files from C:\\Windows\\System32\\Tasks\\",
            "Delete associated registry keys from TaskCache."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1543 (Create or Modify System Process)", "example": "Attackers create a scheduled task for persistence."},
            {"tactic": "Execution", "technique": "T1059 (Command and Scripting Interpreter)", "example": "Attackers use scheduled tasks to execute scripts."}
        ],
        "watchlist": [
            "Monitor for new or modified scheduled tasks.",
            "Investigate scheduled tasks running unexpected processes.",
            "Analyze scheduled tasks with high privileges."
        ],
        "enhancements": [
            "Enable logging for scheduled task events.",
            "Restrict task creation to specific administrative users.",
            "Regularly audit scheduled tasks for unauthorized changes."
        ],
        "summary": "Scheduled tasks can be abused for persistence and execution. Monitoring task creation, modification, and execution is essential for threat detection.",
        "remediation": "Delete unauthorized scheduled tasks, review execution history, and apply least privilege access.",
        "improvements": "Enhance scheduled task monitoring using SIEM alerts and behavioral analysis."
    }

        
'''        
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

'''