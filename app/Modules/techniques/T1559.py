def get_content():
    return {
        "id": "T1559",
        "url_id": "T1559",
        "title": "Inter-Process Communication",
        "description": "Adversaries may abuse inter-process communication (IPC) mechanisms to execute local code or commands. IPC enables processes to share data or synchronize operations and is present in all major operating systems through native interfaces or libraries, such as DDE and COM on Windows or sockets and pipes on Linux.",
        "tags": ["ipc", "dde", "com", "pipes", "sockets", "execution", "process communication"],
        "tactic": "Execution",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor for unexpected child-parent process relationships involving scripting engines or service binaries.",
            "Audit use of IPC-related system calls or APIs like CreatePipe, COM interfaces, or named pipes.",
            "Correlate command-line execution with abnormal DLL/module loads or dynamic string usage related to IPC."
        ],
        "data_sources": "Module, Process, Script",
        "log_sources": [
            {"type": "Module", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Script", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "Runtime Memory", "identify": "Unexpected process access or injection"},
            {"type": "Loaded DLLs", "location": "Module List", "identify": "Modules related to COM or DDE"},
            {"type": "Script Execution", "location": "Shell History", "identify": "Piped or redirected IPC abuse"}
        ],
        "destination_artifacts": [
            {"type": "Named Pipe", "location": "C:\\Windows\\Temp or /tmp/", "identify": "Suspicious inter-process channels"},
            {"type": "Process", "location": "System Logs", "identify": "Unusual parent-child process chains"},
            {"type": "Script", "location": "User Directory", "identify": "Automated scripts containing IPC calls"}
        ],
        "detection_methods": [
            "Monitor for unusual module loads linked to IPC (e.g., DDE-related DLLs)",
            "Track creation of named pipes, UNIX sockets, or COM objects with suspicious access patterns",
            "Inspect script execution logs for commands chaining IPC calls"
        ],
        "apt": ["Turla", "ToddyCat", "Cyclops Blink", "Raspberry Robin"],
        "spl_query": [
            "index=win_logs sourcetype=Sysmon EventCode=7 ImageLoaded=*com* OR *dde* \n| stats count by Image, ProcessId, ParentImage",
            "index=linux_logs command=\"*mkfifo*\" OR command=\"*nc -l*\" \n| stats count by user, command, pid"
        ],
        "hunt_steps": [
            "Identify modules loaded related to COM or DDE interfaces",
            "Scan for usage of named pipes, memory-mapped files, or UNIX sockets between non-standard processes",
            "Hunt script files for IPC-related command sequences"
        ],
        "expected_outcomes": [
            "Discovery of process execution chains relying on IPC",
            "Detection of local code injection or command execution via pipe/socket/COM abuse"
        ],
        "false_positive": "Some scripting environments or remote management tools use IPC legitimately. Whitelist known safe patterns and signed binaries.",
        "clearing_steps": [
            "Terminate unauthorized or suspicious IPC-linked processes",
            "Delete created named pipes or temp files used for IPC abuse",
            "Disable scripting or COM-based execution in protected environments (e.g., via ASR rules)"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Scripting environments abusing IPC"},
            {"tactic": "Lateral Movement", "technique": "T1021.003", "example": "Remote IPC via DCOM"}
        ],
        "watchlist": [
            "DDE or COM-related DLLs loaded in unexpected contexts",
            "Creation of anonymous pipes or UNIX domain sockets by non-root users"
        ],
        "enhancements": [
            "Apply ASR rules to block DDE execution in Office documents",
            "Restrict COM usage via ACLs and enforce Protected View",
            "Monitor IPC system calls and usage frequency"
        ],
        "summary": "Inter-process communication (IPC) mechanisms can be abused by adversaries to execute code, transfer data, or coordinate malicious processes. This includes named pipes, sockets, DDE, COM, and related interfaces across platforms.",
        "remediation": "Disable legacy IPC features where possible (e.g., DDEAUTO), enforce script and binary restrictions, and limit user permissions to create communication channels.",
        "improvements": "Enhance system logging for process interactions, and apply behavior-based rules to identify unexpected IPC usage across environments.",
        "mitre_version": "16.1"
    }
