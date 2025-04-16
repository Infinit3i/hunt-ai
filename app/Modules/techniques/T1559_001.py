def get_content():
    return {
        "id": "T1559.001",
        "url_id": "T1559/001",
        "title": "Inter-Process Communication: Component Object Model",
        "description": "Adversaries may abuse the Windows Component Object Model (COM) to execute arbitrary code. COM enables communication between software components and can be used locally or remotely (via DCOM) to execute DLLs, EXEs, or scripts. Malicious actors may use COM to run payloads, establish persistence, or escalate privileges.",
        "tags": ["com", "ipc", "windows", "code execution", "execution abuse", "dcom", "persistence"],
        "tactic": "Execution",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor creation of processes tied to known COM execution pathways.",
            "Track registry queries for COM CLSIDs and related interfaces.",
            "Watch for unexpected users invoking COM objects on shared or remote hosts."
        ],
        "data_sources": "Module, Process, Script",
        "log_sources": [
            {"type": "Module", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Script", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Hives", "location": "HKCR\\CLSID", "identify": "COM object registration or enumeration"},
            {"type": "Process List", "location": "System Memory", "identify": "Suspicious parent-child process involving rundll32, wscript, etc."},
            {"type": "Script Execution", "location": "User profile scripts or temp folders", "identify": "PowerShell or VBScript invoking COM interfaces"}
        ],
        "destination_artifacts": [
            {"type": "Module", "location": "C:\\Windows\\System32", "identify": "DLLs loaded by COM objects"},
            {"type": "Process", "location": "System Logs", "identify": "Processes executed through DCOM or via CLSID launches"},
            {"type": "Script", "location": "Startup folders or registry keys", "identify": "Persistence via COM-based tasks"}
        ],
        "detection_methods": [
            "Detect creation of processes from COM-based parent processes",
            "Alert on DLL loads linked to suspicious CLSIDs",
            "Identify PowerShell or WMI scripting tied to COM object instantiation"
        ],
        "apt": ["MuddyWater", "NICKEL", "Trickbot", "Hermetic Wizard", "Gamaredon", "Raspberry Robin", "Bumblebee"],
        "spl_query": [
            "index=win_logs sourcetype=Sysmon EventCode=1 ParentImage=*rundll32.exe OR *wscript.exe \n| stats count by Image, ParentImage, CommandLine",
            "index=win_logs EventCode=4688 CommandLine=*New-Object -ComObject* \n| stats count by Account_Name, CommandLine, ParentProcessName"
        ],
        "hunt_steps": [
            "Enumerate registry for COM objects registered with suspicious DLLs",
            "Hunt for use of `New-Object -ComObject` in PowerShell logs",
            "Search for DCOM-based activity across workstations and servers"
        ],
        "expected_outcomes": [
            "Detection of COM object abuse for arbitrary code execution",
            "Discovery of persistent payloads tied to CLSID registration or scripting interfaces"
        ],
        "false_positive": "Legitimate software may use COM objects for automation. Validate user context, parent processes, and signed binaries before response.",
        "clearing_steps": [
            "Remove malicious registry keys associated with abused COM objects",
            "Kill processes launched via COM and audit involved binaries",
            "Apply ASR rules or COM ACL restrictions to sensitive objects"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.001", "example": "PowerShell invoking COM to run payload"},
            {"tactic": "Persistence", "technique": "T1053", "example": "Scheduled task created via COM interface"}
        ],
        "watchlist": [
            "Use of `New-Object -ComObject` in scripts",
            "Abnormal rundll32, mmc, or svchost launches with suspicious arguments"
        ],
        "enhancements": [
            "Harden COM permissions using DCOMCNFG and registry ACLs",
            "Enable ASR rules to prevent Office from creating child processes via COM",
            "Apply script-block logging and CLIP logging for COM instantiation"
        ],
        "summary": "COM provides a mechanism for inter-process interaction in Windows. Adversaries may abuse COM to execute payloads, establish persistence, or escalate privileges by calling COM interfaces through scripts or binary execution paths.",
        "remediation": "Audit and lock down COM object permissions, monitor scripting interfaces, and enforce ASR and Protected View where applicable.",
        "improvements": "Implement user-level COM launch restrictions and monitor for changes to COM-related registry hives.",
        "mitre_version": "16.1"
    }
