def get_content():
    return {
        "id": "T1197",
        "url_id": "1197",
        "title": "BITS Jobs",
        "description": "Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations. The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool. Adversaries may abuse BITS to download (e.g., Ingress Tool Transfer), execute, and even clean up after running malicious code (e.g., Indicator Removal). BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots). BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol.",
        "tags": ["Persistence", "Defense Evasion", "Windows"],
        "tactic": "Defense Evasion, Persistence",
        "protocol": "Windows",
        "os": "Windows",
        "tips": [
            "Monitor the status of BITS service using 'sc query bits'.",
            "Check for active BITS jobs using 'bitsadmin /list /allusers /verbose'."
        ],
        "data_sources": "Command: Command Execution, Network Traffic: Network Connection Creation, Process: Process Creation, Service: Service Metadata",
        "log_sources": [
            {"type": "Command", "source": "BITSAdmin", "destination": "SIEM"},
            {"type": "Service", "source": "Windows Event Logs", "destination": "Security Monitoring"}
        ],
        "source_artifacts": [
            {"type": "Log", "location": "C:\\Windows\\System32\\bits.log", "identify": "BITS job records"}
        ],
        "destination_artifacts": [
            {"type": "Log", "location": "C:\\Windows\\System32\\EventViewer", "identify": "BITS Execution Logs"}
        ],
        "detection_methods": [
            "Monitor usage of BITSAdmin tool and its commands.",
            "Analyze network traffic for unusual HTTP(S) and SMB-based BITS jobs."
        ],
        "apt": ["APT39", "APT41", "PLATINUM", "FIN12"],
        "spl_query": [
            "index=windows_logs | search EventID=7045 | stats count by ImagePath, ServiceName",
            "index=process_creation | search ParentProcessName=bitsadmin.exe | stats count by ProcessName"
        ],
        "hunt_steps": [
            "Identify long-standing BITS jobs with extended lifetimes.",
            "Check for BITS jobs triggering execution of suspicious binaries."
        ],
        "expected_outcomes": [
            "Detection of malicious BITS jobs used for persistence.",
            "Identification of unauthorized downloads or executions."
        ],
        "false_positive": "Legitimate software updates may use BITS jobs for file transfers.",
        "clearing_steps": [
            "Terminate suspicious BITS jobs using 'bitsadmin /cancel'.",
            "Disable unauthorized BITS usage via Group Policy."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.001", "example": "PowerShell Execution via BITS"},
            {"tactic": "Exfiltration", "technique": "T1048", "example": "Exfiltration Over Alternative Protocol"}
        ],
        "watchlist": [
            "Monitor BITS job creations and modifications by non-administrative users.",
            "Alert on unexpected command-line usage of bitsadmin.exe."
        ],
        "enhancements": [
            "Implement logging of BITS jobs to track execution history.",
            "Restrict BITSAdmin execution to authorized administrators."
        ],
        "summary": "BITS jobs can be exploited by adversaries to persist on a system and execute malicious code covertly.",
        "remediation": "Restrict BITS job creation and execution using policy settings.",
        "improvements": "Regularly audit BITS job database for unauthorized entries."
    }