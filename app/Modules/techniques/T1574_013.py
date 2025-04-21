def get_content():
    return {
        "id": "T1574.013",
        "url_id": "T1574/013",
        "title": "Hijack Execution Flow: KernelCallbackTable",
        "description": "Adversaries may abuse the `KernelCallbackTable` within the Process Environment Block (PEB) of a process to hijack execution flow and trigger their own payloads. This table, initialized when `user32.dll` is loaded by a GUI application, stores function pointers for various window message callbacks.\n\nAn attacker can hijack this mechanism by locating the PEB (e.g., using `NtQueryInformationProcess()`), copying the original `KernelCallbackTable`, and modifying function pointers (e.g., `fnCOPYDATA`) to point to injected malicious code via `WriteProcessMemory()`. The process then uses a crafted message (like `WM_COPYDATA`) to invoke the malicious callback. The malware may later restore the table to reduce forensic evidence or detection.\n\nThis technique may be used with other behaviors such as Reflective Code Loading or Process Injection and is notable for its stealth, since it leverages trusted GUI messaging infrastructure for execution.",
        "tags": ["KernelCallbackTable", "PEB", "Process Injection", "NtQueryInformationProcess", "GUI-based evasion", "Windows Internals"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor processes that load `user32.dll` and unexpectedly invoke Windows messages like `WM_COPYDATA`.",
            "Use memory scanning tools to identify changes in callback tables within the PEB of processes.",
            "Correlate API calls like `NtQueryInformationProcess` and `WriteProcessMemory` with GUI-based execution flow."
        ],
        "data_sources": "Process: OS API Execution",
        "log_sources": [
            {"type": "Process", "source": "WinAPI execution monitoring (e.g., NtQueryInformationProcess, WriteProcessMemory)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows API", "location": "Process memory", "identify": "NtQueryInformationProcess call with ProcessBasicInformation"},
            {"type": "Memory Injection", "location": "KernelCallbackTable pointer", "identify": "Modified fnCOPYDATA function"}
        ],
        "destination_artifacts": [
            {"type": "PEB manipulation", "location": "Target process memory", "identify": "Redirected KernelCallbackTable"},
            {"type": "Restored callback table", "location": "After payload execution", "identify": "Cleanup pattern by malware"}
        ],
        "detection_methods": [
            "Detect `NtQueryInformationProcess()` with `ProcessBasicInformation` followed by `WriteProcessMemory()` targeting the KernelCallbackTable.",
            "Monitor Windows message queues for unexpected messages being sent to processes that normally do not handle GUI events.",
            "Inspect PEB structures for modified function pointers during forensic memory analysis."
        ],
        "apt": ["Lazarus", "FinFisher"],
        "spl_query": [
            "index=sysmon EventCode=10 TargetImage=\"*.exe\" CallTrace=\"*NtQueryInformationProcess*\"\n| stats count by TargetImage, SourceImage, CallTrace"
        ],
        "hunt_steps": [
            "Identify non-GUI processes loading `user32.dll` unexpectedly",
            "Scan memory for modified `KernelCallbackTable` entries",
            "Trace behavior following Windows messages triggering injected functions"
        ],
        "expected_outcomes": [
            "Detection of KernelCallbackTable redirection for stealthy payload execution",
            "Identification of GUI message misuse as an execution vector",
            "Recovery of forensic indicators post-execution"
        ],
        "false_positive": "Some legitimate GUI-based tools may use `NtQueryInformationProcess` or handle `WM_COPYDATA`, but these do not modify `KernelCallbackTable` entries. Confirm with behavioral analysis.",
        "clearing_steps": [
            "Restore original KernelCallbackTable if modified",
            "Terminate and isolate affected processes",
            "Perform memory integrity scans to identify persistence mechanisms"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1574.013", "example": "Hijacking GUI callback table to trigger malicious payloads via legitimate message handling"}
        ],
        "watchlist": [
            "Repeated use of `NtQueryInformationProcess` and `WriteProcessMemory` from the same process",
            "Processes sending suspicious messages like `WM_COPYDATA` to high-privilege GUI processes",
            "Unexpected restoration of memory regions within the PEB"
        ],
        "enhancements": [
            "Tag usage of `NtQueryInformationProcess` + `WriteProcessMemory` as high-risk API chaining",
            "Deploy memory-resident EDR heuristics for callback table inspection",
            "Enable Sysmon config for API call logging with tracing"
        ],
        "summary": "Hijacking the KernelCallbackTable enables attackers to run malicious code stealthily using trusted GUI callback paths. It provides an advanced method of code execution while minimizing visibility in traditional logs or hooks.",
        "remediation": "Implement strict control of interprocess communication. Harden GUI processes with memory protections. Monitor for WinAPI abuse through behavioral analysis.",
        "improvements": "Expand EDR signatures to detect PEB field tampering. Use heuristics to identify misused GUI messages and injected memory regions.",
        "mitre_version": "16.1"
    }
