def get_content():
    return {
        "id": "T1055.005",
        "url_id": "T1055/005",
        "title": "Process Injection: Thread Local Storage",
        "description": "Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor Windows API calls indicative of TLS callback injection.",
            "Analyze process behavior to detect unusual activity such as file access or network connections."
        ],
        "data_sources": "Process: OS API Execution, Process: Process Access, Process: Process Modification",
        "log_sources": [
            {"type": "Process", "source": "Windows API", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Code", "location": "TLS Callback", "identify": "Injected code via TLS"}
        ],
        "destination_artifacts": [
            {"type": "Malicious Code", "location": "TLS Callback", "identify": "Injected code via TLS"}
        ],
        "detection_methods": [
            "Monitor API calls such as CreateRemoteThread, SuspendThread, SetThreadContext, ResumeThread, VirtualAllocEx, and WriteProcessMemory.",
            "Detect suspicious process behaviors or memory modifications."
        ],
        "apt": ["FireEye Ursnif", "TrendMicro Ursnif"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search *"
        ],
        "hunt_steps": [
            "Monitor for processes that may be performing unusual actions or loading suspicious code.",
            "Look for memory writes at specific offsets that could indicate TLS callback manipulation."
        ],
        "expected_outcomes": [
            "Identify injected code via TLS callbacks.",
            "Detect suspicious behavior in processes that are performing unauthorized actions."
        ],
        "false_positive": "Legitimate use of TLS callbacks by applications may trigger false positives.",
        "clearing_steps": [
            "Terminate malicious processes.",
            "Remove injected code and restore process integrity."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Use TLS callback injection to evade detection."}
        ],
        "watchlist": [
            "Monitor for unusual TLS callback activity or process behavior."
        ],
        "enhancements": [
            "Enhance detection by correlating TLS callback injection with other suspicious process behaviors."
        ],
        "summary": "TLS callback injection allows attackers to execute malicious code within a process by manipulating the TLS callbacks, potentially evading detection and elevating privileges.",
        "remediation": "Remove injected code and restore processes to normal operation.",
        "improvements": "Strengthen monitoring of TLS callback functions and related process behavior.",
        "mitre_version": "16.1"
    }
