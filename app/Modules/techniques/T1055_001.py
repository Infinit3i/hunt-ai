def get_content():
    return {
        "id": "T1055.001",
        "url_id": "T1055/001",
        "title": "Process Injection: Dynamic-link Library Injection",
        "description": "Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor Windows API calls indicative of DLL injection.",
            "Look for DLLs that are not recognized or not normally loaded into a process."
        ],
        "data_sources": "Module: Module Load, Process: OS API Execution, Process: Process Access, Process: Process Metadata, Process: Process Modification",
        "log_sources": [
            {"type": "Process", "source": "Windows API", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "DLL", "location": "Memory", "identify": "Injected DLL"}
        ],
        "destination_artifacts": [
            {"type": "DLL", "location": "Process", "identify": "Injected DLL"}
        ],
        "detection_methods": [
            "Monitor for suspicious Windows API calls like CreateRemoteThread and VirtualAllocEx.",
            "Detect unusual DLL/PE file events and look for DLLs loaded into unexpected processes."
        ],
        "apt": ["Boominathan Sundaram"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search *"
        ],
        "hunt_steps": [
            "Monitor processes for unusual actions such as opening network connections or reading files.",
            "Look for anomalous processes loading DLLs that are not typically associated with them."
        ],
        "expected_outcomes": [
            "Identify processes with injected DLLs.",
            "Detect abnormal behavior in processes due to injected code."
        ],
        "false_positive": "Legitimate process activity involving DLL loading may trigger false positives.",
        "clearing_steps": [
            "Terminate malicious processes.",
            "Remove injected DLLs and restore processes to normal operation."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Use process injection to evade detection."}
        ],
        "watchlist": [
            "Monitor for DLL injections or suspicious behavior in processes."
        ],
        "enhancements": [
            "Enhance detection by correlating DLL injection activity with other suspicious behaviors."
        ],
        "summary": "DLL injection allows attackers to run arbitrary code in the context of another process, potentially evading detection and elevating privileges.",
        "remediation": "Remove injected DLLs and terminate any malicious processes.",
        "improvements": "Implement stricter monitoring of process behaviors and DLL loading events.",
        "mitre_version": "1.3"
    }
