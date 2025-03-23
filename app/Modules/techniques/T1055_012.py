def get_content():
    return {
        "id": "T1055.012",
        "url_id": "T1055/012",
        "title": "Process Injection: Process Hollowing",
        "description": "Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for API calls indicative of code injection, such as CreateProcess, ZwUnmapViewOfSection, and WriteProcessMemory.",
            "Correlate the creation of suspended processes with other malicious activities like memory modifications."
        ],
        "data_sources": "Process: OS API Execution, Process: Process Access, Process: Process Creation, Process: Process Modification",
        "log_sources": [
            {"type": "Process", "source": "Windows API", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Code", "location": "Process Memory", "identify": "Injected code via process hollowing"}
        ],
        "destination_artifacts": [
            {"type": "Malicious Code", "location": "Process Memory", "identify": "Injected code via process hollowing"}
        ],
        "detection_methods": [
            "Monitor for process creation with a suspended state.",
            "Look for unusual memory modifications, especially in processes created with a suspended thread."
        ],
        "apt": [
            "Proofpoint Leviathan",
            "Telefonica Snip3",
            "Securelist Dtrack"
        ],
        "spl_query": [
            "| index=sysmon sourcetype=process | search CreateProcess OR ZwUnmapViewOfSection OR WriteProcessMemory"
        ],
        "hunt_steps": [
            "Monitor for suspicious process behavior, such as accessing files or network connections unexpectedly.",
            "Identify suspicious API calls related to process suspension and memory manipulation."
        ],
        "expected_outcomes": [
            "Identify injected code in processes created in a suspended state.",
            "Detect abnormal behavior in hollowed processes."
        ],
        "false_positive": "Legitimate use of process creation with suspended threads may trigger false positives.",
        "clearing_steps": [
            "Terminate malicious processes.",
            "Restore the integrity of the affected process by removing injected code."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Use process hollowing to inject code into a running process."}
        ],
        "watchlist": [
            "Monitor for unusual process creation, especially with the suspended thread flag set."
        ],
        "enhancements": [
            "Enhance detection by correlating hollowed process activity with other signs of post-compromise behavior."
        ],
        "summary": "Process hollowing allows attackers to inject malicious code into suspended processes, evading detection and possibly elevating privileges.",
        "remediation": "Terminate malicious processes and remove injected code.",
        "improvements": "Strengthen monitoring of process creation and memory access patterns.",
        "mitre_version": "16.1"
    }
