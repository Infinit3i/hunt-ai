def get_content():
    return {
        "id": "T1055.015",
        "url_id": "T1055/015",
        "title": "Process Injection: ListPlanting",
        "description": "Adversaries may abuse list-view controls to inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. ListPlanting is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor Windows API calls indicative of the various types of code injection, such as FindWindow, EnumWindows, EnumChildWindows, VirtualAllocEx, and WriteProcessMemory.",
            "Consider monitoring for excessive use of SendMessage and/or PostMessage API functions with LVM_SETITEMPOSITION and/or LVM_GETITEMPOSITION arguments."
        ],
        "data_sources": "Process: OS API Execution, Process: Process Modification",
        "log_sources": [
            {"type": "Process", "source": "Windows OS API", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Code", "location": "Injected code via ListView control", "identify": "Injected code executed within the process"}
        ],
        "destination_artifacts": [
            {"type": "Malicious Code", "location": "Hijacked process", "identify": "Malicious code triggered by ListView_SortItems callback"}
        ],
        "detection_methods": [
            "Monitor for abnormal use of window messages such as LVM_SETITEMPOSITION and LVM_GETITEMPOSITION to detect potential ListPlanting attempts.",
            "Analyze process behavior for suspicious actions like unusual network activity or file access."
        ],
        "apt": ["ESET"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search FindWindow OR EnumWindows OR PostMessage"
        ],
        "hunt_steps": [
            "Monitor for messages like LVM_SETITEMPOSITION and LVM_GETITEMPOSITION being sent to process windows.",
            "Detect unusual behavior in processes that may indicate a ListPlanting attack, such as unexpected code execution or payload delivery."
        ],
        "expected_outcomes": [
            "Detection of ListPlanting techniques through the identification of the message-passing attack chain and hijacked processes."
        ],
        "false_positive": "Legitimate use of ListView controls and associated API functions may lead to false positives.",
        "clearing_steps": [
            "Terminate the malicious process and restore the system's integrity.",
            "Remove injected code and undo changes made by the attack."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Inject malicious code into a process via ListPlanting to evade defenses."}
        ],
        "watchlist": [
            "Monitor for abnormal use of window messages and process modifications that involve list-view controls."
        ],
        "enhancements": [
            "Enhance detection by correlating ListPlanting events with other signs of post-compromise behavior."
        ],
        "summary": "ListPlanting is a technique where adversaries inject code into processes by leveraging list-view controls and using message-passing to execute malicious payloads.",
        "remediation": "Terminate the affected processes and restore system integrity. Remove the injected code and monitor for further attacks.",
        "improvements": "Monitor for and correlate the use of message-passing functions that are typically used in ListPlanting, such as PostMessage and SendMessage.",
        "mitre_version": "16.1"
    }
