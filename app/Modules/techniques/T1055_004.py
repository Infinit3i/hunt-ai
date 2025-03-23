def get_content():
    return {
        "id": "T1055.004",
        "url_id": "T1055/004",
        "title": "Process Injection: Asynchronous Procedure Call",
        "description": "Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges. APC injection is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor Windows API calls indicative of APC injection.",
            "Analyze process behavior to identify actions that deviate from normal behavior, such as opening network connections or reading files."
        ],
        "data_sources": "Process: OS API Execution, Process: Process Access, Process: Process Modification",
        "log_sources": [
            {"type": "Process", "source": "Windows API", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Code", "location": "APC Queue", "identify": "Injected code via APC"}
        ],
        "destination_artifacts": [
            {"type": "Malicious Code", "location": "APC Queue", "identify": "Injected code via APC"}
        ],
        "detection_methods": [
            "Monitor API calls like QueueUserAPC, NtQueueApcThread, and other functions associated with APC injection.",
            "Detect suspicious process behaviors or modifications in memory space."
        ],
        "apt": ["IBM IcedID", "ESET InvisiMole", "Symantec FIN8"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search *"
        ],
        "hunt_steps": [
            "Monitor processes for unusual thread execution associated with APCs.",
            "Look for deviations in process behavior, such as access to unusual resources or files."
        ],
        "expected_outcomes": [
            "Identify processes where malicious code has been injected via APC.",
            "Detect unusual execution patterns in processes."
        ],
        "false_positive": "Legitimate use of thread management or asynchronous calls may trigger false positives.",
        "clearing_steps": [
            "Terminate malicious processes.",
            "Remove injected code from the process's memory space."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Use APC to inject code and evade detection."}
        ],
        "watchlist": [
            "Monitor for unusual APC-related activities in processes."
        ],
        "enhancements": [
            "Enhance detection by correlating APC injections with known malicious behaviors or post-compromise actions."
        ],
        "summary": "APC injection allows attackers to execute arbitrary code in the context of another process, which could evade security detection and elevate privileges.",
        "remediation": "Remove injected code and terminate malicious processes.",
        "improvements": "Improve monitoring of API calls and process behavior to detect suspicious thread activities.",
        "mitre_version": "16.1"
    }
