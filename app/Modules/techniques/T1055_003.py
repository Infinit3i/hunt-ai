def get_content():
    return {
        "id": "T1055.003",
        "url_id": "T1055/003",
        "title": "Process Injection: Thread Execution Hijacking",
        "description": "Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor Windows API calls indicative of Thread Execution Hijacking.",
            "Analyze process behavior to determine if a process is performing actions it usually does not."
        ],
        "data_sources": "Process: OS API Execution, Process: Process Access, Process: Process Modification",
        "log_sources": [
            {"type": "Process", "source": "Windows API", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Injected Code", "location": "Process Memory", "identify": "Hijacked Process"}
        ],
        "destination_artifacts": [
            {"type": "Injected Code", "location": "Process Memory", "identify": "Hijacked Process"}
        ],
        "detection_methods": [
            "Monitor for suspicious API calls like CreateRemoteThread, SuspendThread, SetThreadContext, and ResumeThread.",
            "Analyze for unusual process behaviors, such as unauthorized file access or network connections."
        ],
        "apt": ["Elastic Pikabot", "ESET Gazer", "Trend Micro Waterbear"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search *"
        ],
        "hunt_steps": [
            "Monitor for any process with suspicious API calls associated with thread execution hijacking.",
            "Check for processes performing unusual actions such as creating network connections or reading files."
        ],
        "expected_outcomes": [
            "Identify processes with hijacked threads.",
            "Detect abnormal behavior in processes related to injected code."
        ],
        "false_positive": "Legitimate use of thread management in applications may trigger false positives.",
        "clearing_steps": [
            "Terminate malicious processes.",
            "Restore processes to their normal state by removing injected code."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Use thread execution hijacking to evade detection."}
        ],
        "watchlist": [
            "Monitor for suspicious thread management behaviors in processes."
        ],
        "enhancements": [
            "Enhance detection by correlating thread management activities with known malicious behaviors."
        ],
        "summary": "Thread Execution Hijacking allows attackers to execute code within the context of another process, potentially evading detection and elevating privileges.",
        "remediation": "Remove injected code and restore hijacked processes to normal operation.",
        "improvements": "Implement stronger monitoring and auditing of thread execution within critical processes.",
        "mitre_version": "16.1"
    }
