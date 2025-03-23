def get_content():
    return {
        "id": "T1055.008",
        "url_id": "T1055/008",
        "title": "Process Injection: Ptrace System Calls",
        "description": "Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux",
        "tips": [
            "Monitor for Linux-specific ptrace system calls, such as PTRACE_SETREGS, PTRACE_POKETEXT, and PTRACE_POKEDATA.",
            "Analyze process behavior to detect deviations such as abnormal access to network connections or files."
        ],
        "data_sources": "Process: OS API Execution, Process: Process Access, Process: Process Modification",
        "log_sources": [
            {"type": "Process", "source": "Linux ptrace system call", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Code", "location": "Process Memory", "identify": "Injected code via ptrace"}
        ],
        "destination_artifacts": [
            {"type": "Malicious Code", "location": "Process Memory", "identify": "Injected code via ptrace"}
        ],
        "detection_methods": [
            "Monitor for ptrace-related system calls and process behaviors indicating code injection.",
            "Analyze process memory and execution flow for suspicious activity."
        ],
        "apt": ["Mandiant Pulse Secure Zero-Day"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search ptrace"
        ],
        "hunt_steps": [
            "Monitor processes for unusual ptrace system call activity.",
            "Check for abnormal behavior such as processes accessing memory in an unexpected way."
        ],
        "expected_outcomes": [
            "Identify malicious ptrace injection activities.",
            "Detect suspicious behavior that may relate to post-compromise activities."
        ],
        "false_positive": "Legitimate debugging activities using ptrace may trigger false positives.",
        "clearing_steps": [
            "Terminate malicious processes.",
            "Remove injected code and restore process integrity."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Use ptrace to inject code into running processes."}
        ],
        "watchlist": [
            "Monitor ptrace system calls and process behaviors for suspicious activity."
        ],
        "enhancements": [
            "Enhance detection by correlating ptrace activity with other suspicious behaviors."
        ],
        "summary": "Ptrace system call injection allows attackers to inject malicious code into running processes, potentially evading detection and elevating privileges.",
        "remediation": "Remove injected code and terminate malicious processes.",
        "improvements": "Strengthen monitoring of ptrace system calls and process activity to detect suspicious behaviors.",
        "mitre_version": "16.1"
    }
