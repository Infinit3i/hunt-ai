def get_content():
    return {
        "id": "T1055.014",
        "url_id": "T1055/014",
        "title": "Process Injection: VDSO Hijacking",
        "description": "Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux",
        "tips": [
            "Monitor for malicious usage of system calls, such as ptrace and mmap, that can be used to attach to, manipulate memory, and redirect a process' execution path.",
            "Analyze for unusual process behavior after hijacking, such as opening network connections, reading files, or other suspicious post-compromise actions."
        ],
        "data_sources": "Module: Module Load, Process: OS API Execution",
        "log_sources": [
            {"type": "Module", "source": "Linux Kernel", "destination": ""},
            {"type": "Process", "source": "Linux OS API", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Code", "location": "VDSO Hijacked Memory", "identify": "Injected code via VDSO hijacking"}
        ],
        "destination_artifacts": [
            {"type": "Malicious Code", "location": "Hijacked Process", "identify": "Injected code running in hijacked process"}
        ],
        "detection_methods": [
            "Monitor for Linux system calls such as ptrace and mmap that manipulate memory and redirect execution paths.",
            "Monitor processes that deviate from expected behaviors, such as opening network connections or reading files that they don't usually access."
        ],
        "apt": ["ArtOfMemoryForensics", "GNU Acct", "RHEL auditd", "Chokepoint preload rootkits"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search ptrace OR mmap"
        ],
        "hunt_steps": [
            "Monitor for suspicious activity using ptrace and mmap system calls.",
            "Analyze memory manipulation events and redirecting execution paths."
        ],
        "expected_outcomes": [
            "Identify injected malicious code via VDSO hijacking.",
            "Detect suspicious system calls used for hijacking."
        ],
        "false_positive": "Legitimate uses of ptrace and mmap system calls may trigger false positives.",
        "clearing_steps": [
            "Terminate the malicious process and restore the system's integrity.",
            "Remove injected code and undo changes made by the attack."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Use VDSO hijacking to inject malicious code into a process."}
        ],
        "watchlist": [
            "Monitor for abnormal process behavior, such as unexpected memory manipulation or syscall usage."
        ],
        "enhancements": [
            "Enhance detection by correlating VDSO hijacking attempts with other suspicious process behaviors."
        ],
        "summary": "VDSO hijacking allows attackers to inject code into a process via the VDSO shared object, evading detection and potentially gaining elevated privileges.",
        "remediation": "Restore system integrity by removing the injected code and reverting the hijacked process.",
        "improvements": "Monitor for malicious manipulation of memory through VDSO hijacking and correlate with process activity.",
        "mitre_version": "16.1"
    }
