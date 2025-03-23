def get_content():
    return {
        "id": "T1055.009",
        "url_id": "T1055/009",
        "title": "Process Injection: Proc Memory",
        "description": "Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux",
        "tips": [
            "Monitor for modifications to the /proc filesystem.",
            "Analyze process behavior to detect deviations such as accessing network connections or files."
        ],
        "data_sources": "File: File Modification",
        "log_sources": [
            {"type": "File", "source": "/proc filesystem", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Code", "location": "/proc/[pid]/mem", "identify": "Injected code via /proc filesystem"}
        ],
        "destination_artifacts": [
            {"type": "Malicious Code", "location": "/proc/[pid]/mem", "identify": "Injected code via /proc filesystem"}
        ],
        "detection_methods": [
            "Monitor for suspicious changes to the /proc filesystem, especially the memory files of running processes.",
            "Analyze for unusual process behavior such as accessing unexpected resources."
        ],
        "apt": ["Lumen KVBotnet"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search /proc"
        ],
        "hunt_steps": [
            "Monitor processes for unusual modifications within the /proc filesystem.",
            "Look for abnormal process behavior, including accessing files or network resources unexpectedly."
        ],
        "expected_outcomes": [
            "Identify processes where malicious code has been injected via proc memory.",
            "Detect abnormal behavior in processes due to injected code."
        ],
        "false_positive": "Legitimate use of the /proc filesystem may trigger false positives.",
        "clearing_steps": [
            "Terminate malicious processes.",
            "Remove injected code and restore process integrity."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Use /proc filesystem to inject code into running processes."}
        ],
        "watchlist": [
            "Monitor for suspicious activity related to the /proc filesystem, particularly for modifications to process memory."
        ],
        "enhancements": [
            "Enhance detection by correlating /proc filesystem changes with other malicious behaviors."
        ],
        "summary": "Proc memory injection allows attackers to inject malicious code into processes via the /proc filesystem, evading detection and potentially elevating privileges.",
        "remediation": "Remove injected code and terminate malicious processes.",
        "improvements": "Strengthen monitoring of the /proc filesystem and process activity to detect suspicious behaviors.",
        "mitre_version": "16.1"
    }
