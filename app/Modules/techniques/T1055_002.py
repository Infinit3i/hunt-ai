def get_content():
    return {
        "id": "T1055.002",
        "url_id": "T1055/002",
        "title": "Process Injection: Portable Executable Injection",
        "description": "Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges. PE injection is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor Windows API calls indicative of PE injection.",
            "Look for suspicious memory modifications within processes."
        ],
        "data_sources": "Process: OS API Execution, Process: Process Access, Process: Process Modification",
        "log_sources": [
            {"type": "Process", "source": "Windows API", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "PE", "location": "Memory", "identify": "Injected PE"}
        ],
        "destination_artifacts": [
            {"type": "PE", "location": "Process", "identify": "Injected PE"}
        ],
        "detection_methods": [
            "Monitor for suspicious Windows API calls like CreateRemoteThread and VirtualAllocEx.",
            "Detect unusual process behaviors such as accessing memory in unexpected ways."
        ],
        "apt": ["Unit 42 Gorgon Group", "ESET InvisiMole", "FireEye CARBANAK"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search *"
        ],
        "hunt_steps": [
            "Monitor processes for abnormal memory access and DLL injection behavior.",
            "Check for processes running code that typically do not belong to them."
        ],
        "expected_outcomes": [
            "Identify processes with injected PE files.",
            "Detect abnormal behavior in processes due to injected code."
        ],
        "false_positive": "Legitimate process activity involving memory allocation or code loading may trigger false positives.",
        "clearing_steps": [
            "Terminate malicious processes.",
            "Remove injected PE files and restore processes to normal operation."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Use process injection to evade detection."}
        ],
        "watchlist": [
            "Monitor for PE injections or suspicious behavior in processes."
        ],
        "enhancements": [
            "Enhance detection by correlating PE injection activity with other suspicious behaviors."
        ],
        "summary": "PE injection allows attackers to execute arbitrary code in the context of another process, which may help evade detection and elevate privileges.",
        "remediation": "Remove injected PE files and terminate malicious processes.",
        "improvements": "Implement stricter monitoring of process behaviors and memory access patterns.",
        "mitre_version": "16.1"
    }
