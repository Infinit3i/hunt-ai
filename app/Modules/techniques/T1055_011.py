def get_content():
    return {
        "id": "T1055.011",
        "url_id": "T1055/011",
        "title": "Process Injection: Extra Window Memory Injection",
        "description": "Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for API calls related to manipulating EWM such as GetWindowLong and SetWindowLong.",
            "Look for unusual interactions with window classes or unexpected use of SendNotifyMessage."
        ],
        "data_sources": "Process: OS API Execution",
        "log_sources": [
            {"type": "Process", "source": "Windows API", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Code", "location": "Extra Window Memory", "identify": "Injected code via EWM"}
        ],
        "destination_artifacts": [
            {"type": "Malicious Code", "location": "Extra Window Memory", "identify": "Injected code via EWM"}
        ],
        "detection_methods": [
            "Monitor for GetWindowLong and SetWindowLong API calls.",
            "Detect use of SendNotifyMessage to trigger malicious window procedures."
        ],
        "apt": ["WeLiveSecurity Gapz and Redyms", "MalwareTech Power Loader"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search GetWindowLong OR SetWindowLong OR SendNotifyMessage"
        ],
        "hunt_steps": [
            "Monitor for API calls and behaviors associated with EWM manipulation.",
            "Look for suspicious interactions with window procedures or unexpected process behaviors."
        ],
        "expected_outcomes": [
            "Identify malicious code injected via EWM.",
            "Detect abnormal interactions with window procedures or other system functions."
        ],
        "false_positive": "Legitimate use of EWM manipulation or window procedures may trigger false positives.",
        "clearing_steps": [
            "Terminate malicious processes.",
            "Remove injected code and restore the integrity of the target process."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Use EWM to inject code into a running process."}
        ],
        "watchlist": [
            "Monitor for abnormal API calls related to EWM and window procedures."
        ],
        "enhancements": [
            "Enhance detection by correlating EWM activity with other suspicious behaviors."
        ],
        "summary": "EWM injection allows attackers to inject malicious code into processes through the use of Extra Window Memory, potentially evading detection and elevating privileges.",
        "remediation": "Remove injected code and restore the normal operation of the process.",
        "improvements": "Strengthen monitoring of EWM-related API calls and window procedure interactions.",
        "mitre_version": "16.1"
    }
