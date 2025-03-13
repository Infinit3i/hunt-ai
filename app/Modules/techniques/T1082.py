def get_content():
    return {
        "id": "T1082",
        "url_id": "T1082",
        "title": "System Information Discovery",
        "tactic": "discovery",
        "data_sources": "Process monitoring, API monitoring, File monitoring, Windows Registry",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Identify details about the target system for further exploitation or persistence.",
        "scope": "Endpoint",
        "threat_model": "Adversaries attempt to gather information about the system, such as OS version, hardware configuration, and software installations, to tailor their attack strategy.",
        "hypothesis": [
            "An adversary may attempt to collect system details using built-in commands or malicious scripts."
        ],
        "log_sources": [
            {"type": "Process", "source": "Process Creation", "destination": "Security Log"},
            {"type": "Registry", "source": "Registry Key Access", "destination": "Sysmon Event ID 12"},
            {"type": "API", "source": "System API Calls", "destination": "ETW Logs"}
        ],
        "detection_methods": [
            "Monitor process execution for reconnaissance commands",
            "Detect suspicious access to system registry keys",
            "Analyze script execution patterns",
            "Review API calls querying system details"
        ],
        "apt_": [
            "APT28",
            "FIN7",
            "Lazarus Group"
        ],
        "spl_query": [
            'index=security EventCode=4688 CommandLine IN (\"systeminfo\", \"wmic os get\", \"hostname\")'
        ],
        "hunt_steps": [
            "Identify and review execution of system discovery commands",
            "Correlate process creation logs with command-line parameters",
            "Analyze registry modifications indicative of reconnaissance activities"
        ],
        "expected_outcomes": [
            "Suspicious system information gathering attempts detected",
            "Legitimate administrative commands distinguished from malicious activity"
        ],
        "clearing_steps": [
            "Clear executed command history (e.g., using PowerShell or shell history commands)",
            "Modify registry to remove traces of reconnaissance attempts"
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "System Information Discovery", "example": "Adversary runs 'systeminfo' to collect OS details."}
        ],
        "watchlist": [
            "Frequent execution of 'systeminfo', 'hostname', or 'wmic' by non-admin users",
            "Unusual system registry queries related to system configuration"
        ],
        "enhancements": [
            "Implement behavioral baselining to detect anomalies in reconnaissance activity"
        ],
        "summary": "Adversaries use built-in system commands and scripts to collect system information, enabling them to refine their attack strategies.",
        "remediation": "Restrict execution of unnecessary system utilities, enforce least privilege access, and monitor execution of reconnaissance commands.",
        "improvements": "Enhance endpoint monitoring for process execution and registry modifications related to reconnaissance activities.",
        "false_positive": "Legitimate administrative tasks or troubleshooting actions may generate similar logs. Context analysis is required to differentiate malicious from benign activities.",
    }
