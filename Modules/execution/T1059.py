def get_content():
    return {
        "id": "T1059",
        "url_id": "T1059",
        "title": "Command Line Interface",
        "tactic": "Execution",
        "data_sources": "Process Monitoring, API Logs",
        "protocol": "CLI",
        "os": "Windows, Linux, Mac",
        "objective": "Detect adversary abuse of command-line interfaces",
        "scope": "Monitor command execution and scripts",
        "threat_model": "Adversaries use command lines to execute malicious code",
        "hypothesis": [
            "Are attackers using PowerShell to execute scripts?",
            "Are there unauthorized CLI access attempts?"
        ],
        "log_sources": [
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1"},
            {"type": "API Logs", "source": "Windows API Monitoring"}
        ],
        "detection_methods": [
            "Analyze PowerShell execution",
            "Monitor Bash scripts on Linux endpoints"
        ],
        "spl_query": "index=endpoint sourcetype=sysmon EventCode=1 | stats count by CommandLine",
        "sigma_rule": "T1059 Sigma Rule",
        "hunt_steps": [
            "Run SIEM queries to find CLI activity",
            "Correlate with endpoint logs",
            "Check for encoded PowerShell commands"
        ],
        "expected_outcomes": [
            "Detect suspicious CLI execution",
            "Correlate with known attacker behavior"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Adversary using PowerShell to execute malware"}
        ],
        "watchlist": ["Flag PowerShell scripts with encoded commands"],
        "enhancements": ["Enable process auditing for script execution"],
        "summary": "Analysis of CLI execution patterns",
        "remediation": "Block unauthorized CLI execution",
        "improvements": "Enhance logging for process command lines"
    }
