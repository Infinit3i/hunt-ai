def get_content():
    return {
        "id": "T1564.010",
        "url_id": "T1564/010",
        "title": "Hide Artifacts: Process Argument Spoofing",
        "description": "Adversaries may manipulate process memory to spoof or hide command-line arguments. On Windows systems, process arguments are stored in the Process Environment Block (PEB), which can be overwritten using APIs like `WriteProcessMemory`. This technique allows attackers to launch processes with benign-looking arguments, then replace them with malicious ones in memory, or vice versa. This spoofing is often combined with other evasion techniques like Process Hollowing and Parent PID Spoofing to further bypass detection tools and forensic analysis.",
        "tags": ["PEB", "WriteProcessMemory", "Process Hollowing", "Argument Spoofing", "Evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Correlate command-line arguments with process behavior (e.g., accessing LSASS but showing benign args)",
            "Monitor for API calls like `WriteProcessMemory` following a process creation in suspended state",
            "Inspect execution trees for unusual parent-child process behavior"
        ],
        "data_sources": "Process",
        "log_sources": [
            {"type": "Process", "source": "Sysmon", "destination": "Windows Security"},
            {"type": "Process", "source": "ETW", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process", "location": "PEB memory segment", "identify": "Modified command-line arguments"},
            {"type": "File", "location": "Suspicious process logs", "identify": "Argument mismatch from logs vs. memory"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Memory snapshot", "identify": "Overwritten arguments in runtime memory"},
            {"type": "Process", "location": "Sysmon Event ID 1", "identify": "Process creation with misleading arguments"}
        ],
        "detection_methods": [
            "Compare original arguments from Event ID 1 with real-time memory analysis",
            "Trace child processes created in a suspended state followed by memory write operations",
            "Use memory integrity tools to capture discrepancies between argument logs and current state"
        ],
        "apt": [
            "Cobalt Group", "FiveHands", "APT41"
        ],
        "spl_query": [
            "index=sysmon sourcetype=Sysmon:ProcessCreate \n| search CommandLine=\"*explorer.exe*\" \n| join ProcessId [search index=sysmon sourcetype=Sysmon:ProcessAccess \n| search SourceImage=\"*powershell*\" TargetImage=\"*explorer.exe*\"] \n| stats count by SourceImage, TargetImage, CommandLine",
            "index=security EventCode=4688 \n| search CommandLine=\"*cmd*\" AND CreatorProcessName=\"*svchost.exe*\" \n| stats count by CommandLine, CreatorProcessName, NewProcessName"
        ],
        "hunt_steps": [
            "Capture process arguments using event logs (Sysmon Event ID 1, Security Event 4688)",
            "Use Volatility or Rekall to inspect PEB for live memory of suspected processes",
            "Trace WriteProcessMemory calls following process creation in suspended state"
        ],
        "expected_outcomes": [
            "Detection of processes where behavior does not align with logged arguments",
            "Uncovering of spoofed or tampered command-line values in memory",
            "Identification of stealthy execution using memory manipulation APIs"
        ],
        "false_positive": "Certain legitimate software or debugging tools may temporarily alter memory and process attributes. Correlate behavior across multiple telemetry points.",
        "clearing_steps": [
            "Kill the affected process and capture memory dump for analysis",
            "Scan with EDR tools for process memory anomalies",
            "Re-image endpoint if process tampering is confirmed"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055.012", "example": "Process Hollowing followed by argument spoofing"},
            {"tactic": "Execution", "technique": "T1106", "example": "Use of Native API for memory manipulation"}
        ],
        "watchlist": [
            "Processes created in suspended state then accessed via `WriteProcessMemory`",
            "PEB modifications not aligned with parent process intent",
            "Discrepancies between process behavior and command-line log entries"
        ],
        "enhancements": [
            "Enable command-line argument logging at high verbosity (Sysmon, Windows Security)",
            "Deploy memory analysis tools to periodically check running processes",
            "Flag PEB modifications for post-process review"
        ],
        "summary": "Process Argument Spoofing involves manipulating in-memory structures to hide real execution intent. Adversaries use this technique to disguise commands and evade detection tools that rely on process logs or superficial inspection.",
        "remediation": "Enforce secure boot and code integrity. Log all process creations and monitor memory manipulation behavior using advanced EDR solutions.",
        "improvements": "Add memory consistency checks to detect mismatches in PEB and actual process activity. Incorporate process-tree validation during behavioral analysis.",
        "mitre_version": "16.1"
    }
