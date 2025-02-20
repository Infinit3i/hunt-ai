def get_content():
    """
    Returns structured content for the Windows Management Instrumentation (WMI) persistence method.
    """
    return {
        "id": "T1047",
        "url_id": "T1047",
        "title": "Windows Management Instrumentation (WMI)",
        "tactic": "Execution, Persistence, Defense Evasion",
        "data_sources": "Windows Event Logs, Registry, File System, Process Monitoring",
        "protocol": "WMI",
        "os": "Windows",
        "objective": "Adversaries may abuse WMI to execute malicious scripts, establish persistence, or evade detection.",
        "scope": "Monitor WMI execution and changes to the WMI repository.",
        "threat_model": "WMI allows attackers to execute commands, create event filters for persistence, or run malicious payloads without dropping files to disk.",
        "hypothesis": [
            "Are unauthorized WMI event filters and consumers being created?",
            "Are attackers leveraging WMI to execute PowerShell or other malicious scripts?",
            "Are WMI persistence techniques being used to evade detection?"
        ],
        "tips": [
            "Enable logging for WMI activity (Event IDs 5857, 5858, 5860, 5861).",
            "Monitor for processes spawned by WMI (wmiprvse.exe spawning cmd.exe, PowerShell, etc.).",
            "Investigate new or modified WMI Event Consumers and Event Filters."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Microsoft-Windows-WMI-Activity/Operational.evtx", "destination": "System.evtx"},
            {"type": "Registry", "source": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Wbem\\CIMOM"},
            {"type": "File System", "source": "C:\\Windows\\System32\\wbem\\Repository"}
        ],
        "source_artifacts": [
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch", "identify": "wmic.exe, scrcons.exe"}
        ],
        "destination_artifacts": [
            {"type": "WMI Event Filters", "location": "C:\\Windows\\System32\\wbem\\Repository", "identify": "Malicious event filters or consumers"}
        ],
        "detection_methods": [
            "Monitor creation of WMI Event Consumers (Event ID 5861).",
            "Detect execution of suspicious scripts via WMI.",
            "Analyze WMI repository for unauthorized changes."
        ],
        "apt": ["G0096", "G0045"],
        "spl_query": [
            "index=windows EventCode=5857 OR EventCode=5861 | table Time, User, Operation, FilterName, ConsumerName",
            "index=windows process='wmiprvse.exe' OR process='scrcons.exe' \n| table Time, Process, ParentProcess, Command"
        ],
        "hunt_steps": [
            "Search for recently created WMI Event Consumers and Event Filters.",
            "Investigate processes spawned by WMI (wmiprvse.exe executing PowerShell, cmd.exe, etc.).",
            "Analyze registry keys and WMI repository for unauthorized modifications."
        ],
        "expected_outcomes": [
            "Unauthorized WMI persistence detected and removed.",
            "No malicious WMI activity found, improving detection baselines."
        ],
        "false_positive": "Legitimate system administrators may use WMI for remote management and automation tasks.",
        "clearing_steps": [
            "wmic /namespace:\\root\\subscription PATH __EventFilter DELETE",
            "wmic /namespace:\\root\\subscription PATH __EventConsumer DELETE",
            "Remove unauthorized WMI scripts and event filters."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059 (Command and Scripting Interpreter)", "example": "Adversaries execute PowerShell commands via WMI."}
        ],
        "watchlist": [
            "Monitor for unauthorized modifications to WMI repository.",
            "Detect abnormal parent-child relationships involving wmiprvse.exe."
        ],
        "enhancements": [
            "Enable detailed logging of WMI execution.",
            "Implement least privilege policies to restrict WMI usage."
        ],
        "summary": "Adversaries abuse WMI to execute commands, establish persistence, or evade detection.",
        "remediation": "Remove unauthorized WMI Event Filters and Event Consumers, enforce logging and access restrictions.",
        "improvements": "Enhance monitoring of WMI-related logs and integrate threat intelligence for WMI-based attacks."
    }
