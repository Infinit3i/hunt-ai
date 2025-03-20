def get_content():
    return {
        "id": "T1622",  # Tactic Technique ID
        "url_id": "1622",  # URL segment for technique reference
        "title": "Debugger Evasion",  # Name of the attack technique
        "description": "Adversaries may detect and avoid debuggers by using checks such as IsDebuggerPresent(), NtQueryInformationProcess(), or manually inspecting the PEB, potentially altering behavior to conceal malicious activities.",  # Simple description
        "tags": [
            "Debugger Evasion",
            "IsDebuggerPresent",
            "NtQueryInformationProcess",
            "PEB",
            "ProcessHacker",
            "hasherezade debug",
            "AlKhaser",
            "vxunderground",
            "OutputDebugStringW",
            "Dridex"
        ],  # Up to 10 tags
        "tactic": "Defense Evasion, Discovery",  # Associated MITRE ATT&CK tactics
        "protocol": "Native API / System Calls",  # Protocol or interface used
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor suspicious native API calls related to debugger detection",
            "Inspect processes for abnormal checks against BeingDebugged or hardware breakpoints",
            "Look for repeated or unnecessary calls to OutputDebugStringW() which may flood debug logs"
        ],
        "data_sources": "Application Log: Application Log Content, Command: Command Execution, Process: OS API Execution, Process: Process Creation",
        "log_sources": [
            {
                "type": "Application Log",
                "source": "Debug/Process Logs",
                "destination": "SIEM"
            },
            {
                "type": "Command",
                "source": "Process Monitoring",
                "destination": "SIEM"
            },
            {
                "type": "Process",
                "source": "Endpoint Monitoring",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Process Execution",
                "location": "Running application or malware sample",
                "identify": "Debugger checks (e.g., IsDebuggerPresent())"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Altered Malware Behavior",
                "location": "Adversary code or memory",
                "identify": "Conditional logic triggered if a debugger is present"
            }
        ],
        "detection_methods": [
            "Monitor processes for calls to IsDebuggerPresent, NtQueryInformationProcess, or related APIs",
            "Analyze memory for debugger-specific flags in the PEB",
            "Detect unusual usage of OutputDebugStringW in rapid succession"
        ],
        "apt": [],  # No specific APT group listed
        "spl_query": [],
        "hunt_steps": [
            "Search process logs for repeated or suspicious native API calls indicative of debugger detection",
            "Correlate potential debugger evasion checks with subsequent changes in malware behavior",
            "Identify processes that abruptly terminate or change function if a debugger is attached"
        ],
        "expected_outcomes": [
            "Detection of malware attempting to identify and evade debuggers",
            "Identification of processes that alter execution based on debugging artifacts",
            "Prevention of further malicious activity by analyzing evasion tactics"
        ],
        "false_positive": "Some legitimate software (e.g., anti-cheat systems or specialized applications) may also perform debugger checks. Validate context and intended functionality.",
        "clearing_steps": [
            "Terminate or quarantine processes exhibiting suspicious debugger checks",
            "Remove or isolate malicious binaries that incorporate debugger evasion",
            "Strengthen debugging environment controls to avoid tipping off malware"
        ],
        "mitre_mapping": [
            {
                "tactic": "Defense Evasion",
                "technique": "Debugger Evasion (T1622)",
                "example": "Malware modifies or conceals behavior upon detecting an attached debugger"
            }
        ],
        "watchlist": [
            "Processes with repeated calls to debugging-related APIs",
            "Abrupt changes in process flow upon detection of breakpoints",
            "Excessive or spurious logging calls used to flood debug output"
        ],
        "enhancements": [
            "Implement robust endpoint monitoring to detect debugger detection routines",
            "Deploy behavioral analysis tools to identify dynamic evasion attempts",
            "Use anti-evasion features in sandbox solutions to capture stealthy malware behavior"
        ],
        "summary": "Debugger evasion techniques enable adversaries to detect if a debugger is attached and adjust or conceal malicious behavior, impeding analysis and complicating threat response.",
        "remediation": "Harden debugging environments, monitor for suspicious API calls, and ensure robust logging/alerting for potential debugger detection attempts.",
        "improvements": "Enhance endpoint detection with signatures for known debugger evasion methods, train analysts on dynamic analysis of evasive malware, and integrate deeper memory analysis in automated sandboxes."
    }
