def get_content():
    return {
        "id": "T1059.002",  # MITRE ATT&CK technique ID
        "url_id": "T1059/002",  # URL segment for reference
        "title": "Command and Scripting Interpreter: AppleScript",  # Attack technique name
        "description": (
            "Adversaries may abuse AppleScript for execution. AppleScript is a macOS scripting language designed to control "
            "applications and parts of the OS via inter-application messages called AppleEvents. Scripts can be run from the "
            "command-line via osascript, as well as through Mail rules, Calendar.app alarms, and Automator workflows. "
            "AppleScript can be used for post-compromise activities, such as interacting with an SSH connection, moving laterally, "
            "or executing a reverse shell."
        ),
        "tags": [
            "t1059.002",
            "applescript execution",
            "macos scripting",
            "osascript abuse",
            "applescript malware",
            "macos command execution",
            "applescript automation security",
            "macos reverse shell",
            "applescript lateral movement",
            "applescript ssh interaction",
            "applescript privilege escalation",
            "macos security monitoring"
        ],
        "tactic": "Execution",
        "platforms": ["macOS"],
        "data_sources": "Command: Command Execution, Process: OS API Execution, Process: Process Creation",
        "log_sources": [
            {"type": "System Logs", "source": "macOS Unified Logging", "destination": "SIEM"},
            {"type": "Behavioral Monitoring", "source": "Endpoint Detection & Response (EDR)", "destination": "SOC"},
            {"type": "File Integrity Monitoring", "source": "Filesystem Audit Logs", "destination": "Security Operations"}
        ],
        "watchlist": [
            "unexpected osascript execution",
            "suspicious applescript automation",
            "unusual script-based process creation"
        ],
        "detection_methods": ["Process Monitoring", "Command-line Analysis", "Behavioral Anomaly Detection"],
        "apt": ["MacOS-targeting APTs"],
        "expected_outcomes": ["Detection of unauthorized AppleScript usage"],
        "remediation": "Restrict AppleScript execution via policy controls, monitor osascript commands, and validate script integrity.",
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.002", "example": "Adversary using osascript to execute malicious payloads."}
        ],
        "summary": "AppleScript abuse is commonly used in macOS attacks for automation, persistence, and privilege escalation.",
        "improvements": "Enhance macOS script execution monitoring, enforce least privilege, and block unauthorized script execution."
    }
