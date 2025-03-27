def get_content():
    return {
        "id": "T1137.005",
        "url_id": "T1137/005",
        "title": "Office Application Startup: Outlook Rules",
        "description": "Adversaries may abuse Microsoft Outlook rules to obtain persistence on a compromised system. Outlook rules allow a user to define automated behavior to manage email messages. A benign rule might, for example, automatically move an email to a particular folder in Outlook if it contains specific words from a specific sender. Malicious Outlook rules can be created that can trigger code execution when an adversary sends a specifically crafted email to that user. Once malicious rules have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious rules will execute when an adversary sends a specifically crafted email to the user.",
        "tags": ["outlook", "persistence", "office", "email", "rules"],
        "tactic": "Persistence",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Use MFCMapi to inspect mailbox rules that might be hidden from traditional PowerShell scripts.",
            "Look for rules triggering script execution or unusual executable launches."
        ],
        "data_sources": "Application Log, Command, Process",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "C:\\Windows\\System32\\winevt\\Logs", "identify": "Process creation from Outlook.exe"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor for child processes spawned from Outlook.exe.",
            "Analyze rule contents using MFCMapi or other low-level Exchange tools.",
            "Detect usage of Ruler tool signatures."
        ],
        "apt": ["SensePost"],
        "spl_query": [
            "`sysmon` \n| where ParentImage='Outlook.exe'",
        ],
        "hunt_steps": [
            "Review rules applied in Outlook mailboxes using MFCMapi.",
            "Correlate process trees showing Outlook spawning unexpected children.",
            "Check for known Ruler artifacts."
        ],
        "expected_outcomes": [
            "Identification of suspicious Outlook rules configured for persistence.",
            "Detection of process tree anomalies involving Outlook.exe."
        ],
        "false_positive": "Legitimate automation rules may appear suspicious; confirm intent with users or IT policy.",
        "clearing_steps": [
            "Use MFCMapi to remove malicious rules.",
            "Delete registry keys or configuration files set by the rule.",
            "Review mailbox for other persistence methods."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Malicious Outlook rule triggers script execution via cmd.exe or PowerShell."}
        ],
        "watchlist": ["Outlook.exe spawning unexpected child processes"],
        "enhancements": [
            "Enable advanced logging for Outlook process activities.",
            "Integrate mailbox rule scans into EDR solutions."
        ],
        "summary": "Malicious Outlook rules provide a stealthy persistence technique by executing code on Outlook startup or email receipt.",
        "remediation": "Manually remove malicious rules using MFCMapi. Audit mailbox rule creation.",
        "improvements": "Enhance detection via mailbox auditing and deeper integration with Microsoft APIs.",
        "mitre_version": "16.1"
    }
