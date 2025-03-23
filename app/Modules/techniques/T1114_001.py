def get_content():
    return {
        "id": "T1114.001",
        "url_id": "T1114/001",
        "title": "Email Collection: Local Email Collection",
        "description": "Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files.",
        "tags": ["email", "local collection", "pst", "ost", "outlook", "collection"],
        "tactic": "Collection",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor access to .ost and .pst files in user directories.",
            "Alert on suspicious processes accessing email file paths.",
            "Review use of PowerShell or WMI interacting with Outlook storage."
        ],
        "data_sources": "Command: Command Execution, File: File Access",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": "File Access"},
            {"type": "File", "source": "File Access", "destination": "Command Execution"}
        ],
        "source_artifacts": [
            {"type": "OST/PST File", "location": "C:\\Users\\<username>\\Documents\\Outlook Files", "identify": "*.ost or *.pst files"},
            {"type": "OST/PST File", "location": "C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Outlook", "identify": "*.ost or *.pst files"}
        ],
        "destination_artifacts": [
            {"type": "Exfiltrated File", "location": "Remote Storage", "identify": "Exfiltrated email data files"}
        ],
        "detection_methods": [
            "Command-line monitoring for access tools",
            "File access auditing of Outlook data directories",
            "Windows API call monitoring for MAPI access"
        ],
        "apt": [
            "QakBot", "Emotet", "Kimsuky", "WinterVivern", "APT1", "APT35", "CARBANAK", "MuddyWater", "RedCurl", "Cosmicduke", "Night Dragon", "Smoke Loader", "Chimera", "Transparent Tribe", "Turla"
        ],
        "spl_query": [
            "index=main sourcetype=process_logs\n| search CommandLine=\"*.pst\" OR CommandLine=\"*.ost\""
        ],
        "hunt_steps": [
            "Search for any processes accessing Outlook data file paths.",
            "Correlate with known C2 or exfiltration behavior.",
            "Check for staging of email files in temp or user-defined folders."
        ],
        "expected_outcomes": [
            "Detection of local access to sensitive email data",
            "Reconstruction of adversary intent from email harvesting"
        ],
        "false_positive": "Legitimate email backup or archiving tools may access OST/PST files during normal operation.",
        "clearing_steps": [
            "Terminate unauthorized processes accessing email files.",
            "Delete local staging copies and reset credentials if compromise is confirmed."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1555.003", "example": "Credentials from Email Clients"},
            {"tactic": "Exfiltration", "technique": "T1041", "example": "Exfiltration Over C2 Channel"}
        ],
        "watchlist": [
            "Unexpected access to email storage paths",
            "PowerShell or cmd.exe accessing Outlook folders"
        ],
        "enhancements": [
            "Enable file auditing on user profile directories",
            "Restrict access to .pst/.ost files to only authorized processes"
        ],
        "summary": "Local email collection targets user mail stored in .ost/.pst files on disk. These files may contain sensitive communications, credentials, or intel useful to adversaries.",
        "remediation": "Implement file access controls, monitor usage of email tools/scripts, and enforce least privilege to user directories.",
        "improvements": "Integrate DLP to detect and block unauthorized handling of Outlook data files, and enhance visibility into local process behavior."
    }
