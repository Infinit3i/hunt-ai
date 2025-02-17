def get_content():
    """
    Returns structured content for the MS Office Add-In persistence method.
    """
    return {
        "id": "T1137.006",
        "url_id": "1137/006",
        "title": "MS Office Add-In",
        "tactic": "Persistence",
        "data_sources": "Windows Registry, File Monitoring, Process Execution",
        "protocol": "N/A",
        "os": "Windows",
        "objective": "Detect and mitigate adversaries leveraging MS Office add-ins for persistence.",
        "scope": "Monitor registry keys and add-in directories for unauthorized modifications.",
        "threat_model": "Attackers can achieve persistence by installing malicious MS Office add-ins, triggering execution whenever Office applications start.",
        "hypothesis": [
            "Are there unauthorized add-ins registered in the MS Office registry paths?",
            "Are unusual files appearing in Office Add-In directories?",
            "Are scripts executed via Office add-ins suspicious in behavior?"
        ],
        "tips": [
            "Monitor registry changes to MS Office add-in keys.",
            "Regularly inspect the Office Add-Ins folder for anomalous files.",
            "Enable PowerShell Script Block Logging to detect potential abuse."
        ],
        "log_sources": [
            {"type": "Registry Monitoring", "source": "HKCU\\Software\\Microsoft\\Office\\<Version>\\AddIns", "destination": "Local Machine"},
            {"type": "File Monitoring", "source": "C:\\Users\\<Username>\\AppData\\Roaming\\Microsoft\\AddIns", "destination": "Local Machine"},
            {"type": "Process Execution", "source": "Microsoft Office", "destination": "Local Machine"}
        ],
        "detection_methods": [
            "Monitor registry changes for unauthorized add-in registrations.",
            "Detect unusual files appearing in Office Add-In directories.",
            "Analyze PowerShell Event ID 800 for suspicious script execution."
        ],
        "apt": [],
        "spl_query": [
            "index=windows EventCode=800 ScriptBlockText=*Office* | stats count by ScriptBlockText"
        ],
        "hunt_steps": [
            "Check registry paths for unauthorized add-ins.",
            "Inspect the Office Add-Ins directory for unknown files.",
            "Analyze PowerShell event logs for suspicious script execution.",
            "Investigate whether any add-ins exhibit malicious behavior."
        ],
        "expected_outcomes": [
            "Malicious Add-In Detected: Remove the unauthorized add-in and mitigate persistence.",
            "No Malicious Activity Found: Improve monitoring and detection baselines."
        ],
        "false_positive": "Legitimate third-party add-ins may trigger alerts; verify with user or IT policies.",
        "clearing_steps": [
            "Remove unauthorized add-in entries from the registry.",
            "Delete suspicious files from the Office Add-Ins directory.",
            "Monitor for reinstallation attempts after removal."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1137.006 (MS Office Add-In)", "example": "Adversaries install malicious add-ins to maintain persistence."}
        ],
        "watchlist": [
            "Flag new Office add-ins appearing in registry or file system.",
            "Monitor PowerShell logs for suspicious Office-related script execution."
        ],
        "enhancements": [
            "Restrict add-in installation to approved sources only.",
            "Enable logging for Office add-in execution.",
            "Implement application control policies to prevent unauthorized add-ins."
        ],
        "summary": "Monitor and detect unauthorized MS Office add-ins to prevent persistence mechanisms.",
        "remediation": "Remove unauthorized add-ins, apply least-privilege access controls, and improve monitoring.",
        "improvements": "Enhance visibility into Office add-in execution and registry modifications."
    }
