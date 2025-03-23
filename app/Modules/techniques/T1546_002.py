def get_content():
    return {
        "id": "T1546.002",
        "url_id": "T1546/002",
        "title": "Event Triggered Execution: Screensaver",
        "description": "Adversaries may establish persistence by executing malicious content triggered by user inactivity using screensavers (.scr files).",
        "tags": ["screensaver", "persistence", "registry", "event-triggered"],
        "tactic": "Persistence",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor Registry changes to screensaver settings under HKCU\\Control Panel\\Desktop\\",
            "Use Sysinternals Autoruns to identify malicious .scr paths",
            "Investigate unknown or suspicious .scr files in C:\\Windows\\System32\\ or custom paths"
        ],
        "data_sources": "Windows Registry, File, Command, Process",
        "log_sources": [
            {"type": "Windows Registry", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Hives", "location": "HKCU\\Control Panel\\Desktop", "identify": "SCRNSAVE.exe, ScreenSaveActive, ScreenSaverIsSecure, ScreenSaveTimeout"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor process execution of .scr files",
            "Track Registry key modifications to screensaver settings",
            "Detect anomalous or non-default paths for screensavers",
            "Correlate changes with user inactivity or logon sessions"
        ],
        "apt": ["Gazer"],
        "spl_query": [
            'index=main sourcetype=WinRegistry registry_path="*Control Panel\\\\Desktop*" registry_key_name IN ("SCRNSAVE.EXE", "ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeout")'
        ],
        "hunt_steps": [
            "Identify .scr files executed from non-standard directories",
            "Review autorun entries for screensaver settings",
            "Analyze Registry changes to HKCU\\Control Panel\\Desktop keys",
            "Check timestamps of .scr files for suspicious modifications"
        ],
        "expected_outcomes": [
            "Detection of unauthorized persistence via screensaver manipulation",
            "Correlation of .scr execution with malicious file paths"
        ],
        "false_positive": "Legitimate custom screensavers may be used in enterprise environments. Validate .scr file origin and signing.",
        "clearing_steps": [
            'reg delete "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /f',
            'reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveActive /t REG_SZ /d 0 /f',
            'del /f /q C:\\Path\\To\\Malicious.scr'
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1547.001", "example": "Startup Folder persistence as a fallback method"}
        ],
        "watchlist": [
            "*.scr file creation in unusual locations",
            "Modifications to screensaver settings in the Registry"
        ],
        "enhancements": [
            "Alert on .scr execution from outside C:\\Windows\\System32\\",
            "Baseline legitimate screensaver paths across the enterprise"
        ],
        "summary": "Malicious screensavers are used as an event-triggered persistence mechanism by altering Registry settings to execute .scr payloads after user inactivity.",
        "remediation": "Remove unauthorized .scr files, restore legitimate screensaver settings, and enforce GPO to restrict screensaver changes.",
        "improvements": "Implement user behavior analytics to correlate idle time with unexpected .scr execution.",
        "mitre_version": "16.1"
    }
