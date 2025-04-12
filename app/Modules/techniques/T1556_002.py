def get_content():
    return {
        "id": "T1556.002",
        "url_id": "T1556/002",
        "title": "Modify Authentication Process: Password Filter DLL",
        "description": "Adversaries may register a malicious password filter DLL to intercept credentials during password changes. Password filters enforce password policy by receiving password data from LSA in plaintext. Attackers can use this mechanism to harvest credentials from local machines or domain controllers.",
        "tags": ["Password Filter", "Credential Harvesting", "Persistence", "LSASS", "Authentication Hook"],
        "tactic": "Credential Access, Defense Evasion, Persistence",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for unknown DLLs in system directories.",
            "Track changes to Notification Packages registry key.",
            "Detect abnormal lsass.exe module loads.",
            "Inspect DLL exports for password filtering routines."
        ],
        "data_sources": "File: File Creation, Module: Module Load, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Module", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Registry", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages", "identify": "Custom password filter DLLs"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "File write monitoring to system32 for new DLLs",
            "Registry auditing on Notification Packages key",
            "Module load tracking for lsass.exe",
            "Autorun inspection for filter registration"
        ],
        "apt": [
            "ProjectSauron"
        ],
        "spl_query": [
            "index=windows_logs source=Registry path=HKLM*\\Notification Packages\n| search action=modify OR dll_path=*"
        ],
        "hunt_steps": [
            "Search for unexpected DLLs in Notification Packages.",
            "Correlate with recent DLL creation on disk.",
            "Check LSASS memory for loaded custom modules."
        ],
        "expected_outcomes": [
            "Credentials intercepted via malicious filter",
            "LSASS running attacker-controlled DLLs"
        ],
        "false_positive": "Legitimate custom password filters may be used by security products or internal policies. Validate against known baselines.",
        "clearing_steps": [
            "Remove malicious DLL entry from registry.",
            "Delete DLL file from disk.",
            "Restart system to unload module from LSASS."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1003", "example": "Plaintext credential interception via password filter."}
        ],
        "watchlist": [
            "Changes to Notification Packages registry",
            "DLLs with password validation exports",
            "New DLLs in lsass.exe memory space"
        ],
        "enhancements": [
            "Whitelist approved password filters in system policy.",
            "Alert on new DLL registration in Notification Packages"
        ],
        "summary": "Malicious password filters registered with LSA allow attackers to capture credentials at password change events. This technique abuses legitimate Windows functionality and can provide persistent credential access.",
        "remediation": "Audit and clean up unauthorized password filter DLLs. Use EDR or endpoint visibility to track LSA module changes.",
        "improvements": "Deploy registry change monitoring and process module analysis to proactively detect password filter misuse.",
        "mitre_version": "16.1"
    }
