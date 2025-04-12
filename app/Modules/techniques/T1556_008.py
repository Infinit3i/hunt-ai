def get_content():
    return {
        "id": "T1556.008",
        "url_id": "T1556/008",
        "title": "Modify Authentication Process: Network Provider DLL",
        "description": "Adversaries may register malicious network provider dynamic link libraries (DLLs) to capture cleartext user credentials during the authentication process. Network provider DLLs allow Windows to interface with specific network protocols and can also support add-on credential management functions. During the logon process, Winlogon (the interactive logon module) sends credentials to the local `mpnotify.exe` process via RPC. The `mpnotify.exe` process then shares the credentials in cleartext with registered credential managers when notifying that a logon event is happening. Adversaries can configure a malicious network provider DLL to receive credentials from `mpnotify.exe`. Once installed as a credential manager (via the Registry), a malicious DLL can receive and save credentials each time a user logs onto a Windows workstation or domain via the `NPLogonNotify()` function. Adversaries may target systems with high logon activity or administrator sessions to increase the likelihood of credential capture.",
        "tags": ["Credential Access", "Defense Evasion", "Persistence", "Network Provider", "Windows"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for unknown DLLs registered under credential manager Registry keys.",
            "Track mpnotify.exe interactions and unexpected DLL load events.",
            "Audit high-frequency login systems for new DLL registrations.",
            "Use behavioral baselining to detect unexpected credential manager activity."
        ],
        "data_sources": "File: File Creation, Process: OS API Execution, Windows Registry: Windows Registry Key Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "DLL", "location": "C:\\Windows\\System32", "identify": "Suspicious credential manager library"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect unknown DLL registration in credential provider registry keys",
            "Monitor mpnotify.exe for anomalous behavior",
            "Track invocation of NPLogonNotify function",
            "Flag new DLLs interacting with logon processes"
        ],
        "apt": [],
        "spl_query": [
            "index=wineventlog sourcetype=WinRegistry action=modified key_path=*NPLogonNotify* | stats count by user, key_path, registry_value_name, registry_value_data",
            "index=wineventlog sourcetype=WinImageLoad process_name=mpnotify.exe | stats values(image_loaded) by host, timestamp"
        ],
        "hunt_steps": [
            "Enumerate systems with registered credential manager DLLs",
            "Audit user logon events and correlate with DLL load paths",
            "Analyze recently modified registry paths linked to network providers",
            "Reverse engineer unknown DLLs to determine credential capture behavior"
        ],
        "expected_outcomes": [
            "Detection of unauthorized DLLs capturing credentials",
            "Prevention of further credential theft via credential manager abuse"
        ],
        "false_positive": "Custom or legacy authentication modules may appear similar. Confirm with IT teams before actioning detections.",
        "clearing_steps": [
            "Remove malicious DLL entries from credential manager registry keys",
            "Delete rogue DLL files from disk",
            "Change affected user passwords and enforce MFA"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-manager-start-page",
            "https://attack.mitre.org/techniques/T1556/008"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1556.008", "example": "DLL registered as a network provider credential manager to intercept mpnotify.exe logon events."}
        ],
        "watchlist": [
            "DLL registration under LSA\\Notification Packages",
            "New DLL files created in System32 after reboots",
            "Credential manager activity from non-standard accounts"
        ],
        "enhancements": [
            "Deploy registry integrity monitoring on authentication keys",
            "Enforce signed DLL loading and application whitelisting"
        ],
        "summary": "This technique exploits Windows credential manager DLL registration to silently intercept and store user credentials during logon via the mpnotify.exe process.",
        "remediation": "Restrict registry modification rights, audit loaded DLLs, enforce credential hygiene, and monitor interactive logon paths.",
        "improvements": "Incorporate registry and DLL load analytics into UEBA systems and verify DLL signing enforcement on critical endpoints.",
        "mitre_version": "16.1"
    }
