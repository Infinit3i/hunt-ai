def get_content():
    return {
        "id": "G0084",
        "url_id": "Gallmaker",
        "title": "Gallmaker",
        "tags": ["APT", "Middle East", "cyberespionage", "military", "defense", "government"],
        "description": "Gallmaker is a cyberespionage group active since at least December 2017. The group primarily targets entities in the Middle East, focusing on the defense, military, and government sectors. Gallmaker is notable for its 'living off the land' approach, leveraging native OS tools like PowerShell and Dynamic Data Exchange (DDE) rather than deploying traditional malware. The group's operations rely heavily on phishing documents with embedded scripts to gain initial access and execute commands directly from memory, minimizing their on-disk footprint.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1560.001",  # Archive via Utility
            "T1059.001",  # PowerShell
            "T1559.002",  # Dynamic Data Exchange
            "T1027",      # Obfuscated Files or Information
            "T1566.001",  # Spearphishing Attachment
            "T1204.002"   # User Execution: Malicious File
        ],
        "contributors": ["Symantec Security Response"],
        "version": "1.1",
        "created": "30 January 2019",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Symantec Security Response",
                "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/gallmaker-cyberespionage-attack"
            }
        ],
        "resources": [],
        "remediation": "Implement strong anti-phishing policies and user training. Disable Microsoft Office macros and DDE where not required. Monitor PowerShell and scripting activity through event logging and behavioral analytics.",
        "improvements": "Deploy script-block logging and AMSI integration for PowerShell. Use sandbox detonation for email attachments. Monitor for obfuscated command-line execution and suspicious document-based process chains.",
        "hunt_steps": [
            "Search for DDE or macro-based Office document usage in email attachments.",
            "Correlate PowerShell execution from Office applications or spawned by Word/Excel.",
            "Review obfuscated shellcode behaviors in memory using endpoint telemetry.",
            "Identify WinZip or archival tools used in non-standard user workflows."
        ],
        "expected_outcomes": [
            "Detection of DDE-based lateral movement or persistence mechanisms.",
            "Identification of PowerShell-based download and execution chains.",
            "Uncovering shellcode obfuscation tactics used for in-memory execution.",
            "Awareness of attachment-triggered credential or data exfiltration attempts."
        ],
        "false_positive": "PowerShell and WinZip are common in enterprise environments. Focus detection on unusual parent-child process chains and execution context (e.g., Word spawning PowerShell).",
        "clearing_steps": [
            "Clear suspicious startup registry keys and running scripts.",
            "Remove or disable any Office-based macro functionality tied to the lure documents.",
            "Reset credentials used during the breach and rotate access tokens.",
            "Check for signs of persistence via scheduled tasks or WMI event subscriptions."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
