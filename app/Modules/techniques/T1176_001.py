def get_content():
    return {
        "id": "T1176.001",
        "url_id": "T1176/001",
        "title": "Browser Extensions",
        "description": "Adversaries may abuse internet browser extensions to establish persistent access to victim systems.",
        "tags": ["persistence", "browser", "chrome", "extension", "firefox", "mobileconfig", "defense evasion"],
        "tactic": "persistence",
        "protocol": "",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Block unapproved extensions via Group Policy or browser settings.",
            "Monitor for new .crx, .xpi, or .mobileconfig files.",
            "Audit extension usage and permissions across endpoints."
        ],
        "data_sources": "Process, Command, File, Windows Registry, Network Traffic",
        "log_sources": [
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Security.evtx", "identify": "Use of profiles tool or suspicious browser execution arguments"},
            {"type": "File Access Times (MACB Timestamps)", "location": "%APPDATA%\\..", "identify": "New .crx, .xpi, or extension folders created"}
        ],
        "destination_artifacts": [
            {"type": "Windows Registry", "location": "HKCU\\Software\\Google\\Chrome\\Extensions", "identify": "Unexpected registry keys for browser extensions"}
        ],
        "detection_methods": [
            "Monitor process creation for profiles tool or browser with suspicious arguments.",
            "Watch for new file creation in browser extension directories.",
            "Inspect registry modifications related to browser plugins."
        ],
        "apt": ["Kimsuky", "TRANSLATEXT", "Grandoreiro", "Bundlore", "Lumma Stealer", "Mispadu"],
        "spl_query": [
            "sourcetype=WinEventLog:Sysmon EventCode=1(CommandLine=\"profiles install\" OR CommandLine=\".mobileconfig\" OR CommandLine=\"chrome-extension\")\n| stats count by CommandLine, Image, ParentImage, User, Computer, _time\n| sort -_time",
            "sourcetype=WinEventLog:Sysmon EventCode=11(TargetFilename=\\\"\\Extensions\\\" OR TargetFilename=\".crx\" OR TargetFilename=\".xpi\" OR TargetFilename=\"*.mobileconfig\")\n| stats count by TargetFilename, Image, User, Computer, _time\n| sort -_time",
            "sourcetype=WinEventLog:Sysmon EventCode=1(CommandLine=\"--load-extension\" OR CommandLine=\"--pack-extension\")\n| stats count by Image, CommandLine, User, host, _time\n| sort -_time",
            "sourcetype=WinEventLog:Sysmon EventCode=13(TargetObject=\"\\Software\\Google\\Chrome\\Extensions\\\" OR TargetObject=\"\\Software\\Mozilla\\Firefox\\Extensions\\\")\n| stats count by TargetObject, Details, User, Computer, _time\n| sort -_time"
        ],
        "hunt_steps": [
            "Scan for unusual extensions across browsers (Chrome, Firefox, Edge).",
            "Investigate mobileconfig usage on macOS for silent extension installation.",
            "Review registry and filesystem indicators of plugin drops."
        ],
        "expected_outcomes": [
            "Identification of browser extensions used for credential theft, persistence, or remote access."
        ],
        "false_positive": "Some users or admins may install custom extensions. Validate via source, permissions, and behavior.",
        "clearing_steps": [
            "Remove unauthorized extensions via browser UI or extension folders.",
            "Delete related .crx/.xpi/.mobileconfig files and revert registry entries.",
            "Reset browser profiles and permissions where necessary."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "persistence", "technique": "T1176", "example": "Software Extensions"},
            {"tactic": "credential-access", "technique": "T1555.003", "example": "Credentials from Web Browsers"}
        ],
        "watchlist": [
            "Suspicious or newly installed browser extensions",
            "Unexpected registry key creation under known plugin paths"
        ],
        "enhancements": [
            "Enable extension allowlisting and enforce via GPO or MDM.",
            "Continuously monitor extension installs from non-admin users."
        ],
        "summary": "Browser extensions offer adversaries a covert channel for persistence, credential theft, and command and control when abused or installed maliciously.",
        "remediation": "Enforce strict policies on extension installation and actively monitor plugin activity across browsers.",
        "improvements": "Centralize browser management and enforce GPO/MDM restrictions on extension sources.",
        "mitre_version": "17.0"
    }
