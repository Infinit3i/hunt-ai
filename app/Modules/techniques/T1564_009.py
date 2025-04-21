def get_content():
    return {
        "id": "T1564.009",
        "url_id": "T1564/009",
        "title": "Hide Artifacts: Resource Forking",
        "description": "Adversaries may abuse macOS resource forks to hide malicious code, executables, or payloads within alternate data storage mechanisms. Resource forks, historically used to store metadata like icons and menus, can also store arbitrary binary content. Although deprecated, they can still be leveraged by adversaries to hide code from traditional scanning tools and evade detection. Malicious content can be hidden in the `com.apple.ResourceFork` extended attribute and later executed, potentially after being moved or decrypted.",
        "tags": ["resource fork", "macOS", "xattr", "stealth", "HFS+", "com.apple.ResourceFork"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "macOS",
        "tips": [
            "Use `ls -l@` or `xattr -l` to inspect files for resource forks and extended attributes",
            "Monitor for files with `com.apple.ResourceFork` showing large or binary data",
            "Track resource forks followed by suspicious execution or network activity"
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "/Users/<user>/*", "identify": "Suspicious files with `com.apple.ResourceFork` extended attributes"},
            {"type": "Command", "location": "Terminal history", "identify": "`xattr -l`, `ls -l@`, or file-copying commands manipulating forks"},
            {"type": "Process", "location": "Memory", "identify": "Execution from a temporary file containing resource fork content"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "/Applications/<target>.app/Contents/Resources", "identify": "Unusual resource fork content"},
            {"type": "Process", "location": "LaunchServices", "identify": "Application executing content from alternate stream"},
            {"type": "File", "location": "Quarantine or temp folders", "identify": "Payload files previously hidden in forks"}
        ],
        "detection_methods": [
            "Inspect extended attributes on files using `xattr` and flag those with `com.apple.ResourceFork`",
            "Compare file size versus actual content size to detect hidden streams",
            "Trace suspicious command sequences like fork creation followed by process execution"
        ],
        "apt": [
            "Bundlore", "Keydnap", "Shlayer"
        ],
        "spl_query": [
            "index=osquery \n| search xattr_name=com.apple.ResourceFork \n| stats count by file_path, xattr_size",
            "index=mac_logs sourcetype=command_line \n| search command_line=*xattr* OR command_line=*ls -l@* \n| stats count by command_line, user",
            "index=sysmon OR osquery \n| search file_path=*Contents/Resources* AND file_extension!=plist \n| stats count by file_path"
        ],
        "hunt_steps": [
            "Enumerate files with extended attributes using `xattr -l`",
            "Identify files with large or suspiciously binary resource forks",
            "Look for post-fork execution or network behavior"
        ],
        "expected_outcomes": [
            "Identification of files with concealed payloads in forks",
            "Detection of obfuscated or encrypted data within extended attributes",
            "Attribution of execution to hidden forked data"
        ],
        "false_positive": "Some legitimate macOS applications may use resource forks for icon storage or legacy compatibility. Validate content size and behavior before triaging as malicious.",
        "clearing_steps": [
            "Use `xattr -d com.apple.ResourceFork <file>` to remove the fork",
            "Isolate and quarantine the associated file for full behavioral analysis",
            "Check LaunchAgents or other persistence methods referencing the forked content"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1202", "example": "Abusing macOS file metadata to conceal binaries"},
            {"tactic": "Execution", "technique": "T1059.001", "example": "Executing content from resource forks with shell scripts"}
        ],
        "watchlist": [
            "Files with `com.apple.ResourceFork` appearing in non-standard directories",
            "Resource forks attached to recently downloaded or quarantined items",
            "Terminal usage of `xattr`, `cp`, or `dd` with hidden paths"
        ],
        "enhancements": [
            "Implement endpoint monitoring for resource fork abuse",
            "Use macOS-specific EDR tools to flag extended attributes with binary content",
            "Train analysts to validate file metadata as part of triage"
        ],
        "summary": "Resource Forking on macOS enables adversaries to hide malicious content in alternate file streams, bypassing signature-based detection. Despite being deprecated, the mechanism still exists and can be abused for stealthy payload delivery or evasion.",
        "remediation": "Remove suspicious forks using `xattr -d`, audit file metadata in targeted folders, and apply hardened app execution policies.",
        "improvements": "Incorporate extended attribute visibility into file inspection pipelines and continuously monitor for resource fork presence in userland and applications.",
        "mitre_version": "16.1"
    }
