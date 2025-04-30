def get_content():
    return {
        "id": "T1564.014",
        "url_id": "T1564/014",
        "title": "Extended Attributes",
        "description": "Adversaries may abuse extended attributes (xattrs) on macOS and Linux to hide their malicious data in order to evade detection.",
        "tags": ["xattr", "getfattr", "setfattr", "macos", "linux", "defense evasion", "hidden payload"],
        "tactic": "defense-evasion",
        "protocol": "",
        "os": "Linux, macOS",
        "tips": [
            "Inspect extended attributes on suspicious files using xattr (macOS) or getfattr (Linux).",
            "Establish a baseline whitelist of known good xattr keys used in development workflows.",
            "Audit packaging and deployment tools to verify they inspect extended attributes."
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "/usr/bin/", "identify": "Custom xattr keys embedded in system binaries or scripts"}
        ],
        "destination_artifacts": [
            {"type": "File Metadata", "location": "/Library/ or /usr/local/bin", "identify": "Suspicious com.apple.* or user. keys attached to otherwise benign files"}
        ],
        "detection_methods": [
            "Monitor xattr, getfattr, and setfattr command usage.",
            "Detect execution of interpreters like bash or python immediately following attribute reads.",
            "Inspect files for extended attributes with non-standard or uncommon keys."
        ],
        "apt": [],
        "spl_query": [
            "sourcetype=command_logs(command=\"xattr\" OR command=\"getfattr\" OR command=\"setfattr\")\n| transaction session startswith=(command=\"xattr\" OR command=\"getfattr\") endswith=(command=\"bash\" OR command=\"python\" OR command=\"sh\") maxspan=5m\n| table _time, session, command, arguments, user, host\n| sort _time",
            "sourcetype=file_metadata(xattr_key!=\"com.apple.quarantine\")\n| stats count by file_path, xattr_key, xattr_value, host\n| sort -count"
        ],
        "hunt_steps": [
            "List files with extended attributes in critical directories.",
            "Search for hidden payloads or base64 blobs in user or com.apple.* keys.",
            "Identify interpreter activity following xattr reads."
        ],
        "expected_outcomes": [
            "Identification of hidden malicious code embedded in xattrs of trusted files."
        ],
        "false_positive": "Some development and packaging tools use xattrs legitimately. Review based on usage patterns and file context.",
        "clearing_steps": [
            "xattr -d <key> <file> (macOS)",
            "setfattr -x user.<key> <file> (Linux)",
            "Validate and clean suspicious keys using whitelist guidance."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1564", "example": "Hide Artifacts"},
            {"tactic": "execution", "technique": "T1059", "example": "Command and Scripting Interpreter"}
        ],
        "watchlist": [
            "Files with user-defined or non-default xattr keys",
            "Command sequences involving xattr followed by shell interpreters"
        ],
        "enhancements": [
            "Integrate xattr scanning into antivirus and file integrity monitoring tools.",
            "Develop alerts for custom or unknown extended attribute keys."
        ],
        "summary": "Extended attributes on macOS and Linux can be abused to conceal malicious payloads, enabling evasion from security tools that only inspect standard file contents.",
        "remediation": "Regularly scan extended attributes during malware analysis and file review processes.",
        "improvements": "Expand file inspection policies to include xattrs during automated scanning and digital forensics.",
        "mitre_version": "17.0"
    }
