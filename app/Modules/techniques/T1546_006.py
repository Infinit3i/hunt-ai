def get_content():
    return {
        "id": "T1546.006",
        "url_id": "T1546/006",
        "title": "Event Triggered Execution: LC_LOAD_DYLIB Addition",
        "description": "Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries.",
        "tags": ["persistence", "privilege escalation", "macos", "dylib injection", "binary modification"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "macOS",
        "tips": [
            "Monitor for binaries that are modified outside of patch/update cycles.",
            "Validate binary signatures regularly.",
            "Check for unauthorized dylib additions in headers."
        ],
        "data_sources": "Command, File, Module, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Module", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File: File Modification", "location": "/usr/bin", "identify": "Check for tampered binaries with modified LC_LOAD_DYLIB headers"},
            {"type": "Module: Module Load", "location": "/Library/Frameworks/", "identify": "Loaded dylibs not matching baseline"},
            {"type": "Process: Process Creation", "location": "/Applications/", "identify": "Unusual parent-child process execution from modified apps"}
        ],
        "destination_artifacts": [
            {"type": "File: File Metadata", "location": "/usr/bin", "identify": "Binaries without valid code signatures"}
        ],
        "detection_methods": [
            "Monitor binaries for changes in checksum or signature",
            "Detect addition of LC_LOAD_DYLIB header via binary diff tools",
            "Use process monitoring to trace suspicious dylib loads"
        ],
        "apt": [],
        "spl_query": [
            "index=macos_logs event_type=process_creation | search binary_modification=true"
        ],
        "hunt_steps": [
            "Identify recently modified Mach-O binaries",
            "Check for unexpected dylib loads",
            "Verify binary signatures using codesign"
        ],
        "expected_outcomes": [
            "Detection of tampered applications with unauthorized dylibs",
            "Correlated events of unauthorized dylib execution"
        ],
        "false_positive": "Legitimate developers may inject dylibs during active development or troubleshooting.",
        "clearing_steps": [
            "sudo rm /path/to/malicious/dylib.dylib",
            "Restore tampered binary from trusted backup",
            "Re-sign binary if necessary using: codesign -s 'Developer ID' /path/to/binary"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Adversaries may use modified binaries to spawn command interpreters"}
        ],
        "watchlist": [
            "New LC_LOAD_DYLIB references in known binaries",
            "Unsigned binaries in /usr/bin or /Applications"
        ],
        "enhancements": [
            "Deploy file integrity monitoring for binaries and libraries",
            "Use Endpoint Detection & Response (EDR) tools to trace dylib loads"
        ],
        "summary": "This technique leverages dynamic library loading in Mach-O binaries to maintain persistence or escalate privileges on macOS.",
        "remediation": "Remove unauthorized libraries and binaries, restore from backups, and re-sign binaries with proper validation.",
        "improvements": "Automate signature validation and dylib load tracing with custom security tooling.",
        "mitre_version": "16.1"
    }