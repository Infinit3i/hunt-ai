def get_content():
    return {
        "id": "T1553.001",
        "url_id": "T1553/001",
        "title": "Subvert Trust Controls: Gatekeeper Bypass",
        "description": "Adversaries may modify file attributes and subvert Gatekeeper functionality to evade user prompts and execute untrusted programs. Gatekeeper is a set of technologies that act as layer of Apple’s security model to ensure only trusted applications are executed on a host. Gatekeeper was built on top of File Quarantine in Snow Leopard (10.6, 2009) and has grown to include Code Signing, security policy compliance, Notarization, and more. Gatekeeper also treats applications running for the first time differently than reopened applications.",
        "tags": ["macOS", "Gatekeeper", "Defense Evasion", "Quarantine Flag"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "macOS",
        "tips": [
            "Monitor and investigate attempts to modify extended file attributes with utilities such as xattr.",
            "Compare against baseline knowledge for system usage and correlate events with other indicators.",
            "Review LSFileQuarantineEnabled entries in application Info.plist files.",
            "Analyze QuarantineEvents database for com.apple.quarantine entries."
        ],
        "data_sources": "macOS, Command: Command Execution, File: File Metadata, File: File Modification, Process: Process Creation",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2", "identify": "com.apple.quarantine flags, Gatekeeper decisions"},
            {"type": "Registry Hives (Info.plist)", "location": "Application Bundle", "identify": "LSFileQuarantineEnabled entry"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "File attribute monitoring",
            "Application bundle inspection",
            "Behavioral analysis of first-launch patterns",
            "Code signature and notarization validation"
        ],
        "apt": [
            "OceanLotus",
            "Shlayer",
            "DazzleSpy",
            "Cuckoo",
            "CoinTicker"
        ],
        "spl_query": [
            "index=mac_logs sourcetype=mac_xattr command=xattr\n| search attribute=com.apple.quarantine",
            "index=mac_logs sourcetype=plist LSFileQuarantineEnabled=false"
        ],
        "hunt_steps": [
            "Search for files missing quarantine flag after downloads",
            "Inspect Info.plist files for LSFileQuarantineEnabled=false",
            "Look for modified apps in ~/Applications or /Applications with altered xattr"
        ],
        "expected_outcomes": [
            "Detection of unauthorized quarantine flag removal",
            "Identification of bypassed Gatekeeper checks"
        ],
        "false_positive": "Built-in system update utilities or developers may remove quarantine flags legitimately. Compare against known baselines and verify app integrity.",
        "clearing_steps": [
            "sudo xattr -d com.apple.quarantine <target_file>",
            "Review and restore quarantine flags where appropriate",
            "Check application Info.plist and re-enable LSFileQuarantineEnabled if missing"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1211", "example": "Exploitation for Defense Evasion through logic errors in Gatekeeper."}
        ],
        "watchlist": [
            "xattr usage on applications",
            "Plist files missing LSFileQuarantineEnabled",
            "Applications launched from external drives"
        ],
        "enhancements": [
            "Add quarantine flag validation to EDR tools",
            "Alert on removal of xattr from non-whitelisted apps"
        ],
        "summary": "Gatekeeper can be bypassed by manipulating the quarantine flag and other extended file attributes. Adversaries exploit logic errors, drive-by downloads, or unsigned code to subvert Apple's application trust mechanisms.",
        "remediation": "Ensure all downloaded files are properly flagged and only allow execution of notarized and signed applications. Implement endpoint monitoring for changes to application attributes.",
        "improvements": "Expand monitoring to include plist parsing and review of user override behavior. Integrate with Apple security APIs to verify notarization status.",
        "mitre_version": "16.1"
    }
