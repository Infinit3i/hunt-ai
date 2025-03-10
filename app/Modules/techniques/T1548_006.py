def get_content():
    return {
        "id": "T1548.006",
        "url_id": "1548/006",
        "title": "Abuse Elevation Control Mechanism: TCC Manipulation",
        "description": (
            "Adversaries can manipulate or abuse the Transparency, Consent, & Control (TCC) service or database to grant "
            "malicious executables elevated permissions. TCC is a Privacy & Security macOS control mechanism used to determine "
            "if the running process has permission to access data or services protected by TCC, such as screen sharing, camera, "
            "microphone, or Full Disk Access (FDA)."
        ),
        "tags": ["Privilege Escalation", "Defense Evasion", "macOS Exploitation"],
        "tactic": "Defense Evasion, Privilege Escalation",
        "protocol": "macOS Security Mechanisms",
        "os": "macOS",
        "tips": [
            "Monitor for unauthorized modifications to `/Library/Application Support/com.apple.TCC/TCC.db`.",
            "Enable System Integrity Protection (SIP) to prevent unauthorized changes to TCC protections.",
            "Analyze application behavior for unexpected use of inherited permissions via Finder or AppleScript.",
            "Restrict access to TCC-protected services to only trusted applications."
        ],
        "data_sources": "Command: Command Execution, File: File Modification, Process: Process Creation",
        "log_sources": [
            {"type": "File Modification", "source": "TCC Database Logs", "destination": "SIEM"},
            {"type": "Command Execution", "source": "Process Monitoring", "destination": "Endpoint Security"},
        ],
        "source_artifacts": [
            {"type": "TCC Database", "location": "/Library/Application Support/com.apple.TCC/TCC.db", "identify": "Unauthorized permission modifications"},
            {"type": "Process Execution", "location": "/var/log/system.log", "identify": "Unexpected execution of Finder or AppleScript"},
        ],
        "destination_artifacts": [
            {"type": "Malicious Binary Execution", "location": "/Applications", "identify": "Applications executing under Finder with inherited privileges"},
        ],
        "detection_methods": [
            "Monitor changes to the TCC database and detect unauthorized permission grants.",
            "Track application launches to detect abuse of Finder or AppleScript execution.",
            "Identify malicious process injection into applications with existing TCC permissions.",
        ],
        "apt": ["Unknown at this time"],
        "spl_query": [
            "index=macos_logs sourcetype=system_log \n| search TCC.db modification \n| stats count by process_name, user, command",
        ],
        "hunt_steps": [
            "Check `/Library/Application Support/com.apple.TCC/TCC.db` for unauthorized modifications.",
            "Review process execution logs for AppleScript and Finder abuse.",
            "Analyze applications requesting TCC permissions and verify their legitimacy.",
        ],
        "expected_outcomes": [
            "Privilege Escalation Detected: Investigate unauthorized TCC modifications.",
            "No Malicious Activity Found: Ensure TCC database security measures are in place.",
        ],
        "false_positive": "Some legitimate applications may modify TCC permissions, verify before raising an alert.",
        "clearing_steps": [
            "Revert unauthorized changes to TCC database by resetting permissions.",
            "Re-enable SIP to prevent unauthorized modifications to system security settings.",
            "Audit and revoke unnecessary TCC permissions granted to applications.",
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1548.006", "example": "Manipulating TCC database to gain elevated permissions."},
        ],
        "watchlist": [
            "Monitor for unauthorized edits to the TCC database.",
            "Detect processes abusing AppleScript or Finder for privilege escalation.",
            "Analyze system logs for unexpected access requests to protected services.",
        ],
        "enhancements": [
            "Implement continuous monitoring of TCC permission modifications.",
            "Restrict user access to sensitive TCC database files.",
        ],
        "summary": "Adversaries may manipulate the TCC database to grant themselves elevated access to macOS-protected services.",
        "remediation": "Ensure SIP is enabled, restrict access to TCC files, and monitor for unauthorized changes.",
        "improvements": "Enhance logging and auditing of TCC permission changes to detect privilege escalation attempts.",
    }
