def get_content():
    return {
        "id": "T1574.010",
        "url_id": "T1574/010",
        "title": "Hijack Execution Flow: Services File Permissions Weakness",
        "description": "Adversaries may exploit misconfigured file or folder permissions associated with Windows services to hijack execution flow. If a service’s executable binary or its containing directory has weak access control settings (e.g., writable by non-admin users), adversaries may overwrite or replace it with a malicious payload. When the service starts—either automatically at system boot or manually—it will execute the adversary’s binary, often under elevated privileges such as SYSTEM.\n\nThis method can be used to execute arbitrary code, establish persistence, or escalate privileges. If the service is configured to restart on failure, the malicious binary may be persistently triggered. This tactic can go undetected if binaries are replaced during expected update windows or the replacement closely mimics the original binary’s behavior.",
        "tags": ["Privilege Escalation", "Persistence", "Service Hijack", "Misconfigured ACL", "File Overwrite", "Binary Replacement"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Enumerate service binaries and verify that only trusted users have write access.",
            "Monitor for replacement of executables that correspond to high-privilege services.",
            "Audit startup binaries regularly with file integrity monitoring tools (e.g., Tripwire)."
        ],
        "data_sources": "File: File Creation, File: File Modification, Process: Process Creation, Service: Service Metadata",
        "log_sources": [
            {"type": "File", "source": "C:\\Program Files\\*", "destination": ""},
            {"type": "Service", "source": "SCM logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "Service executable or directory", "identify": "Newly written/modified executable replacing a legitimate service binary"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Service host", "identify": "Malicious executable executed under SYSTEM or admin context"}
        ],
        "detection_methods": [
            "Use Windows Audit Policy or Sysmon (Event ID 11) to track changes to service binaries.",
            "Detect file creation or modification events on known service paths.",
            "Monitor for file hash mismatches compared to historical values or known-good baselines.",
            "Alert when non-admin users write to files in privileged directories."
        ],
        "apt": ["BlackEnergy", "APT28"],
        "spl_query": [
            "index=sysmon EventCode=11 TargetFilename=\"C:\\\\Program Files\\\\*\"\n| stats count by TargetFilename, Image, User"
        ],
        "hunt_steps": [
            "Enumerate service binaries with tools like `accesschk.exe`",
            "Identify which binaries have write access for non-admin users",
            "Review logs for recent write or modification activity to service binaries"
        ],
        "expected_outcomes": [
            "Discovery of misconfigured services with insecure ACLs",
            "Evidence of service binaries replaced by attacker-supplied executables",
            "Detection of elevated execution from replaced binaries"
        ],
        "false_positive": "Legitimate software updates or patches may replace service binaries. Verify publisher signatures, process lineage, and timing with patch cycles.",
        "clearing_steps": [
            "Restore original service executables from trusted sources",
            "Set proper ACLs on service paths: only TrustedInstaller or SYSTEM should have write permissions",
            "Harden service configuration via Group Policy or security baselines"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1574.010", "example": "Replacing Windows service executable with malicious binary"},
            {"tactic": "Privilege Escalation", "technique": "T1574.010", "example": "Executing payloads as SYSTEM after replacing service binary"}
        ],
        "watchlist": [
            "Writable service binaries located in `C:\\Program Files\\` or `C:\\Windows\\System32\\`",
            "Services running as SYSTEM but with world-writable paths",
            "Modifications to binaries during odd hours or by unauthorized users"
        ],
        "enhancements": [
            "Use security auditing tools to verify permissions of all services",
            "Apply `icacls` or `SetACL` to explicitly deny write access to service binaries for non-admin groups",
            "Utilize file integrity monitoring to baseline and detect service binary changes"
        ],
        "summary": "This technique exploits file permission weaknesses to replace legitimate service binaries with malicious ones, enabling adversaries to escalate privileges or maintain persistence under high-privilege service contexts.",
        "remediation": "Audit and correct ACLs on service executables. Prevent write access by non-admin users. Monitor binaries for unauthorized changes.",
        "improvements": "Incorporate DACL reviews in regular vulnerability scans. Enforce AppLocker or WDAC policies to restrict execution of unauthorized binaries.",
        "mitre_version": "16.1"
    }
