def get_content():
    return {
        "id": "T1546.008",
        "url_id": "T1546/008",
        "title": "Event Triggered Execution: Accessibility Features",
        "description": "Adversaries may establish persistence or elevate privileges by replacing or redirecting accessibility features (like Sticky Keys) to execute malicious content before user logon.",
        "tags": ["accessibility abuse", "sticky keys", "utilman", "persistence", "privilege escalation"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor changes to binaries in %SystemRoot%\\System32 related to accessibility tools.",
            "Alert on unexpected execution of utilman.exe, sethc.exe, or narrator.exe from the logon screen.",
            "Audit the Image File Execution Options registry key for tampering."
        ],
        "data_sources": "Command: Command Execution, File: File Creation, File: File Modification, Process: Process Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Command", "source": "CLI", "destination": "Registry modification utilities"},
            {"type": "File", "source": "%SystemRoot%\\System32", "destination": "Replaced accessibility binaries"},
            {"type": "Windows Registry", "source": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "destination": "Debugger redirect paths"},
            {"type": "Process", "source": "", "destination": "Unexpected SYSTEM-level shell access pre-logon"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "%SystemRoot%\\System32\\utilman.exe", "identify": "File replaced with cmd.exe or unknown binary"},
            {"type": "Registry Key", "location": "HKLM\\...\\Image File Execution Options\\utilman.exe", "identify": "Debugger value points to alternate binary"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "cmd.exe launched via accessibility hotkey", "identify": "Unexpected parent process chain"},
            {"type": "File", "location": "Malicious binary in System32", "identify": "Unsigned or modified file hash"}
        ],
        "detection_methods": [
            "File integrity monitoring of accessibility binaries (sethc.exe, utilman.exe, etc.)",
            "Process creation monitoring for SYSTEM-level cmd.exe during pre-logon",
            "Registry monitoring of IFEO keys related to accessibility executables",
            "Command-line audit logs for usage of tools like reg.exe or PowerShell Set-ItemProperty"
        ],
        "apt": ["APT29", "APT41", "Shell Crew", "Axiom"],
        "spl_query": [
            'index=main (TargetFilename="*sethc.exe" OR TargetFilename="*utilman.exe") \n| stats count by Image, User, CommandLine, ParentImage'
        ],
        "hunt_steps": [
            "Inspect System32 directory for unauthorized replacements of accessibility executables",
            "Query Image File Execution Options registry keys for debugger hijacks",
            "Look for cmd.exe launched by utilman.exe, osk.exe, or narrator.exe",
            "Review pre-logon SYSTEM process creation logs"
        ],
        "expected_outcomes": [
            "Detection of unauthorized binary replacement",
            "Pre-logon access via SYSTEM command shell",
            "Debugger hijack of accessibility features for privilege escalation"
        ],
        "false_positive": "Legitimate troubleshooting or accessibility testing may execute these binaries, but replacing them or attaching debuggers should be rare and verified with IT change control.",
        "clearing_steps": [
            "Restore default binaries for affected accessibility tools from a trusted source",
            "Remove malicious entries from the Image File Execution Options registry path",
            "Audit permissions on System32 to prevent future modifications",
            "Reboot to ensure modified binaries are no longer loaded"
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1055", "example": "Injecting into utilman.exe to maintain elevated access"},
            {"tactic": "Defense Evasion", "technique": "T1112", "example": "Registry modification to redirect accessibility feature"}
        ],
        "watchlist": [
            "Command execution of sethc.exe, utilman.exe, osk.exe, magnify.exe, etc.",
            "Registry modifications to Image File Execution Options for known accessibility apps",
            "SYSTEM user spawning command shells before interactive logon"
        ],
        "enhancements": [
            "Enable and baseline file integrity monitoring for C:\\Windows\\System32",
            "Implement AppLocker or WDAC to block unauthorized binaries in System32",
            "Use EDR tools to detect SYSTEM shells without user authentication"
        ],
        "summary": "Accessibility features in Windows, such as Sticky Keys or Utilman, can be abused by adversaries to gain SYSTEM access before authentication, offering stealthy persistence or privilege escalation paths.",
        "remediation": "Audit and restore accessibility binaries. Monitor access to System32 and relevant registry keys. Restrict user ability to write to sensitive paths.",
        "improvements": "Apply Secure Boot and Code Integrity Policies. Use EDR to correlate SYSTEM-level shell execution chains.",
        "mitre_version": "16.1"
    }
