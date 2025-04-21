def get_content():
    return {
        "id": "T1653",
        "url_id": "T1653",
        "title": "Power Settings",
        "description": "Adversaries may manipulate power settings to prevent a system from sleeping, hibernating, rebooting, or shutting down, thereby increasing the longevity of their access. Tools like `powercfg` on Windows or `systemctl` on Linux can be abused to disable power-saving features, prolong lock screen timeout, or remove shutdown capabilities. These changes help maintain malware presence, especially for payloads that don't survive reboots.",
        "tags": ["persistence", "powercfg", "hibernate-prevention", "systemctl", "timeout-abuse"],
        "tactic": "Persistence",
        "protocol": "",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Monitor for command-line usage of tools like `powercfg`, `systemctl`, or `/etc/systemd/sleep.conf` edits.",
            "Establish baseline lock screen and power settings across endpoints for policy deviation detection.",
            "Harden GPO or MDM settings to enforce system timeout policies on Windows/macOS."
        ],
        "data_sources": "Command: Command Execution, File: File Modification",
        "log_sources": [
            {"type": "Command", "source": "PowerShell, CMD, Bash", "destination": ""},
            {"type": "File", "source": "/etc/systemd/, registry settings, power plans", "destination": ""},
            {"type": "Process", "source": "Security logs, EDR alerts", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Power Configuration Tools", "location": "Local systems", "identify": "Use of `powercfg`, `systemctl mask sleep.target`, or registry edits"},
            {"type": "Timeout Configurations", "location": "OS-level settings", "identify": "Changes to lock timeout, screen saver policies, or hibernate intervals"},
            {"type": "Log Files", "location": "Event Logs, Syslog", "identify": "Power setting change entries, unexpected persistence activity"}
        ],
        "destination_artifacts": [
            {"type": "Malware Persistence", "location": "Volatile memory or session-dependent storage", "identify": "Malware designed to avoid reboot"},
            {"type": "Modified Config Files", "location": "Windows Registry or /etc/systemd/", "identify": "Sleep/wake configurations edited or removed"},
            {"type": "Missing Binaries", "location": "/sbin or C:\\Windows\\System32", "identify": "Deleted shutdown.exe or related system tools"}
        ],
        "detection_methods": [
            "Monitor for execution of `powercfg /change` or similar parameters that extend idle time",
            "Alert on deletion or tampering with system binaries like `shutdown.exe` or `halt`",
            "Detect process creation with commands disabling sleep, hibernate, or reboot triggers",
            "Correlate failed system reboot attempts with malware persistence indicators"
        ],
        "apt": [
            "Miner Malware Families (CoinLoader, Condi Botnet)",
            "APT groups deploying evasive loaders (BATLOADER)"
        ],
        "spl_query": "index=windows OR index=syslog\n| search (process_name=powercfg.exe AND command_line=*timeout*) OR (command_line=*systemctl* AND command_line=*mask*)\n| stats count by user, host, command_line",
        "spl_rule": "https://research.splunk.com/detections/tactics/persistence/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1653",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1653",
        "hunt_steps": [
            "Look for recent changes to system power policies via `powercfg /query` or `gsettings` on Linux/macOS",
            "Check Windows Registry under `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power` for unexpected modifications",
            "Review audit logs for deleted shutdown/reboot binaries",
            "Correlate suspicious long uptime hosts with blocked sleep or hibernate behavior"
        ],
        "expected_outcomes": [
            "Detected and reversed tampering of system power management settings",
            "Uncovered malware avoiding reboot through timeout extension",
            "Strengthened endpoint policies against malicious persistence techniques"
        ],
        "false_positive": "Legitimate use cases may include kiosk systems or servers with intentional non-sleep configurations. Validate changes against role and baseline policies.",
        "clearing_steps": [
            "Restore default power plans using `powercfg -restoredefaultschemes`",
            "Reinstall removed system binaries if tampered or deleted",
            "Audit and reset tampered files in `/etc/systemd/sleep.conf` or equivalent",
            "Use MDM or GPO to re-enforce secure timeout and power settings"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1653 (Power Settings)", "example": "Adversaries using `powercfg /change standby-timeout-ac 0` to prevent system sleep"}
        ],
        "watchlist": [
            "Alert on usage of `powercfg /change`, `powercfg /setactive` with custom GUIDs",
            "Detect processes deleting or disabling `shutdown.exe`, `halt`, or `reboot` binaries",
            "Watch for excessive uptime in workstations intended for sleep cycles"
        ],
        "enhancements": [
            "Automate power configuration monitoring through SIEM agents",
            "Use GPOs or Endpoint Management to lock key power settings",
            "Introduce log alerts for changes to system binaries or power plan registry keys"
        ],
        "summary": "Adversaries may manipulate power settings to prolong system uptime and ensure malware remains operational. This evasion tactic can impair incident response and complicate eradication strategies.",
        "remediation": "Reset power plans and system defaults, restore critical binaries, and validate timeout and reboot configurations.",
        "improvements": "Deploy enhanced policies for idle timeouts and sleep settings, monitor power command usage, and lock system-critical binaries from tampering.",
        "mitre_version": "16.1"
    }
