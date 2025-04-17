def get_content():
    return {
        "id": "T1562.011",
        "url_id": "T1562/011",
        "title": "Impair Defenses: Spoof Security Alerting",
        "description": "Adversaries may spoof security alerts or system status messages to deceive defenders and delay incident response. These spoofed alerts may show fake positive messages or indicators that imply that security tools are operational, when in reality they have been disabled or compromised.\n\nInstead of completely blocking or disabling telemetry and logging mechanisms, the attacker may inject or display messages that reassure defenders that systems remain secure. This tactic can be used to maintain persistence while evading detection.\n\nFor example, adversaries have been observed displaying a fake Windows Security GUI and tray icon indicating that Windows Defender is running and system protections are healthy, even though key services were disabled.",
        "tags": ["spoofing", "alerting", "deception", "GUI spoof", "fake security status", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Use centralized telemetry and validation from trusted EDR/SIEM sources, not host-level GUIs.",
            "Alert when expected services (e.g., Defender, EDR agents) are silent or fail to heartbeat.",
            "Correlate GUI status claims with actual sensor telemetry from log sources or agents."
        ],
        "data_sources": "Process, Sensor Health",
        "log_sources": [
            {"type": "Process", "source": "Host", "destination": ""},
            {"type": "Sensor Health", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Visual Spoof", "location": "Tray icon or GUI overlay", "identify": "Displays fake healthy security status"},
            {"type": "Malicious Script", "location": "Startup or scheduled tasks", "identify": "Launches spoofed interface or false notifications"},
            {"type": "Tampered Binary", "location": "System32 or %AppData%", "identify": "Fake Windows Security interfaces or icons"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "Security or Application logs", "identify": "May show disabled services or absence of alerts"},
            {"type": "Sensor Heartbeat", "location": "EDR/SIEM", "identify": "No telemetry from endpoint despite healthy appearance"},
            {"type": "UI Artifacts", "location": "Registry or disk", "identify": "Modified icons or service startup screens"}
        ],
        "detection_methods": [
            "Correlate reported health status with active telemetry feeds from endpoint agents",
            "Alert when defensive tools stop reporting while local status remains unchanged",
            "Compare process creation logs for fake GUI or spoofing scripts",
            "Use integrity checks for binaries that represent system security interfaces"
        ],
        "apt": ["Black Basta", "advanced ransomware actors"],
        "spl_query": [
            "index=sysmon EventCode=1 \n| search Image=*WindowsSecurityHealthUI.exe* OR *spoofed_security_gui* \n| stats count by host, Image, CommandLine",
            "index=edr OR heartbeat_logs \n| stats latest(timestamp) by agent_id \n| where now() - timestamp > 300",
            "index=wineventlog EventCode=7036 \n| search Message=\"Windows Defender Antivirus service entered the stopped state\""
        ],
        "hunt_steps": [
            "Identify endpoints with spoofed or unexpected security icons or GUIs",
            "Look for processes mimicking security tools with unusual paths or hashes",
            "Verify agent heartbeat or telemetry against visual indicators presented to users",
            "Search for known spoofing scripts or modified Windows shell components"
        ],
        "expected_outcomes": [
            "Detection of systems where security status is falsely reported as healthy",
            "Alert on spoofed UI artifacts or impersonated system messages",
            "Identification of systems with no telemetry despite claiming operational defenses"
        ],
        "false_positive": "Custom enterprise UIs or third-party monitoring dashboards may provide simplified system status. Investigate discrepancies between GUI and backend data.",
        "clearing_steps": [
            "Terminate spoofed interfaces and remove scheduled tasks or startup entries",
            "Validate and restore legitimate system binaries related to security reporting",
            "Re-enable disabled services and verify health through central EDR dashboards"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.011", "example": "Fake Windows Defender tray icon shown while the service is disabled"}
        ],
        "watchlist": [
            "Host with inconsistent Windows Security status and no Defender telemetry",
            "Presence of non-Microsoft signed binaries mimicking Windows Defender",
            "Processes running in user space replicating EDR or firewall GUI names"
        ],
        "enhancements": [
            "Use cryptographic integrity checks on GUI and system tray binary paths",
            "Deploy deception canaries for security GUI tampering and detect spoofed interfaces",
            "Enhance security awareness training for defenders to spot UI-level deceptions"
        ],
        "summary": "T1562.011 highlights how attackers may deceive defenders by spoofing security alerts and healthy system statuses. This tactic buys adversaries time and reduces response accuracy while real defenses are offline.",
        "remediation": "Reinforce centralized alerting and disable reliance on local status indicators. Monitor telemetry pipelines independently of what is presented in GUI interfaces.",
        "improvements": "Incorporate visual spoofing detection into EDR modules. Develop response playbooks for investigating mismatches between agent status and UI claims.",
        "mitre_version": "16.1"
    }
