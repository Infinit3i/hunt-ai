def get_content():
    return {
        "id": "T1546.017",
        "url_id": "T1546/017",
        "title": "Event Triggered Execution: Udev Rules",
        "description": "Adversaries may maintain persistence by executing malicious content using custom udev rules triggered by hardware events.",
        "tags": ["udev", "linux", "event-triggered", "persistence", "device-events", "RUN+="],
        "tactic": "Persistence",
        "protocol": "",
        "os": "Linux",
        "tips": [
            "Monitor creation and modification of udev rule files, especially those using RUN+=",
            "Flag rules referencing suspicious binaries or detachment techniques like '&'",
            "Watch for sudden execution events following hardware activity"
        ],
        "data_sources": "File, Process",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Hives", "location": "/etc/udev/rules.d/, /lib/udev/rules.d/, /usr/lib/udev/rules.d/", "identify": "Custom or modified rule files with RUN+="},
            {"type": "File Access Times (MACB Timestamps)", "location": "/dev/", "identify": "Triggers that match malicious rule conditions"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor for file modifications in udev rule directories",
            "Analyze content of rules using suspicious RUN+= values",
            "Track associated process executions triggered by device events"
        ],
        "apt": [],
        "spl_query": [
            'index=linux_logs sourcetype=linux_audit file_path IN ("/etc/udev/rules.d/*", "/lib/udev/rules.d/*", "/usr/lib/udev/rules.d/*") action=modified OR action=created',
            'index=linux_logs sourcetype=linux_processes process_name="udevadm" OR cmdline="*RUN+=*"'
        ],
        "hunt_steps": [
            "Search for rule files containing RUN+= with unexpected binaries or background execution symbols",
            "Check timestamps of udev rules and correlate with known compromise times",
            "Look for anomalous device behavior or binary execution tied to pseudo-devices"
        ],
        "expected_outcomes": [
            "Detection of persistence via malicious udev rule files",
            "Identification of binaries configured to trigger on specific device access"
        ],
        "false_positive": "Some custom rules may be legitimate for system management. Validate with system administrators before taking action.",
        "clearing_steps": [
            "rm -f /etc/udev/rules.d/99-malicious.rules",
            "udevadm control --reload",
            "pkill -f /path/to/malicious_binary"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1053.003", "example": "Scheduled Task via cron triggered by device detection"}
        ],
        "watchlist": [
            "udev rules with RUN+= executing unexpected binaries",
            "Changes to rule files outside of patch or configuration change windows"
        ],
        "enhancements": [
            "Deploy file integrity monitoring on udev rules directories",
            "Alert on execution of binaries via device-triggered events"
        ],
        "summary": "Adversaries can abuse the udev subsystem on Linux to persist by adding rules that execute code when specific devices are added or accessed.",
        "remediation": "Review and remove malicious rules. Reload udev to apply clean configuration. Audit all device-triggered execution mechanisms.",
        "improvements": "Enforce strict control and auditing of udev rule changes. Disable unused device classes or plug-n-play support where feasible.",
        "mitre_version": "16.1"
    }
