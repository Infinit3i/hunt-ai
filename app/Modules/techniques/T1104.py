def get_content():
    return {
        "id": "T1104",
        "url_id": "T1104",
        "title": "Multi-Stage Channels",
        "description": "Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.",
        "tags": ["multi-stage", "c2", "layered communication", "fallback", "evasion"],
        "tactic": "command-and-control",
        "protocol": "HTTPS, TCP",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor for multi-domain or multi-IP callout patterns",
            "Alert on unusual sequencing of C2 callbacks with tool drops",
            "Track initial-stage C2 activity that downloads a second agent"
        ],
        "data_sources": "Network Traffic",
        "log_sources": [
            {"type": "Network Traffic", "source": "endpoint", "destination": "C2 infrastructure"},
            {"type": "Network Traffic", "source": "proxy", "destination": ""},
            {"type": "Network Traffic", "source": "EDR/IDS", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "Live memory or tasklist output", "identify": "Initial-stage malware processes"},
            {"type": "Network Connections", "location": "netstat or EDR telemetry", "identify": "Multiple staged domain callbacks"},
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch\\", "identify": "Execution of multiple distinct droppers/loaders"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic Flow", "location": "Proxy/firewall logs", "identify": "Connection to different stages of C2"},
            {"type": "Memory Dumps", "location": "Volatile memory capture", "identify": "Injected second-stage RAT payloads"},
            {"type": "Registry Hives", "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "identify": "Persistence of second-stage payload"}
        ],
        "detection_methods": [
            "Detect changes in C2 IPs or domains over time within same infection",
            "Correlate tool drop and new network behavior with earlier infections",
            "Behavioral analysis of RATs loading additional stages after beaconing"
        ],
        "apt": [
            "APT41", "Turla", "APT30", "Lazarus Group", "Bazar", "Valak", "Snip3", "MuddyWater", "APT17"
        ],
        "spl_query": [
            'index=network OR index=proxy \n| stats count by src_ip, dest_ip, uri_domain \n| eventstats dc(dest_ip) as unique_dest \n| where unique_dest > 2',
            'index=sysmon EventCode=1 \n| search Image=*\\AppData\\* \n| stats values(Image), values(CommandLine) by User, Computer',
            'index=network sourcetype="stream:tcp" \n| stats count by src_ip, dest_ip, dest_port \n| where dest_port IN (443, 80, 8443)'
        ],
        "hunt_steps": [
            "Identify multi-IP or multi-domain callbacks from single host",
            "Trace execution flow from stage one malware to dropped stage two",
            "Hunt for registry or startup persistence added post-initial callback"
        ],
        "expected_outcomes": [
            "Detection of advanced threats using multi-stage C2",
            "Mapped infrastructure used across multiple malware families",
            "Improved ability to stop advanced payload deployment"
        ],
        "false_positive": "Software updaters or telemetry agents may exhibit similar staged download behaviors. Validate file reputation and domain ownership.",
        "clearing_steps": [
            "Block access to known staged C2 domains or IPs",
            "Kill and quarantine both stages of malware agents",
            "Clean persistence mechanisms tied to second-stage execution",
            "Restore system from backup if deeper compromise is confirmed"
        ],
        "mitre_mapping": [
            {"tactic": "persistence", "technique": "T1053.005", "example": "Scheduled task launches second-stage RAT"},
            {"tactic": "defense-evasion", "technique": "T1027", "example": "Obfuscated loader used between stages"},
            {"tactic": "execution", "technique": "T1059.003", "example": "Execution of second-stage PowerShell RAT"}
        ],
        "watchlist": [
            "Endpoints reaching multiple suspicious domains/IPs in short succession",
            "Beaconing patterns that change destination or structure over time",
            "Memory-resident tools that download further modules"
        ],
        "enhancements": [
            "Deploy network sandbox to observe staged malware behavior",
            "Correlate between stage one loader and subsequent connections",
            "Leverage DNS logs to pivot on known first-stage domains"
        ],
        "summary": "Multi-stage channels involve an initial-stage C2 callout followed by loading and activation of additional, more advanced malware. This adds stealth and complexity, making detection and containment more difficult.",
        "remediation": "Block first and second stage C2 servers. Quarantine involved hosts and inspect for toolsets left behind by second-stage RATs.",
        "improvements": "Use network anomaly detection to catch initial callbacks and behavioral detections to recognize when a loader drops a second-stage payload.",
        "mitre_version": "16.1"
    }
