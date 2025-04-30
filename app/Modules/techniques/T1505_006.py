def get_content():
    return {
        "id": "T1505.006",
        "url_id": "T1505/006",
        "title": "vSphere Installation Bundles",
        "description": "Adversaries may abuse vSphere Installation Bundles (VIBs) to establish persistent access to ESXi hypervisors.",
        "tags": ["esxi", "vib", "vsphere", "persistence", "malware", "hypervisor"],
        "tactic": "persistence",
        "protocol": "",
        "os": "ESXi",
        "tips": [
            "Audit installed VIBs regularly using esxcli software vib list.",
            "Enable secure boot and execInstalledOnly to limit unsigned or unauthorized code execution.",
            "Review VIB signature levels and watch for installations using --force or CommunitySupported." 
        ],
        "data_sources": "Application Log, Command",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Application Log", "location": "/var/log/esxupdate.log", "identify": "Log entries showing VIB installations using --force or --no-sig-check"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "/opt/vmware/", "identify": "Malicious files installed by unauthorized VIBs"}
        ],
        "detection_methods": [
            "Analyze esxupdate.log for signature bypass flags.",
            "Monitor shell commands like esxcli software vib install with force or unsigned parameters.",
            "Use esxcli software vib signature verify to confirm VIB integrity."
        ],
        "apt": [],
        "spl_query": [
            "sourcetype=\"esxupdate_log\"(\"Installed\" AND (\"--force\" OR \"--no-sig-check\" OR \"acceptance level: CommunitySupported\"))\n| rex field=_raw \"Installed:\\\s(?<vib_name>\\S+)\"\n| rex field=_raw \"Source:\\\s(?<source_url>\\S+)\"\n| table _time, host, vib_name, source_url, _raw\n| sort by _time desc",
            "sourcetype=\"shell_log\"\"esxcli software vib install\" OR \"acceptance set\"\n| rex field=_raw \"esxcli software vib install\\s+(?<flags>--[^\\s]+)\"\n| table _time, host, user, flags, _raw\n| sort by _time desc"
        ],
        "hunt_steps": [
            "Extract all VIB installation events from /var/log/esxupdate.log.",
            "Check for --force, --no-sig-check, or CommunitySupported levels.",
            "Compare VIB file hashes with known-good baselines."
        ],
        "expected_outcomes": [
            "Discovery of unauthorized or suspicious VIBs that persist across reboots on ESXi hosts."
        ],
        "false_positive": "Legitimate VIB installs by admins may also use force flags in some scenarios. Validate using change controls.",
        "clearing_steps": [
            "Remove unauthorized VIBs with esxcli software vib remove.",
            "Reinstall compromised hosts using known-good baselines.",
            "Enable secure boot and limit VIB acceptance level policy."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "persistence", "technique": "T1505", "example": "Server Software Component"},
            {"tactic": "defense-evasion", "technique": "T1202", "example": "Indirect Command Execution"}
        ],
        "watchlist": [
            "ESXi hosts with CommunitySupported or unsigned VIBs",
            "Installations logged with force flag or bypassed signature validation"
        ],
        "enhancements": [
            "Automate auditing of VIB signatures and versions across all ESXi hosts.",
            "Alert on changes to default acceptance level settings."
        ],
        "summary": "vSphere Installation Bundles (VIBs) can be manipulated to persist malicious configurations or binaries on ESXi hosts across reboots.",
        "remediation": "Enforce signature validation, monitor VIB installation logs, and use secure boot and policy restrictions.",
        "improvements": "Use host profiling to alert on unauthorized VIB deviations. Implement host-based allowlists.",
        "mitre_version": "17.0"
    }
