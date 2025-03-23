def get_content():
    return {
        "id": "T1012",
        "url_id": "T1012",
        "title": "Query Registry",
        "description": "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.",
        "tags": ["discovery", "registry", "windows", "reconnaissance", "information gathering"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for use of `reg query` or PowerShell commands accessing registry keys.",
            "Watch for tools or malware using Windows APIs to read sensitive registry values.",
            "Detect unusual access to rarely queried registry paths."
        ],
        "data_sources": "Command, Process, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "System logs or EDR telemetry", "identify": "Command line processes involving reg.exe or PowerShell registry queries"},
            {"type": "Registry Hives", "location": "HKLM or HKCU", "identify": "Queried for installed software, OS config, or system info"},
            {"type": "Sysmon Logs", "location": "Event ID 13", "identify": "Registry key read events"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Command-line monitoring for reg.exe or PowerShell registry commands",
            "Sysmon registry event logging (Event ID 13, 14)",
            "Process behavior analysis for registry access patterns"
        ],
        "apt": [],
        "spl_query": [
            'index=windows_logs (CommandLine="*reg query*" OR CommandLine="*Get-ItemProperty*")',
            'index=sysmon EventCode=13 TargetObject="*Software\\Microsoft\\Windows*"'
        ],
        "hunt_steps": [
            "Review Sysmon Event ID 13 and 14 for suspicious registry reads",
            "Correlate reg.exe usage with user behavior and login sessions",
            "Track registry queries associated with known malware or dual-use tools"
        ],
        "expected_outcomes": [
            "Detection of registry enumeration commands",
            "Insight into reconnaissance activity targeting installed software or system configs"
        ],
        "false_positive": "Legitimate administrative or software installation/management tasks may query the registry. Validate against change tickets or approved actions.",
        "clearing_steps": [
            "Audit and remove unauthorized scripts or tools",
            "Investigate registry access paths for unauthorized reads",
            "Apply Group Policy restrictions to limit registry access"
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1021", "example": "Post-discovery, adversary queries registry to locate mapped network shares or cached credentials"}
        ],
        "watchlist": [
            "Excessive or automated registry queries",
            "Unexpected use of `reg query` under SYSTEM or non-admin accounts",
            "PowerShell registry access in non-administrative contexts"
        ],
        "enhancements": [
            "Enable detailed registry auditing via Sysmon or Windows Audit Policies",
            "Use endpoint detection to baseline and alert on anomalous registry access patterns",
            "Apply registry ACLs to restrict sensitive paths"
        ],
        "summary": "Registry queries are a lightweight yet powerful method adversaries use to learn about a system. Abnormal querying may indicate preparation for privilege escalation, lateral movement, or data collection.",
        "remediation": "Limit registry access to necessary users and services. Audit registry queries and apply behavior-based rules to flag abnormal access.",
        "improvements": "Correlate registry access with user login times, parent processes, and network activity for enhanced detection fidelity.",
        "mitre_version": "16.1"
    }
