def get_content():
    return {
        "id": "T1518.001",
        "url_id": "T1518/001",
        "title": "Software Discovery: Security Software Discovery",
        "description": "Adversaries may enumerate security software and configurations on a system or within a cloud environment to inform post-compromise actions. This includes tools like anti-virus, endpoint detection and response (EDR), host firewalls, cloud monitoring agents (e.g., AWS CloudWatch, Azure VM Agent, GCP Monitoring), and other defensive mechanisms. Discovery may occur via command-line tools, registry queries, API calls, or by checking specific directories and running processes. Information gathered can be used to evade detection, avoid certain hosts, or adjust malware behavior.",
        "tags": ["discovery", "security-tools", "T1518.001", "cloud", "enumeration"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "IaaS, Linux, Windows, macOS",
        "tips": [
            "Flag uncommon process enumeration tools used outside baseline software lists.",
            "Use threat hunting to correlate known discovery tools like Tasklist, netsh, or reg.exe with suspicious child processes.",
            "Correlate command-line activities with indicators of privilege escalation or persistence."
        ],
        "data_sources": "Command, Firewall, Process",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Firewall", "source": "Firewall Enumeration", "destination": ""},
            {"type": "Firewall", "source": "Firewall Metadata", "destination": ""},
            {"type": "Process", "source": "OS API Execution", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command", "location": "CLI tools", "identify": "Use of reg query, tasklist, netsh, wmic, PowerShell to find security software"},
            {"type": "Process", "location": "System", "identify": "Execution of discovery tools like AVStatus.exe, AntiSpyCheck.ps1"},
            {"type": "Cloud API", "location": "AWS/Azure/GCP", "identify": "API calls to list agents and security settings"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Command-line logs", "identify": "Evidence of security product scans"},
            {"type": "Network", "location": "Cloud telemetry", "identify": "Cloud API calls to query monitoring agents"},
            {"type": "Registry", "location": "HKLM\\SOFTWARE\\*", "identify": "Registry reads on anti-virus or EDR paths"}
        ],
        "detection_methods": [
            "Monitor and alert on suspicious command-line patterns using reg, netsh, tasklist, or WMIC querying AV or EDR software.",
            "Use EDR telemetry to detect processes querying security software-related registry or file locations.",
            "Enable logging of API interactions in cloud platforms to detect queries against security agent configurations."
        ],
        "apt": [],
        "spl_query": [
            'index=winlogbeat EventCode=4688\n| search CommandLine="*tasklist*" OR CommandLine="*reg query*" OR CommandLine="*netsh advfirewall*"',
            'index=cloud_logs source=aws.cloudtrail OR source=gcp.auditlog\n| search eventName="Describe*" OR methodName="projects.*.list*" AND resource="cloudwatch|monitoring"',
            'index=osquery_logs\n| search name="anti_virus_check" OR query="SELECT * FROM processes WHERE name LIKE \'%av%\'"',
        ],
        "hunt_steps": [
            "Look for reg.exe, netsh, tasklist, or PowerShell commands run by users or services not typically associated with administrative activity.",
            "Correlate execution of these commands with discovery of other system info (e.g., hostname, domain, AV version).",
            "In cloud logs, look for bursts of API calls targeting system agent descriptions or monitoring services."
        ],
        "expected_outcomes": [
            "Detection of adversary attempts to discover security software before launching payloads.",
            "Identification of toolmarks related to enumeration of EDR and AV tools.",
            "Cloud-based detections on attempts to enumerate logging agents and security posture remotely."
        ],
        "false_positive": "IT management tools or diagnostic scripts may perform similar queries. Filter by user context, frequency, and time-of-day patterns.",
        "clearing_steps": [
            "Restrict access to registry keys and directories associated with security software.",
            "Audit cloud roles and privileges to prevent over-permissive API access.",
            "Isolate hosts performing frequent AV/EDR checks without known justification."
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1518.001", "example": "reg query HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection"},
            {"tactic": "Discovery", "technique": "T1082", "example": "System Information Discovery often paired with AV enumeration"},
            {"tactic": "Defense Evasion", "technique": "T1562.001", "example": "Adversary may evade or disable security software after discovering it"}
        ],
        "watchlist": [
            "Suspicious use of 'reg query' or 'tasklist' by non-admin users",
            "Cloud API enumeration patterns for VM agents",
            "Sudden spikes in queries against EDR/AV registry keys"
        ],
        "enhancements": [
            "Deploy Sysmon rules for Process Access targeting security software processes.",
            "Enable audit policies on registry keys and service queries linked to AV software.",
            "In cloud, set alerts on high-rate API queries or permission misuses in roles with monitor access."
        ],
        "summary": "Security Software Discovery enables attackers to identify defensive tools in use on a host or within a cloud environment. This helps shape attacker behavior and may precede evasive action or full malware deployment.",
        "remediation": "Implement EDRs with self-defense mechanisms, restrict access to registry paths and agent metadata, and monitor for suspicious discovery commands and API queries.",
        "improvements": "Centralize visibility on AV and monitoring agent interactions. Correlate system discovery with privilege usage and behavioral deviations.",
        "mitre_version": "16.1"
    }
