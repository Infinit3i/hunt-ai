def get_content():
    return {
        "id": "T1003.006",
        "url_id": "T1003/006",
        "title": "OS Credential Dumping: DCSync",
        "description": "Adversaries may abuse Active Directory replication APIs to simulate domain controller behavior and extract credentials via the DCSync technique.",
        "tags": ["dcsync", "mimikatz", "lsadump", "netsync", "drsr", "replication", "credential dumping", "activedirectory"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for non-domain-controller accounts making replication requests",
            "Use logs from Active Directory, NTDS, and DRS to identify suspicious GetNCChanges activity",
            "Restrict membership of Domain Admins, Enterprise Admins, and Administrator groups"
        ],
        "data_sources": "Active Directory, Network Traffic",
        "log_sources": [
            {"type": "Active Directory", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Connections", "location": "From non-DC systems to domain controllers", "identify": "DSGetNCChanges or replication requests"},
            {"type": "Active Directory Object Access", "location": "Domain Controller", "identify": "Replication traffic to unexpected accounts"},
            {"type": "Windows Event Logs", "location": "Directory Services and Security Logs", "identify": "Replication activity, especially Event IDs 4662, 4929"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor Active Directory logs for GetNCChanges calls",
            "Alert on replication API access by non-DC hosts or non-admin users",
            "Track usage of tools like Mimikatz performing lsadump::dcsync"
        ],
        "apt": [
            "StellarParticle", "Earth Lusca", "Wocao", "DEV-0537", "Solorigate"
        ],
        "spl_query": [
            'index=ad_logs EventCode=4662 ObjectType="replication" AND NOT source_host IN ("dc1", "dc2", "dc3")',
            'index=network_logs protocol="DRSR" OR destination_port=135 OR destination_port=389'
        ],
        "hunt_steps": [
            "List all replication requests by machines not designated as domain controllers",
            "Look for unauthorized access to DSGetNCChanges, DRSUAPI, or SAMR",
            "Investigate privileged accounts performing GetNCChanges outside of backup windows"
        ],
        "expected_outcomes": [
            "Detection of unauthorized DCSync attempts from attacker-controlled hosts",
            "Identification of credential theft from AD replication abuse"
        ],
        "false_positive": "Legitimate domain controller communication may resemble DCSync traffic. Validate source system and user context.",
        "clearing_steps": [
            "Remove unauthorized accounts from privileged AD groups",
            "Reset KRBTGT and administrator account passwords",
            "Rebuild trust relationships and review AD replication logs"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1558.001", "example": "Golden Ticket creation from KRBTGT hash retrieved via DCSync"}
        ],
        "watchlist": [
            "Accounts performing GetNCChanges requests",
            "Unusual DS replication activity from non-DC IPs",
            "Access to domain controller APIs by unexpected users"
        ],
        "enhancements": [
            "Enable DCSync detection in SIEM and domain controllers",
            "Deploy Tiered Admin model to segregate AD management roles",
            "Use event log forwarding to aggregate DRS replication events centrally"
        ],
        "summary": "DCSync allows adversaries with elevated permissions to impersonate a domain controller and extract sensitive credentials by querying AD replication APIs.",
        "remediation": "Remove attacker access to AD, rotate critical secrets (KRBTGT, admin), and implement least-privilege AD group practices.",
        "improvements": "Enable advanced auditing, use group tiering and Just-In-Time (JIT) admin models to limit replication abuse.",
        "mitre_version": "16.1"
    }
