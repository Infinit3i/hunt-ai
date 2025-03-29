def get_content():
    return {
        "id": "T1207",
        "url_id": "T1207",
        "title": "Rogue Domain Controller",
        "description": "Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data.",
        "tags": ["Defense Evasion", "Persistence", "DCShadow", "Active Directory", "Replication Abuse"],
        "tactic": "Defense Evasion",
        "protocol": "MS-DRSR (Directory Replication), RPC, Kerberos",
        "os": "Windows",
        "tips": [
            "Baseline the Configuration partition of the AD schema to detect new nTDSDSA object creation.",
            "Monitor replication requests (e.g., GetNCChanges) from non-DC hosts.",
            "Audit SPNs like GC/ set on unauthorized computers."
        ],
        "data_sources": "Active Directory, Network Traffic, User Account",
        "log_sources": [
            {"type": "Active Directory", "source": "Event ID 4928, 4929", "destination": ""},
            {"type": "Active Directory", "source": "nTDSDSA Object Creation", "destination": ""},
            {"type": "Network Traffic", "source": "MS-DRSR RPC Streams", "destination": ""},
            {"type": "User Account", "source": "Kerberos Auth Events", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "SPN Configuration", "location": "AD Object Attributes", "identify": "GC/ SPN set on unauthorized computer account"},
            {"type": "Event Logs", "location": "Security.evtx", "identify": "Directory Replication triggered outside regular intervals"}
        ],
        "destination_artifacts": [
            {"type": "nTDSDSA Object", "location": "Configuration Partition", "identify": "Malicious DC entry"},
            {"type": "AD Object Modifications", "location": "Domain Controller", "identify": "Unauthorized changes replicated by rogue DC"}
        ],
        "detection_methods": [
            "Monitor DRS replication events to and from unauthorized sources",
            "Alert on new nTDSDSA object creation in AD Configuration partition",
            "Detect anomalous Kerberos SPN assignments from non-DC hosts"
        ],
        "apt": ["APT29", "FIN6"],
        "spl_query": [
            "index=windows EventCode=4928 OR EventCode=4929\n| stats count by _time, host, subject_user_name, object_name",
            "index=ad_object_changes object_class=nTDSDSA\n| stats count by object_dn, creator_sid, timestamp"
        ],
        "hunt_steps": [
            "Query for new AD nTDSDSA objects added recently",
            "Monitor GetNCChanges traffic not originating from DC OUs",
            "Check for unauthorized SPNs related to replication (GC/, DRS)"
        ],
        "expected_outcomes": [
            "Detection of rogue DC registration and AD replication manipulation",
            "Suspicious replication or SPN activity flagged for triage"
        ],
        "false_positive": "Legitimate DC additions or maintenance activity—validate user context and OU placement.",
        "clearing_steps": [
            "Remove rogue nTDSDSA object from Configuration partition",
            "Revoke machine account and credentials of rogue DC",
            "Reset KRBTGT twice to mitigate ticket abuse",
            "Re-baseline replication permissions and SPNs"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-active-directory"],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1134.005", "example": "SIDHistory injected by rogue DC to maintain stealthy access"},
            {"tactic": "Defense Evasion", "technique": "T1070", "example": "Replication logs evaded or suppressed by rogue DC"},
            {"tactic": "Credential Access", "technique": "T1003.006", "example": "DCSync-like replication used to obtain credentials"}
        ],
        "watchlist": [
            "Replication traffic from non-DC systems",
            "New DC registrations or nTDSDSA objects in AD",
            "SPNs set on unauthorized computers or in unusual OUs"
        ],
        "enhancements": [
            "Deploy AD change auditing with alerts on sensitive replication object creation",
            "Integrate AD security tools like PingCastle, Purple Knight for schema diffing",
            "Use LSASS/SAM telemetry to detect unauthorized replication of secrets"
        ],
        "summary": "Rogue Domain Controllers allow adversaries to inject or modify AD data by simulating legitimate DC behavior via replication abuse, typically with DCShadow.",
        "remediation": "Purge rogue DCs, reset domain trust anchors (e.g., KRBTGT), and tighten replication controls.",
        "improvements": "Enhance logging of replication operations, alert on DRS calls from non-DCs, and audit Configuration partition regularly.",
        "mitre_version": "16.1"
    }
