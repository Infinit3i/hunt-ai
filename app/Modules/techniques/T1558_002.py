def get_content():
    return {
        "id": "T1558.002",
        "url_id": "T1558/002",
        "title": "Steal or Forge Kerberos Tickets: Silver Ticket",
        "description": "Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets. Silver tickets allow access to a particular resource and its host system without needing to contact the Key Distribution Center (KDC), making them harder to detect.",
        "tags": ["kerberos", "silver ticket", "TGS", "credential access", "mimikatz", "Rubeus"],
        "tactic": "Credential Access",
        "protocol": "Kerberos",
        "os": "Windows",
        "tips": [
            "Look for TGS tickets issued without corresponding TGT requests.",
            "Check for anomalous Event ID 4624 logons with service-related accounts.",
            "Correlate LSASS memory access with forged ticket artifacts."
        ],
        "data_sources": "Windows Security, Logon Session, Sysmon, Windows System",
        "log_sources": [
            {"type": "Windows Security", "source": "", "destination": ""},
            {"type": "Logon Session", "source": "", "destination": ""},
            {"type": "Sysmon", "source": "", "destination": ""},
            {"type": "Windows System", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Memory Dumps", "location": "C:\\Windows\\System32", "identify": "Dumped LSASS memory may show forged tickets"},
            {"type": "Sysmon Logs", "location": "Event ID 10/11", "identify": "Unusual process access to LSASS"},
            {"type": "Event Logs", "location": "Security.evtx", "identify": "4624 with suspicious service accounts"}
        ],
        "destination_artifacts": [
            {"type": "Logon Session Metadata", "location": "Security Logs", "identify": "Malformed or forged TGS logons"},
            {"type": "Registry Hives", "location": "HKLM\\SECURITY", "identify": "Indicators of service ticket cache artifacts"}
        ],
        "detection_methods": [
            "Monitor Event ID 4624 for service account logons without TGT issuance",
            "Detect anomalies in Kerberos ticket structure",
            "Identify unexpected interactions with LSASS by tools like Mimikatz or Rubeus"
        ],
        "apt": ["Cozy Bear", "APT29", "FIN10", "Wicked Panda"],
        "spl_query": [
            "index=security EventCode=4624 LogonType=3 Account_Name!=\"$\" \n| stats count by Account_Name, Workstation_Name, Logon_ID",
            "index=sysmon EventCode=10 TargetImage=*lsass.exe* \n| stats count by SourceImage, User"
        ],
        "hunt_steps": [
            "Search for service account logons without TGT",
            "Inspect LSASS memory for signs of ticket injection",
            "Correlate silver ticket artifacts with recent credential dumping"
        ],
        "expected_outcomes": [
            "Detection of forged Kerberos TGS usage",
            "Correlated LSASS access events with forged tickets",
            "Mapped ticket activity to compromised service accounts"
        ],
        "false_positive": "Legitimate service accounts may logon similarly in automated environments. Correlate with expected behavior and systems.",
        "clearing_steps": [
            "Clear Kerberos ticket cache using `klist purge`",
            "Restart system services relying on affected service accounts",
            "Change passwords for compromised service accounts"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1003", "example": "Used to obtain the hash used in ticket forging"},
            {"tactic": "Credential Access", "technique": "T1558.003", "example": "Kerberoasting used to get service account hashes"}
        ],
        "watchlist": [
            "Service accounts generating 4624 without TGT",
            "Use of ticket creation tools like Rubeus, Mimikatz"
        ],
        "enhancements": [
            "Enable LSASS protection to block memory access",
            "Use endpoint detection to alert on ticket manipulation tools"
        ],
        "summary": "Silver tickets allow adversaries with service account password hashes to forge TGS tickets, bypassing the KDC. This enables stealthy lateral movement and resource access.",
        "remediation": "Rotate affected service account credentials, monitor ticketing activity, and enforce stricter LSASS protections.",
        "improvements": "Deploy Kerberos pre-authentication monitoring and enable Windows Defender Credential Guard.",
        "mitre_version": "16.1"
    }
