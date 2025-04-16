def get_content():
    return {
        "id": "T1558.003",
        "url_id": "T1558/003",
        "title": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "description": "Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to offline brute force attacks on service account hashes encrypted with RC4 (etype 23).",
        "tags": ["kerberoasting", "TGS", "SPN", "brute force", "RC4", "credential access", "kerberos"],
        "tactic": "Credential Access",
        "protocol": "Kerberos",
        "os": "Windows",
        "tips": [
            "Audit Event ID 4769 to detect high-volume SPN ticket requests.",
            "Investigate accounts making unusual TGS-REP requests using RC4 encryption (etype 0x17).",
            "Look for patterns of use on non-standard service accounts or excessive ticket requests."
        ],
        "data_sources": "Windows Security, Active Directory",
        "log_sources": [
            {"type": "Windows Security", "source": "", "destination": ""},
            {"type": "Active Directory", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Security.evtx", "identify": "Event ID 4769 showing RC4 ticket requests"},
            {"type": "Process List", "location": "System Memory", "identify": "Use of tools like Rubeus or Empire"}
        ],
        "destination_artifacts": [
            {"type": "Active Directory Credential Request", "location": "Domain Controller", "identify": "Service ticket request patterns"},
            {"type": "Network Connections", "location": "Captured Traffic", "identify": "SPN requests with etype 23"}
        ],
        "detection_methods": [
            "Monitor for Event ID 4769 with Ticket Encryption Type 0x17 (RC4)",
            "Detect SPN requests generated in high volumes from a single account",
            "Alert on execution of tools like Rubeus or PowerSploit from endpoints"
        ],
        "apt": ["FIN7", "Ryuk", "UNC2165", "Carbon Spider", "Wocao", "SILENTTRINITY", "Praetorian"],
        "spl_query": [
            "index=security EventCode=4769 Ticket_Encryption_Type=0x17 \n| stats count by Account_Name, Service_Name, Client_Address",
            "index=security EventCode=4769 \n| stats count by Account_Name, Ticket_Encryption_Type \n| where count > 20"
        ],
        "hunt_steps": [
            "Collect all 4769 events with etype 0x17 from domain controllers",
            "Correlate accounts making repeated SPN requests",
            "Trace processes using Rubeus, Empire, or Impacket toolkits"
        ],
        "expected_outcomes": [
            "Discovery of service accounts targeted for password cracking",
            "Evidence of Kerberoasting activity in enterprise domain environments"
        ],
        "false_positive": "Legitimate service discovery tools or account misconfigurations may cause similar behavior. Baseline against known activity.",
        "clearing_steps": [
            "Reset passwords for exposed service accounts and disable RC4 support",
            "Clear suspicious ticket caches using `klist purge`",
            "Review AD policies for SPN visibility and access control"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1558.002", "example": "Silver ticket forgery using cracked hashes"},
            {"tactic": "Persistence", "technique": "T1078", "example": "Use of valid accounts post-hash cracking"}
        ],
        "watchlist": [
            "Accounts issuing excessive SPN requests (Event ID 4769)",
            "Execution of known Kerberoasting tools"
        ],
        "enhancements": [
            "Disable RC4 encryption support in Kerberos where possible",
            "Use managed service accounts with long random passwords"
        ],
        "summary": "Kerberoasting enables attackers with domain access to request and extract service tickets from Active Directory, then perform offline brute force attacks against the RC4-encrypted hashes of service account credentials.",
        "remediation": "Rotate affected service account credentials, restrict SPN exposure, and enable stronger Kerberos encryption.",
        "improvements": "Implement tiered administrative accounts, enforce strong password policies, and remove SPNs from unnecessary accounts.",
        "mitre_version": "16.1"
    }
