def get_content():
    return {
        "id": "T1558",
        "url_id": "T1558",
        "title": "Steal or Forge Kerberos Tickets",
        "description": "Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket. Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as 'realms', there are three basic participants: client, service, and Key Distribution Center (KDC). Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting. Adversaries may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access. On Windows, the built-in klist utility can be used to list and analyze cached Kerberos tickets.",
        "tags": ["Credential Access", "Kerberos", "Pass the Ticket", "Persistence", "Defense Evasion"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Enable Audit Kerberos Service Ticket Operations to log TGS requests.",
            "Watch for unexpected usage of RC4 encryption in TGTs.",
            "Investigate accounts with frequent or abnormal Kerberos ticket requests.",
            "Monitor processes that access LSASS memory space."
        ],
        "data_sources": "Active Directory: Active Directory Credential Request, Command: Command Execution, File: File Access, Logon Session: Logon Session Metadata",
        "log_sources": [
            {"type": "Active Directory", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Logon Session", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor malformed or empty fields in Event IDs 4624, 4672, 4634",
            "Detect TGS requests without a preceding TGT",
            "Monitor RC4 (Type 0x17) encryption in TGTs",
            "Check lifetime of TGTs deviating from domain norms",
            "Monitor unexpected access to lsass.exe or /var/lib/sss/secrets/"
        ],
        "apt": ["Mimikatz"],
        "spl_query": [
            "index=windows EventCode=4769 encryptionType=0x17 | stats count by Account_Name, Ticket_Options",
            "index=windows EventCode=4624 OR EventCode=4672 OR EventCode=4634 | stats count by Logon_Type, Workstation_Name, Target_Username"
        ],
        "hunt_steps": [
            "Check Kerberos TGT and TGS issuance logs for inconsistencies",
            "Look for ticket reuse across lateral movement attempts",
            "Correlate LSASS access attempts with Kerberos anomalies",
            "Investigate secrets.ldb and .secrets.mkey file access patterns"
        ],
        "expected_outcomes": [
            "Detection of stolen or forged Kerberos ticket usage",
            "Identify unusual service ticket patterns across accounts"
        ],
        "false_positive": "Automated scripts or monitoring tools that interface with Kerberos may resemble adversary behavior. Contextual review recommended.",
        "clearing_steps": [
            "Revoke affected Kerberos tickets and reset passwords for compromised accounts",
            "Force TGT expiration and clear ticket caches on hosts",
            "Reinitialize LSASS memory protection monitoring"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1558", "example": "Adversary uses forged TGT to authenticate across domain resources without valid credentials."}
        ],
        "watchlist": [
            "Accounts issuing large numbers of TGS requests",
            "Unusual use of klist or memory access to lsass.exe",
            "Rare use of RC4 encryption in TGTs or TGSs"
        ],
        "enhancements": [
            "Implement anomaly-based Kerberos activity detection in SIEM",
            "Use endpoint protection that restricts LSASS access"
        ],
        "summary": "This technique allows adversaries to bypass authentication by abusing Kerberos ticket handling, enabling stealthy lateral movement and credential theft.",
        "remediation": "Enforce LSASS memory protection, restrict ticket reuse, and apply monitoring to detect anomalous Kerberos patterns.",
        "improvements": "Regularly rotate krbtgt passwords and limit Kerberos ticket lifetimes to reduce exposure window.",
        "mitre_version": "16.1"
    }