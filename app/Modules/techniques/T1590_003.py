def get_content():
    return {
        "id": "T1590.003",
        "url_id": "T1590/003",
        "title": "Gather Victim Network Information: Network Trust Dependencies",
        "description": "Adversaries may gather information about the victim's network trust dependencies that can be used during targeting. Information about network trusts may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access. Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about network trusts may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.",
        "tags": ["reconnaissance", "network-trust", "targeting"],
        "tactic": "Reconnaissance",
        "protocol": "LDAP, Kerberos, SMB",
        "os": "Windows, Linux",
        "tips": [
            "Identify all external domain trusts and document access levels",
            "Use honeynets to observe abnormal trust mapping queries",
            "Monitor for queries against Active Directory trust attributes"
        ],
        "data_sources": "Active Directory, Command, Network Traffic, Domain Name",
        "log_sources": [
            {"type": "Active Directory", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Domain Name", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Security.evtx", "identify": "Account enumeration or trust discovery"},
            {"type": "Command History", "location": "~/.bash_history", "identify": "Use of commands like nltest or netdom"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall/IDS logs", "identify": "Queries to known trust relationship IPs"},
            {"type": "Sysmon Logs", "location": "Event ID 1 and 3", "identify": "Execution of enumeration tools"}
        ],
        "detection_methods": [
            "Monitor for Active Directory trust enumeration using nltest, netdom, or PowerShell",
            "Track outbound traffic querying external domain controllers",
            "Alert on LDAP or Kerberos requests to unfamiliar domains"
        ],
        "apt": ["Volt Typhoon"],
        "spl_query": [
            "index=windows EventCode=4662 ObjectType=trustedDomain\n| stats count by Account_Name, Object_Name",
            "index=sysmon EventCode=1 Image=*nltest.exe* OR Image=*netdom.exe*\n| stats count by Image, User, CommandLine"
        ],
        "hunt_steps": [
            "Search for trust enumeration commands in user command histories",
            "Audit Active Directory trust configurations for anomalies",
            "Check for authentication attempts across trust boundaries"
        ],
        "expected_outcomes": [
            "Identification of domain trust mapping by unauthorized users",
            "Detection of scanning activity between internal and partner domains"
        ],
        "false_positive": "Administrative discovery scripts or inventory software may enumerate trust relationships—validate based on user, host, and schedule.",
        "clearing_steps": [
            "Clear PowerShell history: Remove-Item (Get-PSReadlineOption).HistorySavePath",
            "Delete bash history: rm ~/.bash_history && history -c",
            "Clear Sysmon logs: wevtutil cl Microsoft-Windows-Sysmon/Operational",
            "Disable unused domain trust relationships"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1199", "example": "Leverage trusted relationship for lateral access"},
            {"tactic": "Resource Development", "technique": "T1584", "example": "Compromise external infrastructure based on trust data"}
        ],
        "watchlist": [
            "Execution of nltest/netdom",
            "Authentication attempts to external/trusted domains",
            "Access to Active Directory trust settings"
        ],
        "enhancements": [
            "Correlate trust relationship queries with non-admin accounts",
            "Alert on cross-domain authentication anomalies"
        ],
        "summary": "This technique centers on adversaries collecting details about inter-organizational domain or network relationships. Such information can assist attackers in identifying paths for lateral movement or initial access into more secure environments via trusted channels.",
        "remediation": "Implement monitoring and alerting on trust configuration changes. Remove or restrict unused or excessive domain trust links.",
        "improvements": "Use Just-In-Time and Just-Enough-Access (JIT/JEA) models to restrict access across trusted domains. Add analytics on authentication trust boundaries.",
        "mitre_version": "16.1"
    }
