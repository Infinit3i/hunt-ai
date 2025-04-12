def get_content():
    return {
        "id": "T1556.007",
        "url_id": "T1556/007",
        "title": "Modify Authentication Process: Hybrid Identity",
        "description": "Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts. Many organizations maintain hybrid user and device identities that are shared between on-premises and cloud-based environments. These can be maintained in a number of ways. For example, Microsoft Entra ID includes three options for synchronizing identities between Active Directory and Entra ID: Password Hash Synchronization (PHS), Pass Through Authentication (PTA), and Active Directory Federation Services (AD FS). AD FS can also be used with other SaaS and cloud platforms such as AWS and GCP. Adversaries who compromise on-premises servers running PTA agents or AD FS services may inject malicious DLLs to bypass authentication. Similarly, attackers with Global Administrator access to Entra ID may register rogue PTA agents to harvest credentials.",
        "tags": ["Credential Access", "Defense Evasion", "Persistence", "Hybrid Identity", "Cloud", "Azure AD", "Active Directory"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "IaaS, Identity Provider, Office Suite, SaaS, Windows",
        "tips": [
            "Monitor PTA agent registrations and AD FS configuration changes.",
            "Audit authentication patterns across on-prem and cloud infrastructure.",
            "Use baselining tools to detect new or modified DLLs in authentication services.",
            "Track privilege changes to Entra ID Global Administrators."
        ],
        "data_sources": "Application Log: Application Log Content, File: File Modification, Logon Session: Logon Session Creation, Module: Module Load",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Logon Session", "source": "", "destination": ""},
            {"type": "Module", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "DLL", "location": "C:\\Program Files\\Azure AD Connect Authentication Agent", "identify": "Injected PTA module"},
            {"type": "Config File", "location": "C:\\Program Files\\ADFS\\Microsoft.IdentityServer.Servicehost.exe.config", "identify": "Malicious AD FS claim injection"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Audit Entra ID PTA agent registration events",
            "Detect changes to AD FS configuration and injected modules",
            "Monitor DLL loads into AzureADConnectAuthenticationAgentService",
            "Alert on unapproved global admin actions in Azure AD"
        ],
        "apt": [
            "APT29",
            "UNC2452"
        ],
        "spl_query": [
            "`index=azure_audit sourcetype=entra_logs event_type=PTARegistration | stats count by actor, timestamp, source_ip`",
            "`index=windows_logs sourcetype=file_mod path=\\ADFS\\Microsoft.IdentityServer.Servicehost.exe.config | stats values(file_hash) by host, timestamp`"
        ],
        "hunt_steps": [
            "Review Entra ID audit logs for suspicious PTA agent additions",
            "Compare config file hashes of AD FS services across systems",
            "Correlate anomalous authentications with DLL load events",
            "Baseline and monitor all DLLs in AD authentication paths"
        ],
        "expected_outcomes": [
            "Identification of rogue PTA agents or modified AD FS tokens",
            "Detection of bypassed cloud identity enforcement paths"
        ],
        "false_positive": "Some authorized hybrid identity tools or updates may trigger similar behaviors. Correlate with change management logs.",
        "clearing_steps": [
            "Revoke unauthorized PTA agents in Entra ID",
            "Restore original AD FS config and clean rogue DLLs",
            "Review identity provider logs and reset compromised credentials"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-pta-faq",
            "https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-overview"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1556.007", "example": "Malicious PTA agent registered to accept all login requests bypassing identity provider enforcement."}
        ],
        "watchlist": [
            "Entra ID Global Admin accounts performing hybrid identity changes",
            "Unusual DLL loads into authentication services",
            "New PTA agents with external source IPs"
        ],
        "enhancements": [
            "Enable alerting on new PTA agent registrations",
            "Use File Integrity Monitoring on AD FS and PTA directories"
        ],
        "summary": "This technique targets the cloud-to-on-prem trust bridge for identity, enabling adversaries to maintain access by corrupting or hijacking hybrid identity services.",
        "remediation": "Restrict admin rights, apply FIM to hybrid auth paths, and enforce strict controls around PTA and AD FS components.",
        "improvements": "Deploy anomaly-based identity correlation tools to catch hybrid tampering and credential path deviation.",
        "mitre_version": "16.1"
    }
