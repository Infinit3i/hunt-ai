def get_content():
    return {
        "id": "T1615",
        "url_id": "T1615",
        "title": "Group Policy Discovery",
        "description": "Adversaries may enumerate Group Policy settings to understand the security posture, privilege structures, and behavior patterns within a domain. Group Policy Objects (GPOs) are stored in predictable paths such as `\\\\<DOMAIN>\\SYSVOL\\<DOMAIN>\\Policies\\`, and they control how user and computer configurations are applied across Active Directory environments. Tools like `gpresult`, `Get-DomainGPO`, and `Get-DomainGPOLocalGroup` can reveal configurations, group memberships, and local administrator setups that may present opportunities for lateral movement or privilege escalation.",
        "tags": ["Active Directory", "Group Policy", "enumeration", "gpresult", "PowerView", "PowerShell", "LDAP", "GPO", "reconnaissance"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for unexpected usage of `gpresult` from endpoints where it’s not regularly used.",
            "Review PowerShell activity involving domain enumeration scripts, especially those targeting GPO settings.",
            "Correlate LDAP queries for `groupPolicyContainer` objects with source host behavior."
        ],
        "data_sources": "Active Directory: Active Directory Object Access, Command: Command Execution, Network Traffic: Network Traffic Content, Process: Process Creation, Script: Script Execution",
        "log_sources": [
            {"type": "Active Directory", "source": "Windows Security Event Logs (4661, 4662)", "destination": "Domain Controllers"},
            {"type": "Command", "source": "Sysmon, PowerShell Logging", "destination": ""},
            {"type": "Network Traffic", "source": "LDAP monitoring tools, PCAP", "destination": "Domain Controllers"},
            {"type": "Process", "source": "Sysmon", "destination": ""},
            {"type": "Script", "source": "Script Block Logging", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Tool Use", "location": "Command Line", "identify": "gpresult /R, Get-DomainGPO, PowerView modules"},
            {"type": "LDAP Queries", "location": "Network Traffic", "identify": "groupPolicyContainer filters"},
            {"type": "Process Execution", "location": "Host", "identify": "cmd.exe or powershell.exe with GPO references"}
        ],
        "destination_artifacts": [
            {"type": "Policy Content Access", "location": "\\\\<DOMAIN>\\SYSVOL\\<DOMAIN>\\Policies", "identify": "XML or INI config reads"},
            {"type": "LDAP Response", "location": "DC Traffic Logs", "identify": "GPO metadata or security filtering information"}
        ],
        "detection_methods": [
            "Alert on gpresult or other enumeration tools executed by non-admin users.",
            "Monitor PowerShell functions related to GPO such as Get-DomainGPO.",
            "Detect abnormal LDAP traffic with GPO-related object class filters.",
            "Use Windows Event ID 4661 to track directory object access."
        ],
        "apt": [
            "APT29: Known to collect group policy and domain object data during reconnaissance.",
            "Turla: Observed reading GPOs to identify trust relationships and paths to elevate privileges.",
            "APT41: Used PowerView to enumerate Group Policy for lateral movement planning."
        ],
        "spl_query": "index=windows_logs sourcetype=XmlWinEventLog:Security EventCode=4661 \n| search ObjectType=\"groupPolicyContainer\" \n| stats count by Account_Name, ComputerName, ObjectName",
        "spl_rule": "https://research.splunk.com/detections/tactics/discovery/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1615",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1615",
        "hunt_steps": [
            "Hunt for execution of gpresult or PowerView modules across endpoints.",
            "Correlate domain controller access logs with non-standard user behavior.",
            "Identify accounts performing LDAP enumeration of `groupPolicyContainer` objects.",
            "Search for reconnaissance preceding privilege escalation or domain policy changes.",
            "Review any batch or scheduled jobs accessing SYSVOL policy files."
        ],
        "expected_outcomes": [
            "Identification of adversaries gathering policy information for further attacks.",
            "Early detection of potential privilege escalation paths.",
            "Correlated reconnaissance activity used in multi-stage campaigns."
        ],
        "false_positive": "System administrators may routinely use gpresult and GPO enumeration scripts during audits or compliance checks.",
        "clearing_steps": [
            "Revoke access to reconnaissance tools for non-administrative users.",
            "Implement application whitelisting to prevent unauthorized PowerShell usage.",
            "Audit and restrict LDAP filters capable of querying GPO metadata."
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1615 (Group Policy Discovery)", "example": "Use of PowerView to query domain GPOs to find local admin group modifications."}
        ],
        "watchlist": [
            "Monitor for GPO enumeration tools in use on endpoints.",
            "Alert on high-frequency or filtered LDAP queries from a single user or host.",
            "Track scripts that enumerate GPOs as part of credential or lateral movement patterns."
        ],
        "enhancements": [
            "Deploy LDAP honeypots to detect unauthorized GPO enumeration.",
            "Enable full PowerShell logging with deep script block analysis.",
            "Ingest and baseline Group Policy read-access logs from domain controllers."
        ],
        "summary": "Group Policy Discovery enables adversaries to understand AD security configurations and spot potential attack paths. By querying policy settings and domain group memberships, attackers can shape follow-up activity such as privilege escalation or GPO modification.",
        "remediation": "Restrict GPO enumeration to authorized accounts, enable LDAP filtering protections, and deploy behavior-based detection on common discovery tools.",
        "improvements": "Integrate GPO access with behavioral analytics and deploy deception assets that alert on unauthorized GPO browsing.",
        "mitre_version": "16.1"
    }
