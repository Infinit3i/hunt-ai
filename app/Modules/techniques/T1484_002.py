def get_content():
    return {
        "id": "T1484.002",
        "url_id": "T1484/002",
        "title": "Domain or Tenant Policy Modification: Trust Modification",
        "description": "Adversaries may add new domain trusts, modify the properties of existing domain trusts, or otherwise change the configuration of trust relationships between domains and tenants to evade defenses and/or elevate privileges.",
        "tags": [
            "t1484.002", "domain or tenant policy modification", "trust modification", "defense evasion", "privilege escalation", "windows", "identity provider"
        ],
        "tactic": "Defense Evasion, Privilege Escalation",
        "protocol": "Identity Provider, Windows",
        "os": "Windows",
        "tips": [
            "Monitor federation changes using audit logs such as Event ID 307 and 510.",
            "Audit PowerShell commands like Update-MSOLFederatedDomain for unexpected domain modifications.",
            "Correlate domain trust changes with new identity provider activity."
        ],
        "data_sources": "Active Directory: Active Directory Object Creation, Active Directory: Active Directory Object Modification, Application Log: Application Log Content, Command: Command Execution",
        "log_sources": [
            {"type": "Event Log", "source": "Application", "destination": "SIEM"},
            {"type": "Command Line", "source": "PowerShell", "destination": "Security Monitoring"}
        ],
        "source_artifacts": [
            {"type": "PowerShell Command", "location": "Update-MSOLFederatedDomain", "identify": "Federation Change Activity"},
            {"type": "Event Log", "location": "Event ID 307", "identify": "Federation Settings Modified"}
        ],
        "destination_artifacts": [
            {"type": "Federation Config", "location": "Tenant or Domain Federation Settings", "identify": "Malicious Trust Modification"}
        ],
        "detection_methods": [
            "Analyze domain federation changes through audit logs.",
            "Detect new or modified federated identity providers.",
            "Monitor PowerShell and cloud provider CLI usage to update trust configs."
        ],
        "apt": ["IRON RITUAL", "Scattered Spider", "UNC2452", "APT29"],
        "spl_query": [
            "index=wineventlog EventCode=307 OR EventCode=510",
            "index=commandline command=*Update-MSOLFederatedDomain*"
        ],
        "hunt_steps": [
            "List recent trust changes in Active Directory Federation Services or Azure AD.",
            "Look for newly added identity providers or federation relationships.",
            "Correlate with account activity or lateral movement attempts."
        ],
        "expected_outcomes": [
            "Detection of unauthorized domain or tenant trust changes.",
            "Identification of malicious federation relationships."
        ],
        "false_positive": "Legitimate federation or trust reconfiguration by domain admins during integrations or migrations.",
        "clearing_steps": [
            "Revert unauthorized federation or trust changes using administrative tools.",
            "Remove malicious identity providers and rotate federation credentials."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1484", "example": "Modifying trust relationships to bypass security policies"},
            {"tactic": "Privilege Escalation", "technique": "T1484", "example": "Federated identity spoofing via rogue provider"}
        ],
        "watchlist": [
            "Alert on Update-MSOLFederatedDomain usage outside of change windows.",
            "Monitor additions to federation settings or identity providers."
        ],
        "enhancements": [
            "Enable auditing for all changes to federation and trust settings.",
            "Use conditional access and MFA to harden federated domains."
        ],
        "summary": "Adversaries may abuse trust relationships to escalate privileges or bypass defenses by modifying domain or tenant policies.",
        "remediation": "Audit and restrict who can modify federation and trust settings. Use change control policies.",
        "improvements": "Continuously monitor trust configs and use anomaly detection for sudden changes."
    }