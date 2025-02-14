def get_content():
    return {
        "id": "T1199",
        "url_id": "T1199",
        "title": "Trusted Relationship",
        "tactic": "Initial Access",
        "data_sources": "Authentication logs, Network traffic logs, System logs, Cloud service logs",
        "protocol": "Various",
        "os": "Windows, Linux, macOS, Cloud",
        "objective": "Detect and mitigate adversaries leveraging trusted relationships to gain unauthorized access to systems and data.",
        "scope": "Monitor authentication logs, privileged account access, and anomalous connections between organizations or services.",
        "threat_model": "Adversaries may exploit trusted relationships between organizations, partners, or cloud services to gain initial access to a target environment.",
        "hypothesis": [
            "Are there anomalous authentication attempts using partner or service accounts?",
            "Is there unauthorized access to privileged systems from third-party sources?",
            "Are trusted relationships being abused for lateral movement?"
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Active Directory, Azure AD, Okta, Ping Identity"},
            {"type": "Network Traffic Logs", "source": "Firewall, IDS/IPS, NetFlow, Zeek (Bro)"},
            {"type": "Cloud Service Logs", "source": "AWS CloudTrail, Google Cloud Audit, Azure Monitor"}
        ],
        "detection_methods": [
            "Monitor authentication events for unusual login attempts from third-party accounts.",
            "Detect abnormal access patterns to privileged resources via trusted relationships.",
            "Analyze network connections between organizations for anomalies in frequency, volume, or destinations."
        ],
        "spl_query": ["index=auth_logs sourcetype=auth_event event_type=login | stats count by user, source_ip, destination | where count > 10",],
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1199",
        "hunt_steps": [
            "Identify authentication attempts using third-party or service accounts.",
            "Correlate access events with known trusted relationships.",
            "Investigate anomalies in network traffic between organizations or services.",
            "Monitor for privilege escalation attempts via trusted relationships.",
            "Escalate suspicious activity to incident response for further analysis."
        ],
        "expected_outcomes": [
            "Detection of unauthorized access attempts via trusted relationships.",
            "Blocking or alerting on suspicious logins from third-party accounts.",
            "Improved monitoring of authentication events and privileged access."
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1199 (Trusted Relationship)", "example": "Attackers exploit inter-organizational trust to gain access."},
            {"tactic": "Persistence", "technique": "T1078 (Valid Accounts)", "example": "Adversaries use trusted accounts to maintain access."}
        ],
        "watchlist": [
            "Flag unauthorized authentication attempts from external partners.",
            "Monitor sudden privilege escalations from service accounts.",
            "Analyze deviations in network traffic between trusted entities."
        ],
        "enhancements": [
            "Implement MFA and conditional access policies for all trusted accounts.",
            "Restrict access privileges for service accounts to least privilege.",
            "Regularly audit and validate third-party access controls."
        ],
        "summary": "Monitor and detect adversaries leveraging trusted relationships for unauthorized access.",
        "remediation": "Restrict external authentication sources, enforce MFA, and monitor partner/service account activity.",
        "improvements": "Enhance logging and alerting for unusual activity in trusted accounts and relationships."
    }
