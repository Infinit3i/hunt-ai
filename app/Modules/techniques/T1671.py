def get_content():
    return {
        "id": "T1671",
        "url_id": "T1671",
        "title": "Cloud Application Integration",
        "description": "Adversaries may leverage OAuth-based integrations with cloud applications to maintain persistent access to a target environment, potentially bypassing MFA or surviving account revocation.",
        "tags": ["persistence", "oauth", "cloud", "m365", "integration", "token abuse", "service principal"],
        "tactic": "persistence",
        "protocol": "OAuth",
        "os": "Office Suite, SaaS",
        "tips": [
            "Review consented SaaS integrations frequently for unexpected or suspicious apps.",
            "Restrict users from self-consenting to applications via policy (e.g., Entra ID).",
            "Investigate audit logs for repeated app role assignments or excessive token activity."
        ],
        "data_sources": "Active Directory, Cloud Service",
        "log_sources": [
            {"type": "Active Directory", "source": "", "destination": ""},
            {"type": "Cloud Service", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "OAuth Grants", "location": "Entra ID or Google Workspace", "identify": "Suspicious apps with broad delegated permissions"}
        ],
        "destination_artifacts": [
            {"type": "Service Principal", "location": "AzureAD/M365 Portal", "identify": "Persistent apps with access after account removal"}
        ],
        "detection_methods": [
            "Monitor for app role assignment grants and OAuth consent events in M365/Azure logs.",
            "Watch for creation of service principals with mail.read, mail.send, files.read permissions.",
            "Alert on integrations created by unusual user agents or IPs."
        ],
        "apt": [],
        "spl_query": [
            "index=m365_audit sourcetype=azuread_audit(Operation=\"Consent to application\" OR Operation=\"Add app role assignment grant to user\")\n| stats count by UserId, AppDisplayName, AppId, Operation, _time",
            "sourcetype=azuread signin_logs(AppId!=\"known_apps\")\n| stats values(UserPrincipalName) by AppDisplayName, AppId, IPAddress, _time\n| where AppDisplayName IN (\"Unknown\", \"Custom OAuth Client\")",
            "index=cloud_integration_logs event_type=\"app_added\" OR event_type=\"app_permission_changed\"\n| stats count by application_name, added_by, permissions, _time"
        ],
        "hunt_steps": [
            "List all OAuth-integrated apps and identify overly permissive scopes.",
            "Cross-reference service principals with last user login or status (disabled/deleted).",
            "Detect OAuth tokens used from anomalous IPs or regions."
        ],
        "expected_outcomes": [
            "Detection of unauthorized or persistent OAuth applications used to maintain access in cloud environments."
        ],
        "false_positive": "Legitimate workflow automation platforms (Zapier, PowerAutomate, etc.) may show similar behaviors but should be validated against business context.",
        "clearing_steps": [
            "Revoke all OAuth grants issued to suspicious applications.",
            "Delete associated service principals from cloud identity platform.",
            "Audit and update tenant-level app consent settings."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-oauth-apps"
        ],
        "mitre_mapping": [
            {"tactic": "persistence", "technique": "T1671", "example": "Cloud Application Integration"},
            {"tactic": "defense-evasion", "technique": "T1550.001", "example": "Application Access Token Abuse"}
        ],
        "watchlist": [
            "App grants from privileged accounts",
            "OAuth clients with persistent token activity post-user deactivation"
        ],
        "enhancements": [
            "Enable admin consent workflows for app integrations.",
            "Correlate app sign-ins with geolocation and device posture."
        ],
        "summary": "Cloud Application Integration enables adversaries to maintain persistent access through OAuth tokens and service principals, even after account revocation or MFA enforcement.",
        "remediation": "Restrict user app consent, require admin approval, and review all third-party cloud integrations regularly.",
        "improvements": "Automate revocation of OAuth grants upon account disablement or suspicious app detection.",
        "mitre_version": "17.0"
    }