def get_content():
    return {
        "id": "T1528",
        "url_id": "T1528",
        "title": "Steal Application Access Token",
        "description": "Adversaries may steal application access tokens to gain unauthorized access to cloud services, SaaS platforms, CI/CD tools, or container orchestration environments. These tokens often grant access to APIs and services on behalf of users or applications. Once stolen, tokens can allow adversaries to impersonate users, execute actions, and escalate privileges without needing passwords. Common sources of token theft include compromised containers, stolen service account files, OAuth phishing, or exploiting insecure storage of tokens within cloud services.",
        "tags": ["credential-access", "oauth", "cloud", "tokens", "T1528"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Containers, IaaS, Identity Provider, Office Suite, SaaS",
        "tips": [
            "Limit token scopes and durations to minimize impact if stolen.",
            "Apply CASB solutions to detect abnormal app authorization behavior.",
            "Enforce multi-factor authentication (MFA) and device compliance before granting app permissions."
        ],
        "data_sources": "User Account, Active Directory",
        "log_sources": [
            {"type": "User Account", "source": "User Account Modification", "destination": ""},
            {"type": "Active Directory", "source": "Active Directory Object Modification", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Token", "location": "Kubernetes ServiceAccount", "identify": "Token mounted in pod at `/var/run/secrets/kubernetes.io/serviceaccount/`"},
            {"type": "Phishing", "location": "OAuth Consent Screen", "identify": "Malicious app requesting excessive permissions"},
            {"type": "Logs", "location": "Cloud Identity Provider", "identify": "Unusual app registration or consent grant events"}
        ],
        "destination_artifacts": [
            {"type": "Audit Logs", "location": "Azure AD or GCP IAM Logs", "identify": "Suspicious app activity after token grant"},
            {"type": "Access Logs", "location": "API Gateway", "identify": "Access from unusual geolocation or IP using app tokens"},
            {"type": "CI/CD Logs", "location": "Pipeline Execution", "identify": "Unexpected token usage or access to secrets"}
        ],
        "detection_methods": [
            "Monitor OAuth and app consent grant events for over-permissioned or rarely-used apps.",
            "Alert on tokens accessing cloud resources from unusual IPs or device fingerprints.",
            "Track token issuance and expiration logs in identity providers (Azure, Okta, GCP)."
        ],
        "apt": [],
        "spl_query": [
            'index=azuread OR index=okta OR index=gcp_identity\n| search eventType="ConsentGranted" OR appDisplayName="*" scope="*"\n| stats count by user, appDisplayName, scope',
            'index=cloudtrail OR index=azure_activity\n| search eventName="AssumeRoleWithWebIdentity" OR eventName="GetAccessToken"',
            'index=container_logs OR index=kubernetes_audit\n| search objectRef.resource="secrets" AND verb="get"\n| stats count by user.username, sourceIPs'
        ],
        "hunt_steps": [
            "Identify newly authorized OAuth applications across cloud identity platforms.",
            "Check for service account tokens exposed in pods or filesystems.",
            "Review past 30 days of token activity for privilege escalation or role creation."
        ],
        "expected_outcomes": [
            "Discovery of stolen or over-permissioned access tokens.",
            "Identification of malicious app registrations or app consent grants.",
            "Mitigation of long-lived or refresh-enabled token persistence."
        ],
        "false_positive": "Some legitimate apps may request wide scopes; contextual review is required. Shared DevOps tokens may be reused frequently.",
        "clearing_steps": [
            "Revoke affected OAuth tokens and app authorizations from user and admin portals.",
            "Disable or rotate compromised service account credentials and tokens.",
            "Review app registration permissions and remove unnecessary delegated access."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1528", "example": "Token stolen from CI pipeline secret store or OAuth phishing"},
            {"tactic": "Initial Access", "technique": "T1566.002", "example": "Spearphishing link used to trick user into granting OAuth consent"},
            {"tactic": "Persistence", "technique": "T1550.001", "example": "Reuse of stolen token until expiration or token refresh"}
        ],
        "watchlist": [
            "OAuth apps with low user count and high privilege scopes",
            "New API tokens issued for long-inactive accounts",
            "Service accounts accessing sensitive resources with no recent job executions"
        ],
        "enhancements": [
            "Use conditional access policies based on device compliance or IP reputation.",
            "Implement token boundary protections (TTL, binding to IP/device).",
            "Require approval workflows for apps requesting high-risk permissions."
        ],
        "summary": "Application access tokens are critical cloud credentials. If stolen, adversaries can impersonate users or services to access data and perform actions. These tokens are commonly used in cloud-native environments and can be obtained via container compromise, CI/CD misuse, or OAuth phishing.",
        "remediation": "Revoke access tokens and refresh tokens. Audit and remove unnecessary app registrations. Rotate affected service accounts and implement scoped access.",
        "improvements": "Automate token lifecycle management and apply least privilege for token scopes. Monitor for high-risk app permissions and unusual token activity.",
        "mitre_version": "16.1"
    }
