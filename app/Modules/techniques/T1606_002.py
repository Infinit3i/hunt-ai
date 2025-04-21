def get_content():
    return {
        "id": "T1606.002",
        "url_id": "T1606/002",
        "title": "Forge Web Credentials: SAML Tokens",
        "description": "An adversary may forge SAML tokens with arbitrary claims, permissions, and lifetimes if they gain access to a valid SAML token-signing certificate. These forged tokens allow authentication across services using SAML 2.0 as a Single Sign-On (SSO) mechanism. This differs from access token theft (e.g., T1528) because the tokens are fabricated from scratch, not stolen.\n\nForged tokens may be created using stolen [Private Keys](https://attack.mitre.org/techniques/T1552/004), or by establishing a malicious federation trust if the adversary has sufficient AD FS privileges. Forged SAML tokens can lead to [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550), bypassing multi-factor authentication (MFA) and granting persistent elevated access, especially if impersonating privileged Entra ID or Active Directory accounts.",
        "tags": ["saml", "token forgery", "identity abuse", "mfa bypass", "solarwinds"],
        "tactic": "Credential Access",
        "protocol": "SAML 2.0",
        "os": "Windows, SaaS, IaaS",
        "tips": [
            "Monitor SAML assertions for anomalies, such as unexpected issuers or tokens with extended lifetimes.",
            "Use certificate pinning or enhanced SAML validation for critical services.",
            "Alert on logins using SAML tokens with no preceding Kerberos events (e.g., 4769, 1200)."
        ],
        "data_sources": "Logon Session: Logon Session Creation, Logon Session Metadata, Process Creation, Web Credential Usage, User Account Authentication",
        "log_sources": [
            {"type": "Authentication Logs", "source": "AD FS", "destination": "Cloud Services"},
            {"type": "Web Server Logs", "source": "SAML Provider", "destination": "Application"},
            {"type": "SIEM", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Private Key", "location": "Compromised AD FS Server", "identify": "Used to forge valid SAML signatures"},
            {"type": "SAML Policy Config", "location": "Token Policy Store", "identify": "Modified for longer token lifetimes"},
            {"type": "Federation Trust", "location": "Identity Provider", "identify": "Adversary-controlled federation established"}
        ],
        "destination_artifacts": [
            {"type": "Forged Token", "location": "SAML Assertion", "identify": "Used to access multiple services with arbitrary roles"},
            {"type": "Service Provider Logs", "location": "Cloud/SaaS Applications", "identify": "Indicate token usage without Kerberos login"},
            {"type": "User Session", "location": "Cloud Account", "identify": "May show lateral movement via forged identity"}
        ],
        "detection_methods": [
            "Correlate authentication attempts using SAML with domain-side events (Kerberos, AD FS logs).",
            "Detect SAML assertions signed by unknown or unexpected certificate authorities.",
            "Look for anomalous roles or session lifetimes in SAML tokens used across cloud environments."
        ],
        "apt": [
            "UNC2452 (NOBELIUM): Used forged SAML tokens during SolarWinds intrusion.",
            "APT29: Leveraged token-signing certs for stealthy access to Azure and Microsoft 365.",
            "IRON RITUAL: Known for abuse of federated identity mechanisms including SAML."
        ],
        "spl_query": "index=auth sourcetype=\"azure:aad:signin\" \n| where authenticationProtocol=\"SAML\" AND NOT [search index=wineventlog EventCode IN (4769,1200,1202)] \n| stats count by user, appDisplayName, ipAddress",
        "spl_rule": "https://research.splunk.com/detections/credential-access/forged-saml-sso-detection/",
        "elastic_rule": "https://github.com/elastic/detection-rules/search?q=golden+saml",
        "sigma_rule": "https://github.com/SigmaHQ/sigma/search?q=golden+saml",
        "hunt_steps": [
            "Review all token-signing certs trusted by identity providers and their issuance paths.",
            "Search for login sessions using SAML that do not correlate with Kerberos authentication events.",
            "Inspect token lifetimes and NotOnOrAfter claims that exceed expected limits."
        ],
        "expected_outcomes": [
            "Discovery of forged token usage in multi-cloud environments.",
            "Identification of unauthorized access without credential reuse.",
            "Revealing impersonation of privileged accounts."
        ],
        "false_positive": "Custom SAML integrations or federated systems without corresponding Kerberos event logging may result in benign anomalies.",
        "clearing_steps": [
            "Revoke or rotate compromised token-signing certificates.",
            "Audit and remove unauthorized federation trusts.",
            "Force logout and reset affected accounts and services."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1606.002", "example": "UNC2452 forged SAML tokens during SolarWinds attack to access Azure/M365 resources"}
        ],
        "watchlist": [
            "SAML tokens from external AD FS providers with long validity durations",
            "Cloud sessions authenticated via SAML without recent login history",
            "SSO traffic from unknown or suspicious source IPs"
        ],
        "enhancements": [
            "Deploy SAML anomaly detection using token issuer validation and session telemetry.",
            "Limit the trusted certificate authorities for SAML tokens in cloud identity configurations.",
            "Log and review all certificate changes and federation trust modifications in identity infrastructure."
        ],
        "summary": "Forging SAML tokens allows attackers to impersonate users, including admins, across multiple services without triggering MFA. This provides long-term, covert access especially if certificates are compromised.",
        "remediation": "Rotate and audit SAML signing certificates. Implement strict monitoring of token issuance and authentication paths. Segment identity federation trust configurations.",
        "improvements": "Apply conditional access policies that require context-aware checks even when SAML is used. Utilize behavioral analytics to baseline token usage patterns.",
        "mitre_version": "16.1"
    }
