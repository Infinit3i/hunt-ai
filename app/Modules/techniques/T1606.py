def get_content():
    return {
        "id": "T1606",
        "url_id": "T1606",
        "title": "Forge Web Credentials",
        "description": "Adversaries may forge credential materials such as session cookies, SAML tokens, or cloud access tokens to gain unauthorized access to web applications and services. Unlike techniques that involve stealing existing credentials ([T1539](https://attack.mitre.org/techniques/T1539), [T1528](https://attack.mitre.org/techniques/T1528)), this method involves crafting **new web credentials** using acquired secrets like private keys, passwords, or API access. \n\nWeb credential forging is especially dangerous when MFA is not enforced on session validation or if the forged tokens carry elevated privileges. Examples include forging tokens using `AssumeRole` in AWS or using Zimbra’s `zmprov gdpak` to impersonate any user in the domain.",
        "tags": ["forging", "web authentication", "bypass", "session", "cloud abuse"],
        "tactic": "Credential Access",
        "protocol": "HTTPS, SAML, OAuth",
        "os": "Windows, Linux, macOS, SaaS, IaaS, Office Suite, Identity Provider",
        "tips": [
            "Enforce strict validation of authentication tokens against recent login activity.",
            "Bind session cookies to IP address and device fingerprint.",
            "Set token expiration policies with re-authentication on privilege escalation."
        ],
        "data_sources": "Logon Session: Logon Session Creation, Web Credential: Web Credential Creation, Web Credential: Web Credential Usage",
        "log_sources": [
            {"type": "Authentication Logs", "source": "IAM or SSO Provider", "destination": "Cloud or On-prem App"},
            {"type": "Audit Logs", "source": "Web Service", "destination": "SIEM"},
            {"type": "Network Logs", "source": "Proxy or WAF", "destination": "Target SaaS Resource"}
        ],
        "source_artifacts": [
            {"type": "Private Key", "location": "Compromised Certificate Authority", "identify": "Used to sign forged SAML tokens"},
            {"type": "Session Schema", "location": "Source Code or Traffic Capture", "identify": "Used to recreate token structure"},
            {"type": "Cloud API Access", "location": "Stolen Credentials", "identify": "Used to generate temporary tokens"}
        ],
        "destination_artifacts": [
            {"type": "SAML Token", "location": "Identity Provider", "identify": "Used to impersonate federated user"},
            {"type": "Access Cookie", "location": "Web Browser", "identify": "Used to gain unauthorized app access"},
            {"type": "JWT", "location": "OAuth Provider", "identify": "Used to interact with cloud APIs"}
        ],
        "detection_methods": [
            "Compare session cookie and token usage with interactive logon events.",
            "Alert on usage of administrative tokens without recent credential input.",
            "Detect SAML usage from machines not configured as federation providers."
        ],
        "apt": [
            "UNC2452 (NOBELIUM): Used forged SAML tokens to persist access during the SolarWinds breach.",
            "APT29: Exploited federated trust and token replay methods in cloud environments.",
            "FIN12: Used token generation through malware to interact with cloud panels."
        ],
        "spl_query": "index=auth sourcetype=\"cloud:access\" \n| where method IN (\"cookie\", \"token\") \n| stats count by user, src_ip, method \n| where count > 10 and user IN [\"admin\", \"root\", \"superuser\"]",
        "spl_rule": "https://research.splunk.com/detections/credential-access/forged-web-token-usage/",
        "elastic_rule": "https://github.com/elastic/detection-rules/search?q=web+token+forge",
        "sigma_rule": "https://github.com/SigmaHQ/sigma/search?q=SAML+or+cookie",
        "hunt_steps": [
            "Search logs for session or token usage without preceding credential input.",
            "Check for abnormal issuer fields in SAML assertions.",
            "Investigate any long-lived tokens or tokens with excessive privileges."
        ],
        "expected_outcomes": [
            "Detection of token/cookie reuse or forging without matching login events.",
            "Identification of token usage from untrusted or foreign systems.",
            "Reveal elevated access using forged credentials across cloud environments."
        ],
        "false_positive": "Legitimate SSO integrations, testing tools, or identity federation setups may appear suspicious if misconfigured or overly verbose.",
        "clearing_steps": [
            "Revoke all session cookies and tokens across affected systems.",
            "Rotate signing certificates and secrets involved in web auth flows.",
            "Force re-authentication and logoff of all users with privileged access."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1606", "example": "SolarWinds incident involving forged SAML credentials"},
            {"tactic": "Credential Access", "technique": "T1606", "example": "AWS AssumeRole API used to obtain cloud session tokens"}
        ],
        "watchlist": [
            "SAML tokens with irregular timestamps or lifetimes",
            "Session cookies used across geographically disparate locations",
            "Logins with admin roles but no MFA token validation"
        ],
        "enhancements": [
            "Use certificate pinning and strong key rotation policies.",
            "Deploy Just-in-Time privilege elevation models to limit token abuse.",
            "Implement session behavioral analytics for authentication workflows."
        ],
        "summary": "Forging web credentials gives attackers unauthorized access to critical systems by creating valid-looking session materials. It enables lateral movement, persistence, and privilege escalation, especially when MFA or token validation checks are not robust.",
        "remediation": "Use hardware-backed secrets for signing, regularly rotate credentials, and enforce session validation with behavioral context.",
        "improvements": "Add layered session security controls, real-time anomaly detection, and cloud-native identity protection policies.",
        "mitre_version": "16.1"
    }
