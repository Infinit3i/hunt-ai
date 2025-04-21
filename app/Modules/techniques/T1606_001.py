def get_content():
    return {
        "id": "T1606.001",
        "url_id": "T1606/001",
        "title": "Forge Web Credentials: Web Cookies",
        "description": "Adversaries may forge web cookies in order to gain unauthorized access to web applications and services. Unlike [T1539](https://attack.mitre.org/techniques/T1539) where session cookies are stolen, this technique involves **creating new cookies** by forging valid structures using secret signing materials or known configurations.\n\nForged cookies can grant access to systems that rely on them for authentication or session validation. These attacks typically exploit weaknesses in session management, use predictable signing methods, or abuse access to secret values such as [Private Keys](https://attack.mitre.org/techniques/T1552/004). If Multi-Factor Authentication (MFA) is not properly enforced at the cookie validation stage, adversaries may completely bypass security controls.",
        "tags": ["web credential", "cookie forging", "session hijack", "auth bypass", "pass the cookie"],
        "tactic": "Credential Access",
        "protocol": "HTTPS, HTTP",
        "os": "Linux, Windows, macOS, SaaS, IaaS",
        "tips": [
            "Monitor for multiple concurrent sessions from different IPs or devices using the same account.",
            "Use cryptographically strong and unpredictable cookie signing algorithms.",
            "Enforce MFA validation on every authentication-sensitive request, not just login."
        ],
        "data_sources": "Logon Session: Logon Session Creation, Web Credential Usage",
        "log_sources": [
            {"type": "Web Server Logs", "source": "Application Gateway", "destination": "App Backend"},
            {"type": "Authentication Logs", "source": "Cloud IAM", "destination": "SaaS Service"},
            {"type": "Endpoint Detection", "source": "User Machine", "destination": "Web Resource"}
        ],
        "source_artifacts": [
            {"type": "Private Key", "location": "Signing Authority", "identify": "Used to create HMAC-signed cookie"},
            {"type": "Cookie Template", "location": "Developer Docs or Memory Dump", "identify": "Used to format cookie structure"},
            {"type": "User Identifier", "location": "Harvested User Data", "identify": "Used to simulate valid session"}
        ],
        "destination_artifacts": [
            {"type": "Forged Cookie", "location": "Web Application", "identify": "Used to impersonate a user"},
            {"type": "Access Token", "location": "Cloud Session", "identify": "Derived from a forged session cookie"},
            {"type": "Log Entry", "location": "IAM Audit Logs", "identify": "Contains access without interactive login"}
        ],
        "detection_methods": [
            "Monitor for unusual or geographically improbable access using session cookies.",
            "Check for web sessions with valid cookies that bypassed login events.",
            "Alert on excessive usage of short-lived cookies from unfamiliar systems."
        ],
        "apt": [
            "UNC2452 (NOBELIUM): Leveraged forged cookies in SolarWinds intrusion.",
            "APT29: Known to abuse session manipulation for persistence in Microsoft 365 environments.",
            "Threat groups exploiting OAuth or session replay techniques may use forged cookies."
        ],
        "spl_query": "index=web sourcetype=\"cloud:auth\" \n| where userAgent IN (\"Firefox\", \"Chrome\", \"curl\") AND authenticationStep=\"cookie_only\" \n| stats count by user, src_ip, userAgent \n| where count > 1",
        "spl_rule": "https://research.splunk.com/detections/credential-access/forged-session-cookie-use/",
        "elastic_rule": "https://github.com/elastic/detection-rules/search?q=forged+cookie",
        "sigma_rule": "https://github.com/SigmaHQ/sigma/search?q=session+cookie",
        "hunt_steps": [
            "Identify active sessions using cookies without a preceding interactive login.",
            "Correlate session creation times and devices for anomalies or inconsistencies.",
            "Check for cookies referencing non-existent users or expired sessions."
        ],
        "expected_outcomes": [
            "Detection of unauthorized access through fabricated session tokens.",
            "Uncovering impersonation of legitimate users in web apps or cloud portals.",
            "Discovery of cookie abuse even in MFA-protected environments."
        ],
        "false_positive": "Third-party SSO solutions or proxy tools that replay valid cookies might trigger similar behavior under legitimate usage.",
        "clearing_steps": [
            "Revoke all active sessions and regenerate signing keys.",
            "Invalidate browser cookies via logout policies or global session expiration.",
            "Audit access logs and compare against legitimate login flows."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1606.001", "example": "UNC2452 used forged cookies to impersonate users in SaaS services"}
        ],
        "watchlist": [
            "Session cookie usage from unexpected IP addresses",
            "Access without login activity (no 'logon' events)",
            "Use of legacy or undocumented cookie formats"
        ],
        "enhancements": [
            "Implement cryptographic binding of sessions to IP/user agents.",
            "Require re-authentication for high-privilege functions even with valid sessions.",
            "Set short expiration lifetimes for session cookies and audit renewal logic."
        ],
        "summary": "Forging session cookies can allow threat actors to impersonate users and bypass authentication controls, especially in web/cloud environments where cookies are trusted without re-verification. Attackers need access to signing secrets or predictable structures to execute this technique.",
        "remediation": "Rotate session signing secrets regularly, enforce re-validation of session tokens, and implement anomaly-based session monitoring.",
        "improvements": "Introduce behavioral validation checks during session token usage, such as device fingerprinting or TLS channel binding.",
        "mitre_version": "16.1"
    }
