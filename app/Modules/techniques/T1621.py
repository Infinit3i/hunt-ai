def get_content():
    return {
        "id": "T1621",
        "url_id": "T1621",
        "title": "Multi-Factor Authentication Request Generation",
        "description": "Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms by triggering repeated authentication requests, typically via push notifications. This tactic, known as 'MFA fatigue', involves bombarding the user with login prompts until the user unintentionally or mistakenly approves the request. In addition to deliberate misuse of stolen credentials, adversaries may exploit self-service password reset (SSPR) features to trigger MFA requests.",
        "tags": ["MFA fatigue", "SSPR abuse", "Duo", "Okta", "Microsoft Authenticator", "Credential Access", "Valid Accounts", "push notification abuse"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Monitor high-frequency MFA push notifications.",
            "Correlate IP geolocation between login source and MFA request receiver.",
            "Review accounts with frequent failed authentication attempts followed by successful logins."
        ],
        "data_sources": "Application Log: Application Log Content, Logon Session: Logon Session Creation, Logon Session: Logon Session Metadata, User Account: User Account Authentication",
        "log_sources": [
            {"type": "Application Log", "source": "Azure AD, Duo Admin Panel, Okta Logs", "destination": ""},
            {"type": "Logon Session", "source": "SSO providers, IAM system logs", "destination": ""},
            {"type": "User Account", "source": "Authentication event logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Login Attempts", "location": "Authentication Systems", "identify": "Repeated login failures with valid usernames"},
            {"type": "MFA Requests", "location": "Push Notification Logs", "identify": "High-frequency notifications sent to end-user"},
            {"type": "SSPR Invocation", "location": "Identity Provider", "identify": "Triggering reset flows causing MFA generation"}
        ],
        "destination_artifacts": [
            {"type": "Approved Access", "location": "User Account Sessions", "identify": "Successful login following flood of MFA attempts"},
            {"type": "Modified Credentials", "location": "SSPR Endpoint", "identify": "Password reset linked to excessive MFA prompt activity"}
        ],
        "detection_methods": [
            "Detect login attempts generating a high number of MFA prompts in a short period.",
            "Flag mismatched geographic locations between login origin and MFA recipient.",
            "Alert when MFA requests are approved rapidly after multiple denied requests."
        ],
        "apt": [
            "Scattered Spider: Reported to have used MFA fatigue against enterprise targets.",
            "APT29: Suspected in multiple attacks leveraging this tactic to bypass MFA protections."
        ],
        "spl_query": "index=auth_logs sourcetype=mfa_logs \n| stats count by user, mfa_type, status, src_ip \n| where count > 10 AND status=\"denied\"",
        "spl_rule": "https://research.splunk.com/detections/tactics/credential-access/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1621",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1621",
        "hunt_steps": [
            "Review accounts with over 5 MFA attempts in a short time window.",
            "Cross-check IP origin of login with geolocation of MFA recipient’s device.",
            "Investigate SSPR logs for repeated abuse patterns.",
            "Query for users with frequent password resets followed by MFA prompts."
        ],
        "expected_outcomes": [
            "Identification of adversary attempts to bypass MFA via fatigue or SSPR abuse.",
            "Suspicious login patterns associated with brute-force MFA abuse.",
            "Reinforced MFA configurations to block repeat push attempts."
        ],
        "false_positive": "Employees traveling or working remotely may exhibit geolocation mismatches. Legitimate users may repeatedly request push notifications if facing issues logging in.",
        "clearing_steps": [
            "Revoke user sessions and reset credentials for affected accounts.",
            "Require re-enrollment in MFA with strict geo-based access controls.",
            "Audit SSPR settings and restrict its abuse by limiting self-service triggers."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1621 (Multi-Factor Authentication Request Generation)", "example": "Repeated MFA push notifications used to induce user approval via fatigue."}
        ],
        "watchlist": [
            "Flag accounts with high MFA denial rates followed by approval.",
            "Monitor for sudden spikes in SSPR requests.",
            "Track devices that frequently approve MFA across varied geolocations."
        ],
        "enhancements": [
            "Rate-limit MFA prompt retries.",
            "Implement MFA based on user behavior risk scoring.",
            "Incorporate user training on MFA fatigue and phishing resistance."
        ],
        "summary": "T1621 involves generating excessive MFA prompts to trick or fatigue users into approving access. This method circumvents MFA protections by manipulating human behavior rather than technical vulnerabilities.",
        "remediation": "Temporarily disable affected accounts, rotate credentials, and review SSPR configurations. Enforce stronger MFA mechanisms such as FIDO2 or biometric auth.",
        "improvements": "Adopt adaptive MFA policies, limit push frequency, and integrate conditional access with risk-based evaluations.",
        "mitre_version": "16.1"
    }
