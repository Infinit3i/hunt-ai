def get_content():
    return {
        "id": "T1550.004",
        "url_id": "T1550/004",
        "title": "Use Alternate Authentication Material: Web Session Cookie",
        "tactic": "Defense Evasion, Lateral Movement",
        "data_sources": "Application Log: Application Log Content, Web Credential: Web Credential Usage",
        "protocol": "HTTPS",
        "os": "IaaS, Office Suite, SaaS",
        "objective": "Detect and mitigate adversaries abusing stolen web session cookies to impersonate users and bypass authentication mechanisms.",
        "scope": "Identify usage of hijacked session cookies across cloud services or web apps by unauthorized hosts or locations.",
        "threat_model": "Adversaries leverage stolen or harvested session cookies to impersonate authenticated users without triggering MFA challenges.",
        "hypothesis": [
            "Are stolen session cookies being used from locations atypical for the user?",
            "Are multiple logins observed with the same session cookie from different IPs?",
            "Is there anomalous access to sensitive web applications without fresh authentication?"
        ],
        "log_sources": [
            {"type": "Application Log", "source": "Cloud Provider Access Logs (e.g., Google Workspace, Microsoft 365)", "destination": "SIEM"},
            {"type": "Web Credential", "source": "Web Server Logs and Authentication Middleware", "destination": "SIEM or Log Aggregator"}
        ],
        "detection_methods": [
            "Monitor web logs for reused session tokens from disparate geographic locations.",
            "Analyze cookie usage across sessions for anomalies in user-agent, IP, or time intervals.",
            "Alert on login activity that bypasses MFA yet results in elevated privilege access."
        ],
        "spl_query": [
            "index=cloud_logs sourcetype=web_authentication_logs \n| search event_type=login session_cookie_exists=true \n| stats dc(src_ip) as unique_ips by session_cookie, user \n| where unique_ips > 1"
        ],
        "hunt_steps": [
            "Identify all authentication events using session cookies.",
            "Cross-reference session activity with user device fingerprints and IP geolocation.",
            "Search for web requests that access privileged resources shortly after cookie-based login.",
            "Isolate accounts that exhibit access without corresponding MFA or login prompts.",
            "Notify Incident Response team for confirmed suspicious cookie usage."
        ],
        "expected_outcomes": [
            "Detection of session hijacking using valid cookies.",
            "Alert generation for user impersonation via session tokens.",
            "Improved monitoring around cloud account access vectors."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1539 (Steal Web Session Cookie)", "example": "Harvested session cookie reused for unauthorized login."},
            {"tactic": "Initial Access", "technique": "T1078 (Valid Accounts)", "example": "Used session token without triggering password prompt."},
            {"tactic": "Defense Evasion", "technique": "T1036.005 (Match Legitimate Name or Location)", "example": "Used hijacked session from a host mimicking valid browser headers."}
        ],
        "watchlist": [
            "Session tokens used from more than one geographic region in a short time window.",
            "Logins missing user-agent or other fingerprinting data.",
            "Unusual IP behavior tied to consistent session cookies."
        ],
        "enhancements": [
            "Enable IP anomaly detection on cookie-based sessions.",
            "Implement short session expiry policies.",
            "Integrate cookie binding with device/user fingerprinting."
        ],
        "summary": "Adversaries can hijack authenticated web sessions using stolen cookies to impersonate users and bypass MFA, often without triggering detection.",
        "remediation": "Revoke all active sessions, enforce reauthentication for critical web apps, and rotate authentication tokens immediately.",
        "improvements": "Implement strict session management policies and cookie usage monitoring tied to behavioral baselines.",
        "mitre_version": "16.1"
    }
