def get_content():
    return {
        "id": "T1550.001",
        "url_id": "T1550/001",
        "title": "Use Alternate Authentication Material: Application Access Token",
        "tactic": "Lateral Movement",
        "data_sources": "Process Creation Logs, Authentication Logs, Security Monitoring Tools, Memory Analysis",
        "protocol": "Windows API, OAuth, SAML, Kerberos",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries leveraging stolen application access tokens to move laterally and gain unauthorized access to cloud services or on-premise environments.",
        "scope": "Identify unauthorized token-based authentication attempts, abuse of cloud access tokens, and process injection leveraging stolen tokens.",
        "threat_model": "Adversaries steal and use access tokens from applications, cloud services, or authentication protocols to impersonate legitimate users and bypass authentication mechanisms for lateral movement.",
        "hypothesis": [
            "Are there unauthorized authentication attempts using stolen access tokens?",
            "Are adversaries leveraging access token manipulation to move laterally?",
            "Is there an increase in token-based authentication failures or anomalies?"
        ],
        "log_sources": [
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs (Event ID 4688)"},
            {"type": "Authentication Logs", "source": "Azure AD Sign-In Logs, Okta Logs, Windows Event Logs (Event ID 4624, 4769)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Memory Analysis", "source": "Volatility, Rekall, Process Hacker"}
        ],
        "detection_methods": [
            "Monitor for authentication attempts using access tokens outside normal user behavior.",
            "Detect process injection or token impersonation techniques.",
            "Identify unauthorized API calls using stolen or replayed tokens."
        ],
        "spl_query": [
            "index=auth_logs sourcetype=windows_security OR sourcetype=cloud_authentication \n| search event_id=4624 OR event_id=4769 \n| stats count by src_ip, dest_ip, user, authentication_method"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify authentication anomalies involving access tokens.",
            "Analyze Process Creation Logs: Detect unusual token-based authentication attempts.",
            "Monitor for Cloud-Based Attacks: Identify unauthorized API calls with stolen tokens.",
            "Correlate with Threat Intelligence: Compare with known adversary tactics leveraging token theft.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Application Access Token Abuse Detected: Block unauthorized access and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for token-based lateral movement techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1550.001 (Use Alternate Authentication Material: Application Access Token)", "example": "Adversaries using stolen OAuth tokens to authenticate into cloud services."},
            {"tactic": "Credential Access", "technique": "T1528 (Steal Application Access Token)", "example": "Attackers extracting SAML or OAuth tokens to bypass authentication."}
        ],
        "watchlist": [
            "Flag authentication attempts using stolen or replayed tokens.",
            "Monitor for anomalies in token usage across cloud and on-prem environments.",
            "Detect unauthorized modifications of authentication tokens in memory."
        ],
        "enhancements": [
            "Deploy anomaly-based detection for access token abuse.",
            "Implement token expiration and rotation policies to reduce risk.",
            "Improve correlation between token-based attacks and known threat actor techniques."
        ],
        "summary": "Document detected malicious access token abuse and affected systems.",
        "remediation": "Revoke compromised tokens, enforce multi-factor authentication, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of access token-based lateral movement techniques."
    }
