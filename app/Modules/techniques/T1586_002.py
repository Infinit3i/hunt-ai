def get_content():
    return {
        "id": "T1586.002",
        "url_id": "1586/002",
        "title": "Compromise Accounts: Email Accounts",
        "description": "Adversaries may compromise email accounts that can be used during targeting. Adversaries can use compromised email accounts to further their operations, such as leveraging them to conduct 'Phishing for Information', 'Phishing', or large-scale spam email campaigns. Using an existing persona with a compromised email account can engender a level of trust in a potential victim if they have a relationship with, or knowledge of, the compromised persona. Compromised email accounts can also be used in the acquisition of infrastructure (e.g., Domains). A variety of methods exist for compromising email accounts, such as gathering credentials via 'Phishing for Information', purchasing credentials from third-party sites, brute forcing credentials (e.g., password reuse from breach credential dumps), or paying employees, suppliers, or business partners for access to credentials. Prior to compromising email accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise. Adversaries may also target well-known email accounts or domains to bypass reputation-based email filtering rules. Once an email account is compromised, adversaries can hijack existing email threads with targets of interest.",
        "tags": [
            "resource-development",
            "email-compromise",
            "phishing"
        ],
        "tactic": "Resource Development",
        "protocol": "N/A",
        "os": "N/A",
        "tips": [
            "Enable multi-factor authentication (MFA) on all email accounts to reduce unauthorized access risk.",
            "Monitor for unusual or suspicious login attempts (e.g., impossible travel, unknown IP addresses).",
            "Regularly audit and review mailbox forwarding rules that could exfiltrate messages to external accounts.",
            "Search for compromised credentials in known breach data and dark web marketplaces."
        ],
        "data_sources": "Persona, Email, Network Traffic",
        "log_sources": [
            {
                "type": "Persona",
                "source": "Social Media or Brand Monitoring Platforms",
                "destination": "SIEM"
            },
            {
                "type": "Email",
                "source": "Mail Server or Cloud Email Provider Logs (e.g., O365 Audit Logs)",
                "destination": "SIEM"
            },
            {
                "type": "Network Traffic",
                "source": "Inbound/Outbound Traffic Logs",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Credentials",
                "location": "Email accounts (corporate or webmail)",
                "identify": "Stolen or purchased username/password combos"
            },
            {
                "type": "Persona",
                "location": "Hijacked email user identity",
                "identify": "Compromised or impersonated email account"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Email",
                "location": "Compromised or newly created inbox",
                "identify": "Used for spam, phishing, or command and control"
            },
            {
                "type": "Infrastructure",
                "location": "Domains or servers registered using compromised email",
                "identify": "Malicious infrastructure or hosting set up with stolen credentials"
            }
        ],
        "detection_methods": [
            "Analyze email server logs for anomalous logins or mailbox forwarding rule changes",
            "Monitor high-volume or high-frequency outbound emails that deviate from normal patterns",
            "Correlate newly compromised accounts with known data breaches or phishing campaigns",
            "Check for unusual patterns in email thread hijacking or replies to older email chains"
        ],
        "apt": [
            "APT29",
            "Kimsuky",
            "APT40",
            "DEV-0537",
            "IndigoZebra"
        ],
        "spl_query": [
            "index=email_logs (event=\"login_attempt\" OR event=\"mail_forward_rule\") \n| stats count by user, src_ip \n| where count > 5"
        ],
        "hunt_steps": [
            "Collect and centralize email login and access logs from all mail providers in SIEM.",
            "Search for abnormal geolocations or IP addresses associated with email logins.",
            "Identify newly created mailbox rules or suspicious auto-forwarding configurations.",
            "Correlate known phishing or data breach events with suspicious email account usage."
        ],
        "expected_outcomes": [
            "Identification of compromised email accounts used for spam or phishing attacks.",
            "Detection of suspicious login attempts and mailbox configuration changes.",
            "Reduced risk of domain or brand damage by catching impersonation attempts early."
        ],
        "false_positive": "Legitimate email forwarding and user travel can mimic malicious patterns; proper baselining is needed.",
        "clearing_steps": [
            "Reset compromised email account passwords and revoke active sessions or tokens.",
            "Remove malicious forwarding rules and review mailbox permissions for anomalies.",
            "Notify affected individuals or departments and enforce stronger authentication controls.",
            "Disable or suspend compromised email accounts if necessary to contain damage."
        ],
        "mitre_mapping": [
            {
                "tactic": "Initial Access",
                "technique": "Phishing (T1566)",
                "example": "Adversaries may use compromised email accounts to send phishing messages."
            },
            {
                "tactic": "Collection",
                "technique": "Phishing for Information (T1598)",
                "example": "Compromised email accounts can be used to gather sensitive data from targets."
            }
        ],
        "watchlist": [
            "Email accounts sending large volumes of outbound messages in a short period",
            "Suspicious changes to email inbox rules (e.g., auto-forward, redirect, deletion)",
            "Unusual login patterns (e.g., repeated password reset attempts, new device sign-ins)"
        ],
        "enhancements": [
            "Implement advanced spam/phishing filters and domain-based message authentication (DMARC, DKIM, SPF).",
            "Use machine learning to detect anomalies in email behavior and user login locations.",
            "Enable conditional access policies that limit sign-in based on risk level or device compliance."
        ],
        "summary": "Compromised email accounts enable adversaries to leverage trusted identities for phishing, spam, or infrastructure setup, often bypassing reputation-based security controls.",
        "remediation": "Reset compromised account credentials, remove malicious forwarding rules, enforce MFA, and educate users on recognizing suspicious email behaviors.",
        "improvements": "Adopt continuous monitoring of email account usage, integrate threat intelligence for compromised credentials, and enforce least privilege and separation of duties for email administration."
    }
