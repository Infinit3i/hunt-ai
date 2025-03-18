def get_content():
    return {
        "id": "T1586.003",  # Tactic Technique ID
        "url_id": "1586/003",  # URL segment for technique reference
        "title": "Compromise Accounts: Cloud Accounts",  # Name of the attack technique
        "description": "Adversaries may compromise cloud accounts to further malicious operations, including using cloud services for exfiltration, infrastructure, or messaging platforms for spam and phishing.",
        "tags": [
            "resource-development",
            "cloud",
            "account-compromise"
        ],
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "N/A",  # Typically no single protocol for cloud account compromise
        "os": "N/A",  # Not specific to an operating system
        "tips": [
            "Enable multi-factor authentication (MFA) for all cloud accounts, including administrative and service accounts.",
            "Monitor cloud logs for unusual or suspicious login attempts, especially from unexpected geolocations.",
            "Regularly audit cloud service permissions and access policies to detect misconfigurations.",
            "Search for leaked credentials on dark web or breach data repositories to identify compromised accounts."
        ],
        "data_sources": "Cloud Service, Cloud Storage",
        "log_sources": [
            {
                "type": "Cloud Service",
                "source": "Azure AD Logs, AWS CloudTrail, GCP Cloud Audit Logs",
                "destination": "SIEM"
            },
            {
                "type": "Cloud Storage",
                "source": "Access Logs (e.g., S3 Access Logs, Azure Storage Analytics)",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Credentials",
                "location": "Cloud accounts (e.g., AWS, Azure, GCP, SaaS services)",
                "identify": "Stolen or purchased cloud credentials"
            },
            {
                "type": "Token",
                "location": "Cloud-based identity and access management (IAM)",
                "identify": "Compromised access tokens or API keys"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Service",
                "location": "Adversary-controlled or compromised cloud environment",
                "identify": "Cloud infrastructure used for malicious operations (e.g., serverless apps, VMs)"
            },
            {
                "type": "Storage",
                "location": "Cloud file repositories",
                "identify": "Buckets or containers used for exfiltration or hosting malicious files"
            }
        ],
        "detection_methods": [
            "Monitor for anomalous logins, such as impossible travel or unusual IP ranges in cloud logs",
            "Review newly created or modified access policies, API keys, and permissions within cloud environments",
            "Correlate suspicious cloud activity with known credential phishing or password spraying attempts",
            "Track usage of high-privilege or service provider accounts for unexpected administrative actions"
        ],
        "apt": [
            "APT29",
            "APT41",
            "Nobelium"
        ],
        "spl_query": [
            "index=cloud_logs (eventName=ConsoleLogin OR eventName=AssumeRole) user=* \n| stats count by user, sourceIPAddress \n| where count > 5"
        ],
        "hunt_steps": [
            "Collect and centralize cloud provider logs (AWS CloudTrail, Azure Activity Logs, GCP Audit Logs).",
            "Identify anomalous or high-volume login failures and successful logins from foreign IP addresses.",
            "Check for newly created or escalated privileges in IAM roles or service accounts.",
            "Correlate known phishing campaigns or stolen credentials with suspicious cloud activity."
        ],
        "expected_outcomes": [
            "Detection of compromised cloud accounts used for malicious activities like exfiltration, infrastructure hosting, or phishing.",
            "Early identification of suspicious privilege escalations or unauthorized access attempts.",
            "Comprehensive mapping of how adversaries leverage cloud accounts to further intrusion campaigns."
        ],
        "false_positive": "Legitimate use of shared or service accounts may trigger alerts if not properly baselined. Also, multinational logins from traveling staff can appear suspicious without context.",
        "clearing_steps": [
            "Reset compromised credentials, revoke sessions/tokens, and enforce MFA for impacted accounts.",
            "Audit and remove maliciously created cloud resources (e.g., serverless functions, S3 buckets, VMs).",
            "Update and tighten IAM policies to adhere to least privilege.",
            "Notify relevant stakeholders (e.g., cloud providers, internal teams) to investigate and remediate further."
        ],
        "mitre_mapping": [
            {
                "tactic": "Initial Access",
                "technique": "Phishing (T1566)",
                "example": "Adversaries may obtain cloud credentials via phishing to access victim environments."
            },
            {
                "tactic": "Privilege Escalation",
                "technique": "Steal Application Access Token (T1528)",
                "example": "Compromised tokens can be used to assume privileged roles in cloud environments."
            }
        ],
        "watchlist": [
            "Accounts performing actions outside normal business hours or from anomalous locations",
            "Rapid creation or modification of cloud resources in a short timeframe",
            "Frequent password reset or MFA bypass attempts"
        ],
        "enhancements": [
            "Enable conditional access policies that factor in device compliance, user risk, and location.",
            "Implement just-in-time access for privileged operations to reduce attack surface.",
            "Use automated detection rules to flag abnormal usage patterns in cloud accounts."
        ],
        "summary": "Compromising cloud accounts allows adversaries to abuse hosted services and infrastructure, enabling activities such as exfiltration, tool hosting, phishing, and lateral movement within cloud environments.",
        "remediation": "Implement strong identity protection (e.g., MFA, password policies, zero-trust principles), enforce least-privilege access, and continuously monitor cloud logs for signs of unauthorized activity.",
        "improvements": "Adopt comprehensive cloud security posture management solutions, integrate threat intelligence for cloud-based indicators, and train staff to recognize and report suspicious cloud activity."
    }
