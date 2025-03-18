def get_content():
    return {
        "id": "T1586",  # Tactic Technique ID
        "url_id": "1586",  # URL segment for technique reference
        "title": "Compromise Accounts",  # Name of the attack technique
        "description": "Adversaries may compromise existing accounts to facilitate social engineering or other malicious activities. Using compromised personas can engender trust with potential victims or provide access to restricted services.",  # Simple description
        "tags": [
            "resource-development",
            "account-compromise",
            "persona"
        ],
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "N/A",  # Not tied to a specific protocol
        "os": "N/A",  # Not specific to an operating system
        "tips": [
            "Enable multi-factor authentication (MFA) on all critical accounts to reduce the risk of unauthorized access.",
            "Monitor for unusual or suspicious login attempts (e.g., impossible travel, unusual IP ranges).",
            "Leverage brand protection or social media monitoring services to detect impersonation or suspicious persona changes.",
            "Regularly check for leaked credentials in public breach data or on the dark web."
        ],
        "data_sources": "Persona: Social Media, Network Traffic: Network Traffic Content",
        "log_sources": [
            {
                "type": "Persona",
                "source": "Social Media or Brand Monitoring Platforms",
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
                "location": "Compromised accounts (email, social media, etc.)",
                "identify": "Leaked or stolen username/password combinations"
            },
            {
                "type": "Persona",
                "location": "Online platforms",
                "identify": "Hijacked or modified social media profiles"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Credentials",
                "location": "Adversary-controlled systems or underground marketplaces",
                "identify": "Resold or reused stolen credentials"
            },
            {
                "type": "Persona",
                "location": "Target environment or external platforms",
                "identify": "Compromised user accounts leveraged for malicious campaigns"
            }
        ],
        "detection_methods": [
            "Monitor unusual login attempts, including anomalous geolocations or multiple failed password attempts",
            "Track newly created or recently modified accounts claiming affiliation with the organization",
            "Correlate public breach data with internal user directories to identify compromised credentials",
            "Investigate suspicious inbound messages from known contacts that appear abnormal or malicious"
        ],
        "apt": [
            "DEV-0537",  # Example from references
            "APT28",     # Commonly associated with credential theft and account compromise
            "Charming Kitten"  # Another group known for compromising accounts
        ],
        "spl_query": [
            "index=auth (action=failure OR action=success) user=* \n| stats count by user, src_ip, action \n| where count > 10"  
        ],
        "hunt_steps": [
            "Review logs for brute-force attempts, password spraying, or repeated login failures.",
            "Identify new or unexpected accounts in corporate directory or social media presence.",
            "Compare known data breaches against internal credential use for potential account compromise.",
            "Check for sudden changes in user account details, especially those with privileged access."
        ],
        "expected_outcomes": [
            "Detection of compromised accounts used for social engineering or further attacks.",
            "Identification of suspicious login behavior and impersonation attempts on social media or email.",
            "Increased visibility into account-based threats, enabling proactive remediation."
        ],
        "false_positive": "Legitimate new hires, rebranding efforts, or changes in user job roles may appear similar to adversary compromise. Baseline and validate these scenarios.",
        "clearing_steps": [
            "Reset or revoke credentials for compromised accounts and enable MFA.",
            "Remove or disable any newly created malicious accounts, especially if they impersonate legitimate users.",
            "Notify impacted users or business partners of potential compromise and instruct them to change passwords.",
            "Perform a thorough review of account permissions and reduce privileges where possible."
        ],
        "mitre_mapping": [
            {
                "tactic": "Initial Access",
                "technique": "Phishing (T1566)",
                "example": "Adversaries may use compromised accounts to phish other users."
            },
            {
                "tactic": "Collection",
                "technique": "Phishing for Information (T1598)",
                "example": "Adversaries may leverage compromised email or social media accounts to gather sensitive data."
            }
        ],
        "watchlist": [
            "New or significantly modified social media accounts claiming organizational affiliation",
            "Repeated login attempts from unusual geolocations or IP addresses",
            "Password reset events not initiated by the legitimate user"
        ],
        "enhancements": [
            "Implement advanced threat intelligence feeds to identify stolen credentials on underground forums.",
            "Use risk-based conditional access policies to lock accounts after suspicious activity.",
            "Leverage machine learning anomaly detection to spot unusual login behaviors at scale."
        ],
        "summary": "Compromising existing accounts enables adversaries to leverage established trust relationships for social engineering, phishing, or further intrusion activities.",
        "remediation": "Reset compromised accounts, enforce MFA, limit user privileges, and remove or suspend maliciously modified personas or profiles.",
        "improvements": "Adopt robust identity and access management solutions, proactively monitor brand mentions and suspicious persona changes, and maintain rigorous security awareness training around account compromise threats."
    }
