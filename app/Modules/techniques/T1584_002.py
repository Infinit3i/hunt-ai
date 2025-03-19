def get_content():
    return {
        "id": "T1584.002",  # Tactic Technique ID
        "url_id": "1584/002",  # URL segment for technique reference
        "title": "Compromise Infrastructure: DNS Server",  # Name of the attack technique
        "description": "Adversaries may compromise third-party DNS servers to alter DNS records, redirect traffic, and facilitate malicious activities such as command and control or credential access.",  # Simple description
        "tags": [
            "dns server compromise",
            "dns hijacking",
            "infrastructure compromise",
            "resource development"
        ],
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "DNS",  # Protocol used in the attack technique
        "os": "N/A",  # Targeted operating systems
        "tips": [
            "Consider monitoring for anomalous resolution changes for domain addresses.",
            "Tailor monitoring to specific domains of interest, as benign resolution changes occur frequently.",
            "Focus detection efforts on Command and Control traffic if direct detection is difficult."
        ],
        "data_sources": "Domain Name",  # Data sources relevant to detection
        "log_sources": [
            {"type": "Domain Name", "source": "Active DNS", "destination": ""},
            {"type": "Domain Name", "source": "Passive DNS", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "", "location": "", "identify": ""}
        ],
        "destination_artifacts": [
            {"type": "", "location": "", "identify": ""}
        ],
        "detection_methods": [
            "Monitor DNS record changes and anomalies in domain resolution.",
            "Check for suspicious subdomains pointing to malicious servers.",
            "Monitor certificate issuance logs for unexpected domain certificates."
        ],
        "apt": [
            "OilRig"
        ],
        "spl_query": [
            "index=dns \n| stats count by query, answer"
        ],
        "hunt_steps": [
            "Check for unusual or sudden DNS resolution changes in logs.",
            "Identify subdomains that unexpectedly point to non-standard or malicious IP addresses.",
            "Correlate DNS changes with certificate issuance or other suspicious network events."
        ],
        "expected_outcomes": [
            "Identification of compromised DNS records or subdomains.",
            "Detection of malicious infrastructure used for redirection or data exfiltration."
        ],
        "false_positive": "Legitimate DNS changes can occur regularly; verify business context and domain owner intentions before concluding malicious activity.",
        "clearing_steps": [
            "Revert any unauthorized DNS changes at the registrar or DNS hosting provider.",
            "Reset credentials associated with compromised DNS server or registrar accounts.",
            "Enable multifactor authentication (MFA) on domain registrar and DNS provider accounts.",
            "Monitor DNS records closely for further unauthorized changes."
        ],
        "mitre_mapping": [
            {
                "tactic": "Resource Development",
                "technique": "Obtain Capabilities: Digital Certificates (T1588.004)",
                "example": "Adversaries may combine compromised DNS with valid certificates to mimic trusted communications."
            }
        ],
        "watchlist": [
            "New or unknown subdomains suddenly appearing in DNS records.",
            "Unusual or frequent changes to DNS configurations.",
            "Suspicious certificate requests for domains/subdomains."
        ],
        "enhancements": [
            "Automate DNS monitoring and integrate results with threat intelligence feeds.",
            "Leverage certificate transparency logs to detect unauthorized certificate issuance."
        ],
        "summary": "Adversaries can compromise third-party DNS servers to redirect or intercept network traffic, enabling them to facilitate malicious activities such as C2, data collection, and credential access.",
        "remediation": "Secure DNS server accounts, implement MFA, regularly audit DNS records, consider DNSSEC, and monitor certificate transparency logs.",
        "improvements": "Adopt robust domain monitoring solutions, maintain strong domain registrar security practices, and integrate DNS/certificate monitoring into your SIEM for continuous oversight."
    }
