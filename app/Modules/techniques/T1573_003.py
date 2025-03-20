def get_content():
    return {
        "id": "T1587.003",  # Tactic Technique ID
        "url_id": "1587/003",  # URL segment for technique reference
        "title": "Develop Capabilities: Digital Certificates",  # Name of the attack technique
        "description": "Adversaries may create self-signed SSL/TLS certificates to facilitate encrypted communications, such as C2 traffic, or to enable adversary-in-the-middle attacks if the certificate is installed in a trusted store.",  # Simple description
        "tags": [
            "Digital Certificates",
            "SSL/TLS",
            "Resource Development",
            "Self-Signed Certificates",
            "Adversary-in-the-Middle",
            "Install Root Certificate",
            "PWC WellMess",
            "Talos Promethium",
            "Cisco Talos Transparent Tribe",
            "Encryption"
        ],  # Up to 10 tags
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "SSL/TLS",  # Protocol used in the attack technique
        "os": "N/A",  # Not OS-specific (PRE-ATT&CK)
        "tips": [
            "Use certificate transparency services to track suspicious or newly issued certificates",
            "Pivot on certificate metadata to discover related adversary infrastructure",
            "Correlate usage of self-signed certificates with encrypted C2 or adversary-in-the-middle activity"
        ],
        "data_sources": "Internet Scan: Response Content",
        "log_sources": [],
        "source_artifacts": [
            {
                "type": "Self-Signed Digital Certificates",
                "location": "Adversary environment or infrastructure",
                "identify": "Certificates used to encrypt malicious traffic or facilitate MitM"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Trusted or Deployed Certificates",
                "location": "Adversary-controlled infrastructure or compromised systems",
                "identify": "Certificates installed or leveraged for malicious SSL/TLS"
            }
        ],
        "detection_methods": [
            "Track SSL/TLS certificates in use across known adversary infrastructure",
            "Focus on follow-on behaviors such as encrypted C2 traffic or root certificate installations",
            "Monitor for certificate details (issuer, subject, validity) that deviate from trusted norms"
        ],
        "apt": [
            "Promethium",
            "Transparent Tribe",
            "WellMess"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Search for newly observed certificates with suspicious or generic issuer/subject details",
            "Correlate certificate usage with known adversary IP ranges or domains",
            "Identify abrupt changes in SSL/TLS certificate usage on malicious or suspicious servers"
        ],
        "expected_outcomes": [
            "Detection of self-signed certificates used for malicious activities",
            "Identification of related adversary infrastructure through certificate metadata pivoting",
            "Mitigation of adversary-in-the-middle attempts by blocking untrusted certificates"
        ],
        "false_positive": "Legitimate testing or development environments may use self-signed certificates. Validate context and usage to differentiate malicious behavior.",
        "clearing_steps": [
            "N/A (Occurs outside victim visibility; clearing steps not typically applicable in victim environment)"
        ],
        "mitre_mapping": [
            {
                "tactic": "Resource Development",
                "technique": "Develop Capabilities: Digital Certificates (T1587.003)",
                "example": "Creating self-signed SSL/TLS certificates to encrypt C2 traffic or enable MitM"
            }
        ],
        "watchlist": [
            "Certificates with mismatched or incomplete issuer/subject data",
            "Rapid or frequent certificate rotations on known adversary infrastructure",
            "Certificates used by domains or IPs associated with malicious activity"
        ],
        "enhancements": [
            "Leverage certificate transparency logs to detect suspicious certificate issuances",
            "Integrate certificate intelligence into threat hunting and correlation with adversary domains",
            "Implement certificate pinning or known/trusted CA checks to mitigate self-signed certificate usage"
        ],
        "summary": "Adversaries may create self-signed SSL/TLS certificates to provide encryption for malicious traffic or to facilitate adversary-in-the-middle attacks, bypassing trust mechanisms normally reliant on recognized certificate authorities.",
        "remediation": "Implement robust certificate validation, monitor for suspicious or untrusted certificates in use, and ensure environment is configured to reject unauthorized root certificates.",
        "improvements": "Adopt certificate transparency monitoring, share threat intelligence on malicious certificate usage, and enforce best practices for SSL/TLS to reduce the effectiveness of self-signed certificates in adversary operations."
    }
